"""Intentional teardown classification, with controlled actual transport witnesses."""
import asyncio
import hashlib
import json
import signal

import pytest
from tests.test_experimental_session import session as owner_fixture


@pytest.fixture
def session(tmp_path):
    return owner_fixture.__wrapped__(tmp_path, None)


async def test_owned_teardown_completes_after_native_drain_failure(session, monkeypatch, tmp_path):
    fixture = tmp_path / 'controlled.py'
    fixture.write_text(session.backend_launcher.read_text().replace('def main():',
        "def main():\n    signal.signal(signal.SIGUSR1, lambda *_: emit({'method': 'test/teardown', 'params': {}}))"))
    session.backend_launcher = fixture
    session.backend_digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    await session.start()
    closing = None
    release = asyncio.Event()
    entered = asyncio.Event()
    native = []
    try:
        await session.initialize_only()
        bridge = session.backends['worker'].bridge
        writer = bridge.writer
        drain = writer.drain
        async def held_drain():
            entered.set()
            await release.wait()
            try:
                await drain()
            except (BrokenPipeError, ConnectionResetError) as error:
                native.append(type(error).__name__)
                raise
        monkeypatch.setattr(writer, 'drain', held_drain)
        session.backends['worker'].process.send_signal(signal.SIGUSR1)
        await asyncio.wait_for(entered.wait(), 3)
        stop = session._stop_role
        observations = []
        async def stop_after_transport_teardown(role):
            observations.append({'owner_closing': session._closing, 'bridge_closing': bridge.closing,
                                 'broker_inactive': session.broker._active is None})
            # Real owned asyncio TCP transport closure; drain raises natively.
            writer.close()
            await writer.wait_closed()
            release.set()
            pumps = set(bridge.tasks)
            await asyncio.wait(pumps, timeout=1)
            await stop(role)
        monkeypatch.setattr(session, '_stop_role', stop_after_transport_teardown)
        closing = asyncio.create_task(session.close())
        done, pending = await asyncio.wait({closing}, timeout=12)
        assert done and not pending
        closing.result()
        failures = [type(t.exception()).__name__ for t in bridge.tasks
                    if t.done() and not t.cancelled() and t.exception() is not None]
        result = {'ordering': observations, 'native_errors': native, 'failed_tasks': failures,
                  'quarantined': session.quarantined, 'diagnostics': session.diagnostics(),
                  'reaped': all(x.process.returncode is not None for x in
                                [*session.roles.values(), *session.backends.values()])}
        (tmp_path / 'teardown-result.json').write_text(json.dumps(result, indent=2))
        assert native == ['ConnectionResetError'] and not failures and not session.quarantined
        assert observations == [{'owner_closing': True, 'bridge_closing': True, 'broker_inactive': True}]
        assert bridge.cleanup.owner.done()
        assert all(t.done() for t in bridge.tasks)
        assert all(t.done() and not t.cancelled() for t in bridge.cleanup.writers.values())
        assert session.startup_diagnostics['worker'].snapshot()['failure'] is None
        journal = (session.root / 'journal.jsonl').read_text()
        assert not any('\"event\": \"' + event + '\"' in journal for event in ('reserve', 'send', 'ack'))
        assert result['reaped']
    finally:
        release.set()
        if closing is None:
            closing = asyncio.create_task(session.close())
        done, pending = await asyncio.wait({closing}, timeout=12)
        if pending:
            for x in [*session.roles.values(), *session.backends.values()]:
                if x.process.returncode is None:
                    x.process.kill()
            await asyncio.wait({closing}, timeout=4)
        if closing.done() and not closing.cancelled():
            closing.exception()


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('stage', ['read', 'write', 'drain', 'write_eof', 'close', 'restrict', 'observe', 'eof'])
@pytest.mark.parametrize('error_type', [BrokenPipeError, ConnectionResetError, ConnectionError, OSError, TimeoutError])
@pytest.mark.parametrize('marked', [False, True])
async def test_operation_boundary(direction, stage, error_type, marked):
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_relay import Writer

    error = error_type('PRIVATE_CALLBACK_OR_IO_BODY')
    def fail(*args):
        raise error
    class Reader(asyncio.StreamReader):
        async def read(self, n=-1):
            if stage == 'read':
                fail()
            return await super().read(n)
    reader = Reader()
    reader.feed_data(b'PRIVATE_PAYLOAD' if stage not in ('write_eof', 'close', 'eof') else b'')
    reader.feed_eof()
    class Target(Writer):
        def write(self, data):
            if stage == 'write':
                fail()
            super().write(data)
        async def drain(self):
            if stage == 'drain':
                fail()
        def can_write_eof(self):
            return stage != 'close'
        def write_eof(self):
            if stage == 'write_eof':
                fail()
            super().write_eof()
        def close(self):
            if stage == 'close':
                fail()
            super().close()
    writer = Target()
    bridge = Bridge(reader if direction == 'backend' else asyncio.StreamReader(),
                    writer if direction == 'adapter' else Writer(),
                    fail if stage == 'eof' else lambda: None)
    if marked:
        bridge.begin_shutdown()
        bridge.begin_shutdown()
    task = asyncio.create_task(bridge._pump(reader, writer,
        fail if stage == 'observe' else None, fail if stage == 'restrict' else None))
    bridge.tasks.add(task)
    expected = marked and stage in ('read', 'write', 'drain', 'write_eof', 'close') and error_type in (BrokenPipeError, ConnectionResetError)
    if expected:
        await task
        await bridge.close()
    else:
        with pytest.raises(error_type) as caught:
            await task
        assert caught.value is error
        # A marker set after failure cannot retroactively turn it into success.
        bridge.begin_shutdown()
        with pytest.raises(TimeoutError, match='cleanup_uncertain'):
            await bridge.close()
        assert task.exception() is error


async def test_marker_is_synchronous_and_only_changes_classification():
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_relay import Writer
    writer = Writer()
    bridge = Bridge(asyncio.StreamReader(), writer, lambda: None)
    pending = asyncio.create_task(asyncio.Event().wait())
    bridge.tasks.add(pending)
    bridge.begin_shutdown()
    bridge.begin_shutdown()
    assert bridge.closing and not writer.closed and not pending.done()
    assert bridge.cleanup.owner is None and not bridge.cleanup.closing
    await bridge.close()
    assert pending.cancelled()


@pytest.mark.parametrize('marked', [False, True])
async def test_native_pipe_write_and_drain(marked):
    import os
    from unrest_harness.experimental_relay import Bridge
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(write_fd, 'wb', buffering=0)
    loop = asyncio.get_running_loop()
    protocol = asyncio.streams.FlowControlMixin(loop=loop)
    transport, _ = await loop.connect_write_pipe(lambda: protocol, stream)
    writer = asyncio.StreamWriter(transport, protocol, None, loop)
    # Close the actual read peer; asyncio reports its native pipe loss on drain.
    os.close(read_fd)
    reader = asyncio.StreamReader()
    reader.feed_data(b'owned-test-bytes')
    reader.feed_eof()
    bridge = Bridge(reader, writer, lambda: None)
    if marked:
        bridge.begin_shutdown()
    try:
        task = asyncio.create_task(bridge._pump(reader, writer, None, None))
        bridge.tasks.add(task)
        if marked:
            await task
            await bridge.close()
        else:
            with pytest.raises((BrokenPipeError, ConnectionResetError)):
                await task
            with pytest.raises(TimeoutError):
                await bridge.close()
    finally:
        transport.close()


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('marked', [False, True])
async def test_native_tcp_reset_read(direction, marked, monkeypatch):
    import socket
    import struct
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_relay import Writer
    accepted = asyncio.get_running_loop().create_future()
    server = await asyncio.start_server(lambda r, w: accepted.set_result((r, w)), '127.0.0.1', 0)
    peer = socket.socket()
    peer.setblocking(False)
    writer = None
    try:
        await asyncio.get_running_loop().sock_connect(peer, server.sockets[0].getsockname())
        reader, writer = await asyncio.wait_for(accepted, 1)
        original = reader.read
        observed = []
        async def read(n=-1):
            try:
                return await original(n)
            except ConnectionResetError as error:
                observed.append(error)
                raise
        monkeypatch.setattr(reader, 'read', read)
        target = Writer()
        bridge = Bridge(reader if direction == 'backend' else asyncio.StreamReader(),
                        target if direction == 'adapter' else Writer(), lambda: None)
        if marked:
            bridge.begin_shutdown()
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        peer.close()
        task = asyncio.create_task(bridge._pump(reader, target, None, None))
        bridge.tasks.add(task)
        done, pending = await asyncio.wait({task}, timeout=2)
        assert done and not pending
        assert len(observed) == 1 and type(observed[0]) is ConnectionResetError
        if marked:
            task.result()
            await bridge.close()
        else:
            with pytest.raises(ConnectionResetError):
                task.result()
            with pytest.raises(TimeoutError):
                await bridge.close()
    finally:
        peer.close()
        if writer is not None:
            writer.close()
            await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        server.close()
        await asyncio.wait_for(server.wait_closed(), 2)


@pytest.mark.parametrize('launch_number', [1, 2])
async def test_late_registration_marks_every_bridge_before_peer_teardown(session, monkeypatch, launch_number):
    from tests.test_experimental_session import test_registration_after_close_deadline_bounded
    stop = session._stop_role_owned
    observations = []
    async def checked(role):
        observations.append(len(session.backends))
        assert session.stopped and session.broker._active is None
        assert all(b.bridge.closing for b in session.backends.values())
        await stop(role)
    monkeypatch.setattr(session, '_stop_role_owned', checked)
    await test_registration_after_close_deadline_bounded(session, monkeypatch, launch_number)
    assert all(b.bridge.closing for b in session.backends.values())
    if launch_number == 2:
        assert observations == [1]


async def test_all_bridges_marked_before_first_adapter_stop(session, monkeypatch):
    await session.start()
    try:
        await session.initialize_only()
        await session._launch_role('validator', session.ledger.turn_deadline())
        assert len(session.backends) == 2
        stop = session._stop_role_owned
        order = []
        async def checked(role):
            assert all(b.bridge.closing for b in session.backends.values())
            assert all(b.stop_task is None for b in session.backends.values())
            order.append(role)
            await stop(role)
        monkeypatch.setattr(session, '_stop_role_owned', checked)
        await session.close()
        assert len(order) == 2 and not session.quarantined
    finally:
        await session.close()


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
async def test_actual_socket_halfclose_preserves_opposite_stream(direction):
    import socket
    from unrest_harness.experimental_relay import Bridge
    streams = []
    for _ in range(2):
        a, b = socket.socketpair()
        streams.extend([await asyncio.open_connection(sock=a), await asyncio.open_connection(sock=b)])
    upstream, adapter = streams[:2]
    backend, service = streams[2:]
    bridge = Bridge(*backend, lambda: None)
    bridge.cleanup.register(upstream[1])
    bridge.tasks.update({asyncio.create_task(bridge._pump(upstream[0], backend[1], None, None)),
                         asyncio.create_task(bridge._pump(backend[0], upstream[1], None, None))})
    first, second = (adapter, service) if direction == 'adapter' else (service, adapter)
    try:
        first[1].write(b'first\x00\xff')
        first[1].write_eof()
        assert await asyncio.wait_for(second[0].read(), 1) == b'first\x00\xff'
        second[1].write(b'after-half-close')
        second[1].write_eof()
        assert await asyncio.wait_for(first[0].read(), 1) == b'after-half-close'
        done, pending = await asyncio.wait(bridge.tasks, timeout=1)
        assert not pending and all(t.exception() is None for t in done)
        await bridge.close()
    finally:
        for _, writer in streams:
            writer.close()
        await asyncio.gather(*(w.wait_closed() for _, w in streams), return_exceptions=True)


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('marked', [False, True])
async def test_native_os_write_broken_pipe(direction, marked):
    import os
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_relay import Writer
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    observed = []
    class PipeWriter(Writer):
        def write(self, data):
            try:
                os.write(write_fd, data)
            except BrokenPipeError as error:
                observed.append(error)
                raise
    reader = asyncio.StreamReader()
    reader.feed_data(b'controlled-pipe')
    reader.feed_eof()
    writer = PipeWriter()
    bridge = Bridge(reader if direction == 'backend' else asyncio.StreamReader(),
                    writer if direction == 'adapter' else Writer(), lambda: None)
    if marked:
        bridge.begin_shutdown()
    try:
        task = asyncio.create_task(bridge._pump(reader, writer, None, None))
        bridge.tasks.add(task)
        if marked:
            await task
            await bridge.close()
        else:
            with pytest.raises(BrokenPipeError) as caught:
                await task
            assert caught.value is observed[0]
            with pytest.raises(TimeoutError):
                await bridge.close()
        assert len(observed) == 1 and type(observed[0]) is BrokenPipeError
    finally:
        os.close(write_fd)


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('halfclose', [False, True])
@pytest.mark.parametrize('marked', [False, True])
async def test_native_buffered_pipe_halfclose_failure(direction, halfclose, marked):
    import os
    from unrest_harness.experimental_relay import Bridge
    from tests.test_experimental_relay import Writer
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(write_fd, 'wb')
    stream.write(b'pending-native-buffer')
    os.close(read_fd)
    observed = []
    class PipeWriter(Writer):
        def can_write_eof(self):
            return halfclose
        def finish(self):
            # Closing the write side flushes actual pending pipe bytes. The
            # departed read peer makes the native buffered close raise EPIPE.
            try:
                stream.close()
            except BrokenPipeError as error:
                observed.append(error)
                raise
        def write_eof(self):
            self.finish()
        def close(self):
            self.finish()
    reader = asyncio.StreamReader()
    reader.feed_eof()
    writer = PipeWriter()
    bridge = Bridge(reader if direction == 'backend' else asyncio.StreamReader(),
                    writer if direction == 'adapter' else Writer(), lambda: None)
    if marked:
        bridge.begin_shutdown()
    try:
        task = asyncio.create_task(bridge._pump(reader, writer, None, None))
        bridge.tasks.add(task)
        if marked:
            await task
            await bridge.close()
        else:
            with pytest.raises(BrokenPipeError) as caught:
                await task
            assert caught.value is observed[0]
            with pytest.raises(TimeoutError):
                await bridge.close()
        assert len(observed) == 1 and stream.closed
    finally:
        stream.close()
