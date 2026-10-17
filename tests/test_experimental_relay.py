"""Independent exact-byte oracle for the synthetic bridge (no protocol parsing)."""
import asyncio
from types import SimpleNamespace

import pytest

from unrest_harness import experimental_relay as relay


class Writer:
    def __init__(self, blocked=False):
        self.data = bytearray()
        self.eof = False
        self.closed = False
        self.blocked = blocked
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.transport = SimpleNamespace(set_write_buffer_limits=lambda **kw: None,
                                         abort=lambda: None)

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        self.entered.set()
        if self.blocked:
            await self.release.wait()

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof = True

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


async def test_fragmented_interleaved_auth_payload_and_half_close():
    upstream, backend = asyncio.StreamReader(), asyncio.StreamReader()
    to_backend, to_relay = Writer(), Writer()
    losses = []
    bridge = relay.Bridge(backend, to_backend, lambda: losses.append(True))
    task = asyncio.create_task(bridge.attach(upstream, to_relay))
    greeting = (bridge.nonce + '\n').encode()
    request = bytes(range(256)) * 513
    response = bytes(reversed(range(256))) * 511
    for byte in greeting[:-1]:
        upstream.feed_data(bytes([byte]))
        await asyncio.sleep(0)
    upstream.feed_data(greeting[-1:] + request[:17])
    await bridge.connected.wait()
    for i in range(0, max(len(request), len(response)), 73):
        upstream.feed_data(request[17 + i:17 + i + 73])
        backend.feed_data(response[i:i + 73])
        await asyncio.sleep(0)
    upstream.feed_eof()
    await asyncio.sleep(0)
    assert to_backend.eof
    backend.feed_eof()
    await task
    assert bytes(to_backend.data) == request
    assert bytes(to_relay.data) == response
    assert to_relay.eof and len(losses) >= 2


@pytest.mark.parametrize('kind', ['wrong', 'oversize', 'short', 'stall'])
async def test_auth_refuses_without_forwarding(kind, monkeypatch):
    monkeypatch.setattr(relay, 'AUTH_SECONDS', .01)
    reader, backend = asyncio.StreamReader(), asyncio.StreamReader()
    outbound, peer = Writer(), Writer()
    losses = []
    bridge = relay.Bridge(backend, outbound, lambda: losses.append(True))
    if kind in ('wrong', 'oversize'):
        reader.feed_data(b'x' * (65 if kind == 'wrong' else 4096))
    elif kind == 'short':
        reader.feed_data(b'x')
        reader.feed_eof()
    await bridge.attach(reader, peer)
    assert not bridge.connected.is_set()
    assert not outbound.data and peer.closed and losses


async def test_first_connection_consumed_even_on_wrong_auth():
    backend = asyncio.StreamReader()
    bridge = relay.Bridge(backend, Writer(), lambda: None)
    bridge.server = SimpleNamespace(close=lambda: None)
    reader = asyncio.StreamReader()
    reader.feed_data(b'x' * 65)
    bridge.accept(reader, Writer())
    await asyncio.gather(*bridge.tasks)
    replay = asyncio.StreamReader()
    replay.feed_data((bridge.nonce + '\n').encode())
    rejected = Writer()
    bridge.accept(replay, rejected)
    assert rejected.closed and len(bridge.tasks) == 1


async def test_stalled_writer_bounded_and_cancellation_drains(monkeypatch):
    monkeypatch.setattr(relay, 'WRITE_SECONDS', .01)
    reader = asyncio.StreamReader()
    reader.feed_data(b'x' * (relay.BUFFER * 3))
    writer = Writer(blocked=True)
    with pytest.raises(TimeoutError):
        await relay.pump(reader, writer, lambda: None)
    assert len(writer.data) == relay.BUFFER
    upstream, backend = asyncio.StreamReader(), asyncio.StreamReader()
    upstream.feed_data((b'a' * 64) + b'\ninitial')
    bridge = relay.Bridge(backend, Writer(blocked=True), lambda: None, nonce='a' * 64)
    task = asyncio.create_task(bridge.attach(upstream, Writer()))
    bridge.tasks.add(task)
    await bridge.connected.wait()
    await bridge.close()
    assert task.done()


def test_wrong_argv_rejected_before_network(monkeypatch):
    monkeypatch.setattr(relay.sys, 'argv', ['relay', 'app-server', '--anything'])
    monkeypatch.setattr(relay.socket, 'create_connection', lambda *a, **k: pytest.fail('connected'))
    with pytest.raises(ValueError, match='argv'):
        relay.main()


@pytest.mark.parametrize('first_eof', [0, 10])
def test_relay_forward_exact_bytes_both_half_close_orders(monkeypatch, first_eof):
    source = {0: [b'\x00request\xff', b'fragment', b''],
              10: [b'response\x00', b'\xfftail', b'']}
    expected = {10: b'\x00request\xfffragment', 1: b'response\x00\xfftail'}
    result = {10: bytearray(), 1: bytearray()}
    closed, shutdown = [], []
    def ready(readers, writers, errors, timeout):
        # Finish one input side early; the other must continue after half-close.
        preferred = first_eof if first_eof in readers else next(iter(readers), None)
        return ([] if preferred is None else [preferred], writers, [])
    monkeypatch.setattr(relay.select, 'select', ready)
    monkeypatch.setattr(relay.os, 'set_blocking', lambda *a: None)
    monkeypatch.setattr(relay.os, 'read', lambda fd, size: source[fd].pop(0))
    def partial_write(fd, data):
        count = min(3, len(data))
        result[fd].extend(data[:count])
        return count
    monkeypatch.setattr(relay.os, 'write', partial_write)
    monkeypatch.setattr(relay.os, 'close', closed.append)
    connection = SimpleNamespace(setblocking=lambda b: None, fileno=lambda: 10,
                                 shutdown=shutdown.append)
    relay.forward(connection)
    assert {fd: bytes(data) for fd, data in result.items()} == expected
    assert closed == [1] and shutdown == [relay.socket.SHUT_WR]


async def test_close_before_attach_first_instruction_closes_owned_socket():
    bridge = relay.Bridge(asyncio.StreamReader(), Writer(), lambda: None)
    bridge.server = SimpleNamespace(close=lambda: None, wait_closed=asyncio.sleep)
    # A real server's wait_closed has no positional argument.
    async def closed():
        pass
    bridge.server.wait_closed = closed
    writer = Writer()
    bridge.accept(asyncio.StreamReader(), writer)
    await bridge.close()
    assert writer.closed and all(task.done() for task in bridge.tasks)


@pytest.mark.parametrize('kind', ['bridge', 'lifetime'])
@pytest.mark.parametrize('greeting', ['idle', 'wrong', 'stalled', 'prestart'])
async def test_real_server_drains_active_and_queued_connections(kind, greeting):
    from unrest_harness.experimental_session import _FixtureLifetime
    owner = (relay.Bridge(asyncio.StreamReader(), Writer(), lambda: None)
             if kind == 'bridge' else _FixtureLifetime())
    accepted = asyncio.Event()
    def accept(reader, writer):
        owner.accept(reader, writer)
        if greeting == 'prestart':
            for task in owner.tasks:
                task.cancel()
        accepted.set()
    owner.server = await asyncio.start_server(accept, '127.0.0.1', 0)
    peer = None
    closing = None
    rescued = False
    try:
        _, peer = await asyncio.open_connection('127.0.0.1', owner.server.sockets[0].getsockname()[1])
        await accepted.wait()
        if greeting in ('idle', 'wrong'):
            peer.write(((owner.nonce if greeting == 'idle' else 'x' * 64) + '\n').encode())
            await peer.drain()
        if greeting == 'idle':
            await asyncio.wait_for(owner.connected.wait(), 1)
        closing = asyncio.create_task(owner.close())
        done, _ = await asyncio.wait({closing}, timeout=5)
        assert done, 'real Python Server.wait_closed blocked on accepted transport'
        closing.result()
        assert all(task.done() for task in owner.tasks)
        assert owner.writer.is_closing()
        assert all(task.done() and not task.cancelled() for task in owner.cleanup.writers.values())
        await owner.close()
    finally:
        if closing is not None and not closing.done():
            rescued = True
            for writer in owner.cleanup.writers:
                writer.transport.abort()
            for task in owner.tasks:
                task.cancel()
            await asyncio.wait({closing}, timeout=2)
        if peer is not None:
            peer.close()
            await asyncio.gather(peer.wait_closed(), return_exceptions=True)
        owner.server.close()
        await asyncio.wait_for(owner.server.wait_closed(), 2)
    assert not rescued


async def test_queued_replay_second_and_closing_callbacks_are_owned():
    from unrest_harness.experimental_session import _FixtureLifetime
    for kind in ('bridge', 'lifetime'):
        owner = (relay.Bridge(asyncio.StreamReader(), Writer(), lambda: None)
                 if kind == 'bridge' else _FixtureLifetime())
        # Accept all sockets into a deterministic callback queue before dispatch.
        queued = []
        owner.server = await asyncio.start_server(lambda r, w: queued.append((r, w)), '127.0.0.1', 0)
        port = owner.server.sockets[0].getsockname()[1]
        peers = []
        try:
            for _ in range(4):
                _, peer = await asyncio.open_connection('127.0.0.1', port)
                peers.append(peer)
                peer.write((owner.nonce + '\n').encode())
                await peer.drain()
            async with asyncio.timeout(1):
                while len(queued) != 4:
                    await asyncio.sleep(0)
            owner.accept(*queued[0])
            owner.accept(*queued[1])  # second/replayed authentication cannot attach
            closing = asyncio.create_task(owner.close())
            await asyncio.sleep(0)
            assert owner.closing
            for pair in queued[2:]:
                asyncio.get_running_loop().call_soon(owner.accept, *pair)
            done, _ = await asyncio.wait({closing}, timeout=5)
            assert done
            closing.result()
            assert len(owner.cleanup.writers) == 4
            assert all(wait.done() and not wait.cancelled() for wait in owner.cleanup.writers.values())
        finally:
            for _, writer in queued:
                writer.transport.abort()
            for peer in peers:
                peer.close()
            await asyncio.gather(*(peer.wait_closed() for peer in peers), return_exceptions=True)
            owner.server.close()
            await asyncio.wait_for(owner.server.wait_closed(), 2)


async def test_cleanup_timeout_retains_waiters_and_repeated_cancel(monkeypatch):
    monkeypatch.setattr(relay, 'WRITE_SECONDS', .03)
    release, entered = asyncio.Event(), asyncio.Event()
    class DelayedWriter(Writer):
        async def wait_closed(self):
            entered.set()
            await release.wait()
    writer = DelayedWriter()
    cleanup = relay.ConnectionCleanup()
    cleanup.register(writer)
    closing = asyncio.create_task(cleanup.close(None, set()))
    try:
        await entered.wait()
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        done, _ = await asyncio.wait({closing}, timeout=1)
        assert done
        with pytest.raises(TimeoutError, match='cleanup_uncertain'):
            closing.result()
        waiter = cleanup.writers[writer]
        assert not waiter.done() and not waiter.cancelled()
        owner = cleanup.owner
        with pytest.raises(TimeoutError):
            await cleanup.close(None, set())
        assert cleanup.owner is owner
    finally:
        release.set()
        await asyncio.gather(*cleanup.writers.values())


async def test_server_barrier_and_successful_close_survive_repeated_cancellation():
    released, waiting, transport_closed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    class ControlledWriter(Writer):
        def close(self):
            super().close()
            transport_closed.set()
        async def wait_closed(self):
            waiting.set()
            await released.wait()
    async def server_closed():
        await transport_closed.wait()  # Python 3.13 active-transport semantics.
    writer = ControlledWriter()
    bridge = relay.Bridge(asyncio.StreamReader(), Writer(), lambda: None)
    bridge.server = SimpleNamespace(close=lambda: None, wait_closed=server_closed)
    bridge.accept(asyncio.StreamReader(), writer)
    for task in bridge.tasks:
        task.cancel()  # observer never gets its first instruction
    closing = asyncio.create_task(bridge.close())
    try:
        await asyncio.wait_for(waiting.wait(), 1)
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        owner = bridge.cleanup.owner
        waiter = bridge.cleanup.writers[writer]
        assert not waiter.cancelled() and writer.closed
        released.set()
        done, _ = await asyncio.wait({closing}, timeout=1)
        assert done
        with pytest.raises(asyncio.CancelledError):
            closing.result()
        await bridge.close()
        assert bridge.cleanup.owner is owner and waiter.done() and not waiter.cancelled()
    finally:
        released.set()
        await asyncio.gather(closing, return_exceptions=True)


@pytest.mark.parametrize('blocked', ['server', 'observer'])
async def test_final_barriers_are_bounded_and_refusal_is_retained(blocked, monkeypatch):
    monkeypatch.setattr(relay, 'WRITE_SECONDS', .02)
    release, entered = asyncio.Event(), asyncio.Event()
    async def observer():
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
    async def server_closed():
        if blocked == 'server':
            await release.wait()
    tasks = set()
    if blocked == 'observer':
        tasks.add(asyncio.create_task(observer()))
        await entered.wait()
    server = SimpleNamespace(close=lambda: None, wait_closed=server_closed)
    cleanup = relay.ConnectionCleanup()
    closing = asyncio.create_task(cleanup.close(server, tasks))
    try:
        done, _ = await asyncio.wait({closing}, timeout=1)
        assert done
        with pytest.raises(TimeoutError, match='cleanup_uncertain'):
            closing.result()
        with pytest.raises(TimeoutError):
            await cleanup.close(server, tasks)
        if tasks:
            assert not next(iter(tasks)).done()
    finally:
        release.set()
        await asyncio.gather(*tasks)


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('stage', ['restrict', 'observe', 'read', 'write', 'drain'])
@pytest.mark.parametrize('broken_diagnostic', [False, True])
@pytest.mark.parametrize('io_error', [False, True])
async def test_pump_failure_revokes_in_same_callback_slot(
        direction, stage, broken_diagnostic, io_error):
    from unrest_harness.experimental_diagnostics import StartupDiagnostics
    from unrest_harness.experimental_lease import LeaseRefused

    original = (OSError('PRIVATE_IO_FAILURE') if io_error
                else LeaseRefused('provider_notification_invalid'))
    category = 'os_error' if io_error else 'provider_notification_invalid'
    diagnostics = StartupDiagnostics()
    events, slots, errors = [], [], []
    revoked = False
    def record_slot():
        slots.append((revoked, diagnostics.snapshot()['failure']['category']))
    def fail():
        asyncio.get_running_loop().call_soon(record_slot)
        raise original
    class FailedReader(asyncio.StreamReader):
        async def read(self, n=-1):
            fail()
    class FailedWriter(Writer):
        def write(self, data):
            if stage == 'write':
                fail()
            super().write(data)
        async def drain(self):
            if stage == 'drain':
                fail()
            await super().drain()
    def diagnostic(error):
        errors.append(error)
        events.append('diagnostic')
        diagnostics.fail(error)
        if broken_diagnostic:
            raise RuntimeError('PRIVATE_DIAGNOSTIC_CALLBACK_BODY')
    def lost():
        nonlocal revoked
        events.append('lost')
        revoked = True
    upstream, backend = asyncio.StreamReader(), asyncio.StreamReader()
    target_reader = FailedReader() if stage == 'read' else asyncio.StreamReader()
    if direction == 'adapter':
        upstream = target_reader
    else:
        backend = target_reader
    outbound, peer = Writer(), Writer()
    if direction == 'adapter':
        outbound = FailedWriter()
    else:
        peer = FailedWriter()
    bridge = relay.Bridge(backend, outbound, lost, diagnostic_failure=diagnostic)
    if stage == 'restrict':
        setattr(bridge, 'restrict_' + direction, lambda data: fail())
    if stage == 'observe':
        setattr(bridge, 'observe_' + direction, lambda data: fail())
    # Admission consumes only the greeting, preserving the failing payload.
    upstream.feed_data((bridge.nonce + '\n').encode())
    target_reader.feed_data(b'PRIVATE_FRAME_BODY')
    task = asyncio.create_task(bridge.attach(upstream, peer))
    bridge.tasks.add(task)
    if io_error:
        await task  # attach keeps its existing handled-I/O-error behavior.
    else:
        with pytest.raises(LeaseRefused) as caught:
            await task
        assert caught.value is original
    assert errors[0] is original and events[:2] == ['diagnostic', 'lost']
    assert slots == [(True, category)]
    assert any(t is not task and not t.cancelled() and t.exception() is original
               for t in bridge.tasks)
    if stage != 'drain':
        assert not (outbound if direction == 'adapter' else peer).data
    assert 'PRIVATE' not in str(diagnostics.snapshot())
    first = diagnostics.snapshot()['failure']
    diagnostics.fail(RuntimeError('PRIVATE_LATER_FAILURE'))
    assert diagnostics.snapshot()['failure'] == first
    with pytest.raises(TimeoutError, match='synthetic_connection_cleanup_uncertain'):
        await bridge.close()
    cleanup_owner = bridge.cleanup.owner
    with pytest.raises(TimeoutError, match='synthetic_connection_cleanup_uncertain'):
        await bridge.close()
    assert bridge.cleanup.owner is cleanup_owner and cleanup_owner.done()


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
@pytest.mark.parametrize('intentional', [False, True])
async def test_pump_cancellation_revokes_before_done_callback(direction, intentional):
    entered = asyncio.Event()
    events, slots = [], []
    class WaitingReader(asyncio.StreamReader):
        async def read(self, n=-1):
            entered.set()
            return await super().read(n)
    upstream, backend = asyncio.StreamReader(), asyncio.StreamReader()
    if direction == 'adapter':
        upstream = WaitingReader()
    else:
        backend = WaitingReader()
    bridge = relay.Bridge(backend, Writer(), lambda: events.append('lost'),
                         diagnostic_failure=lambda error: events.append(error))
    upstream.feed_data((bridge.nonce + '\n').encode())
    task = asyncio.create_task(bridge.attach(upstream, Writer()))
    bridge.tasks.add(task)
    await entered.wait()
    # Select the actual task running this direction, without timing sleeps.
    target = next(t for t in bridge.tasks if t is not task
                  and t.get_coro().cr_frame.f_locals['reader'] is
                  (upstream if direction == 'adapter' else backend))
    target.add_done_callback(lambda _: slots.append(list(events)))
    if intentional:
        await bridge.close()
    else:
        target.cancel('PRIVATE_CANCEL_BODY')
        with pytest.raises(asyncio.CancelledError):
            await task
        await bridge.close()
    assert slots
    if intentional:
        assert slots == [[]] and events == []
    else:
        assert isinstance(slots[0][0], asyncio.CancelledError)
        assert slots[0][0].args == ('PRIVATE_CANCEL_BODY',)
        assert slots[0][1] == 'lost'


@pytest.mark.parametrize('direction', ['adapter', 'backend'])
async def test_ordinary_eof_revokes_synchronously_without_failure(direction):
    upstream, backend = asyncio.StreamReader(), asyncio.StreamReader()
    events, slots = [], []
    outbound, peer = Writer(), Writer()
    bridge = relay.Bridge(backend, outbound, lambda: events.append('lost'),
                         diagnostic_failure=lambda error: events.append(error))
    upstream.feed_data((bridge.nonce + '\n').encode())
    task = asyncio.create_task(bridge.attach(upstream, peer))
    bridge.tasks.add(task)
    await bridge.connected.wait()
    reader = upstream if direction == 'adapter' else backend
    reader.feed_eof()
    asyncio.get_running_loop().call_soon(lambda: slots.append(list(events)))
    # The other EOF lets attach finish, without turning either EOF into failure.
    (backend if direction == 'adapter' else upstream).feed_eof()
    await task
    assert slots and slots[0] and all(e == 'lost' for e in events)
    assert outbound.eof and peer.eof
    await bridge.close()


async def test_attach_cancellation_before_pumps_start_records_original_and_revokes():
    events = []
    def diagnostic(error):
        events.append(error)
        raise RuntimeError('PRIVATE_DIAGNOSTIC_CALLBACK_BODY')
    bridge = relay.Bridge(asyncio.StreamReader(), Writer(), lambda: events.append('lost'),
                         diagnostic_failure=diagnostic)
    upstream = asyncio.StreamReader()
    upstream.feed_data((bridge.nonce + '\n').encode())
    task = asyncio.create_task(bridge.attach(upstream, Writer()))
    bridge.tasks.add(task)
    await bridge.connected.wait()
    task.cancel('original-cancellation')
    with pytest.raises(asyncio.CancelledError) as caught:
        await task
    assert any(e is caught.value for e in events)
    assert events[-1] == 'lost'
    assert all(t.done() for t in bridge.tasks)
    await bridge.close()
