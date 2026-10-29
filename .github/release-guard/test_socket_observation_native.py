"""Actual kernel cookies and reciprocal peer inodes; no fabricated tables."""
import importlib.util
import os
from pathlib import Path
import socket
import struct
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.uname().machine != "x86_64",
    reason="requires actual Linux socket diagnostics")

spec = importlib.util.spec_from_file_location(
    "socket_observation", Path(__file__).with_name("socket_observation.py")
)
assert spec is not None and spec.loader is not None
observation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observation)


def cookie(stream):
    return struct.unpack("=Q", stream.getsockopt(socket.SOL_SOCKET, 57, 8))[0]


def test_actual_same_loop_admission_precedes_ordinary_send_and_accept():
    import asyncio
    from endpoint_policy import Endpoints, Owner, Route
    from linux_observation import process_identity
    from process_ledger import Birth, Ledger
    from socket_observation import acquire_tcp
    async def run():
        ledger = Ledger('queued-control')
        actual = process_identity(os.getpid())
        birth = Birth.read(actual)
        ledger.kernel(0, {'kind': 'kernel_root', 'identity': actual})
        pins = (('control', 'a' * 64),)
        ledger.register(birth, 'root', pins, 'seal', case='queued-control', command_class='socket-control')
        ledger.control(birth, 'root', 0, 0, 'core-ready', {'pins': pins})
        ledger.control(birth, 'root', 0, 1, 'body-ready', {'seal': 'seal'})
        owner = Owner(birth, 'root', 0)
        endpoints = Endpoints(ledger)
        loop = asyncio.get_running_loop()
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.setblocking(False)
            client.setblocking(False)
            port = listener.getsockname()[1]
            route = Route('queued', 'queued-control', owner, owner, port)
            endpoints.declare(route)
            fresh_listener = acquire_tcp(birth, listener.fileno())
            endpoints.listen(route.name, fresh_listener)
            ticket = endpoints.connect(route.name, fresh_listener, acquire_tcp(birth, client.fileno()))
            await loop.sock_connect(client, ('127.0.0.1', port))
            assert client.send(b'queued') == 6
            assert ticket.listener==fresh_listener and endpoints.connection_counts[route.name]==1
            accepted, _ = await asyncio.wait_for(loop.sock_accept(listener), 1)
            with accepted:
                accepted.setblocking(False)
                assert acquire_tcp(birth,accepted.fileno()).uid==birth.uid
                assert await asyncio.wait_for(loop.sock_recv(accepted, 6), 1) == b'queued'
                assert not endpoints.poison and not ledger.poison
    asyncio.run(run())


@pytest.mark.parametrize('buffered', [False, True])
def test_actual_dead_client_keeps_original_wait_and_socket_cookie(buffered):
    """Keep actual kernel acquisition and wait; no guard payload/EOF claim."""
    import select
    import signal
    import time
    from linux_observation import credential_identity
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        address = listener.getsockname()
        read, write = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(read)
                listener.close()
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                signal.alarm(5)
                client.connect(address)
                if buffered:
                    client.sendall(b'x')
                os.write(write, b'R')
                while True:
                    signal.pause()
            finally:
                os._exit(125)
        os.close(write)
        client.close()  # Do not retain the child's file description in its parent.
        try:
            assert select.select([read], [], [], 2)[0] and os.read(read, 1) == b'R'
            born = credential_identity(child)
            assert born['ppid'] == os.getpid()
            os.kill(child, signal.SIGTERM)
            actual, raw = os.waitpid(child, 0)
            assert actual == child and raw == int(signal.SIGTERM)
            server, _ = listener.accept()  # Deliberately after actual death/reap.
            with server:
                deadline = time.monotonic() + 1
                while observation.retained_tcp_descriptor(os.getpid(), server.fileno())['state'] != 8:
                    assert time.monotonic() < deadline
                    time.sleep(.001)
                if buffered:
                    assert server.recv(1) == b'x'  # The query neither reads nor discards payload.
                eof = observation.retained_tcp_descriptor(os.getpid(), server.fileno())
                assert eof['state'] == 8 and eof['socket_cookie'] == cookie(server)
                assert server.recv(1) == b''
        finally:
            try:
                pending, _ = os.waitpid(child, os.WNOHANG)
                if not pending:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            except ChildProcessError:
                pass
            os.close(read)


def tcp_row(descriptor):
    row=observation.retained_tcp_descriptor(os.getpid(),descriptor)
    assert row is not None
    local,remote=row['local_address'],row['peer_address']
    return {**row,'local_host':local[0],'local_port':local[1],
        'remote_host':remote[0] if remote else '0.0.0.0','remote_port':remote[1] if remote else 0}


def test_tcp_fd_inode_cookie_and_closed_descriptor():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            accepted, _ = listener.accept()
            with accepted:
                rows = [tcp_row(stream.fileno()) for stream in (listener,client,accepted)]
                saved = {}
                for stream in (listener, client, accepted):
                    row = next(value for value in rows if value["fd"] == stream.fileno())
                    assert row["socket_cookie"] == cookie(stream)
                    assert row["inode"] == os.fstat(stream.fileno()).st_ino
                    assert row["socket_uid"] == os.getuid()
                    saved[stream.fileno()] = row
                client_cookie = cookie(client)
                client_fd = client.fileno()
                assert saved[listener.fileno()]["state"] == 10
                assert saved[client.fileno()]["state"] == saved[accepted.fileno()]["state"] == 1
                assert saved[client.fileno()]["local_port"] == saved[accepted.fileno()]["remote_port"]
        assert observation.retained_tcp_descriptor(os.getpid(),client_fd) is None
        assert all(row["socket_cookie"] != client_cookie for row in (tcp_row(listener.fileno()),))


def test_unix_pair_reciprocal_kernel_inodes():
    left, right = socket.socketpair()
    try:
        rows = observation.unix_pair(os.getpid(), [left.fileno(), right.fileno()])
        assert [row["socket_cookie"] for row in rows] == [cookie(left), cookie(right)]
        assert rows[0]["peer_inode"] == os.fstat(right.fileno()).st_ino
        assert rows[1]["peer_inode"] == os.fstat(left.fileno()).st_ino
    finally:
        left.close()
        right.close()


def test_retained_closed_tcp_identity_and_descriptor_reuse():
    import time
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    client = socket.socket()
    client.connect(listener.getsockname())
    server, _ = listener.accept()
    descriptor = server.fileno()
    try:
        live = observation.retained_tcp_descriptor(os.getpid(), descriptor)
        assert live is not None and live['state'] == 1
        assert live['local_address'] == server.getsockname()
        assert live['peer_address'] == client.getsockname()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        client.close()
        deadline = time.monotonic() + 2
        while True:
            closed = observation.retained_tcp_descriptor(os.getpid(), descriptor)
            if closed is not None and closed['state'] == 7:
                break
            assert time.monotonic() < deadline
            time.sleep(.001)
        assert closed['peer_address'] is None
        assert (closed['inode'], closed['socket_cookie']) == (live['inode'], live['socket_cookie'])
        with socket.socket() as replacement:
            os.dup2(replacement.fileno(), descriptor)
            reused = observation.retained_tcp_descriptor(os.getpid(), descriptor)
            assert reused is not None and reused['state'] == 7
            assert reused['socket_cookie'] != live['socket_cookie']
    finally:
        server.close()
        client.close()
        listener.close()


def test_accepted_peer_survives_one_shot_listener_close():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    client = socket.socket()
    try:
        admitted = tcp_row(listener.fileno())
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            listener.close()
            rows = [tcp_row(stream.fileno()) for stream in (client,server)]
            own = next(row for row in rows if row['fd'] == client.fileno())
            peer = next(row for row in rows if row['fd'] == server.fileno())
            assert peer['socket_cookie'] == cookie(server)
            assert (peer['local_host'], peer['local_port']) == (own['remote_host'], own['remote_port'])
            assert (peer['remote_host'], peer['remote_port']) == (own['local_host'], own['local_port'])
            assert peer['local_port'] == admitted['local_port']

    finally:
        listener.close()
        client.close()


def test_stale_unix_pair_cannot_authorize_reused_tcp_descriptor():
    import pytest
    left, right = socket.socketpair()
    descriptors = [left.fileno(), right.fileno()]
    pair = observation.unix_pair(os.getpid(), descriptors)
    right.close()
    try:
        with pytest.raises(RuntimeError, match='two live kernel descriptors'):
            observation.unix_pair(os.getpid(), descriptors)
        retained_pair = observation.retained_unix_member(os.getpid(), left.fileno(), pair)
        assert retained_pair is not None
        assert retained_pair['socket_cookie'] == pair[0]['socket_cookie']
        assert observation.retained_unix_member(os.getpid(), right.fileno(), pair) is None
        with socket.socket() as replacement:
            os.dup2(replacement.fileno(), left.fileno())
            assert observation.retained_unix_member(os.getpid(), left.fileno(), pair) is None
            with pytest.raises(RuntimeError, match='two live kernel descriptors'):
                observation.unix_pair(os.getpid(), descriptors)
            retained = observation.retained_tcp_descriptor(os.getpid(), left.fileno())
            assert retained is not None
            assert retained['socket_cookie'] not in {row['socket_cookie'] for row in pair}
    finally:
        left.close()


def test_actual_tcp_observations_drive_same_process_endpoint_policy():
    from dataclasses import replace
    from endpoint_policy import Endpoints, Owner, Route
    from linux_observation import process_identity
    from process_ledger import Birth, Ledger

    actual = process_identity(os.getpid())
    birth = Birth.read(actual)
    ledger = Ledger('native-socket-control')
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': actual})
    pins, seal = (('runtime', 'a' * 64),), 'b' * 64
    ledger.register(birth, 'owner', pins, seal, case='native-tcp', command_class='control')
    ledger.control(birth, 'owner', 0, 0, 'core-ready', {'pins': pins})
    ledger.control(birth, 'owner', 0, 1, 'body-ready', {'seal': seal})
    owner = Owner(birth, 'owner', 0)
    endpoints = Endpoints(ledger)
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        route = Route('native', 'native-tcp', owner, owner, listener.getsockname()[1])
        endpoints.declare(route)
        admitted = observation.acquire_tcp(birth, listener.fileno())
        endpoints.listen(route.name, admitted)
        ticket = endpoints.connect(route.name, observation.acquire_tcp(birth, listener.fileno()),
                                   observation.acquire_tcp(birth, client.fileno()))
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            assert ticket.listener==admitted
            saved=observation.acquire_tcp(birth,server.fileno())
            listener.close()
            assert observation.acquire_tcp(birth,server.fileno()).description()==saved.description()
            import time
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            client.close()
            deadline = time.monotonic() + 2
            while True:
                closed = observation.acquire_tcp(birth, server.fileno())
                if closed is not None and closed.state == 7:
                    break
                assert time.monotonic() < deadline
                time.sleep(.001)
            assert closed.description()==saved.description()
            descriptor = server.fileno()
            with socket.socket() as replacement:
                os.dup2(replacement.fileno(), descriptor)
                assert observation.acquire_tcp(birth,descriptor).description()!=saved.description()
            assert not endpoints.poison
    with pytest.raises(RuntimeError, match='stale_or_reused_ownership'):
        observation.acquire_tcp(replace(birth, ticks=birth.ticks + 1), 0)


def unix_authority():
    from endpoint_policy import Endpoints, Owner
    from linux_observation import process_identity
    from process_ledger import Birth, Ledger
    from unix_endpoints import UnixPairs
    actual = process_identity(os.getpid())
    birth = Birth.read(actual)
    ledger = Ledger('native-unix-control')
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': actual})
    pins, seal = (('runtime', 'a' * 64),), 'b' * 64
    ledger.register(birth, 'owner', pins, seal, case='native-unix', command_class='control')
    ledger.control(birth, 'owner', 0, 0, 'core-ready', {'pins': pins})
    ledger.control(birth, 'owner', 0, 1, 'body-ready', {'seal': seal})
    return UnixPairs(Endpoints(ledger)), Owner(birth, 'owner', 0)


def test_actual_unix_pair_payload_and_survivor_after_peer_close():
    pairs, owner = unix_authority()
    left, right = socket.socketpair()
    try:
        members = observation.acquire_unix_pair(owner.birth, [left.fileno(), right.fileno()])
        pair = pairs.admit(owner, 'native-unix', members)
        for stream in (left, right):
            pairs.retained(pair, owner, observation.acquire_unix_member(owner.birth, stream.fileno(), pair))
        assert left.send(b'x') == 1 and right.recv(1) == b'x'
        right.close()
        pairs.retained(pair, owner, observation.acquire_unix_member(owner.birth, left.fileno(), pair))
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize('replacement', ['alias', 'unix', 'tcp'])
def test_actual_unix_pair_cannot_authorize_alias_or_replacement(replacement):
    from content_manifest import Refused
    pairs, owner = unix_authority()
    left, right = socket.socketpair()
    other_left, other_right = socket.socketpair() if replacement != 'tcp' else (socket.socket(), socket.socket())
    alias = None
    try:
        pair = pairs.admit(owner, 'native-unix', observation.acquire_unix_pair(
            owner.birth, [left.fileno(), right.fileno()]))
        if replacement == 'alias':
            alias = os.dup(left.fileno())
            descriptor = alias
        else:
            descriptor = left.fileno()
            os.dup2(other_left.fileno(), descriptor)
        observed = observation.acquire_unix_member(owner.birth, descriptor, pair)
        with pytest.raises(Refused):
            pairs.retained(pair, owner, observed)
        assert pairs.poison
    finally:
        if alias is not None:
            os.close(alias)
        for stream in (left, right, other_left, other_right):
            stream.close()


def test_two_actual_clients_share_only_the_same_listener_description():
    from endpoint_policy import Endpoints, Owner, Route
    from linux_observation import process_identity
    from process_ledger import Birth, Ledger
    from socket_observation import acquire_tcp
    actual = process_identity(os.getpid())
    birth = Birth.read(actual)
    ledger = Ledger('shared-listener-control')
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': actual})
    pins = (('control', 'a' * 64),)
    ledger.register(birth, 'owner', pins, 'seal', case='shared', command_class='socket-control')
    ledger.control(birth, 'owner', 0, 0, 'core-ready', {'pins': pins})
    ledger.control(birth, 'owner', 0, 1, 'body-ready', {'seal': 'seal'})
    owner, endpoints = Owner(birth, 'owner', 0), Endpoints(ledger)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        observed = acquire_tcp(birth, listener.fileno())
        for index in range(2):
            route = Route('client-' + str(index), 'shared', owner, owner, port)
            endpoints.declare(route, shared_listener=observed if index else None)
            endpoints.listen(route.name, acquire_tcp(birth, listener.fileno()))
            with socket.socket() as client:
                ticket = endpoints.connect(route.name, acquire_tcp(birth, listener.fileno()),
                                           acquire_tcp(birth, client.fileno()))
                client.connect(('127.0.0.1', port))
                accepted, _ = listener.accept()
                with accepted:
                    assert ticket.listener==acquire_tcp(birth,listener.fileno())
                    assert acquire_tcp(birth,accepted.fileno()).uid==birth.uid
        assert endpoints.connection_counts[route.name] == 2 and not endpoints.poison and not ledger.poison
