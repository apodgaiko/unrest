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


def test_tcp_fd_inode_cookie_and_closed_descriptor():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket() as client:
            client.connect(listener.getsockname())
            accepted, _ = listener.accept()
            with accepted:
                rows = observation.sockets(os.getpid())
                saved = {}
                for stream in (listener, client, accepted):
                    row = next(value for value in rows if value["fd"] == stream.fileno())
                    assert row["socket_cookie"] == cookie(stream)
                    assert row["inode"] == os.fstat(stream.fileno()).st_ino
                    assert row["socket_uid"] == os.getuid()
                    saved[stream.fileno()] = row
                client_cookie = cookie(client)
                assert saved[listener.fileno()]["state"] == 10
                assert saved[client.fileno()]["state"] == saved[accepted.fileno()]["state"] == 1
                assert saved[client.fileno()]["local_port"] == saved[accepted.fileno()]["remote_port"]
        assert all(row["socket_cookie"] != client_cookie
                   for row in observation.sockets(os.getpid()))


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
        binding = (os.getpid(), live['socket_cookie'], live['inode'],
                   server.getsockname()[1], client.getsockname()[1])
        assert observation.closed_binding(live, {binding}) is None
        assert observation.live_binding(live, {binding}) == binding
        assert observation.live_binding(live, set()) is None
        assert observation.live_binding(live, {(*binding[:4], binding[4] + 1)}) is None
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
        assert observation.closed_binding(closed, {binding}) == binding
        assert observation.closed_binding(closed, set()) is None
        assert observation.closed_binding(closed, {(os.getpid() + 1, *binding[1:])}) is None
        with socket.socket() as replacement:
            os.dup2(replacement.fileno(), descriptor)
            reused = observation.retained_tcp_descriptor(os.getpid(), descriptor)
            assert reused is not None and reused['state'] == 7
            assert reused['socket_cookie'] != live['socket_cookie']
            assert observation.closed_binding(reused, {binding}) is None
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
        admitted = next(row for row in observation.sockets(os.getpid())
                        if row['fd'] == listener.fileno())
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            listener.close()
            rows = observation.sockets(os.getpid())
            own = next(row for row in rows if row['fd'] == client.fileno())
            peer = observation.reciprocal_peer(admitted, own, rows)
            assert peer is not None and peer['fd'] == server.fileno()
            assert peer['socket_cookie'] == cookie(server)
            assert observation.reciprocal_peer(admitted, own, []) is None
            for key in ('pid', 'socket_uid', 'local_port'):
                changed = {**admitted, key: admitted[key] + 1}
                assert observation.reciprocal_peer(changed, own, rows) is None
            changed = {**own, 'local_port': own['local_port'] + 1}
            assert observation.reciprocal_peer(admitted, changed, rows) is None
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
            assert observation.closed_binding(retained, set()) is None
    finally:
        left.close()


def test_actual_tcp_observations_drive_same_process_endpoint_policy():
    from dataclasses import replace
    from content_manifest import Refused
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
                                   observation.acquire_tcp(birth, client.fileno(), retained=True))
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            connection = endpoints.accepted(ticket, observation.acquire_tcp(birth, client.fileno()),
                                            observation.acquire_tcp(birth, server.fileno()))
            listener.close()
            endpoints.retained(connection, owner, observation.acquire_tcp(birth, server.fileno(), retained=True))
            import time
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            client.close()
            deadline = time.monotonic() + 2
            while True:
                closed = observation.acquire_tcp(birth, server.fileno(), retained=True)
                if closed is not None and closed.state == 7:
                    break
                assert time.monotonic() < deadline
                time.sleep(.001)
            endpoints.retained(connection, owner, closed)
            descriptor = server.fileno()
            with socket.socket() as replacement:
                os.dup2(replacement.fileno(), descriptor)
                with pytest.raises(Refused):
                    endpoints.retained(connection, owner, observation.acquire_tcp(birth, descriptor, retained=True))
            assert endpoints.poison
    with pytest.raises(RuntimeError, match='stale_or_reused_ownership'):
        observation.acquire_tcp(replace(birth, ticks=birth.ticks + 1), 0)
