"""Actual kernel cookies and reciprocal peer inodes; no fabricated tables."""
import importlib.util
import os
from pathlib import Path
import socket
import struct

spec = importlib.util.spec_from_file_location(
    "linux_sockets", Path(__file__).with_name("linux_sockets.py")
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
