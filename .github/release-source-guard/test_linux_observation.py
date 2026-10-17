"""Focused observer controls. Linux execution is required, never simulated."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import sys

import pytest

spec = importlib.util.spec_from_file_location(
    "linux_observation", Path(__file__).with_name("linux_observation.py")
)
assert spec is not None and spec.loader is not None
observation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observation)


@pytest.mark.parametrize("value", [0, -1, True, "1"])
def test_reject_non_pid(value):
    with pytest.raises(ValueError):
        observation.process_identity(value)


def test_kernel_birth_and_namespaces():
    assert sys.platform == "linux"
    result = observation.require_linux_abi()
    identity = result["identity"]
    assert identity["pid"] == os.getpid()
    assert identity["ppid"] == os.getppid()
    assert identity["pgid"] == os.getpgid(0)
    assert identity["sid"] == os.getsid(0)
    assert identity["uids"] == [os.getuid(), os.geteuid(), os.geteuid(), os.geteuid()]
    assert identity["start_ticks"] > 0
    assert set(identity["namespaces"]) == set(observation.NAMESPACES)
    assert all(identity["namespaces"].values())
    assert result["pidfd"] is True


def test_descriptor_objects_and_peer_credentials(tmp_path):
    path = tmp_path / "descriptor"
    with path.open("wb") as stream:
        info = os.fstat(stream.fileno())
        rows = observation.descriptors(os.getpid())
        selected = next(row for row in rows if row["fd"] == stream.fileno())
        assert (selected["device"], selected["inode"]) == (info.st_dev, info.st_ino)
    left, right = socket.socketpair()
    try:
        assert observation.peer_identity(left) == {
            "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
        }
        assert observation.peer_identity(right) == observation.peer_identity(left)
    finally:
        left.close()
        right.close()


def test_raw_parent_wait_is_distinct_from_process_absence():
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.read(read_fd, 1)
        os._exit(17)
    os.close(read_fd)
    try:
        identity = observation.process_identity(pid)
    finally:
        os.write(write_fd, b"1")
        os.close(write_fd)
    actual, raw = os.waitpid(pid, 0)
    assert actual == pid and os.WIFEXITED(raw)
    assert raw == 17 << 8 and os.waitstatus_to_exitcode(raw) == 17
    assert identity["ppid"] == os.getpid()
    assert not Path(f"/proc/{pid}").exists()
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
