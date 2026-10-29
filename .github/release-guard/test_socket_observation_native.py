"""Actual descriptor copies, cookies, names and leak checks on Linux/x86-64."""

from dataclasses import replace
import fcntl
import os
from pathlib import Path
import socket
import sys

import pytest

from content_manifest import Refused
from linux_observation import process_identity
from process_ledger import Birth
from socket_observation import acquire, descriptor

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.uname().machine != "x86_64",
    reason="actual Linux pidfd_getfd and socket descriptions required",
)


def birth():
    return Birth.read(process_identity(os.getpid()))


def test_actual_unnamed_description_copy_preserves_flags_data_and_cookie():
    left, right = socket.socketpair()
    try:
        flags = fcntl.fcntl(left.fileno(), fcntl.F_GETFL)
        expected = [left.fileno(), *descriptor(left.fileno(), os.getuid())]
        assert acquire(birth(), left.fileno()) == expected
        assert fcntl.fcntl(left.fileno(), fcntl.F_GETFL) == flags
        assert left.send(b"x") == 1 and right.recv(1) == b"x"
        right.close()
        assert acquire(birth(), left.fileno()) == expected
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("replacement", ["unix", "tcp", "regular"])
def test_replaced_descriptor_cannot_match_a_saved_cookie(replacement):
    left, right = socket.socketpair()
    other, peer = socket.socketpair()
    try:
        saved = acquire(birth(), left.fileno())
        if replacement == "unix":
            os.dup2(other.fileno(), left.fileno())
        elif replacement == "tcp":
            with socket.socket() as stream:
                os.dup2(stream.fileno(), left.fileno())
        else:
            with open("/dev/null") as stream:
                os.dup2(stream.fileno(), left.fileno())
        if replacement == "unix":
            assert acquire(birth(), left.fileno()) != saved
        else:
            with pytest.raises((Refused, OSError)):
                acquire(birth(), left.fileno())
    finally:
        for stream in (left, right, other, peer):
            stream.close()


@pytest.mark.parametrize("abstract", [False, True])
def test_named_and_control_style_unix_endpoints_are_not_inherited(tmp_path, abstract):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        address = (
            ("\0guard-control-" + str(os.getpid())) if abstract else str(tmp_path / "control.sock")
        )
        server.bind(address)
        server.listen(1)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(address)
            accepted, _ = server.accept()
            with accepted:
                for stream in (client, accepted):
                    with pytest.raises(Refused, match="unnamed"):
                        acquire(birth(), stream.fileno())


def test_acquisition_refuses_foreign_birth_and_releases_every_duplicate():
    left, right = socket.socketpair()
    try:
        current = birth()
        with pytest.raises(Refused, match="birth changed"):
            acquire(replace(current, ticks=current.ticks + 1), left.fileno())
        baseline = len(list(Path("/proc/self/fd").iterdir()))
        for _ in range(128):
            acquire(current, left.fileno())
        assert len(list(Path("/proc/self/fd").iterdir())) == baseline
        with socket.socket() as invalid:
            for _ in range(32):
                with pytest.raises(Refused):
                    acquire(current, invalid.fileno())
        assert len(list(Path("/proc/self/fd").iterdir())) == baseline
    finally:
        left.close()
        right.close()
