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
            assert cookie(replacement) not in {row['socket_cookie'] for row in pair}
    finally:
        left.close()




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
