"""Actual Linux peer credentials and birth checks; source-free controls only."""
from __future__ import annotations

from dataclasses import replace
import os
import socket
import sys

import pytest

from content_manifest import Refused
from control_transport import Admission, Frame, REQUEST_LIMIT, RESPONSE_LIMIT, encode, peer, reply, verify_reply
from linux_observation import process_identity
from process_ledger import Birth, Ledger

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='requires actual Linux Unix peer credentials')


def setup():
    actual = process_identity(os.getpid())
    birth = Birth.read(actual)
    ledger = Ledger('a' * 64)
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': actual})
    ledger.register(birth, 'root', (('runtime', 'b' * 64),), 'c' * 64,
                    case='control', command_class='root')
    request = {'pid': birth.pid, 'nonce': ledger.nonce, 'token': 'root', 'generation': 0,
               'id': 'd' * 32, 'kind': 'ready', 'payload': {}}
    return ledger, birth, request


def test_actual_kernel_peer_and_frame_roundtrip_with_exact_echo():
    ledger, birth, request = setup()
    left, right = socket.socketpair()
    with left, right:
        # Same-process control intentionally has the same peer on both ends.
        # Production source and observer must each pin their distinct peer.
        peer(left, birth, os.getgid())
        peer(right, birth, os.getgid())
        outgoing = Frame(left, RESPONSE_LIMIT, [])
        incoming = Frame(right, REQUEST_LIMIT, ledger.poison)
        incoming.capture(ledger, birth, 'root', os.getgid())
        outgoing.answer(request)
        assert outgoing.send()
        decoded = incoming.read()
        admission = Admission(ledger, frozenset({'ready'}))
        assert admission.admit(incoming) == request
        incoming.answer(reply(decoded, {'ok': True}))
        assert incoming.send()
        assert verify_reply(outgoing.read(), request) == {'ok': True}
        with pytest.raises(Refused):
            admission.admit(incoming)
        assert admission.poison


@pytest.mark.parametrize('field,value', [('nonce', 'other'), ('pid', True), ('token', 'other'),
    ('generation', True), ('kind', 'unknown'), ('id', 'z' * 32), ('payload', [])])
def test_actual_peer_does_not_rescue_foreign_request_authority(field, value):
    ledger, birth, request = setup()
    left, right = socket.socketpair()
    with left, right:
        admission = Admission(ledger, frozenset({'ready'}))
        incoming = Frame(right, REQUEST_LIMIT, ledger.poison)
        incoming.capture(ledger, birth, 'root', os.getgid())
        left.sendall(encode({**request, field: value}, REQUEST_LIMIT))
        assert incoming.read() is not None
        with pytest.raises(Refused):
            admission.admit(incoming)
        assert admission.poison


def test_actual_peer_rejects_stale_birth_and_wrong_gid():
    _, birth, _ = setup()
    left, right = socket.socketpair()
    with left, right:
        with pytest.raises(Refused):
            peer(right, replace(birth, ticks=birth.ticks + 1), os.getgid())
        with pytest.raises(Refused):
            peer(right, birth, os.getgid() + 1)


def test_duplicate_json_fields_cannot_reach_admission():
    ledger, _, request = setup()
    left, right = socket.socketpair()
    with left, right:
        frame = Frame(right, REQUEST_LIMIT, ledger.poison)
        import struct
        payload = encode(request, REQUEST_LIMIT)[4:-1] + b',"nonce":"other"}'
        left.sendall(struct.pack('!I', len(payload)) + payload)
        with pytest.raises(Refused):
            frame.read()
        assert frame.received is None and frame.poison


@pytest.mark.parametrize('failure', ['malformed', 'expired', 'io'])
def test_channel_poison_blocks_ordinary_but_allows_captured_authenticated_drain(failure):
    ledger, birth, request = setup()
    admission = Admission(ledger, frozenset({'ready', 'custody_close'}))
    left, right = socket.socketpair()
    with left, right:
        failed = Frame(right, REQUEST_LIMIT, ledger.poison)
        if failure == 'malformed':
            left.sendall(b'\0\0\0\0')
        elif failure == 'expired':
            failed.started -= 5
        else:
            right.close()
        with pytest.raises((Refused, OSError)):
            failed.read()
    assert ledger.poison and admission.poison
    for kind in ('ready', 'custody_close'):
        left, right = socket.socketpair()
        with left, right:
            frame = Frame(right, REQUEST_LIMIT, ledger.poison)
            frame.capture(ledger, birth, 'root', os.getgid())
            outgoing = {**request, 'kind': kind, 'id': ('e' if kind == 'ready' else 'f') * 32}
            left.sendall(encode(outgoing, REQUEST_LIMIT))
            assert frame.read() == outgoing
            if kind == 'ready':
                with pytest.raises(Refused):
                    admission.admit(frame)
            else:
                assert admission.admit(frame) == outgoing
    assert ledger.poison
