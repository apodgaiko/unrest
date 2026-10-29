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
        outgoing = Frame(left, RESPONSE_LIMIT)
        incoming = Frame(right, REQUEST_LIMIT)
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


@pytest.mark.parametrize('field,value', [('nonce', 'other'), ('pid', True), ('token', 'other'),
    ('generation', True), ('kind', 'unknown'), ('id', 'z' * 32), ('payload', [])])
def test_actual_peer_does_not_rescue_foreign_request_authority(field, value):
    ledger, birth, request = setup()
    left, right = socket.socketpair()
    with left, right:
        admission = Admission(ledger, frozenset({'ready'}))
        incoming = Frame(right, REQUEST_LIMIT)
        incoming.capture(ledger, birth, 'root', os.getgid())
        left.sendall(encode({**request, field: value}, REQUEST_LIMIT))
        assert incoming.read() is not None
        with pytest.raises(Refused):
            admission.admit(incoming)


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
        frame = Frame(right, REQUEST_LIMIT)
        import struct
        payload = encode(request, REQUEST_LIMIT)[4:-1] + b',"nonce":"other"}'
        left.sendall(struct.pack('!I', len(payload)) + payload)
        with pytest.raises(Refused):
            frame.read()
        assert frame.received is None


def test_distinct_processes_authenticate_each_other_before_consuming_reply(tmp_path):
    import signal
    import time

    observer_birth = Birth.read(process_identity(os.getpid()))
    path = str(tmp_path / 'control.sock')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    listener.settimeout(4)
    child = os.fork()
    if child == 0:
        listener.close()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(4)
                stream.connect(path)
                peer(stream, observer_birth, os.getgid())
                source = Frame(stream, RESPONSE_LIMIT)
                request = {'pid': os.getpid(), 'nonce': 'a' * 64, 'token': 'child', 'generation': 0,
                           'id': '1' * 32, 'kind': 'ready', 'payload': {}}
                source.answer(request)
                while not source.send():
                    time.sleep(.001)
                response = None
                while response is None:
                    response = source.read()
                    time.sleep(.001)
                peer(stream, observer_birth, os.getgid())
                assert verify_reply(response, request) == {'ok': True}
        except BaseException:
            os._exit(125)
        os._exit(0)
    waited = False
    try:
        stream, _ = listener.accept()
        with stream:
            actual = process_identity(child)
            child_birth = Birth.read(actual)
            ledger = Ledger('a' * 64)
            # Authentication-only setup from actual proc identities. These rows
            # do not claim ptrace event or source-completion certification.
            ledger.kernel(0, {'kind': 'kernel_root', 'identity': process_identity(os.getpid())})
            ledger.kernel(1, {'kind': 'kernel_child', 'parent': os.getpid(), 'child': child,
                              'event': 1, 'identity': actual})
            ledger.register(child_birth, 'child', (('runtime', 'b' * 64),), 'c' * 64,
                            case='peer-control', command_class='control')
            incoming = Frame(stream, REQUEST_LIMIT)
            incoming.capture(ledger, child_birth, 'child', os.getgid())
            while incoming.read() is None:
                time.sleep(.001)
            request = Admission(ledger, frozenset({'ready'})).admit(incoming)
            incoming.answer(reply(request, {'ok': True}))
            while not incoming.send():
                time.sleep(.001)
        actual_pid, raw = os.waitpid(child, 0)
        waited = True
        assert actual_pid == child and raw == 0
        assert child_birth.pid != observer_birth.pid
    finally:
        listener.close()
        if not waited:
            actual_pid, _ = os.waitpid(child, os.WNOHANG)
            if actual_pid == 0:
                os.kill(child, signal.SIGKILL)
                assert os.waitpid(child, 0)[0] == child
