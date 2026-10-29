"""Bounded frame controls with actual local sockets; no source-launch authority."""
from __future__ import annotations

import json
import socket
import struct

import pytest

from content_manifest import Refused
import control_transport as control


@pytest.fixture
def channels():
    left, right = socket.socketpair()
    try:
        yield left, right, control.Frame(right, control.REQUEST_LIMIT)
    finally:
        left.close()
        right.close()


def wire(raw):
    return struct.pack('!I', len(raw)) + raw


def test_partial_frame_is_read_once_and_delivered_once(channels):
    left, _, frame = channels
    data = control.encode({'kind': 'control', 'payload': {}}, control.REQUEST_LIMIT)
    for block in (data[:1], data[1:3], data[3:-1]):
        left.sendall(block)
        assert frame.read() is None
    left.sendall(data[-1:])
    assert frame.read() == {'kind': 'control', 'payload': {}}
    assert frame.read() is None
    frame.answer({'ok': True})
    assert frame.send()
    received = left.recv(100)
    assert json.loads(received[4:]) == {'ok': True}
    assert frame.send()  # no second write or redispatch
    with pytest.raises(Refused):
        frame.answer({'second': True})


@pytest.mark.parametrize('raw', [b'{"x":1,"x":2}', b'[]', b'null', b'{"x":NaN}',
    b'{"x":1.5}', b'{"x":18446744073709551616}', b'{' + b'x' * 20,
    b'{"x":' + b'[' * 30 + b'0' + b']' * 30 + b'}'])
def test_malformed_or_unbounded_json_raises_to_its_owner(channels, raw):
    left, _, frame = channels
    left.sendall(wire(raw))
    with pytest.raises(Refused):
        frame.read()
    assert frame.stream.fileno() == -1


@pytest.mark.parametrize('raw', [struct.pack('!I', 0), struct.pack('!I', 8193),
                                wire(b'{}') + wire(b'{}')])
def test_frame_size_and_two_requests_refused_before_dispatch(channels, raw):
    left, _, frame = channels
    left.sendall(raw)
    with pytest.raises(Refused):
        frame.read()
    assert frame.received is None


def test_empty_eof_is_not_an_admission(channels):
    left, _, frame = channels
    left.close()
    assert frame.read() is None and frame.eof
    assert frame.received is None and frame.binding is None


def test_partial_eof_refuses(channels):
    left, _, frame = channels
    left.sendall(b'\0\0')
    assert frame.read() is None
    left.close()
    with pytest.raises(Refused, match='partial EOF'):
        frame.read()


def test_deadline_never_resets_on_partial_progress(channels, monkeypatch):
    left, _, frame = channels
    left.sendall(b'\0')
    assert frame.read() is None
    monkeypatch.setattr(control.time, 'monotonic', lambda: frame.started + frame.seconds + .001)
    with pytest.raises(Refused, match='deadline'):
        frame.read()
    assert frame.stream.fileno() == -1


def test_work_budget_bounds_shared_container_expansion():
    value = ['small']
    for _ in range(10):
        value = [value] * 10
    with pytest.raises(Refused, match='work bound'):
        control.finite(value)
    cycle = []
    cycle.append(cycle)
    with pytest.raises(Refused, match='work bound'):
        control.finite(cycle)


def test_reply_requires_exact_request_echo():
    request = {'id': 'a' * 32, 'payload': {'fd': 2}}
    response = control.reply(request, {'ok': True})
    assert control.verify_reply(response, request) == {'ok': True}
    for changed in ({**response, 'extra': True}, {**response, 'request': {'id': 'b' * 32}},
                    {**response, 'answer': []}):
        with pytest.raises(Refused):
            control.verify_reply(changed, request)


def test_partial_writes_do_not_reencode_or_duplicate_effect(channels, monkeypatch):
    left, _, frame = channels
    send, encode = control._SEND, control.encode
    calls = {'encode': 0, 'send': 0}
    def partial(stream, data):
        calls['send'] += 1
        return send(stream, data[:3])
    def once(value, limit):
        calls['encode'] += 1
        return encode(value, limit)
    monkeypatch.setattr(control, '_SEND', partial)
    monkeypatch.setattr(control, 'encode', once)
    answer = {'ok': True, 'count': 123}
    frame.answer(answer)
    for _ in range(100):
        if frame.send():
            break
    else:
        pytest.fail('bounded partial send failed')
    expected = encode(answer, control.RESPONSE_LIMIT)
    received = bytearray()
    left.settimeout(1)
    while len(received) < len(expected):
        received.extend(left.recv(len(expected) - len(received)))
    assert bytes(received) == expected
    assert calls['encode'] == 1 and calls['send'] > 1
    sends = calls['send']
    assert frame.send()
    assert calls == {'encode': 1, 'send': sends}
    left.setblocking(False)
    with pytest.raises(BlockingIOError):
        left.recv(1)



def test_reply_echo_does_not_equate_json_boolean_and_integer():
    with pytest.raises(Refused):
        control.verify_reply({'request': {'value': True}, 'answer': {}}, {'value': 1})


def test_transport_oserror_propagates_without_reuse(channels):
    _, right, frame = channels
    right.close()
    with pytest.raises(OSError):
        frame.read()


@pytest.mark.parametrize('missing', ['none', 'capture', 'parent-wait', 'empty', 'class', 'sigterm'])
def test_empty_cancellation_requires_captured_birth_and_complete_sigterm_parent_join(channels, missing):
    from test_process_ledger import setup, terminal, wait4
    ledger, root, child = setup()
    ledger.process(child).command_class = 'controlled-acp' if missing != 'class' else 'other'
    _, _, frame = channels
    # Reduction control only. Native capture and kernel joins have separate tests.
    frame.owner = ledger
    frame.binding = None if missing == 'capture' else (child, 'child-token', 0, 'controlled-acp', 20000)
    frame.eof = True
    if missing == 'empty':
        frame.buffer.extend(b'partial')
    raw = 0 if missing == 'sigterm' else 15
    terminal(ledger, child, raw)
    if missing != 'parent-wait':
        wait4(ledger, root, child, raw)
    assert control.cancelled_empty(frame, ledger, child, 'child-token') == (missing == 'none')


def test_empty_reap_does_not_extend_channel_deadline(channels, monkeypatch):
    from test_process_ledger import setup
    ledger, _, child = setup()
    _, _, frame = channels
    frame.owner = ledger
    frame.binding, frame.eof = (child, 'child-token', 0, 'controlled-acp', 20000), True
    monkeypatch.setattr(control.time, 'monotonic', lambda: frame.started + 4.001)
    with pytest.raises(Refused, match='deadline'):
        control.cancelled_empty(frame, ledger, child, 'child-token')


@pytest.mark.parametrize('changed', ['generation', 'token', 'class'])
def test_preexec_empty_channel_cannot_discharge_a_later_registration(channels, changed):
    from test_process_ledger import setup, terminal, wait4
    ledger, root, child = setup()
    process = ledger.process(child)
    process.command_class = 'controlled-acp'
    _, _, frame = channels
    frame.owner = ledger
    frame.binding, frame.eof = (child, 'child-token', 0, 'controlled-acp', 20000), True
    terminal(ledger, child, 15)
    wait4(ledger, root, child, 15)
    assert ledger.reaped(child, 'child-token')
    if changed == 'generation':
        process.generation += 1
    elif changed == 'token':
        process.token = 'replacement'
    else:
        process.command_class = 'replacement'
    assert not control.cancelled_empty(frame, ledger, child, 'child-token')



def test_empty_channel_cannot_discharge_using_another_ledger(channels):
    from test_process_ledger import setup, terminal, wait4
    original, _, child = setup()
    other, root, same_child = setup()
    other.nonce = 'different-epoch-nonce'
    other.process(same_child).command_class = 'controlled-acp'
    _, _, frame = channels
    frame.owner = original
    frame.binding, frame.eof = (child, 'child-token', 0, 'controlled-acp', 20000), True
    terminal(other, same_child, 15)
    wait4(other, root, same_child, 15)
    assert other.reaped(same_child, 'child-token')
    assert not control.cancelled_empty(frame, other, same_child, 'child-token')


def test_private_framing_never_reenters_payload_io_wrappers(channels, monkeypatch):
    left, right, frame = channels
    send, recv = socket.socket.send, socket.socket.recv
    def payload_only(*args, **kwargs):
        raise AssertionError('private control channel reentered payload mediation')
    with monkeypatch.context() as patch:
        for method in ('send', 'recv', 'close'):
            patch.setattr(socket.socket, method, payload_only)
        assert send(left, wire(b'{"control":true}')) > 0
        assert frame.read() == {'control': True}
        frame.answer({'ok': True})
        assert frame.send()
        assert json.loads(recv(left, 100)[4:]) == {'ok': True}
        with pytest.raises(Refused):
            frame.refuse('controlled refusal')
        assert right.fileno() == -1
