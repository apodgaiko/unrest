"""Bounded receipt transport controls; policy acceptance remains separate."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys

import pytest

spec = importlib.util.spec_from_file_location(
    'receipt_supervisor', Path(__file__).with_name('linux_supervisor.py'))
assert spec is not None and spec.loader is not None
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def test_closed_diagnostic_does_not_copy_request_material():
    supervisor = host.Supervisor.__new__(host.Supervisor)
    supervisor.registered = {}
    supervisor.tick_count, supervisor.event_count = 3, 7
    supervisor.trace_progress = {'records': 11, 'active': 2, 'pending': 1}
    state = {'request': {'kind': ['secret'], 'nonce': 'private', 'body': 'private'},
             'buffer': bytearray(struct.pack('!I', 19)), 'authenticated': False,
             'output': None, 'started': host.time.monotonic(), 'accepted_tick': 1,
             'pending_reason': 'peer_registration'}
    row = supervisor.channel_snapshot(state, 'refused')
    assert row['kind'] == 'unknown' and len(row['unknown_kind_sha256']) == 64
    assert row['declared_size'] == 19 and row['frame_bytes'] == 4
    assert 'private' not in json.dumps(row) and 'secret' not in json.dumps(row)
    assert row['tick_count'] == 3 and row['trace_progress']['records'] == 11


@pytest.fixture
def transport(tmp_path, monkeypatch):
    if sys.platform != 'linux':
        pytest.skip('actual Linux SO_PEERCRED and proc birth identity required')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text('{}')
    config = {'manifest': str(manifest), 'pins': {str(manifest): host.sha(manifest)},
              'endpoint': {'responses': str(tmp_path), 'nonce': 'a' * 64,
                           'socket': str(tmp_path / 'receipt.sock')}}
    supervisor = host.Supervisor(config, type('Child', (), {'pid': os.getpid()})())
    monkeypatch.setattr(supervisor, 'refresh', lambda: [])
    clock = [host.time.monotonic()]
    def monotonic():
        clock[0] += .006
        return clock[0]
    monkeypatch.setattr(host.time, 'monotonic', monotonic)
    effects = []
    def handle(request, events):
        if request['kind'] == 'custody_spawned':
            raise host.AwaitOwnedPeer('finite_custody_pending')
        effects.append(request['id'])
        return {'accepted': True}
    monkeypatch.setattr(supervisor, 'handle', handle)
    clients = []
    def connect(kind='ready', identifier='b' * 32):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(config['endpoint']['socket'])
        client.settimeout(1)
        clients.append(client)
        request = {'kind': kind, 'id': identifier, 'pid': os.getpid(), 'token': 'root',
                   'nonce': 'a' * 64, 'identity': supervisor.root}
        body = json.dumps(request, sort_keys=True).encode()
        return client, struct.pack('!I', len(body)) + body
    yield supervisor, effects, connect
    for client in clients:
        client.close()
    supervisor.close()


def test_pending_client_does_not_starve_another_authenticated_request(transport):
    supervisor, effects, connect = transport
    first, frame = connect('custody_spawned')
    first.sendall(frame)
    second, frame = connect(identifier='c' * 32)
    second.sendall(frame)
    supervisor.tick()
    assert effects == ['c' * 32] and len(supervisor.clients) == 1
    assert second.recv(16388) and not supervisor.poisoned
    state = next(iter(supervisor.clients.values()))
    assert state['pending_reason'] == 'finite_custody_pending'
    state['started'] -= 5
    supervisor.tick()
    assert supervisor.poisoned and not supervisor.clients
    assert supervisor.channel_diagnostics[-1]['elapsed'] > 4
    assert effects == ['c' * 32]


def test_partial_frame_and_partial_write_keep_single_effect(transport):
    supervisor, effects, connect = transport
    client, frame = connect()
    client.sendall(frame[:2])
    supervisor.tick()
    assert not effects
    stream, state = next(iter(supervisor.clients.items()))
    class PartialWriter:
        def __getattr__(self, name):
            return getattr(stream, name)
        def send(self, body):
            return stream.send(body[:7])
    del supervisor.clients[stream]
    supervisor.clients[PartialWriter()] = state
    client.sendall(frame[2:])
    for _ in range(1000):
        supervisor.tick()
        if not supervisor.clients:
            break
        client.recv(7)
    assert not supervisor.clients and not supervisor.poisoned
    assert effects == ['b' * 32]
    assert supervisor.channel_diagnostics[-1]['outcome'] == 'complete'


def test_unknown_peer_never_has_effect_and_expires_at_original_bound(transport):
    supervisor, effects, connect = transport
    client, frame = connect()
    supervisor.registered.clear()
    client.sendall(frame)
    supervisor.tick()
    state = next(iter(supervisor.clients.values()))
    assert not state['authenticated'] and not effects
    assert state['pending_reason'] == 'peer_registration'
    state['started'] -= 5
    supervisor.tick()
    assert supervisor.poisoned and not effects and not supervisor.clients
    assert not supervisor.channel_diagnostics[-1]['authenticated']


def test_incomplete_frame_disconnect_retains_poison_without_effect(transport):
    supervisor, effects, connect = transport
    client, frame = connect()
    client.sendall(frame[:3])
    supervisor.tick()
    client.close()
    supervisor.tick()
    assert supervisor.poisoned and not effects and not supervisor.clients
    assert supervisor.channel_diagnostics[-1]['pending_reason'] == 'frame'



def test_completed_diagnostic_redundancy_is_bounded_without_changing_receipts(monkeypatch):
    import hashlib
    import ast
    # Invoke the exact predecessor producer, not a mirrored projection oracle.
    reference = Path(__file__).with_name('test_channel_snapshot_reference.py').read_text()
    namespace = {'struct': struct, 'hashlib': hashlib, 'json': json, 'time': host.time}
    exec(compile(reference, 'direct_original_channel_snapshot', 'exec'), namespace)
    reference_fn = next(n for n in ast.parse(reference).body if isinstance(n, ast.FunctionDef))
    current_fn = next(n for n in ast.walk(ast.parse(Path(host.__file__).read_text()))
                      if isinstance(n, ast.FunctionDef) and n.name == 'channel_snapshot')
    assert ast.dump(reference_fn, include_attributes=False) == ast.dump(current_fn, include_attributes=False)
    supervisor = host.Supervisor.__new__(host.Supervisor)
    supervisor.registered = {}
    supervisor.tick_count, supervisor.event_count = 0, 0
    supervisor.trace_progress = {'records': 10, 'active': 2, 'pending': 1}
    supervisor.receipts = [{'request': {'id': i}, 'ok': True} for i in range(10000)]
    before = json.dumps(supervisor.receipts, sort_keys=True).encode()
    supervisor.channel_diagnostics = []
    supervisor.channel_diagnostic_hash = hashlib.sha256()
    supervisor.channel_diagnostic_summary = {'records': 0, 'successful_completions': 0,
        'aggregated_successful_completions': 0, 'sample_ordinals': [], 'last_successful_completion': None}
    monkeypatch.setattr(host.time, 'monotonic', lambda: 10.0)
    state = {'request': {'kind': 'custody_poll'}, 'buffer': bytearray(struct.pack('!I', 10)),
             'authenticated': True, 'output': b'', 'started': 9.0, 'accepted_tick': 1,
             'pending_reason': 'output', 'diagnostic_success': True}
    sequence_hash = hashlib.sha256()
    original_rows = []
    for i in range(10003):
        supervisor.tick_count = i
        # Refused, closed and a completed error response must all be retained.
        outcome = 'refused' if i == 129 else 'closed' if i == 130 else 'complete'
        state['diagnostic_success'] = i != 131
        row = namespace['channel_snapshot'](supervisor, state, outcome)
        original_rows.append(row)
        encoded = json.dumps(row, sort_keys=True).encode()
        sequence_hash.update(len(encoded).to_bytes(8, 'big'))
        sequence_hash.update(encoded)
        supervisor.record_channel_diagnostic(state, outcome)
    summary = supervisor.diagnostic_summary()
    assert summary['records'] == 10003 and summary['successful_completions'] == 10000
    assert summary['aggregated_successful_completions'] == 9872
    assert summary['sequence_sha256'] == sequence_hash.hexdigest()
    assert supervisor.channel_diagnostics == [original_rows[i] for i in summary['sample_ordinals']]
    assert len(supervisor.channel_diagnostics) == 131
    assert all(i in summary['sample_ordinals'] for i in (129, 130, 131))
    assert summary['last_successful_completion'] == {'ordinal': 10002, 'snapshot': original_rows[-1]}
    assert json.dumps(supervisor.receipts, sort_keys=True).encode() == before
    assert len(json.dumps({'samples': supervisor.channel_diagnostics, 'summary': summary})) < 131072


@pytest.mark.parametrize('change', ['none', 'missing', 'fd', 'pid', 'inode', 'socket_cookie',
                                   'socket_uid', 'state', 'local_host', 'local_port'])
def test_connect_exact_listener_keeps_full_original_row_equality(monkeypatch, change):
    value = host.Supervisor.__new__(host.Supervisor)
    value.poisoned = False
    value.authenticate = lambda *args: None  # Pure post-authentication policy predicate.
    birth = {'pid': 20, 'start_ticks': 11}
    value.registered = {20: {'identity': birth}}
    entry = {'pid': 20, 'fd': 16, 'inode': 279801, 'socket_cookie': 7369,
             'socket_uid': 20000, 'state': 10, 'local_host': '127.0.0.1', 'local_port': 45415}
    value.listeners, value.connect_admissions = {45415: entry}, {}
    monkeypatch.setattr(host.kernel, 'identity', lambda pid: dict(birth))
    current = dict(entry)
    if change == 'missing':
        current = None
    elif change not in {'none', 'missing'}:
        current[change] = '192.0.2.1' if change == 'local_host' else current[change] + 1
    monkeypatch.setattr(host.sockets, 'socket_descriptor', lambda pid, fd: current)
    request = {'kind': 'connect', 'pid': 99, 'fd': 3, 'host': '127.0.0.1', 'port': 45415}
    if change == 'none':
        assert value.handle(request, []) == {'listener': entry}
        assert value.connect_admissions == {(99, 3): entry}
    else:
        with pytest.raises(RuntimeError, match='listener_closed_or_changed_binding'):
            value.handle(request, [])
        assert value.connect_admissions == {}


@pytest.mark.parametrize('after', [False, True])
def test_listener_snapshot_still_matches_registered_birth_before_and_after(monkeypatch, after):
    value = host.Supervisor.__new__(host.Supervisor)
    value.registered = {20: {'identity': {'pid': 20, 'start_ticks': 11}}}
    calls = []
    def identity(pid):
        calls.append(pid)
        return {'pid': pid, 'start_ticks': 12 if not after or len(calls) > 1 else 11}
    monkeypatch.setattr(host.kernel, 'identity', identity)
    monkeypatch.setattr(host.sockets, 'socket_descriptor', lambda pid, fd: {'pid': pid, 'fd': fd})
    with pytest.raises(RuntimeError, match='stale_or_reused_ownership'):
        value.observe_listener({'pid': 20, 'fd': 16})
