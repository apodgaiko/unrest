"""Zero-byte cancellation close needs prospective peer birth and actual wait proof."""
from copy import deepcopy
import struct
import socket
from types import SimpleNamespace

import pytest

import linux_trace
from receipt_lifecycle import capture, empty_exit
from test_listener_lifecycle import session_fixture


@pytest.fixture(autouse=True)
def simulated_peer_option_on_non_linux(monkeypatch):
    # Synthetic streams ignore the option; native transport controls use Linux.
    if not hasattr(socket, 'SO_PEERCRED'):
        monkeypatch.setattr(socket, 'SO_PEERCRED', 17, raising=False)


def model():
    _, registered, events, records = session_fixture()
    for row in events:
        if row.get('kind') in {'registered', 'admitted'}:
            row['class'] = 'controlled-acp'
    supervisor = SimpleNamespace(registered=registered, root={'uid': 20000},
                                 spec={'endpoint': {'nonce': 'nonce'}})
    supervisor.owned_trace = linux_trace.OwnedTrace.__new__(linux_trace.OwnedTrace)
    supervisor.owned_trace.records = records
    state = {'buffer': bytearray(), 'request': None, 'authenticated': False, 'output': None}
    stream = SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 20, 20000, 20000))
    capture(supervisor, stream, state, lambda pid: deepcopy(registered[pid]['identity']))
    return supervisor, state, events


def test_empty_close_never_rewrites_terminal_evidence():
    supervisor, state, events = model()
    before = deepcopy((supervisor.registered, state, events, supervisor.owned_trace.records))
    assert empty_exit(supervisor, state, events)
    assert (supervisor.registered, state, events, supervisor.owned_trace.records) == before


def test_exit_alone_defers_until_tracer_and_actual_parent_wait_arrive():
    supervisor, state, events = model()
    records = supervisor.owned_trace.records
    for stop in (2, 3):
        supervisor.owned_trace.records = records[:stop]
        assert not empty_exit(supervisor, state, events)
    supervisor.owned_trace.records = records
    assert empty_exit(supervisor, state, events)


@pytest.mark.parametrize('change', ['partial', 'request', 'authenticated', 'output', 'missing-birth',
                                   'stale-birth', 'uid', 'token', 'unknown', 'class', 'duplicate',
                                   'not-python', 'owner', 'trace'])
def test_no_partial_request_or_foreign_channel_can_use_empty_close(change):
    supervisor, state, events = model()
    if change == 'partial':
        state['buffer'].extend(b'\x00')
    elif change == 'request':
        state['request'] = {}
    elif change == 'authenticated':
        state['authenticated'] = True
    elif change == 'output':
        state['output'] = b''
    elif change == 'missing-birth':
        state['accepted_peer'] = None
    elif change == 'stale-birth':
        state['accepted_peer']['identity']['start_ticks'] += 1
    elif change == 'uid':
        state['peer_uid'] = 0
    elif change == 'token':
        state['accepted_peer']['token'] = 'foreign'
    elif change == 'unknown':
        supervisor.registered.pop(20)
    elif change == 'class':
        events[2]['class'] = 'foreign'
    elif change == 'duplicate':
        events.append(deepcopy(events[2]))
    elif change == 'not-python':
        events[2]['python'] = False
    elif change == 'owner':
        events[2]['owner_pid'] = 99
    else:
        supervisor.owned_trace = SimpleNamespace(records=supervisor.owned_trace.records)
    with pytest.raises(RuntimeError, match='closed_before_request'):
        empty_exit(supervisor, state, events)


@pytest.mark.parametrize('change', ['missing-source', 'duplicate-source', 'raw', 'numeric', 'nonce',
                                   'source-owner', 'source-token', 'missing-kernel', 'kernel-status',
                                   'kernel-order', 'kernel-birth', 'kernel-snapshot'])
def test_missing_or_altered_actual_wait_never_completes_empty_close(change):
    supervisor, state, events = model()
    records = supervisor.owned_trace.records
    if change == 'missing-source':
        events.pop(0)
    elif change == 'duplicate-source':
        events.append(deepcopy(events[0]))
    elif change == 'raw':
        events[0]['raw_status'] = 0
    elif change == 'numeric':
        events[0]['numeric_returncode'] = 0
    elif change == 'nonce':
        events[0]['nonce'] = 'foreign'
    elif change == 'source-owner':
        events[0]['owner_token'] = 'foreign'
    elif change == 'source-token':
        events[0]['child_token'] = 'foreign'
    elif change == 'missing-kernel':
        records.pop()
    elif change == 'kernel-status':
        records[-1]['raw'] = 0
    elif change == 'kernel-order':
        records.reverse()
    elif change == 'kernel-birth':
        records[0]['identity']['start_ticks'] += 1
    else:
        records[2]['identity']['pgid'] = 20
    assert not empty_exit(supervisor, state, events)


@pytest.mark.parametrize('change', ['unavailable', 'stale', 'unknown', 'uid'])
def test_capture_never_infers_birth_from_an_unavailable_or_foreign_peer(change):
    supervisor, state, _ = model()
    stream = SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 20, 0 if change == 'uid' else 20000, 20000))
    def identity(pid):
        if change == 'unavailable':
            raise FileNotFoundError('gone')
        value = deepcopy(supervisor.registered[pid]['identity'])
        if change == 'stale':
            value['start_ticks'] += 1
        return value
    if change == 'unknown':
        supervisor.registered.pop(20)
    capture(supervisor, stream, state, identity)
    assert state['peer_pid'] == 20 and state['accepted_peer'] is None



def test_root_peer_adds_no_identity_read_or_empty_close_authority():
    supervisor, state, _ = model()
    supervisor.root['pid'] = 20
    stream = SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 20, 20000, 20000))
    def unexpected(pid):
        raise AssertionError('root never uses controlled-child empty close')
    capture(supervisor, stream, state, unexpected)
    assert state['accepted_peer'] is None and state['peer_pid'] == 20


def test_native_sigterm_empty_channel_waits_for_real_terminal_join(tmp_path, monkeypatch):
    import hashlib
    import json
    import os
    import signal
    import sys
    from linux_supervisor import Supervisor
    if sys.platform != 'linux':
        pytest.skip('actual Linux ptrace, SO_PEERCRED and numeric parent wait required')
    body = '''
import json,os,signal,socket,sys,time
from pathlib import Path
root=Path(sys.argv[1]);child=os.fork()
if child==0:
    os.setsid()
    (root/'ready.tmp').write_text(json.dumps({'child':os.getpid(),'parent':os.getppid()}))
    (root/'ready.tmp').replace(root/'ready.json')
    while not (root/'go').exists(): time.sleep(.001)
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    client.connect(str(root/'channel.sock'))
    signal.pause()
    os._exit(99)
while not (root/'accepted').exists(): time.sleep(.001)
os.kill(child,signal.SIGTERM)
actual,raw=os.waitpid(child,0)
assert actual==child and raw==15 and os.waitstatus_to_exitcode(raw)==-15
(root/'wait.tmp').write_text(json.dumps({'child':actual,'raw':raw}))
(root/'wait.tmp').replace(root/'wait.json')
while not (root/'closed').exists(): time.sleep(.001)
'''
    argv = [sys.executable, '-I', '-S', '-c', body, str(tmp_path)]
    allowed = [{'path': sys.executable, 'argv': argv, 'environment': {}, 'cwd': os.getcwd(),
                'sha256': hashlib.sha256(__import__('pathlib').Path(sys.executable).read_bytes()).hexdigest()}]
    manifest = tmp_path / 'manifest.json'
    manifest.write_text('{}')
    config = {'manifest': str(manifest), 'pins': {str(manifest): hashlib.sha256(b'{}').hexdigest()},
              'endpoint': {'responses': str(tmp_path), 'nonce': 'a' * 64,
                           'socket': str(tmp_path / 'channel.sock')}}
    supervisor = Supervisor(config, SimpleNamespace(pid=os.getpid()))
    events, observed = [], {}
    monkeypatch.setattr(supervisor, 'refresh', lambda: events)
    def tick(trace):
        ready = tmp_path / 'ready.json'
        if not ready.exists():
            return
        if not observed:
            peer = json.loads(ready.read_bytes())
            from linux_supervisor import kernel
            parent, child = peer['parent'], peer['child']
            parent_birth, child_birth = kernel.identity(parent), kernel.identity(child)
            supervisor.registered[parent] = {'identity': parent_birth, 'token': 'parent'}
            supervisor.registered[child] = {'identity': child_birth, 'token': 'child'}
            events.extend([
                {'kind': 'launch_lifecycle_binding', 'owner_pid': parent, 'token': 'child',
                 'start_new_session': True, 'case': 'native-empty-close'},
                {'kind': 'registered', 'owner_pid': parent, 'pid': child, 'token': 'child',
                 'python': True, 'class': 'controlled-acp', 'case': 'native-empty-close'},
                {'kind': 'admitted', 'owner_pid': parent, 'token': 'child',
                 'class': 'controlled-acp', 'case': 'native-empty-close'},
            ])
            observed.update(peer=peer, parent_birth=parent_birth, waited=False)
            supervisor.owned_trace = trace
            (tmp_path / 'go').touch()
        wait = tmp_path / 'wait.json'
        if wait.exists() and not observed['waited']:
            value = json.loads(wait.read_bytes())
            events.append({'kind': 'raw_actual_parent_waitpid', 'pid': value['child'],
                           'child_token': 'child', 'owner_pid': observed['peer']['parent'],
                           'owner_identity': observed['parent_birth'], 'owner_token': 'parent',
                           'nonce': 'a' * 64, 'requested_pid': value['child'], 'options': 0,
                           'raw_status': value['raw'], 'numeric_returncode': os.waitstatus_to_exitcode(value['raw']),
                           'wait_event': 'actual_os_waitpid_return'})
            observed['waited'] = True
        supervisor.tick()
        assert not supervisor.poisoned
        if supervisor.clients:
            state = next(iter(supervisor.clients.values()))
            assert state['accepted_peer'] == supervisor.registered[observed['peer']['child']]
            assert not state['authenticated'] and state['request'] is None
            (tmp_path / 'accepted').touch(exist_ok=True)
        if any(row['outcome'] == 'owned_empty_reaped' for row in supervisor.channel_diagnostics):
            assert observed['waited']
            (tmp_path / 'closed').touch(exist_ok=True)
    child = os.fork()
    if child == 0:
        try:
            supervisor.channel.close()
            linux_trace.install_observation_filter()
            linux_trace.trace_me()
            os.execve(sys.executable, argv, {})
        finally:
            os._exit(127)
    try:
        result = linux_trace.OwnedTrace(child, allowed, timeout=15, selective=True, on_tick=tick).run()
        assert result['root_parent_wait_raw'] == 0 and not result['poison']
        assert (tmp_path / 'closed').exists() and observed['waited']
        assert not supervisor.receipts and not supervisor.ledger.seen and not supervisor.clients
        assert any(row['kind'] == 'original_parent_wait4' and row['child'] == observed['peer']['child']
                   and row['raw'] == signal.SIGTERM and row['normalized'] == -signal.SIGTERM
                   for row in result['records'])
    finally:
        supervisor.close()
