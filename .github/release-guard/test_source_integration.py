"""Independent request mutations and immutable-input controls for source entry."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import signal
import sys
import threading
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from controlled_startup import BACKEND_PIN, CASES, SESSION
from endpoint_policy import Socket
from launch_policy import Rule, render
from process_ledger import Birth
from source_code import Bodies
from source_host import inventory
import source_host
from source_entry import Policy
from source_observer import Observer
from source_profile import ROOT_COMMAND
import source_observer


def test_private_input_inventory_rejects_aliases_and_writeable_members(tmp_path):
    member = tmp_path / 'module.py'
    member.write_text('value = 1\n')
    member.chmod(0o644)
    original = inventory(tmp_path)
    member.write_text('value = 2\n')
    assert inventory(tmp_path) != original
    member.chmod(0o666)
    with pytest.raises(RuntimeError, match='mutable'):
        inventory(tmp_path)
    member.chmod(0o644)
    (tmp_path / 'alias').symlink_to(member)
    with pytest.raises(RuntimeError, match='custody'):
        inventory(tmp_path)


def backend_request(tmp_path):
    observer = object.__new__(Observer)
    observer.root_birth = Birth(1, 1, 1, 1, 'test-boot', 20000)
    observer.finished, observer.case, observer.serial = False, CASES[0], 0
    observer.meta = {'owned': str(tmp_path)}
    observer.binding = {'entry': {'path': '/pinned/python', 'sha256': 'a' * 64}}
    observer.intents = {}
    home = tmp_path / 'case' / 'owner' / 'worker'
    home.mkdir(parents=True)
    cwd = str(home)
    native = '/pinned/python'
    rule = Rule('controlled-startup:backend', SESSION + ':_open_role_owned', (CASES[0],),
        native, 'a' * 64, (native, str(home.parent / 'fake-app-server'), 'app-server'),
        tuple(sorted({'HOME': cwd, 'CODEX_HOME': str(home / 'codex'), 'TMPDIR': str(home / 'tmp'),
                      'PATH': '/usr/bin:/bin'}.items())), cwd, 'python-script', BACKEND_PIN)
    expected = render(rule, CASES[0], rule.owner, {}, {})
    request = {'case': CASES[0], 'source_line': 506, 'script_sha256': BACKEND_PIN,
               'original': json.loads(json.dumps(asdict(expected))),
               'translated': [native, '-I', '-S', *expected.argv[1:]]}
    actor = {'birth': observer.root_birth, 'role': 'root'}
    return observer, actor, request


@pytest.mark.parametrize('mutation', ('case', 'site', 'script', 'argv', 'environment', 'cwd', 'owner', 'runtime'))
def test_host_reconstructs_exact_original_launch(tmp_path, mutation):
    observer, actor, request = backend_request(tmp_path)
    changed = deepcopy(request)
    if mutation == 'case':
        changed['case'] = CASES[1]
    elif mutation == 'site':
        changed['source_line'] = 507
    elif mutation == 'script':
        changed['script_sha256'] = 'b' * 64
    elif mutation == 'argv':
        changed['translated'].append('--foreign')
    elif mutation == 'environment':
        changed['original']['environment'].append(['UNDECLARED', '1'])
    elif mutation == 'cwd':
        changed['original']['cwd'] = str(tmp_path)
    elif mutation == 'owner':
        changed['original']['owner'] = 'borrowed-source-name'
    else:
        changed['original']['executable_sha256'] = 'b' * 64
    with pytest.raises(Refused):
        observer.launch(actor, changed)
    assert not observer.intents
    assert observer.launch(actor, request)['ok'] is True
    assert len(observer.intents) == 1
    with pytest.raises(Refused):
        observer.launch(actor, request)


def test_fixed_root_entry_precedes_ordinary_inprocess_computation():
    bodies = Bodies({'role': 'root'})
    with pytest.raises(Refused, match='unknown Python execution'):
        bodies.audit('exec', (compile('print("foreign")', '<string>', 'exec'),))
    assert bodies.next == 0
    assert bodies.audit('compile', ((ROOT_COMMAND + '\n').encode(), '<string>'))
    assert bodies.audit('exec', (compile(ROOT_COMMAND + '\n', '<string>', 'exec', dont_inherit=True),))
    assert bodies.audit('compile', (b'value = 1', '<ordinary-library-code>'))
    assert bodies.audit('exec', (compile('value = 1', '<ordinary-library-code>', 'exec'),))


def test_existing_listener_can_relisten_without_new_endpoint_authority(tmp_path, monkeypatch):
    observer, actor, _ = backend_request(tmp_path)
    initial = Socket(actor['birth'], 7, 1000, 2000, 7, 20000, ('0.0.0.0', 0), None)
    bound = replace(initial, local=('127.0.0.1', 12345))
    listening = replace(bound, state=10)
    observer.bindings = {(actor['birth'], 7): {'socket': initial, 'tag': 'broker', 'nonce': None,
        'case': CASES[0], 'listening': False, 'listen_pending': False}}
    observer.listeners, observer.listener_fds = {}, {}
    observed = bound
    monkeypatch.setattr(source_observer, 'acquire_tcp', lambda *args, **kwargs: observed)
    def stage(value):
        return observer.dispatch(actor, {'kind': 'listen', 'payload': {'fd': 7, 'stage': value}})
    assert stage('before') == {'ok': True}
    observed = listening
    assert stage('after') == {'ok': True}
    assert stage('before') == {'ok': True}
    assert stage('after') == {'ok': True}
    assert len(observer.listeners) == 1
    observed = replace(listening, cookie=2001)
    with pytest.raises(Refused, match='descriptor'):
        stage('before')


def test_sealed_leaf_keeps_exact_fixture_execution(tmp_path):
    checkout = Path(__file__).resolve().parents[2]
    fixture = checkout / 'tests/fixtures/experimental_session_app_server.py'
    script = tmp_path / 'fake-app-server'
    script.write_bytes(fixture.read_bytes())
    bodies = Bodies({'role': 'backend', 'checkout': str(checkout), 'script': str(script)})
    with pytest.raises(Refused, match='compilation bytes'):
        bodies.audit('compile', (b'print("foreign")', str(script)))
    assert bodies.audit('compile', (script.read_bytes(), str(script)))
    assert bodies.audit('exec', (compile(script.read_bytes(), str(script), 'exec', dont_inherit=True),))
    with pytest.raises(Refused, match='unknown Python execution'):
        bodies.audit('exec', (compile('print("foreign")', str(script), 'exec'),))


@pytest.mark.parametrize('sig', [signal.SIGTERM, 15])
def test_original_signal_enum_is_normalized_without_signal_substitution(monkeypatch, sig):
    import subprocess
    checked, requested = [], []
    def check(pid, number, group):
        checked.append((pid, number, group))
        assert type(number) is int and number == 15
    def request(kind, payload):
        requested.append((kind, payload))
        return {'ok': True, 'live': False}  # Actual terminal evidence forbids delivery.
    policy = SimpleNamespace(profile={'role': 'root'}, local=threading.local(),
        calls=SimpleNamespace(signal=check), children={123: {'token': 'owned'}},
        client=SimpleNamespace(request=request))
    def refuse(code):
        raise Refused(code)
    policy.refuse = refuse
    for obj, name in ((subprocess.Popen, '__init__'), (os, 'waitpid'), (os, 'kill'), (os, 'killpg')):
        monkeypatch.setattr(obj, name, getattr(obj, name))  # Register restoration before installation.
    Policy.install_process_hooks(policy)
    with pytest.raises(ProcessLookupError):
        os.killpg(123, sig)
    assert checked == [(123, 15, True)]
    assert requested == [('custody_signal', {'pid': 123, 'child_token': 'owned', 'signal': 15, 'group': True})]
    with pytest.raises(Refused, match='nonnumeric'):
        os.killpg(123, True)
    assert len(requested) == 1


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux subreaper ownership')
def test_adopted_parent_drain_rechecks_newly_adopted_descendant():
    import ctypes
    import select
    read, write = os.pipe()
    driver = os.fork()
    if driver == 0:
        os.close(read)
        try:
            assert not source_host.children()
            assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
            ready_read, ready_write = os.pipe()
            parent = os.fork()
            if parent == 0:
                os.close(ready_read)
                descendant = os.fork()
                if descendant == 0:
                    os.write(ready_write, b'R')
                # Finite failure fallback even if the dedicated driver dies.
                __import__('time').sleep(8)
                os._exit(125)
            os.close(ready_write)
            assert select.select([ready_read], [], [], 2)[0] and os.read(ready_read, 1) == b'R'
            os.close(ready_read)
            assert source_host.children() == [parent]
            rows = []
            source_host.drain_owned(rows)
            assert len(rows) == 2 and rows[0]['pid'] == parent
            assert all(row['actual_wait'] == signal.SIGKILL and row['original_parent_wait_proven'] is False for row in rows)
            assert not source_host.children()
            os.write(write, b'OK')
        except BaseException:
            os._exit(125)
        os._exit(0)
    os.close(write)
    try:
        assert select.select([read], [], [], 7)[0] and os.read(read, 3) == b'OK'
        assert source_host.settle(driver) == 0
    finally:
        source_host.settle(driver, terminate=True)
        os.close(read)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual wait and Unix peer birth')
def test_poisoned_cleanup_retains_actual_parent_wait_without_restoring_authority():
    import socket
    import control_transport as transport
    from linux_observation import process_identity
    from process_ledger import Ledger
    ledger = Ledger('cleanup-nonce')
    root_id = process_identity(os.getpid())
    birth = Birth.read(root_id)
    ledger.kernel(0, {'kind': 'kernel_root', 'identity': root_id})
    ledger.register(birth, 'root-token', (('pin', 'a' * 64),), 'seal', case='case', command_class='bootstrap-root', expected_generation=1)
    ledger.process(birth).generation = 1  # Reducer epoch setup, not kernel-exec evidence.
    held_read, held_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(held_write)
        os.read(held_read, 1)
        os._exit(17)
    os.close(held_read)
    try:
        child_id = process_identity(child)
        child_birth = Birth.read(child_id)
        ledger.kernel(1, {'kind': 'kernel_child', 'parent': birth.pid, 'child': child, 'event': 1, 'identity': child_id})
        ledger.register(child_birth, 'child-token', (('pin', 'a' * 64),), 'seal', case='case', command_class='child')
        os.close(held_write)
        held_write = -1
        actual, raw = os.waitpid(child, 0)
        assert actual == child and raw == 17 << 8
        observer = object.__new__(Observer)
        observer.root_birth, observer.root, observer.ledger, observer.finished = birth, birth.pid, ledger, False
        actor = {'birth': birth, 'role': 'root', 'token': 'root-token', 'sequence': 0}
        observer.actors = {child: {'birth': child_birth, 'returned': True}}
        payload = {'pid': child, 'requested_pid': child, 'child_token': 'child-token',
                   'raw_status': raw, 'numeric_returncode': os.waitstatus_to_exitcode(raw), 'options': 0}
        request = {'pid': birth.pid, 'nonce': ledger.nonce, 'token': 'root-token', 'generation': 1,
                   'id': 'a' * 32, 'kind': 'drain_child', 'payload': payload}
        left, right = socket.socketpair()
        try:
            frame = transport.Frame(right, transport.REQUEST_LIMIT, ledger.poison)
            frame.capture(ledger, birth, 'root-token', os.getgid())
            left.sendall(transport.encode(request, transport.REQUEST_LIMIT))
            assert frame.read() == request
            ledger.poison.append('preserved source refusal')
            admission = transport.Admission(ledger, frozenset({'drain_child', 'launch-intent'}))
            assert observer.dispatch(actor, admission.admit(frame)) == {'ok': True}
            assert ledger.process(child_birth).receipt['raw_status'] == raw
            assert ledger.poison == ['preserved source refusal']
            assert not ledger.reaped(child_birth, 'child-token')  # No fabricated kernel wait joins.
            frame.received = {**request, 'id': 'b' * 32, 'kind': 'launch-intent'}
            with pytest.raises(Refused):
                admission.admit(frame)
        finally:
            left.close()
            right.close()
    finally:
        if held_write >= 0:
            os.close(held_write)
        source_host.settle(child, terminate=True)
