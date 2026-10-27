"""Independent request mutations and immutable-input controls for source entry."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from content_manifest import Refused
from controlled_startup import BACKEND_PIN, CASES, SESSION
from endpoint_policy import Socket
from launch_policy import Rule, render
from process_ledger import Birth
from source_code import Bodies
from source_host import inventory
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
