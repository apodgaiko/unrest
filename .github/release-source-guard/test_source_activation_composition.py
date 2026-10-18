"""Callback composition controls; hosted TEST proves the unchanged source owner."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'finite'))
from source_activation import SourceActivation, CONSUMERS
from primary_source_inputs import python_environment

ROOT = Path(__file__).resolve().parent

def named(code, name):
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            if value.co_name == name:
                return value
            if (found := named(value, name)) is not None:
                return found
    return None


def module(name, path, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, result)
    spec.loader.exec_module(result)
    return result


class Refusal(RuntimeError):
    pass


class Consumed(Exception):
    pass


def setup(tmp_path, monkeypatch):
    guard = module('runtime_guard', ROOT / 'finite/runtime_guard.py', monkeypatch)
    source = tmp_path / 'owner.py'
    source.write_text('import subprocess\ndef launch(vector, directory, environment):\n'
                      '    subprocess.run(vector, cwd=directory, env=environment)\n')
    owner = module('composition_owner', source, monkeypatch)
    vector = [sys.executable, '-I', '-S', '-c', 'pass']
    registration = {'class': 'isolated-role-startup', 'python': True,
                    'argv': vector[1:], 'checkout_cwd': False,
                    'source_binding': {'path': str(source), 'line': 3,
                                       'sha256': guard.digest(source)}}
    registry = tmp_path / 'registry.py'
    registry.write_text('COMMANDS = ' + repr([registration]))
    files = {str(p): guard.digest(p) for p in (ROOT / 'finite').glob('*.py')}
    files.pop(str(ROOT / 'finite/anchor_probe.py'))
    state = {'guard': str(ROOT / 'finite/runtime_guard.py'),
             'guard_sha256': guard.digest(ROOT / 'finite/runtime_guard.py'),
             'registry': {'path': str(registry), 'sha256': guard.digest(registry)},
             'direct_support': {'files': files}, 'commands': [registration],
             'checkout': str(tmp_path), 'owned_root': str(tmp_path),
             'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                         'sha256': guard.digest(sys.executable)},
             'isolated_named': named, 'token': 'root', 'product_pins': {},
             'isolated_composition': types.SimpleNamespace(before_popen=lambda *a: None)}
    guard._STATE = state
    activation = SourceActivation.__new__(SourceActivation)
    activation.state, activation.direct = state, None
    activation.python_consumed = set()
    poison, events = [], []
    def refuse(reason):
        poison.append(reason)
        raise Refusal(reason)
    activation.refuse, activation.ready, activation.emit = refuse, lambda *a: None, events.append
    guard.refuse = refuse
    activation.shared = lambda: None
    state['operation_activation'] = activation
    state['source_activation_support'] = True
    # Stop immediately after successful consumption, before any OS launch. The
    # unchanged initialize_inner code is used, with only admission/IO test doubles.
    def emit(event):
        events.append(event)
        if event['kind'].endswith('startup_consumption'):
            raise Consumed
    activation.emit = emit
    guard.admit = lambda args, cwd, env: (registration, list(args))
    guard.require_ready = lambda *a: None
    guard.append = events.append
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({k: state[k] for k in (
        'owned_root', 'checkout', 'registry', 'direct_support', 'product_pins', 'runtime')}))
    code = named(compile(Path(state['guard']).read_bytes(), state['guard'], 'exec',
                         dont_inherit=True), 'initialize_inner')
    cells = {'command_class': 'pytest-root', 'manifest': str(manifest),
             'pin': guard.digest(manifest), 'state': state,
             'original_init': None, 'teardown': None}
    inner = types.FunctionType(code, vars(guard), closure=tuple(
        types.CellType(cells[name]) for name in code.co_freevars))
    monkeypatch.setattr(owner.subprocess.Popen, '__init__', inner)
    monkeypatch.chdir(tmp_path)
    return types.SimpleNamespace(guard=guard, activation=activation, state=state, source=source,
                                 owner=owner, vector=vector, registration=registration,
                                 poison=poison, events=events, tmp=tmp_path)


def test_ordinary_registration_consumes_in_original_guard_frame(tmp_path, monkeypatch):
    h = setup(tmp_path, monkeypatch)
    with pytest.raises(Consumed):
        h.owner.launch(h.vector, h.tmp, {'FINITE': 'original'})
    assert len(h.activation.python_consumed) == 1
    assert not h.poison and h.events[-1]['class'] == 'isolated-role-startup'


@pytest.mark.parametrize('change', ['source', 'registration', 'runtime', 'argv', 'cwd',
                                   'unknown', 'copied-globals', 'code'])
def test_changed_or_unbound_ordinary_registration_refuses(tmp_path, monkeypatch, change):
    h = setup(tmp_path, monkeypatch)
    call = h.owner.launch
    if change == 'source':
        h.source.write_text(h.source.read_text() + '# changed\n')
    elif change == 'registration':
        h.registration['source_binding']['line'] = 2
    elif change == 'runtime':
        h.state['runtime']['sha256'] = '0' * 64
    elif change == 'argv':
        h.vector[-1] = 'changed'
    elif change == 'cwd':
        h.tmp = tmp_path.parent
    elif change == 'unknown':
        h.registration = {**h.registration, 'class': 'unknown'}
        h.guard.admit = lambda args, cwd, env: (h.registration, list(args))
    elif change == 'copied-globals':
        call = types.FunctionType(call.__code__, dict(call.__globals__))
    elif change == 'code':
        call = types.FunctionType(call.__code__.replace(co_name='copied'), call.__globals__)
    with pytest.raises(Refusal):
        call(h.vector, h.tmp, {'FINITE': 'original'})
    assert h.poison
    assert not any(e.get('kind') == 'source_ordinary_startup_consumption' for e in h.events)


def test_outside_callback_and_caught_refusal_retain_poison(tmp_path, monkeypatch):
    h = setup(tmp_path, monkeypatch)
    for _ in range(2):
        try:
            h.activation.before_python(h.vector, h.tmp, {}, h.registration)
        except Refusal:
            pass
    assert len(h.poison) == 2 and not h.activation.python_consumed


def test_duplicate_launch_token_refuses(tmp_path, monkeypatch):
    h = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(h.guard.uuid, 'uuid4', lambda: types.SimpleNamespace(hex='a' * 32))
    with pytest.raises(Consumed):
        h.owner.launch(h.vector, h.tmp, {})
    with pytest.raises(Refusal, match='duplicate_consumption'):
        h.owner.launch(h.vector, h.tmp, {})
    assert h.poison == ['source_python_duplicate_consumption']


@pytest.mark.parametrize('keyword', ['env', 'cwd'])
def test_callback_rechecks_environment_and_directory_from_source(tmp_path, monkeypatch, keyword):
    h = setup(tmp_path, monkeypatch)
    inner = h.owner.subprocess.Popen.__init__
    def changed(handle, args, **kwargs):
        kwargs[keyword] = {'FINITE': 'changed'} if keyword == 'env' else tmp_path / 'different'
        return inner(handle, args, **kwargs)
    monkeypatch.setattr(h.owner.subprocess.Popen, '__init__', changed)
    with pytest.raises(Refusal, match='source_ordinary_caller_drift'):
        h.owner.launch(h.vector, tmp_path, {'FINITE': 'original'})
    assert h.poison


@pytest.mark.parametrize('kind', sorted(CONSUMERS))
def test_producer_consumers_keep_exact_direct_profile(tmp_path, monkeypatch, kind):
    h = setup(tmp_path, monkeypatch)
    h.registration = {'class': kind, 'python': True, 'source_binding': {}}
    h.guard.admit = lambda args, cwd, env: (h.registration, list(args))
    with pytest.raises(Refusal, match='source_direct_profile_drift'):
        h.owner.launch(h.vector, h.tmp, {})


def test_exact_producer_consumption_clears_only_its_direct_token(tmp_path, monkeypatch):
    h = setup(tmp_path, monkeypatch)
    h.registration = {'class': 'source-checker', 'python': True, 'source_binding': {}}
    h.guard.admit = lambda args, cwd, env: (h.registration, list(args))
    h.activation.direct = (h.vector, str(h.tmp), {})
    with pytest.raises(Consumed):
        h.owner.launch(h.vector, h.tmp, {})
    assert h.activation.direct is None and not h.poison


@pytest.mark.parametrize('drift', [False, True])
def test_reference_re_resolves_original_binding(tmp_path, monkeypatch, drift):
    h = setup(tmp_path, monkeypatch)
    h.registration = {'class': 'reference-integrity:test_passes', 'python': True,
                      'source_binding': {'original': True}}
    h.guard.admit = lambda args, cwd, env: (h.registration, list(args))
    h.state['direct_admit'] = lambda *a: ({**h.registration, 'source_binding': {}}
                                         if drift else dict(h.registration))
    with pytest.raises(Refusal if drift else Consumed):
        h.owner.launch(h.vector, h.tmp, {})
    assert bool(h.poison) is drift


def test_native_locale_binding_is_specific_and_preserves_exec_environment():
    registration = {'class': 'isolated-role-startup',
                    'source_binding': {'path': '/source/tests/test_stdio_startup.py'}}
    original = {'HOME': '/work/owned/home', 'PATH': '/bin:/usr/bin'}
    assert python_environment(original, registration, [1, 0, 0]) == {
        **original, 'LC_CTYPE': 'C.UTF-8'}
    assert 'LC_CTYPE' not in original
    for key in ('LANG', 'LC_CTYPE', 'LC_ALL'):
        env = {**original, key: 'C'}
        assert python_environment(env, registration, [1, 0, 0]) == env
    for other in ({**registration, 'class': 'unknown'},
                  {**registration, 'source_binding': {'path': '/foreign/copy.py'}}):
        assert python_environment(original, other, [1, 0, 0]) == original
    assert python_environment(original, registration, [0, 0, 0]) == original
