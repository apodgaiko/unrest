"""Read original code identities without invoking or replacing an original test."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

acp_runner = importlib.import_module('unrest_harness.acp_runner')
original = importlib.import_module('tests.test_capability_policy')
SUPPORT = Path(__file__).with_name('finite')
SPEC = importlib.util.spec_from_file_location('indirect_terminal_control', SUPPORT / 'indirect_terminal_binding.py')
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


def named(code, name):
    if getattr(code, 'co_name', None) == name:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType) and (result := named(value, name)) is not None:
            return result
    return None


@pytest.mark.parametrize('change', [None, 'case', 'class', 'token', 'payload', 'phase',
    'request-key', 'request-vector', 'handler', 'instance-handler', 'handler-code',
    'handler-globals', 'caller-code', 'caller-globals', 'missing-owner', 'duplicate-owner',
    'client', 'policy', 'role', 'cwd', 'parent-cwd', 'env', 'env-copy', 'vector',
    'executable', 'runtime', 'source', 'registration', 'owner-function', 'nested-wrong',
    'nested-token'])
def test_closed_original_request_binding(tmp_path, monkeypatch, change):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    policy = original._resolved(tmp_path)
    env = {'PATH': '/bin', 'ZAI_API_KEY': 'RAW_ACP_CREDENTIAL_79d0b1'}
    client = acp_runner.ACPClient(object(), str(workspace), policy=policy, terminal_environment=env)
    env = dict(env)
    vector = [sys.executable, *BINDING.VECTOR]
    request = {'command': sys.executable, 'args': list(BINDING.VECTOR)}
    fn = getattr(original, BINDING.OWNER)
    handler = acp_runner.ACPClient._handle_terminal_create
    owner = types.SimpleNamespace(f_code=fn.__code__, f_globals=vars(original), f_lineno=546,
        f_locals={'client': client, 'terminal_environment': env, 'policy': policy, 'tmp_path': tmp_path})
    launch = types.SimpleNamespace(f_code=handler.__code__, f_globals=vars(acp_runner), f_lineno=1034,
        f_locals={'self': client, 'params': request, 'command': sys.executable,
                  'args': request['args'], 'env': env, 'cwd': workspace})
    frames = [launch, owner]
    pins = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in (
        'tests/test_capability_policy.py', 'src/unrest_harness/acp_runner.py')}
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'guard': str(SUPPORT / 'runtime_guard.py'),
        'product_pins': pins, 'phase': 'READY', 'class': 'pytest-root', 'token': 'root',
        'case': BINDING.CASE, 'isolated_named': named,
        'isolated_source_code': lambda p: fn.__code__,
        'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                    'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}}
    reg = {'class': 'reference-descendant:terminal-redaction', 'argv': list(BINDING.VECTOR),
           'python': True, 'caller_bindings': [], 'checkout_cwd': True,
           'source_binding': {'path': str(ROOT / 'tests/test_capability_policy.py'), 'line': 549,
                              'sha256': pins['tests/test_capability_policy.py']}}
    ready = []
    guard = types.SimpleNamespace(require_ready=ready.append)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.chdir(ROOT)
    cwd = str(workspace)
    if change in {'case', 'class', 'token', 'phase'}:
        state[change] = 'foreign'
    elif change == 'payload':
        state['registered_payload'] = {'token': 'foreign'}
    elif change == 'request-key':
        request['env'] = []
    elif change == 'request-vector':
        request['args'][-1] = 'pass'
    elif change == 'handler':
        monkeypatch.setattr(acp_runner.ACPClient, '_handle_terminal_create', lambda: None)
    elif change == 'instance-handler':
        client._handle_terminal_create = lambda: None
    elif change == 'handler-code':
        launch.f_code = launch.f_code.replace(co_name='foreign')
    elif change == 'handler-globals':
        launch.f_globals = dict(launch.f_globals)
    elif change == 'caller-code':
        owner.f_code = owner.f_code.replace(co_name='foreign')
    elif change == 'caller-globals':
        owner.f_globals = dict(owner.f_globals)
    elif change == 'missing-owner':
        frames.pop()
    elif change == 'duplicate-owner':
        frames.append(types.SimpleNamespace(**vars(owner)))
    elif change == 'client':
        launch.f_locals['self'] = object()
    elif change == 'policy':
        owner.f_locals['policy'] = object()
    elif change == 'role':
        client._policy = original._resolved(tmp_path, role='orchestrator')
        owner.f_locals['policy'] = client._policy
    elif change == 'cwd':
        cwd = str(tmp_path)
    elif change == 'parent-cwd':
        monkeypatch.chdir(tmp_path)
    elif change == 'env':
        env['EXTRA'] = 'foreign'
    elif change == 'env-copy':
        env = dict(env)
    elif change == 'vector':
        vector[-1] = 'pass'
    elif change == 'executable':
        vector[0] += '-foreign'
    elif change == 'runtime':
        state['runtime']['sha256'] = '0' * 64
    elif change == 'source':
        pins['src/unrest_harness/acp_runner.py'] = '0' * 64
    elif change == 'registration':
        reg['source_binding']['line'] = 546
    elif change == 'owner-function':
        monkeypatch.setattr(original, BINDING.OWNER, lambda: None)
    elif change in {'nested-wrong', 'nested-token'}:
        state.update(case=BINDING.OUTER, token='child', registered_payload={'token': 'other'})
        path = SUPPORT / 'execution_owner.py'
        state['direct_support'] = {'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}
        guard.refuse = lambda reason: (_ for _ in ()).throw(RuntimeError(reason))
        if change == 'nested-wrong':
            guard.checked_source = lambda *a: {'resolve': lambda *a: 'foreign'}
        else:
            # The real resolver rejects custody before it can authorize ownership.
            spec = importlib.util.spec_from_file_location('owner_control', path)
            resolver = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(resolver)
            state['class'] = 'reference:tests/contracts/test_lean_evidence_crosswalk.py'
            guard.checked_source = lambda *a: {'resolve': resolver.resolve, 'DATA': {'selections': [
                {'module': 'tests/contracts/test_lean_evidence_crosswalk.py', 'source_sha256': 'pin'}],
                'bindings': {'reference': {'sha256': 'wrong'}}}}
            with pytest.raises((RuntimeError, KeyError)):
                BINDING.matches(reg, vector, cwd, env, state, frames)
            return
    result = BINDING.matches(reg, vector, cwd, env, state, frames)
    assert bool(result) is (change is None)
    if result:
        assert result['line'] == 546 and result['handler_line'] == 1034
        assert ready == ['root']


def test_actual_handler_and_protected_admission_refuse_a_guard_control_owner(tmp_path, monkeypatch):
    import asyncio
    import json
    import subprocess
    spec = importlib.util.spec_from_file_location('runtime_guard', SUPPORT / 'runtime_guard.py')
    guard = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    spec.loader.exec_module(guard)
    events = tmp_path / 'events'
    events.mkdir()
    reg = {'class': 'reference-descendant:terminal-redaction', 'argv': list(BINDING.VECTOR),
           'python': True, 'caller_bindings': [], 'checkout_cwd': True,
           'source_binding': {'path': str(ROOT / 'tests/test_capability_policy.py'), 'line': 549,
                             'sha256': guard.digest(ROOT / 'tests/test_capability_policy.py')}}
    state = {'guard': str(SUPPORT / 'runtime_guard.py'), 'events': str(events),
        'checkout': str(ROOT), 'owned_root': str(tmp_path), 'phase': 'READY',
        'class': 'pytest-root', 'token': 'root',
        'case': '.github/release-source-guard/test_indirect_terminal_binding.py::test_actual_handler_and_protected_admission_refuse_a_guard_control_owner',
        'commands': [reg], 'direct_admit': lambda *a: None,
        'direct_support': {'files': {str(SUPPORT / n): guard.digest(SUPPORT / n) for n in (
            'fallback_binding.py', 'indirect_terminal_binding.py')}},
        'product_pins': {'tests/test_capability_policy.py': reg['source_binding']['sha256']},
        'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                    'sha256': guard.digest(sys.executable)}}
    guard._STATE = state
    poison = []
    monkeypatch.setitem(sys.modules, 'endpoint', types.SimpleNamespace(
        request=lambda kind, **fields: poison.append((kind, fields))))
    def admission_only(handle, args, **kwargs):
        guard.admit(args, kwargs.get('cwd'), kwargs.get('env'))
        pytest.fail('unowned original route reached OS launch')
    monkeypatch.setattr(subprocess.Popen, '__init__', admission_only)
    monkeypatch.chdir(ROOT)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    client = acp_runner.ACPClient(object(), str(workspace), policy=original._resolved(tmp_path),
                                  terminal_environment={'PATH': '/bin'})
    for _ in range(2):
        try:
            asyncio.run(client._handle_terminal_create(
                {'command': sys.executable, 'args': list(BINDING.VECTOR)}))
        except guard.GuardRefusal as error:
            assert str(error).endswith('unknown_command')
    assert len(poison) == 2 and all(kind == 'poison' and fields == {
        'reason': 'unknown_command', 'token': 'root'} for kind, fields in poison)
    rows = [json.loads(line) for line in (events / (str(__import__('os').getpid()) + '.jsonl')).read_text().splitlines()]
    assert len([row for row in rows if row['kind'] == 'forbidden' and row['reason'] == 'unknown_command']) == 2
