"""Closed nested ownership controls; no original test or OS process is run."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import runpy
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
control = importlib.import_module('test_indirect_terminal_binding')
BINDING, SUPPORT, original, acp_runner = control.BINDING, control.SUPPORT, control.original, control.acp_runner


@pytest.mark.parametrize('outer_module', sorted(BINDING.NESTED_MODULES))
@pytest.mark.parametrize('mutation', ['none', 'token', 'payload-case', 'payload-class', 'mode', 'isolated',
    'target', 'selection-order', 'selection-missing', 'sys-argv', 'marker', 'outer-function',
    'parent-bytes', 'reference-bytes', 'kind', 'unknown-module',
    'leaf-code', 'leaf-globals', 'missing-leaf', 'owner-function'])
def test_each_original_reference_selection_keeps_exact_leaf_custody(tmp_path, monkeypatch, outer_module, mutation):
    data = runpy.run_path(str(SUPPORT / 'source_bindings.py'))['DATA']
    row = next(row for row in data['selections'] if row['module'] == outer_module)
    assert BINDING.CASE in row['external_ordered_nodes']
    syntax = __import__('ast').parse((ROOT / outer_module).read_bytes())
    function = next(node.name for node in syntax.body if isinstance(node, __import__('ast').FunctionDef)
                    and any(arg.arg == 'lean_reference_run' for arg in node.args.args))
    custody = outer_module + '::' + function + '[original-control-case]'
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    report = tmp_path / 'reference/pytest.xml'
    report.parent.mkdir()
    policy = original._resolved(tmp_path)
    environment = {'PATH': '/bin', 'ZAI_API_KEY': 'RAW_ACP_CREDENTIAL_79d0b1'}
    client = acp_runner.ACPClient(object(), str(workspace), policy=policy, terminal_environment=environment)
    request = {'command': sys.executable, 'args': list(BINDING.VECTOR)}
    fn = getattr(original, BINDING.OWNER)
    handler = acp_runner.ACPClient._handle_terminal_create
    caller = types.SimpleNamespace(f_code=fn.__code__, f_globals=vars(original), f_lineno=546,
        f_locals={'client': client, 'terminal_environment': environment, 'policy': policy, 'tmp_path': tmp_path})
    launch = types.SimpleNamespace(f_code=handler.__code__, f_globals=vars(acp_runner), f_lineno=1034,
        f_locals={'self': client, 'params': request, 'command': sys.executable,
                  'args': request['args'], 'env': environment, 'cwd': workspace})
    pins = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        'tests/test_capability_policy.py', 'src/unrest_harness/acp_runner.py',
        'tests/contracts/conftest.py', outer_module)}
    kind = 'reference:' + outer_module
    args = ['pytest', '-q', '-ra', '-p', 'no:cacheprovider', '--junitxml=' + str(report),
            *row['external_ordered_nodes']]
    payload = {'token': 'owned-child', 'case': custody, 'class': kind, 'mode': 'module',
               'target': 'pytest', 'isolated': False, 'source_binding': data['bindings']['reference'],
               'orig_argv': [sys.executable, '-m', *args], 'sys_argv': list(args), 'path0': str(ROOT)}
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'guard': str(SUPPORT / 'runtime_guard.py'),
        'product_pins': pins, 'phase': 'READY', 'class': kind, 'token': 'owned-child', 'case': custody,
        'registered_payload': payload, 'isolated_named': control.named,
        'isolated_source_code': lambda path: fn.__code__,
        'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                    'sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
        'direct_support': {'files': {str(SUPPORT / name): hashlib.sha256((SUPPORT / name).read_bytes()).hexdigest()
                                    for name in ('execution_owner.py', 'source_bindings.py')}}}
    def checked(path, pin):
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin
        return runpy.run_path(str(path))
    def refuse(reason):
        raise RuntimeError(reason)
    ready = []
    guard = types.SimpleNamespace(require_ready=ready.append, checked_source=checked, refuse=refuse)
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.setenv('PYTEST_CURRENT_TEST', BINDING.CASE + ' (call)')
    monkeypatch.chdir(ROOT)
    frames = [launch, caller]
    if mutation == 'leaf-code':
        caller.f_code = caller.f_code.replace(co_name='foreign')
    elif mutation == 'leaf-globals':
        caller.f_globals = dict(caller.f_globals)
    elif mutation == 'missing-leaf':
        frames = [launch]
    elif mutation == 'owner-function':
        monkeypatch.setattr(original, BINDING.OWNER, lambda: None)
    elif mutation == 'token':
        payload['token'] = 'foreign'
    elif mutation == 'payload-case':
        payload['case'] = 'foreign'
    elif mutation == 'payload-class':
        payload['class'] = 'foreign'
    elif mutation == 'mode':
        payload['mode'] = 'script'
    elif mutation == 'isolated':
        payload['isolated'] = True
    elif mutation == 'target':
        payload['target'] = 'foreign'
    elif mutation == 'selection-order':
        payload['orig_argv'][-1], payload['orig_argv'][-2] = payload['orig_argv'][-2], payload['orig_argv'][-1]
        payload['sys_argv'] = payload['orig_argv'][2:]
    elif mutation == 'selection-missing':
        payload['orig_argv'].pop()
        payload['sys_argv'] = payload['orig_argv'][2:]
    elif mutation == 'sys-argv':
        payload['sys_argv'][-1] = 'foreign'
    elif mutation == 'marker':
        monkeypatch.setenv('PYTEST_CURRENT_TEST', 'foreign (call)')
    elif mutation == 'outer-function':
        state['case'] = payload['case'] = outer_module + '::foreign'
    elif mutation == 'parent-bytes':
        pins[outer_module] = '0' * 64
    elif mutation == 'reference-bytes':
        pins['tests/contracts/conftest.py'] = '0' * 64
    elif mutation == 'kind':
        state['class'] = 'reference:foreign'
    elif mutation == 'unknown-module':
        state['case'] = payload['case'] = 'tests/contracts/foreign.py::' + function
        state['class'] = payload['class'] = 'reference:tests/contracts/foreign.py'
    registration = {'class': 'reference-descendant:terminal-redaction', 'argv': list(BINDING.VECTOR),
                    'python': True, 'caller_bindings': [], 'checkout_cwd': True,
                    'source_binding': {'path': str(ROOT / 'tests/test_capability_policy.py'), 'line': 549,
                                       'sha256': pins['tests/test_capability_policy.py']}}
    try:
        result = BINDING.matches(registration, [sys.executable, *BINDING.VECTOR], str(workspace),
                                 environment, state, frames)
    except RuntimeError:
        assert mutation != 'none'
    else:
        assert bool(result) is (mutation == 'none')
        if result:
            assert result['token'] == 'owned-child' and ready == ['owned-child']
            assert os.environ['PYTEST_CURRENT_TEST'] == BINDING.CASE + ' (call)'
            assert payload['case'] == custody and state['case'] == custody
            assert json.dumps(registration['argv']) == json.dumps(BINDING.VECTOR)


def test_nested_domain_is_exactly_the_existing_leaf_selection_inventory():
    data = runpy.run_path(str(SUPPORT / 'source_bindings.py'))['DATA']
    assert BINDING.NESTED_MODULES == frozenset(
        row['module'] for row in data['selections'] if BINDING.CASE in row['external_ordered_nodes'])
