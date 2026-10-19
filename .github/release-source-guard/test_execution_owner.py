"""Own-identity controls for the common nested-owner boundary; no original runs."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
import types

import pytest

SUPPORT = Path(__file__).resolve().parent
ROOT = SUPPORT.parent.parent


def pin(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def named(code, name):
    if code.co_name == name:
        return code
    for child in code.co_consts:
        if isinstance(child, types.CodeType) and (found := named(child, name)) is not None:
            return found
    return None


@pytest.mark.parametrize('mutation', [None, 'outer', 'payload-outer', 'token', 'payload-token',
    'class', 'mode', 'target', 'isolated', 'binding-path', 'binding-pin', 'binding-line',
    'selection', 'extra-selection', 'marker', 'marker-parameter', 'source', 'code', 'globals', 'callsite',
    'cwd', 'report', 'live-vector', 'no-caller'])
def test_real_own_identity_requires_complete_nested_context(tmp_path, monkeypatch, mutation):
    resolver = load('execution_owner_control', SUPPORT / 'finite/execution_owner.py', monkeypatch)
    route = load('owner_probe_control', SUPPORT / 'finite/owner_probe.py', monkeypatch)
    methods = load('nested_methods_control', SUPPORT / 'nested_owner_methods.py', monkeypatch)
    directory = tmp_path / 'execution-owner-probe'
    directory.mkdir()
    source = ROOT / route.METHOD
    tree = ast.parse(source.read_bytes())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_nested_owner_probe')
    call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'subprocess.run')
    args = ['pytest', '-q', '-ra', '-p', 'no:cacheprovider',
            '--junitxml=' + str(directory / 'pytest.xml'), route.INNER]
    binding = {'path': str(source), 'line': call.lineno, 'sha256': pin(source),
               'function': '_nested_owner_probe'}
    payload = {'token': 'own-unit-token', 'class': 'source-execution-owner-probe',
               'case': route.OUTER, 'mode': 'module', 'target': 'pytest', 'isolated': False,
               'source_binding': binding, 'sys_argv': list(args),
               'orig_argv': [sys.executable, '-m', *args], 'path0': str(ROOT)}
    state = {'checkout': str(ROOT), 'owned_root': str(tmp_path), 'case': route.OUTER,
             'class': payload['class'], 'token': payload['token'], 'registered_payload': payload,
             'guard': str(SUPPORT / 'finite/runtime_guard.py'),
             'direct_support': {'files': {str(p): pin(p) for p in (SUPPORT / 'finite').glob('*.py')}},
             'product_pins': {name: pin(ROOT / name) for name in (route.METHOD, route.NESTED)},
             'isolated_source_code': lambda p: compile(p.read_bytes(), str(p), 'exec', dont_inherit=True)}
    def checked(path, expected):
        assert pin(path) == expected
        ns = {'__file__': str(path)}
        exec(compile(Path(path).read_bytes(), str(path), 'exec', dont_inherit=True), ns)
        return ns
    observed = []
    def refuse(reason):
        raise RuntimeError(reason)
    monkeypatch.setitem(sys.modules, 'runtime_guard', types.SimpleNamespace(
        _STATE=state, checked_source=checked, append=observed.append))
    monkeypatch.setenv('PYTEST_CURRENT_TEST', route.INNER + ' (call)')
    if mutation == 'outer':
        state['case'] = payload['case'] = route.METHOD + '::foreign'
    elif mutation == 'payload-outer':
        payload['case'] = 'foreign'
    elif mutation == 'token':
        state['token'] = 'foreign'
    elif mutation == 'payload-token':
        payload['token'] = 'foreign'
    elif mutation == 'class':
        payload['class'] = 'foreign'
    elif mutation in ('mode', 'target'):
        payload[mutation] = 'foreign'
    elif mutation == 'isolated':
        payload['isolated'] = True
    elif mutation == 'binding-path':
        binding['path'] = '/foreign'
    elif mutation == 'binding-pin':
        binding['sha256'] = '0' * 64
    elif mutation in ('binding-line', 'callsite'):
        binding['line'] -= 1
    elif mutation == 'selection':
        payload['orig_argv'][-1] = 'foreign'
    elif mutation == 'extra-selection':
        payload['orig_argv'].append('foreign')
    elif mutation == 'marker':
        monkeypatch.setenv('PYTEST_CURRENT_TEST', route.OUTER + ' (call)')
    elif mutation == 'marker-parameter':
        monkeypatch.setenv('PYTEST_CURRENT_TEST', route.INNER + '[foreign] (call)')
    elif mutation == 'source':
        state['product_pins'][route.NESTED] = '0' * 64
    elif mutation == 'code':
        methods.test_nested_owner.__code__ = methods.test_nested_owner.__code__.replace(co_name='foreign')
    elif mutation == 'globals':
        methods.test_nested_owner = types.FunctionType(methods.test_nested_owner.__code__,
                                                       dict(vars(methods)))
    elif mutation == 'cwd':
        payload['path0'] = '/foreign'
    elif mutation == 'report':
        payload['orig_argv'][-2] = '--junitxml=/foreign/pytest.xml'
        payload['sys_argv'][-2] = '--junitxml=/foreign/pytest.xml'
    elif mutation == 'live-vector':
        payload['sys_argv'][-1] = 'foreign'
    def intercept(*args, **kwargs):
        selected = resolver.current(state, refuse)
        assert selected == route.INNER
        observed.append({'selected': selected})
        return types.SimpleNamespace(returncode=0)
    monkeypatch.setattr(methods.subprocess, 'run', intercept)
    real_listdir = methods.os.listdir
    monkeypatch.setattr(methods.os, 'listdir', lambda p: [] if p == '/proc/self/fd' else real_listdir(p))
    if mutation is None:
        methods.test_nested_owner()
        assert state['case'] == route.OUTER and observed[0] == {'selected': route.INNER}
    else:
        with pytest.raises((RuntimeError, AssertionError)):
            if mutation == 'no-caller':
                resolver.current(state, refuse)
            else:
                methods.test_nested_owner()


def test_original_nested_inventory_joins_immutable_source_AST_only():
    """Source compilation/AST mapping is not original source-case acceptance."""
    data = ast.literal_eval(ast.parse((SUPPORT / 'finite/source_bindings.py').read_bytes()).body[1].value)
    sites = {}
    for cohort in (2, 3, 4):
        path = SUPPORT / 'finite' / ('cohort_routes.py' if cohort == 2 else f'cohort{cohort}_routes.py')
        tree = ast.parse(path.read_bytes())
        sites[cohort] = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                             and any(isinstance(t, ast.Name) and t.id == 'SITES' for t in n.targets))
    shared = {(path, line): tuple(c for c, table in sites.items() if line in table.get(path, ()))
              for table in sites.values() for path, lines in table.items() for line in lines}
    assert {key: cohorts for key, cohorts in shared.items() if len(cohorts) > 1} == {
        ('src/unrest_harness/server.py', 266): (2, 3), ('tools/release_binding.py', 36): (3, 4)}
    for row in data['selections']:
        assert pin(ROOT / row['module']) == row['source_sha256']
        for node in row['external_ordered_nodes']:
            relative, *parts = node.split('[')[0].split('::')
            scope = ast.parse((ROOT / relative).read_bytes())
            for part in parts:
                scope = next(n for n in scope.body if isinstance(n, (ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)) and n.name == part)
            assert isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))


@pytest.mark.parametrize('mutation', [None, 'proof', 'leaf', 'fds', 'custody', 'consumed',
                                     'selection', 'token', 'birth'])
def test_nested_reduction_requires_both_actual_child_joins(mutation):
    from primary_source_probe import check_execution_owner_probes
    outer = '.github/release-source-guard/multiprocess_guard_methods.py::test_owned_exit17_keeps_raw_status'
    inner = '.github/release-source-guard/nested_owner_methods.py::test_nested_owner'
    events = [{'kind': kind, 'returncode': 0, 'before_fds': 7, 'after_fds': 7, 'custody_case': outer}
              for kind in ('guard_nested_execution_owner_proof', 'guard_nested_execution_owner_leaf')]
    events += [{'kind': 'source_execution_owner_startup_consumption', 'custody_case': outer,
                'execution_owner': case, 'launch_token': token}
               for case, token in ((outer, 'parent'), (inner, 'leaf'))]
    events += [{'kind': 'registered', 'class': kind, 'token': token, 'pid': pid}
               for kind, token, pid in (('source-execution-owner-probe', 'parent', 40),
                                        ('source-execution-owner-leaf', 'leaf', 41))]
    kernel = {'records': [{'kind': 'kernel_child', 'child': pid, 'identity': {'tgid': pid}}
                          for pid in (40, 41)]}
    if mutation == 'proof':
        events.pop(0)
    elif mutation == 'leaf':
        events.pop(1)
    elif mutation == 'fds':
        events[0]['after_fds'] += 1
    elif mutation == 'custody':
        events[0]['custody_case'] = 'foreign'
    elif mutation == 'consumed':
        events.pop(2)
    elif mutation == 'selection':
        events[2]['execution_owner'] = 'foreign'
    elif mutation == 'token':
        events[2]['launch_token'] = 'foreign'
    elif mutation == 'birth':
        kernel['records'].pop()
    if mutation is None:
        assert check_execution_owner_probes({'events': events}, kernel)
    else:
        with pytest.raises(RuntimeError):
            check_execution_owner_probes({'events': events}, kernel)
