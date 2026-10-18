"""Bind the actual endpoint closure and original guard installation frame."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import types

import pytest

from test_primary_native_route import route as route

ROOT = Path(__file__).parent


def loaded(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


@pytest.fixture
def installed_binding(route, monkeypatch):
    guard_path = ROOT / 'finite/runtime_guard.py'
    guard = loaded('runtime_guard', guard_path)
    endpoint_path = ROOT / 'finite/endpoint.py'
    endpoint = loaded('endpoint', endpoint_path)
    endpoint.STATE = {'spec': {}}
    monkeypatch.setitem(sys.modules, 'runtime_guard', guard)
    monkeypatch.setitem(sys.modules, 'endpoint', endpoint)
    monkeypatch.setattr(os, 'waitpid', os.waitpid)
    original = guard.install
    endpoint.attach(guard)
    namespace = route.namespace
    namespace.update(sys=sys, types=types)
    legacy = ast.parse((ROOT / 'finite/source_operations.py').read_bytes())
    identity = next(n for n in legacy.body if isinstance(n, ast.FunctionDef) and n.name == 'code_identity')
    helper = next(n for n in ast.parse((ROOT / 'primary_operations.py').read_bytes()).body
                  if isinstance(n, ast.FunctionDef) and n.name == 'original_guard_install')
    exec(compile(ast.Module(body=[identity, helper], type_ignores=[]), '<binding>', 'exec'), namespace)
    state = {'guard': str(guard_path), 'endpoint': {
        'sha256': hashlib.sha256(endpoint_path.read_bytes()).hexdigest()}}
    return types.SimpleNamespace(guard=guard, endpoint=endpoint, state=state, original=original,
                                 resolve=namespace['original_guard_install'], route=route)


@pytest.mark.parametrize('change', ['none', 'missing_endpoint', 'foreign_globals', 'wrapper_code',
                                    'wrapper_function', 'guard_cell', 'original_code',
                                    'original_globals', 'endpoint_pin'])
def test_only_exact_endpoint_wrapper_resolves_original_install(installed_binding, monkeypatch, change):
    f = installed_binding
    assert f.guard.install.__code__ is not f.original.__code__
    cells = dict(zip(f.guard.install.__code__.co_freevars, f.guard.install.__closure__))
    if change == 'missing_endpoint':
        monkeypatch.delitem(sys.modules, 'endpoint')
    elif change == 'foreign_globals':
        monkeypatch.setitem(sys.modules, 'endpoint', types.ModuleType('foreign'))
    elif change == 'wrapper_code':
        monkeypatch.setattr(f.guard, 'install', types.FunctionType((lambda: None).__code__, f.endpoint.__dict__))
    elif change == 'wrapper_function':
        monkeypatch.setattr(f.guard, 'install', object())
    elif change == 'guard_cell':
        cells['guard'].cell_contents = object()
    elif change == 'original_code':
        cells['original_install'].cell_contents = lambda: None
    elif change == 'original_globals':
        cells['original_install'].cell_contents = types.FunctionType(f.original.__code__, {}, 'install')
    elif change == 'endpoint_pin':
        f.state['endpoint']['sha256'] = '0' * 64
    body = Path(f.state['guard']).read_bytes()
    if change == 'none':
        assert f.resolve(f.guard, f.state, body, f.route.operation.refuse) is f.original
    else:
        with pytest.raises(RuntimeError, match='primary_native_route_'):
            f.resolve(f.guard, f.state, body, f.route.operation.refuse)


def test_constructor_runs_in_actual_original_guard_install_frame(installed_binding, monkeypatch, tmp_path):
    f = installed_binding
    namespace = f.route.namespace
    namespace['subprocess'] = __import__('subprocess')
    before = namespace['subprocess'].Popen.__init__
    monkeypatch.setattr(namespace['subprocess'].Popen, '__init__', before)
    def legacy_init(self, state, emit, refuse, ready):
        self.state, self.emit, self.refuse, self.ready = state, emit, refuse, ready
    monkeypatch.setattr(namespace['Legacy'], '__init__', legacy_init)
    # Only pre-constructor setup is synthetic. Both installer code objects and
    # endpoint closure are the actual byte-current sources; no child is launched.
    state = {**f.state, 'registry': {'path': 'registry', 'sha256': 'pin'},
             'guard_sha256': hashlib.sha256(Path(f.state['guard']).read_bytes()).hexdigest(),
             'direct_support': {'path': 'direct', 'files': {'direct': 'pin'}},
             'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                         'sha256': 'pin'},
             'operation_support': {'path': 'operations', 'sha256': 'pin',
                                   'spec_path': str(tmp_path / 'spec.json'), 'spec_sha256': 'pin'}}
    for name in ('isolated_refusal.py', 'refusal_composition.py'):
        state['direct_support']['files'][str(ROOT / 'finite' / name)] = 'pin'
    (tmp_path / 'spec.json').write_text('{}')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps(state))
    f.guard.digest = lambda path: state['guard_sha256'] if str(path) == state['guard'] else 'pin'
    f.guard.append = lambda row: None
    f.guard.refuse = f.route.operation.refuse
    f.guard.require_ready = lambda token: None
    def checked(path, pin):
        if str(path) == 'registry':
            return {'COMMANDS': {}}
        if str(path) == 'direct':
            return {'admit': lambda: None}
        if str(path).endswith('isolated_refusal.py'):
            return {'source_code': lambda: None, 'named': None, 'IsolatedComposition': lambda *a: None}
        if str(path).endswith('refusal_composition.py'):
            return {'Composition': lambda *a: None}
        assert str(path) == 'operations'
        return {'Operations': namespace['Operations']}
    f.guard.checked_source = checked
    monkeypatch.setattr(sys, 'addaudithook', lambda hook: None)
    monkeypatch.setattr(sys, '_unrest_finite_source_audit', None, raising=False)
    # Stop immediately after the real constructor, before unrelated setup.
    with pytest.raises(AttributeError, match='profile'):
        f.guard.install(str(manifest), 'pin')
    assert namespace['subprocess'].Popen.__init__ is not before
    assert f.guard._STATE['operations'].state is f.guard._STATE
