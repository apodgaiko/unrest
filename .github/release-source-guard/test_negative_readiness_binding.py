"""Frozen original readiness owner bindings; metadata only, no fixture launch."""
import hashlib
from pathlib import Path
import sys
import types

import pytest

from finite import negative_readiness as route


def named(code, name):
    for value in code.co_consts:
        if type(value) is types.CodeType:
            if value.co_name == name:
                return value
            result = named(value, name)
            if result is not None:
                return result
    return None


@pytest.fixture
def model(monkeypatch):
    source = Path(__file__).resolve().parents[2] / route.SOURCE
    body = source.read_bytes()
    assert hashlib.sha256(body).hexdigest() == route.PIN
    virtual = Path('/source') / route.SOURCE
    code = compile(body, str(virtual), 'exec', dont_inherit=True)
    module = types.ModuleType('negative_readiness_owner_control')
    function = types.FunctionType(named(code, route.OWNER), vars(module))
    exercise_code = named(function.__code__, 'exercise')
    exercise = types.FunctionType(exercise_code, vars(module), closure=tuple(
        types.CellType(None) for _ in exercise_code.co_freevars))
    setattr(module, route.OWNER, function)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    owner = types.SimpleNamespace(f_code=function.__code__, f_globals=vars(module),
                                 f_locals={'mode': 'never_ready', 'exercise': exercise})
    active = types.SimpleNamespace(f_code=exercise_code, f_globals=vars(module), f_lineno=70,
                                  f_locals={'mode': 'never_ready', 'body': route.BODY})
    state = {'case': route.SOURCE + '::' + route.OWNER + '[never_ready]', 'class': 'pytest-root',
             'token': 'root', 'checkout': '/source', 'product_pins': {route.SOURCE: route.PIN},
             'guard': '/guard/finite/runtime_guard.py',
             'direct_support': {'files': {'/guard/finite/fallback_binding.py': 'fallback'}},
             'isolated_named': named, 'isolated_source_code': lambda path: code}
    def refuse(reason):
        raise RuntimeError(reason)
    def frames(path, pin):
        assert str(path) == '/guard/finite/fallback_binding.py' and pin == 'fallback'
        return {'active_frames': lambda: [owner, active, active]}
    guard = types.SimpleNamespace(_STATE=state, digest=lambda path: route.PIN,
                                  checked_source=frames, refuse=refuse)
    payload = {'class': route.CLASS, 'case': state['case'], 'mode': 'inline', 'target': route.BODY,
               'orig_argv': [sys.executable, '-c', route.BODY], 'token': 'a' * 32,
               'source_binding': {'path': str(virtual), 'line': 70, 'sha256': route.PIN,
                                  'function': route.OWNER + '.<locals>.exercise'}}
    monkeypatch.setattr(route.os, 'getcwd', lambda: '/source')
    return guard, payload, owner, active


@pytest.mark.parametrize('mode', ['never_ready', 'cancel'])
def test_only_original_negative_case_publishes_non_admitting_plan(model, mode):
    guard, payload, owner, active = model
    guard._STATE['case'] = payload['case'] = route.SOURCE + '::' + route.OWNER + '[' + mode + ']'
    owner.f_locals['mode'] = active.f_locals['mode'] = mode
    calls = []
    route.plan(guard, payload, lambda kind, **kw: calls.append((kind, kw)))
    assert calls == [('plan', {'host': '127.0.0.1', 'port': 1, 'child_token': 'a' * 32,
        'argv_sha256': hashlib.sha256(__import__('json').dumps(payload['orig_argv']).encode()).hexdigest()})]
    with pytest.raises(RuntimeError, match='duplicate_plan'):
        route.plan(guard, payload, lambda *a, **k: pytest.fail('duplicate request'))


@pytest.mark.parametrize('change', ['source', 'globals', 'owner', 'exercise', 'line', 'mode',
                                   'body', 'binding', 'vector', 'token', 'payload-case'])
def test_foreign_live_claims_refuse_without_network_plan(model, change):
    guard, payload, owner, active = model
    if change == 'source':
        guard._STATE['product_pins'][route.SOURCE] = 'foreign'
    elif change == 'globals':
        active.f_globals = dict(active.f_globals)
    elif change == 'owner':
        setattr(sys.modules[owner.f_globals['__name__']], route.OWNER, lambda: None)
    elif change == 'exercise':
        owner.f_locals['exercise'] = lambda: None
    elif change == 'line':
        active.f_lineno = 74
    elif change == 'mode':
        active.f_locals['mode'] = 'ready'
    elif change == 'body':
        active.f_locals['body'] = 'foreign'
    elif change == 'binding':
        payload['source_binding']['line'] = 71
    elif change == 'vector':
        payload['orig_argv'][-1] = 'foreign'
    elif change == 'token':
        payload['token'] = 'foreign'
    else:
        payload['case'] = 'foreign'
    with pytest.raises(RuntimeError, match='negative_readiness_'):
        route.plan(guard, payload, lambda *a, **k: pytest.fail('foreign plan'))


def test_distinct_concurrent_owner_is_not_a_duplicate_reference(model):
    guard, payload, owner, active = model
    other = types.SimpleNamespace(**vars(owner))
    guard.checked_source = lambda *args: {'active_frames': lambda: [owner, other, active]}
    with pytest.raises(RuntimeError, match='live_owner'):
        route.plan(guard, payload, lambda *a, **k: pytest.fail('ambiguous plan'))
