"""Metadata-only custody controls for both exact original inflight parameters."""
import asyncio.subprocess
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
from types import CodeType, FunctionType, ModuleType, SimpleNamespace

import pytest

from finite import inflight_cleanup as route

ROOT = Path(__file__).resolve().parents[2]


def named(code, name):
    for item in code.co_consts:
        if isinstance(item, CodeType):
            if item.co_name == name:
                return item
            found = named(item, name)
            if found is not None:
                return found
    return None


@pytest.fixture
def model(tmp_path, monkeypatch):
    source = ROOT / route.SOURCE
    code = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True)
    module = ModuleType('inflight_owner_control')
    function = FunctionType(named(code, route.OWNER), vars(module))
    setattr(module, route.OWNER, function)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    frame = SimpleNamespace(f_code=function.__code__, f_globals=vars(module), f_lineno=421,
        f_locals={'settlement_fault': False, 'tmp_path': tmp_path,
                  'spawn': asyncio.subprocess.create_subprocess_exec})
    state = {'case': route.SOURCE + '::' + route.OWNER + '[False]',
        'checkout': str(ROOT), 'owned_root': str(tmp_path),
        'product_pins': {route.SOURCE: hashlib.sha256(source.read_bytes()).hexdigest()},
        'isolated_named': named,
        'isolated_source_code': lambda p: compile(p.read_bytes(), str(p), 'exec', dont_inherit=True)}
    def refuse(reason):
        raise RuntimeError(reason)
    return SimpleNamespace(frame=frame, state=state, refuse=refuse,
                           argv=[sys.executable, '-c', route.BODY], temporary=tmp_path, code=code)


@pytest.mark.parametrize('fault', [False, True])
def test_two_initial_children_reuse_only_original_literal_class(model, fault):
    m = model
    m.frame.f_locals['settlement_fault'] = fault
    m.state['case'] = route.SOURCE + '::' + route.OWNER + '[' + str(fault) + ']'
    result = route.admit(m.argv, None, None, m.state, [m.frame, m.frame], m.refuse)
    assert result['class'] == 'inline:test_acp_cleanup.py:51'
    assert result['source_binding']['line'] == 421


@pytest.mark.parametrize('change', ['vector', 'alias', 'environment', 'cwd', 'pin', 'parameter'])
def test_foreign_initial_claims_refuse(model, change):
    m = model
    cwd, env = None, None
    if change == 'vector':
        m.argv[-1] += ';foreign()'
    elif change == 'alias':
        m.frame.f_locals['spawn'] = lambda *a: None
    elif change == 'environment':
        env = {}
    elif change == 'cwd':
        cwd = str(m.temporary)
    elif change == 'pin':
        m.state['product_pins'][route.SOURCE] = '0' * 64
    else:
        m.frame.f_locals['settlement_fault'] = True
    with pytest.raises(RuntimeError, match='inflight_'):
        route.admit(m.argv, cwd, env, m.state, [m.frame], m.refuse)


def test_third_child_requires_original_paused_producer_and_product_frame(model, monkeypatch):
    m = model
    source = ROOT / 'src/unrest_harness/acp_runner.py'
    loader = SourceFileLoader('inflight_product_control', str(source))
    module = ModuleType(loader.name)
    module.__loader__ = loader
    module.__spec__ = importlib.util.spec_from_loader(loader.name, loader)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    code = loader.source_to_code(source.read_bytes(), str(source))
    children = [object(), object()]
    client = SimpleNamespace(_process=children[0], _terminals={'existing': SimpleNamespace(process=children[1])})
    m.frame.f_lineno = 472
    m.frame.f_locals.update(client=client, children=children)
    paused = SimpleNamespace(f_code=named(m.code, 'paused_spawn'), f_globals=m.frame.f_globals,
        f_lineno=437, f_locals={'spawn': asyncio.subprocess.create_subprocess_exec,
            'args': tuple(m.argv), 'kwargs': {'cwd': str(m.temporary), 'env': {}}})
    product = SimpleNamespace(f_code=named(code, '_handle_terminal_create'), f_globals=vars(module),
        f_lineno=1034, f_locals={'self': client})
    m.state['product_pins']['src/unrest_harness/acp_runner.py'] = hashlib.sha256(source.read_bytes()).hexdigest()
    result = route.admit(m.argv, str(m.temporary), {}, m.state, [m.frame, paused, product], m.refuse)
    assert result['source_binding']['path'] == str(source)
    product.f_locals['self'] = object()
    with pytest.raises(RuntimeError, match='terminal_context'):
        route.admit(m.argv, str(m.temporary), {}, m.state, [m.frame, paused, product], m.refuse)


def test_paused_spawn_anchor_is_the_original_await_expression():
    import ast
    tree = ast.parse((ROOT / route.SOURCE).read_bytes())
    owner = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                 and node.name == route.OWNER)
    paused = next(node for node in owner.body if isinstance(node, ast.AsyncFunctionDef)
                  and node.name == 'paused_spawn')
    calls = [node for node in ast.walk(paused) if isinstance(node, ast.Await)
             and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
             and node.value.func.id == 'spawn']
    assert len(calls) == 1 and calls[0].lineno == 437
    wrong = next(node for node in owner.body if node.lineno == 434)
    assert isinstance(wrong, ast.Assign) and ast.unparse(wrong.value) == 'a._close_subprocess'
