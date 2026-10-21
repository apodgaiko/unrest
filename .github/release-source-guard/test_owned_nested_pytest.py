"""Metadata custody of both unchanged original nested negative pytest calls."""
from pathlib import Path
from types import CodeType, FunctionType, ModuleType, SimpleNamespace
import ast
import hashlib
import sys

import pytest
from finite import owned_nested_pytest as nested

ROOT = Path(__file__).resolve().parents[2]


def named(code, name):
    for value in code.co_consts:
        if isinstance(value, CodeType):
            if value.co_name == name:
                return value
            found = named(value, name)
            if found is not None:
                return found
    return None


@pytest.fixture
def model(tmp_path, monkeypatch):
    source = ROOT / nested.SOURCE
    body = source.read_bytes()
    code = compile(body, str(source), 'exec', dont_inherit=True)
    module = ModuleType('owned_nested_original_control')
    function = FunctionType(named(code, nested.OWNER), vars(module))
    setattr(module, nested.OWNER, function)
    observer = ModuleType('_session_ownership_observer')
    observer.owners = []
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setitem(sys.modules, observer.__name__, observer)
    target = tmp_path / 'test_owned_failure_setup.py'
    target.write_text(nested.literal(body).replace('PHASE', repr('setup')))
    frame = SimpleNamespace(f_code=function.__code__, f_globals=vars(module), f_lineno=267,
                            f_locals={'phase': 'setup', 'tmp_path': tmp_path,
                                      'source': target, 'root': ROOT, 'observer': observer})
    state = {'case': nested.SOURCE + '::' + nested.OWNER + '[setup]', 'class': 'pytest-root',
             'token': 'root', 'checkout': '/source', 'owned_root': str(tmp_path),
             'product_pins': {nested.SOURCE: hashlib.sha256(body).hexdigest()},
             'isolated_named': named,
             'isolated_source_code': lambda p: compile(p.read_bytes(), str(p), 'exec', dont_inherit=True)}
    events = []
    def refuse(reason):
        raise RuntimeError(reason)
    guard = SimpleNamespace(_STATE=state, refuse=refuse, append=events.append)
    path = nested.Path
    monkeypatch.setattr(nested, 'Path', lambda p: ROOT if str(p) == '/source' else path(p))
    monkeypatch.setattr(nested, 'active_frames', lambda: [frame])
    monkeypatch.setattr(nested.os, 'getcwd', lambda: str(ROOT))
    return SimpleNamespace(guard=guard, state=state, frame=frame, target=target,
                           body=body, events=events, observer=observer, module=module,
                           args=['-c', str(ROOT / 'pyproject.toml'), '-q', str(target)])


@pytest.mark.parametrize('phase', ['setup', 'body'])
def test_both_original_generated_negative_sessions_remain_real_and_separate(model, phase):
    m = model
    target = m.target.with_name('test_owned_failure_' + phase + '.py')
    target.write_text(nested.literal(m.body).replace('PHASE', repr(phase)))
    m.frame.f_locals.update(phase=phase, source=target)
    m.state['case'] = nested.SOURCE + '::' + nested.OWNER + '[' + phase + ']'
    m.args[-1] = str(target)
    assert nested.owned(m.guard, m.args, None) is True
    assert m.events[-1]['kind'] == 'primary_owned_nested_pytest'
    assert m.events[-1]['phase'] == phase


@pytest.mark.parametrize('change', ['class', 'token', 'pin', 'phase', 'line', 'args', 'plugins',
                                   'body', 'module', 'observer', 'inventory', 'root', 'alias'])
def test_foreign_or_modified_inner_scope_refuses(model, change):
    m = model
    plugins = None
    if change in {'class', 'token'}:
        m.state[change] = 'foreign'
    elif change == 'pin':
        m.state['product_pins'][nested.SOURCE] = '0' * 64
    elif change == 'phase':
        m.frame.f_locals['phase'] = 'foreign'
    elif change == 'line':
        m.frame.f_lineno += 1
    elif change == 'args':
        m.args.append('--ignore=tests')
    elif change == 'plugins':
        plugins = [object()]
    elif change == 'body':
        m.target.write_text('raise SystemExit(0)')
    elif change == 'module':
        m.frame.f_globals = dict(m.frame.f_globals)
    elif change == 'observer':
        m.frame.f_locals['observer'] = ModuleType('_session_ownership_observer')
    elif change == 'inventory':
        m.observer.owners.append(object())
    elif change == 'root':
        m.frame.f_locals['root'] = m.target.parent
    else:
        content = m.target.read_bytes()
        m.target.unlink()
        other = m.target.with_suffix('.alias')
        other.write_bytes(content)
        m.target.symlink_to(other)
    with pytest.raises(RuntimeError, match='primary_nested_'):
        nested.owned(m.guard, m.args, plugins)
    assert m.events == []


def test_only_original_direct_inprocess_pytest_owner_is_cataloged():
    owners = set()
    for source in (ROOT / 'tests').rglob('*.py'):
        for function in ast.parse(source.read_bytes()).body:
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == 'pytest'
                    and n.func.attr == 'main' for n in ast.walk(function)):
                owners.add((source.relative_to(ROOT).as_posix(), function.name))
    assert owners == {(nested.SOURCE, nested.OWNER)}


def test_non_owner_keeps_outer_certification_without_reading_a_synthetic_file():
    guard = SimpleNamespace(_STATE={'case': 'foreign'})
    assert nested.owned(guard, ['-q'], None) is False
