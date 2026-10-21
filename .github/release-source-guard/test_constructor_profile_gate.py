"""Actual compiled predicate forwards only the bound constructor return."""
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

PATH = Path(os.environ.get('UNREST_NATIVE_PROFILE_CONTROL', '/opt/source-guard/profile_gate.so'))
pytestmark = pytest.mark.skipif(not PATH.is_file(), reason='compiled native profile control required')


@pytest.fixture
def gate():
    spec = importlib.util.spec_from_file_location('profile_gate', PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def target(name, path):
    namespace = {}
    exec(compile('def ' + name + '():\n    return 23\n', path, 'exec'), namespace)
    return namespace[name]


def exercise(gate, state, functions):
    rows = []
    callback = gate.make(lambda frame, event, value: rows.append((frame.f_code, event, value)), state, set())
    previous = sys.getprofile()
    try:
        sys.setprofile(callback)
        for function in functions:
            assert function() == 23
    finally:
        sys.setprofile(previous)
    return rows


def test_bound_constructor_forwards_one_exact_original_return(gate):
    chosen = target('initialize_inner', '/proof/runtime_guard.py')
    foreign = target('initialize_inner', '/foreign/runtime_guard.py')
    other = target('other', '/proof/runtime_guard.py')
    state = {'guard': '/proof/runtime_guard.py', 'primary_snapshot_observer': lambda *a: None,
             'isolated_composition': SimpleNamespace(codes=None)}
    assert exercise(gate, state, [chosen, foreign, other]) == [(chosen.__code__, 'return', 23)]


@pytest.mark.parametrize('change', ['missing-observer', 'noncallable-observer', 'missing-guard', 'foreign-guard'])
def test_no_unbound_observer_or_foreign_path_can_select_the_event(gate, change):
    chosen = target('initialize_inner', '/proof/runtime_guard.py')
    state = {'guard': '/proof/runtime_guard.py', 'primary_snapshot_observer': lambda *a: None,
             'isolated_composition': SimpleNamespace(codes=None)}
    if change == 'missing-observer':
        del state['primary_snapshot_observer']
    elif change == 'noncallable-observer':
        state['primary_snapshot_observer'] = None
    elif change == 'missing-guard':
        del state['guard']
    else:
        state['guard'] = '/foreign/runtime_guard.py'
    assert exercise(gate, state, [chosen]) == []


def test_constructor_observer_refusal_propagates_without_an_extra_call(gate):
    chosen = target('initialize_inner', '/proof/runtime_guard.py')
    state = {'guard': '/proof/runtime_guard.py', 'primary_snapshot_observer': lambda *a: None,
             'isolated_composition': SimpleNamespace(codes=None)}
    rows = []
    def refuse(frame, event, value):
        rows.append((frame.f_code, event, value))
        raise RuntimeError('authenticated constructor refused')
    native = gate.make(refuse, state, set())
    previous = sys.getprofile()
    try:
        sys.setprofile(native)
        with pytest.raises(RuntimeError, match='authenticated constructor refused'):
            chosen()
    finally:
        sys.setprofile(previous)
    assert rows == [(chosen.__code__, 'return', 23)]


def test_compiled_controls_are_wired_before_original_source_execution():
    import ast
    path = Path(__file__).with_name('compartment_probe.py')
    tree = ast.parse(path.read_bytes())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'run'
             and node.args and isinstance(node.args[0], ast.List)
             and any(isinstance(item, ast.Constant) and item.value == 'pytest'
                     for item in node.args[0].elts)]
    assert len(calls) == 1
    assert [item.value for item in calls[0].args[0].elts if isinstance(item, ast.Constant)].count(
        '/guard/test_constructor_profile_gate.py') == 1
