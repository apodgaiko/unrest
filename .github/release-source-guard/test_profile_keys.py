"""Only immutable lookup spellings are cached; every policy value stays current."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
PATH = Path(os.environ.get('UNREST_NATIVE_PROFILE_CONTROL', '/opt/source-guard/profile_gate.so'))
KEYS = ('operations', 'operation_profile_sources', 'isolated_composition', 'codes',
        'primary_snapshot_observer', 'guard')


def test_complete_native_predicate_normalizes_only_constant_key_storage():
    body = (ROOT / 'profile_gate.c').read_text()
    additions = [
        '    PyObject *keys[6];\n',
        '    for (int i = 0; i < 6; i++) Py_VISIT(self->keys[i]);\n',
        '    for (int i = 0; i < 6; i++) Py_CLEAR(self->keys[i]);\n',
        '    for (int i = 0; i < 6; i++) gate->keys[i] = NULL;\n',
        '    const char *names[6] = {"operations", "operation_profile_sources", "isolated_composition", "codes", "primary_snapshot_observer", "guard"};\n'
        '    for (int i = 0; i < 6; i++) {\n'
        '        gate->keys[i] = PyUnicode_InternFromString(names[i]);\n'
        '        if (!gate->keys[i]) {\n'
        '            Py_DECREF(gate);\n'
        '            return NULL;\n'
        '        }\n'
        '    }\n',
    ]
    for text in additions:
        assert body.count(text) == 1
        body = body.replace(text, '')
    for i, name in enumerate(KEYS):
        if name == 'codes':
            old, new = f'PyObject_GetAttr(composition, self->keys[{i}])', 'PyObject_GetAttrString(composition, "codes")'
        else:
            old, new = f'PyDict_GetItem(self->state, self->keys[{i}])', f'PyDict_GetItemString(self->state, "{name}")'
        assert body.count(old) == 1
        body = body.replace(old, new)
    assert '->keys' not in body
    assert hashlib.sha256(body.encode()).hexdigest() == '6f6fc3d7056c9e2f7e32265b78c977730262537298513e6745d906fc1d79ab46'


@pytest.fixture
def gate():
    if not PATH.is_file():
        pytest.skip('actual compiled native gate required')
    spec = importlib.util.spec_from_file_location('profile_gate', PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def target(name='selected', filename='/proof/selected.py'):
    namespace = {}
    exec(compile('def ' + name + '():\n return 23\n', filename, 'exec'), namespace)
    return namespace[name]


def probe(gate, state, sources=()):
    rows = []
    source_set = sources if type(sources) is set else set(sources)
    observer = gate.make(lambda frame, event, value: rows.append((frame.f_code, event, value)), state, source_set)
    def observed(functions):
        rows.clear()
        saved = sys.getprofile()
        try:
            sys.setprofile(observer)
            for function in functions:
                assert function() == 23
        finally:
            sys.setprofile(saved)
        codes = {function.__code__ for function in functions}
        return [(code, event, value) for code, event, value in rows if code in codes]
    return observed


def test_current_state_membership_is_never_replaced_by_constructor_snapshot(gate):
    chosen = target()
    state = {'isolated_composition': SimpleNamespace(codes=None)}
    observed = probe(gate, state)
    assert observed([chosen]) == []
    state['operations'] = object()
    assert observed([chosen]) == [(chosen.__code__, 'call', None), (chosen.__code__, 'return', 23)]
    state['operation_profile_sources'] = frozenset()
    assert observed([chosen]) == []
    state['isolated_composition'].codes = chosen.__code__
    assert observed([chosen]) == [(chosen.__code__, 'call', None), (chosen.__code__, 'return', 23)]
    state['isolated_composition'] = SimpleNamespace(codes=None)
    assert observed([chosen]) == []


def test_current_property_access_and_property_errors_are_retained(gate):
    chosen = target()
    class Composition:
        current = None
        @property
        def codes(self):
            if isinstance(self.current, Exception):
                raise self.current
            return self.current
    value = Composition()
    state = {'isolated_composition': value}
    observed = probe(gate, state)
    assert observed([chosen]) == []
    value.current = chosen.__code__
    assert observed([chosen]) == [(chosen.__code__, 'call', None), (chosen.__code__, 'return', 23)]
    value.current = RuntimeError('live property refusal')
    with pytest.raises(RuntimeError, match='live property refusal'):
        observed([chosen])


def test_constructor_observer_and_guard_values_remain_live(gate):
    chosen = target('initialize_inner', '/proof/runtime_guard.py')
    state = {'isolated_composition': SimpleNamespace(codes=None),
             'primary_snapshot_observer': None, 'guard': '/proof/runtime_guard.py'}
    observed = probe(gate, state)
    assert observed([chosen]) == []
    state['primary_snapshot_observer'] = lambda *args: None
    assert observed([chosen]) == [(chosen.__code__, 'return', 23)]
    state['guard'] = '/foreign/runtime_guard.py'
    assert observed([chosen]) == []
    state['guard'] = '/proof/runtime_guard.py'
    state['primary_snapshot_observer'] = None
    assert observed([chosen]) == []


def test_cyclic_gate_state_is_collectable(gate):
    import gc
    import weakref
    class Callback:
        def __call__(self, *args):
            return None
    callback = Callback()
    reference = weakref.ref(callback)
    state = {}
    observer = gate.make(callback, state, set())
    state['cycle'] = observer
    del observer, callback, state
    gc.collect()
    assert reference() is None


@pytest.mark.parametrize('sources', [None, set(), [], {}])
def test_missing_composition_and_nonfinite_operation_mode_preserve_full_callback(gate, sources):
    chosen = target()
    state = {}
    observe = probe(gate, state)
    expected = [(chosen.__code__, 'call', None), (chosen.__code__, 'return', 23)]
    assert observe([chosen]) == expected
    state['isolated_composition'] = SimpleNamespace(codes=None)
    assert observe([chosen]) == []
    state['operations'] = object()
    state['operation_profile_sources'] = sources
    assert observe([chosen]) == expected
    state['operation_profile_sources'] = frozenset()
    assert observe([chosen]) == []
    state['operations'] = None
    state['operation_profile_sources'] = sources
    assert observe([chosen]) == []


def test_original_source_set_remains_live_after_gate_construction(gate):
    chosen = target()
    paths = set()
    observe = probe(gate, {'isolated_composition': SimpleNamespace(codes=None)}, paths)
    assert observe([chosen]) == []
    paths.add('/proof/selected.py')
    assert observe([chosen]) == [(chosen.__code__, 'call', None), (chosen.__code__, 'return', 23)]
    paths.clear()
    assert observe([chosen]) == []
