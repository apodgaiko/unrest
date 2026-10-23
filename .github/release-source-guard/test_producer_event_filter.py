"""Current-record selection preserves live producer effects and original ordering."""
from copy import deepcopy
import ast
import gc
import hashlib
import importlib.util
import os
from pathlib import Path
from types import MethodType, SimpleNamespace
import weakref

import pytest

import linux_producers
import producer_event_filter

ROOT = Path(__file__).parent
NATIVE = Path(os.environ.get('UNREST_NATIVE_PROFILE_CONTROL', '/opt/source-guard/profile_gate.so'))


def normalize_native_filter(body):
    start = body.index('/* Iterate current trace rows without repeating no-effect producer callbacks.\n')
    end = body.index('static PyMethodDef methods[] = {', start)
    block = body[start:end]
    assert hashlib.sha256(block.encode()).hexdigest() == 'd853654cf2fd68279dbab362270f6f5a6ef9ca556d7a9e5f813045f3b2f852d4'
    body = body[:start] + body[end:]
    for line in ('    {"producer_events", producer_events, METH_VARARGS, "Read current producer-relevant trace rows."},\n',
                 '    if (PyType_Ready(&ProducerEventsType) < 0) return NULL;\n'):
        assert body.count(line) == 1
        body = body.replace(line, '')
    return body


@pytest.fixture
def native():
    if not NATIVE.is_file():
        pytest.skip('actual compiled native event predicate required')
    spec = importlib.util.spec_from_file_location('profile_gate', NATIVE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.producer_events


def original_tick():
    tree = ast.parse((ROOT / 'linux_producers.py').read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeProducers')
    node = deepcopy(next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'tick'))
    assert ast.unparse(node.body[0]) == "select = getattr(self, 'event_rows', None)"
    assert ast.unparse(node.body[1]) == 'rows = trace.records if select is None else select(trace.records, self)'
    node.body = node.body[2:]
    assert len(node.body) == 1 and isinstance(node.body[0], ast.For)
    assert ast.unparse(node.body[0].iter) == 'rows'
    node.body[0].iter = ast.parse('trace.records', mode='eval').body
    assert hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() == '9b0af53d310fbf71c400024e20d723efa62940008f6f7de8dde356a3bfe0d3f6'
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), '<original-tick>', 'exec'), namespace)
    return namespace['tick']


def owner(native=None):
    value = linux_producers.NativeProducers.__new__(linux_producers.NativeProducers)
    value.common = {'primary_producer': {'enabled': True}}
    value.children, value.uv, value.response_receipts = {}, {}, {}
    value.cache_current, value.cache_completed, value.poisoned_exits = None, set(), set()
    value.effects = []
    value.supervisor = SimpleNamespace(poison=value.effects.append)
    if native is not None:
        value.event_rows = native
    def response(self, row, trace):
        if (self.common.get('primary_producer') and row['kind'] == 'original_parent_wait4'
                and row['child'] in self.children and row['child'] not in self.response_receipts):
            self.effects.append(('response', row['child']))
            self.response_receipts[row['child']] = True
    def cache(self, row, trace):
        if (self.cache_current is not None and row['kind'] == 'kernel_exit'
                and row['pid'] in self.uv and row['pid'] not in self.cache_completed and row['raw'] == 0):
            self.effects.append(('cache', row['pid']))
            self.cache_completed.add(row['pid'])
    value.completed_response = MethodType(response, value)
    value.completed_cache = MethodType(cache, value)
    return value


def invoke(call, value, trace):
    try:
        call(value, trace)
        error = None
    except Exception as cause:
        error = type(cause), cause.args
    return error, list(value.effects), set(value.poisoned_exits)


def test_full_original_authority_bodies_are_unchanged():
    tree = ast.parse((ROOT / 'linux_producers.py').read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeProducers')
    expected = {'completed_response': '650a97d85b4812bfe4e0de0a4e394dfaa56cbbd8449bdf4462f431d5491bf5b4', 'completed_cache': '7e2d454b4366be556e15de6d075d6d429502697cd840420cd88b9f76ed2a08cb'}
    for name, pin in expected.items():
        node = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
        assert hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() == pin
    assert callable(original_tick())


def test_current_ownership_and_completion_changes_revisit_all_prior_rows(native):
    rows = [{'kind': 'exec_attempt'}, {'kind': 'original_parent_wait4', 'child': 7, 'raw': 0},
            {'kind': 'kernel_exit', 'pid': 8, 'raw': 0}, {'kind': 'kernel_exit', 'pid': 7, 'raw': 86 << 8}]
    left, right = owner(), owner(native)
    trace = SimpleNamespace(records=rows)
    original = original_tick()
    for change in ('none', 'children', 'uv', 'clear-completions'):
        for value in (left, right):
            if change == 'children':
                value.children[7] = {}
            elif change == 'uv':
                value.uv[8], value.cache_current = {}, {}
            elif change == 'clear-completions':
                value.response_receipts.clear()
                value.cache_completed.clear()
                value.poisoned_exits.clear()
        assert invoke(original, left, trace) == invoke(linux_producers.NativeProducers.tick, right, trace)
    assert ('response', 7) in right.effects and ('cache', 8) in right.effects
    assert 'native_preinitialization_refusal' in right.effects


@pytest.mark.parametrize('bad', [{}, None, [], {'kind': []}, {'kind': 'original_parent_wait4'},
                                {'kind': 'original_parent_wait4', 'child': []},
                                {'kind': 'kernel_exit'}, {'kind': 'kernel_exit', 'pid': []}])
def test_unknown_shapes_and_later_errors_keep_prior_effects_and_exception_order(native, bad):
    rows = [{'kind': 'kernel_exit', 'pid': 7, 'raw': 86 << 8}, bad]
    left, right = owner(), owner(native)
    left.children[7] = right.children[7] = {}
    trace = SimpleNamespace(records=rows)
    assert invoke(original_tick(), left, trace) == invoke(linux_producers.NativeProducers.tick, right, trace)
    assert right.effects == ['native_preinitialization_refusal']


def test_iteration_keeps_current_list_append_and_row_mutation_semantics(native):
    value = owner(native)
    value.children[7] = {}
    rows = [{'kind': 'kernel_exit', 'pid': 7, 'raw': 0}, {'kind': 'other'}]
    iterator = native(rows, value)
    assert next(iterator) is rows[0]
    rows[1].update(kind='kernel_exit', pid=7, raw=0)
    rows.append({'kind': 'original_parent_wait4', 'child': 7})
    assert next(iterator) is rows[1]
    assert next(iterator) is rows[2]
    with pytest.raises(StopIteration):
        next(iterator)


def test_owner_dictionary_replacement_and_map_replacement_are_read_after_yield(native):
    value = owner(native)
    value.children[7] = {}
    rows = [{'kind': 'kernel_exit', 'pid': 7}, {'kind': 'kernel_exit', 'pid': 8}]
    iterator = native(rows, value)
    assert next(iterator) is rows[0]
    value.__dict__ = {**value.__dict__, 'children': {8: {}}}
    assert next(iterator) is rows[1]


@pytest.mark.parametrize('change', ['common', 'primary', 'missing-cache', 'children', 'uv'])
def test_unknown_owner_state_preserves_the_full_original_iterator(native, change):
    value = owner(native)
    if change == 'common':
        value.common = []
    elif change == 'primary':
        value.common['primary_producer'] = object()
    elif change == 'missing-cache':
        del value.cache_current
    elif change == 'children':
        value.children = []
    else:
        value.uv = []
    rows = [{'kind': 'irrelevant'}, {}]
    assert list(native(rows, value)) == rows


def test_iterator_exception_keeps_earlier_rows_and_original_exception(native):
    value = owner(native)
    value.children[7] = {}
    first = {'kind': 'kernel_exit', 'pid': 7}
    cause = RuntimeError('original iterator')
    def rows():
        yield first
        raise cause
    iterator = native(rows(), value)
    assert next(iterator) is first
    with pytest.raises(RuntimeError) as caught:
        next(iterator)
    assert caught.value is cause


def test_iterator_owner_cycle_is_collectable(native):
    value = owner(native)
    reference = weakref.ref(value)
    value.cycle = native([], value)
    del value
    gc.collect()
    assert reference() is None


def test_binding_refusal_precedes_loading_a_selector(monkeypatch):
    cause = RuntimeError('module source binding refused')
    def refused():
        raise cause
    monkeypatch.setattr(producer_event_filter, 'verify', refused)
    with pytest.raises(RuntimeError) as caught:
        producer_event_filter.load()
    assert caught.value is cause


def test_custom_iterator_can_replace_owner_maps_before_original_handling(native):
    def run(call, selected):
        value = owner(selected)
        class Rows:
            def __iter__(self):
                value.effects.append('original-iter')
                return self
            def __next__(self):
                if getattr(self, 'done', False):
                    raise StopIteration
                self.done = True
                value.children = {8: {}}
                return {'kind': 'kernel_exit', 'pid': 8, 'raw': 86 << 8}
        rows = Rows()
        if selected is not None:
            assert selected(rows, value) is rows
        return invoke(call, value, SimpleNamespace(records=rows))
    assert run(original_tick(), None) == run(linux_producers.NativeProducers.tick, native)


@pytest.mark.parametrize('location', ['row', 'children', 'uv', 'state', 'common'])
def test_unknown_dictionary_keys_never_execute_inside_the_native_filter(native, location):
    class Key:
        def __hash__(self):
            return 0
        def __eq__(self, other):
            raise AssertionError('native predicate executed a Python comparison')
    value = owner(native)
    row = {'kind': 'irrelevant'}
    if location == 'row':
        row[Key()] = True
    elif location == 'state':
        value.__dict__[Key()] = True
    elif location == 'common':
        value.common[Key()] = True
    else:
        getattr(value, location)[Key()] = {}
    assert list(native([row], value)) == [row]
