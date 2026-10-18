"""Closed native-producer diagnostics preserve the original refusal program."""
import ast
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('startup_producers', ROOT / 'linux_producers.py')
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ORIGINAL_RESOLVE = 'ea4f0caa50410102a19484d98bd759be780bdb5254ca684bbc7182528e2eb362'


class Inverse(ast.NodeTransformer):
    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'producer_check':
            assert len(node.args) == 3 and not node.keywords
            return node.args[2]
        return node

    def visit_Expr(self, node):
        if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == 'producer_check'):
            return None
        return self.generic_visit(node)


def inverse_pin(source):
    node = next(n for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.FunctionDef) and n.name == 'resolve_child')
    return hashlib.sha256(ast.dump(Inverse().visit(node), include_attributes=False).encode()).hexdigest()


def test_diagnostic_inverse_preserves_original_resolve():
    assert inverse_pin((ROOT / 'linux_producers.py').read_text()) == ORIGINAL_RESOLVE


@pytest.mark.parametrize('old,new', [
    ("self.kernel.identity(parent) != context['identity']", 'False'),
    ("len(context['children']) >= 8", "len(context['children']) >= 9"),
    ('path != vector[0]', 'False'),
    ("Path(path).resolve() != Path(self.common['base'])", 'False'),
    ("digest(path) != self.common['base_identity']['sha256']", 'False'),
    ('environment != expected_environment', 'False'),
    ("identity['ppid'] != parent", 'False'),
    ("identity['uid'] != 20000", 'False'),
    ("context['seen_requests'].add(key)", 'pass'),
    ('return False', 'return True'),
])
def test_diagnostic_inverse_detects_admission_mutation(old, new):
    source = (ROOT / 'linux_producers.py').read_text()
    assert old in source
    assert inverse_pin(source.replace(old, new)) != ORIGINAL_RESOLVE


def producer():
    value = object.__new__(module.NativeProducers)
    value.records = []
    value.producer_diagnostic_keys = set()
    return value


def test_fixed_schema_and_global_bound():
    value = producer()
    for pid in range(1000):
        assert value.producer_check(pid, 'parent_identity', False) is False
    assert len(value.records) == len(value.producer_diagnostic_keys) == 128
    assert all(set(row) == {'kind', 'pid', 'stage', 'value'} for row in value.records)
    assert value.records[0] == {'kind': 'native_producer_predicate', 'pid': 0,
                                'stage': 'parent_identity', 'value': False}
    value.producer_check(0, 'parent_identity', True)
    assert len(value.records) == 128


@pytest.mark.parametrize('failure', ['duplicate_child', 'parent_identity', 'child_limit',
                                     'argv_path', 'realpath', 'image_bytes'])
def test_early_first_refusal_and_short_circuit(monkeypatch, failure):
    value = producer()
    context = {'identity': {'birth': 1}, 'children': list(range(8)) if failure == 'child_limit' else []}
    value.uv = {10: context}
    value.children = {11: {}} if failure == 'duplicate_child' else {}
    calls = []
    def identity(pid):
        calls.append(('identity', pid))
        return {'birth': 2 if failure == 'parent_identity' else 1}
    value.kernel = SimpleNamespace(identity=identity)
    value.common = {'base': '/base', 'base_identity': {'sha256': 'expected'}}
    class Path:
        def __init__(self, path):
            self.path = path
        def resolve(self):
            calls.append(('resolve', self.path))
            return Path('/foreign' if failure == 'realpath' else '/base')
        def __eq__(self, other):
            return self.path == other.path
    monkeypatch.setattr(module, 'Path', Path)
    def digest(path):
        calls.append(('digest', path))
        return 'foreign'
    monkeypatch.setattr(module, 'digest', digest)
    vector = ['/foreign' if failure == 'argv_path' else '/python']
    assert value.resolve_child(11, 10, '/python', vector, {}, '/') is False
    rows = value.records
    assert rows[-1]['stage'] == failure and rows[-1]['value'] is True
    assert all(row['value'] is False for row in rows[:-1])
    if failure != 'image_bytes':
        assert not any(call[0] == 'digest' for call in calls)
    if failure in {'duplicate_child', 'parent_identity', 'child_limit', 'argv_path'}:
        assert not any(call[0] == 'resolve' for call in calls)
    if failure == 'duplicate_child':
        assert calls == []


def test_original_exception_is_not_replaced():
    value = producer()
    value.uv = {10: {'identity': {}, 'children': []}}
    value.children = {}
    def broken(pid):
        raise FileNotFoundError('controlled identity loss')
    value.kernel = SimpleNamespace(identity=broken)
    with pytest.raises(FileNotFoundError, match='controlled identity loss'):
        value.resolve_child(11, 10, '/python', ['/python'], {}, '/')
    assert [row['stage'] for row in value.records] == ['duplicate_child']
