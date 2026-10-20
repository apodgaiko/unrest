"""Constructor/custody negatives; the own-identity Linux probe proves integration."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

import child_relative_custody as custody

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('child_relative', ROOT / 'finite/child_relative.py')
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


def test_closed_applicable_inventory_includes_ordinary_routes():
    from finite.registry import COMMANDS
    assert {row['class'] for row in COMMANDS if row['python']} <= boundary.APPLICABLE
    assert 'source-child-relative-probe' in boundary.APPLICABLE
    assert 'unknown' not in boundary.APPLICABLE


@pytest.mark.parametrize('mutation', ['count', 'cwd', 'argv', 'class', 'original', 'transform'])
def test_stopped_child_binding_refuses_before_receipt(monkeypatch, mutation):
    import hashlib
    import json
    vector = ['python', '-c', 'pass']
    pin = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
    facts = {'cwd': '/source', 'identity': [1, 2]}
    row = {'kind': 'child_relative_constructor', 'owner_pid': 11, 'token': 'token',
           'original_cwd': None, 'constructor_cwd': '.', 'class': 'class',
           'argv_sha256': pin, 'parent_view': facts}
    selected = {'owner_pid': 11, 'token': 'token', 'bootstrap_sha256': 'pin',
                'registration': {'class': 'class'}, 'transformed_argv_sha256': pin, 'cwd': '/source'}
    rows = [row]
    if mutation == 'count':
        rows.append(dict(row))
    elif mutation == 'cwd':
        facts = {**facts, 'identity': [1, 3]}
    elif mutation == 'argv':
        vector = [*vector, 'other']
    elif mutation == 'class':
        row['class'] = 'other'
    elif mutation == 'original':
        row['original_cwd'] = '/source'
    else:
        row['constructor_cwd'] = '/source'
    monkeypatch.setattr(custody, 'view', lambda **kwargs: facts)
    poison = []
    authority = SimpleNamespace(bound={22: selected}, supervisor=SimpleNamespace(
        events=lambda: rows, poison=poison.append))
    trace = SimpleNamespace(poison=[])
    with pytest.raises(RuntimeError):
        custody.check(authority, trace, 22, vector)
    assert poison == trace.poison == ['primary_source_child_relative_cwd']


def test_no_constructor_record_retains_original_custody():
    authority = SimpleNamespace(bound={22: {'bootstrap_sha256': 'pin'}},
                                supervisor=SimpleNamespace(events=lambda: []))
    custody.check(authority, None, 22, [])


def test_prebody_extension_precedes_bootstrap_ready():
    source = (ROOT / 'primary_source_entry.py').read_text()
    assert source.index('module.view()') < source.index("if profile['source_role'] == 'source-bootstrap':")
    assert source.index('module.view()') < source.index('endpoint.early(')


def test_stock_constructor_has_no_retry_or_private_execute_child_copy():
    source = (ROOT / 'finite/child_relative.py').read_text()
    assert 'except' not in source[source.index('    def constructor('):]
    import ast
    assert not any(isinstance(node, ast.FunctionDef) and node.name == '_execute_child'
                   for node in ast.walk(ast.parse(source)))
    assert "'cwd': '.'" in source
