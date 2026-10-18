"""Closed diagnostics cannot change original cache refusal or assertion operands."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_escape_diagnostic_retains_original_strict_refusal(tmp_path):
    closure = module('dependency_closure')
    root = tmp_path / 'cache'
    root.mkdir()
    target = tmp_path / 'external'
    target.write_bytes(b'private content')
    (root / 'link').symlink_to(target)
    rows = []
    for callback in (None, lambda *args: rows.append(args)):
        with pytest.raises(RuntimeError, match='dependency symlink escapes its finite runtime closure'):
            closure.inventory(root, on_escape=callback)
    assert len(rows) == 1
    assert rows[0][:3] == (root, root / 'link', target)


def test_inventory_inverse_is_exact_original_program():
    tree = ast.parse((ROOT / 'dependency_closure.py').read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'inventory')
    function.args.kwonlyargs = []
    function.args.kw_defaults = []
    class Strip(ast.NodeTransformer):
        def visit_If(self, node):
            if ast.unparse(node.test) == 'on_escape is not None':
                assert len(node.body) == 1 and ast.unparse(node.body[0]) == 'on_escape(root, path, resolved, info)'
                return None
            return self.generic_visit(node)
    actual = ast.dump(Strip().visit(function), include_attributes=False)
    assert hashlib.sha256(actual.encode()).hexdigest() == ORIGINAL_INVENTORY


ORIGINAL_INVENTORY = 'c6ea0fd53aa32d5a4ae28da86b45aff2b8506a38a1f0640bcb0cd55a8f10f20a'


@pytest.mark.parametrize('old,new', [
    ('not resolved.is_relative_to(root)', 'False'),
    ('resolved != Path("/usr/local/bin/python3.13")', 'False'),
    ('path.resolve(strict=True)', 'path.resolve()'),
])
def test_inverse_rejects_weakened_original(tmp_path, old, new):
    source = (ROOT / 'dependency_closure.py').read_text()
    original = ast.parse(source)
    altered = ast.parse(source.replace(old, new))
    assert ast.dump(original, include_attributes=False) != ast.dump(altered, include_attributes=False)


def snapshot():
    return dict(attempt_id='private-attempt', blocker_code=None, checkpoint_requests=0,
                checkpoint_sequence=1, completed_target_ids=[], elapsed_nanoseconds=0,
                last_effect_sequence=0, mission_id='private-mission', node_id='private-node',
                phase='waiting_at_checkpoint', project_id='private-project',
                remaining_target_ids=['private-target'], role='worker', scope_status='in_scope',
                supervision_status='waiting', terminal_review_id=None)


def test_snapshot_diagnostic_closed_and_operands_unchanged():
    entry = module('primary_source_entry')
    rows = []
    case = 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'
    guard = SimpleNamespace(_STATE={'case': case}, append=rows.append)
    observer = entry.Observer(guard, None, {}, {})
    left, right = [snapshot()], [snapshot()]
    left[0]['elapsed_nanoseconds'] = 30000000000
    left[0]['project_id'] = 'different-private-project'
    before = copy.deepcopy((left, right))
    for _ in range(3):
        assert observer.pytest_assertrepr_compare(None, '==', left, right) is None
    assert (left, right) == before and len(rows) == 1
    row = rows[0]
    assert row['differing_keys'] == ['elapsed_nanoseconds', 'project_id']
    assert row['values'] == {'elapsed_nanoseconds': [30000000000, 0]}
    assert row['cardinalities'] == [1, 1]
    assert 'private' not in json.dumps(row)


@pytest.mark.parametrize('change', ['case', 'op', 'shape', 'keys'])
def test_unrelated_comparisons_are_not_observed(change):
    entry = module('primary_source_entry')
    rows = []
    guard = SimpleNamespace(_STATE={'case': 'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct'}, append=rows.append)
    observer = entry.Observer(guard, None, {}, {})
    left, right, op = [snapshot()], [snapshot()], '=='
    if change == 'case':
        guard._STATE['case'] = 'unrelated'
    elif change == 'op':
        op = '!='
    elif change == 'shape':
        left = []
    elif change == 'keys':
        left[0]['foreign'] = 'private'
    assert observer.pytest_assertrepr_compare(None, op, left, right) is None
    assert rows == []
