"""Exact source pins compose atomically; no generic drift is reclassified."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import candidate_template_source_inputs as patch

ROOT = Path(__file__).parent.parent.parent


def baseline():
    value = json.loads((Path(__file__).parent / 'finite/source-template.json').read_bytes())
    assert all(value['product_pins'][name] == pin for name, pin in patch.PRE.items())
    return value


def require_inputs():
    if not all((ROOT / name).is_file() for name in patch.POST):
        pytest.skip('source payload is absent from isolated control capsule')


def test_exact_object_reader_inputs_retire_only_removed_launch_anchor():
    require_inputs()
    manifest = baseline()
    expected = deepcopy(manifest)
    expected['product_pins'].update(patch.POST)
    expected['anchor_inventory'].remove(patch.ANCHOR)
    next(row for row in expected['anchor_inventory'] if row['path'] == patch.FIXTURE_ANCHOR['path'])['source_sha256'] = patch.POST[patch.FIXTURE_ANCHOR['path']]
    patch.admit(manifest, ROOT, lambda root, name: (root / name).read_bytes())
    assert manifest == expected


@pytest.mark.parametrize('name', sorted(patch.PRE))
def test_unknown_preimage_cannot_reach_any_read(name):
    manifest = baseline()
    manifest['product_pins'][name] = 'foreign'
    before = deepcopy(manifest)
    def forbidden(*args):
        pytest.fail('unknown preimage was allowed to inspect source')
    with pytest.raises(RuntimeError, match='candidate_template_preimage'):
        patch.admit(manifest, ROOT, forbidden)
    assert manifest == before


def test_addition_must_be_absent_from_original_inventory():
    manifest = baseline()
    manifest['product_pins']['tests/test_experimental_candidate_templates.py'] = patch.POST['tests/test_experimental_candidate_templates.py']
    before = deepcopy(manifest)
    with pytest.raises(RuntimeError, match='candidate_template_preimage'):
        patch.admit(manifest, ROOT, lambda *args: pytest.fail('unexpected source read'))
    assert manifest == before


@pytest.mark.parametrize('name', sorted(patch.POST))
def test_each_changed_postimage_refuses_without_partial_repin(name):
    require_inputs()
    manifest = baseline()
    before = deepcopy(manifest)
    def read(root, selected):
        return (root / selected).read_bytes() + (b'changed' if selected == name else b'')
    with pytest.raises(RuntimeError, match='candidate_template_postimage'):
        patch.admit(manifest, ROOT, read)
    assert manifest == before


def test_product_delta_has_only_pinned_no_child_object_reader():
    require_inputs()
    import ast
    source = ROOT / patch.SOURCE
    assert hashlib.sha256(source.read_bytes()).hexdigest() == patch.POST[patch.SOURCE]
    module = ast.parse(source.read_bytes())
    owner = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == '_Observation')
    assert not any(isinstance(n, ast.FunctionDef) and n.name == 'git' for n in owner.body)
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'object')
    assert hashlib.sha256(ast.dump(method, include_attributes=False).encode()).hexdigest() == patch.OWNER_AST
    assert not any(isinstance(n, ast.Call) and ast.unparse(n.func).startswith('subprocess.') for n in ast.walk(module))


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'count', 'source_sha256', 'line', 'owner', 'route', 'family', 'expression_ast_sha256'])
def test_anchor_membership_or_identity_drift_never_changes_manifest(change):
    require_inputs()
    manifest = baseline()
    row = next(v for v in manifest['anchor_inventory'] if v['path'] == patch.SOURCE)
    if change == 'missing':
        manifest['anchor_inventory'].remove(row)
    elif change == 'duplicate':
        manifest['anchor_inventory'].append(deepcopy(row))
    elif change == 'count':
        manifest['anchor_inventory'].pop(0)
    else:
        row[change] = 'foreign'
    before = deepcopy(manifest)
    with pytest.raises(RuntimeError, match='candidate_template_anchor_preimage'):
        patch.admit(manifest, ROOT, lambda root, name: (root / name).read_bytes())
    assert manifest == before


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'source_sha256', 'line', 'owner', 'route', 'family', 'expression_ast_sha256'])
def test_fixture_anchor_identity_drift_refuses_atomically(change):
    require_inputs()
    manifest = baseline()
    row = next(v for v in manifest['anchor_inventory'] if v['path'] == patch.FIXTURE_ANCHOR['path'])
    if change == 'missing':
        manifest['anchor_inventory'].remove(row)
    elif change == 'duplicate':
        manifest['anchor_inventory'].append(deepcopy(row))
    else:
        row[change] = 'foreign'
    before = deepcopy(manifest)
    expected = 'candidate_template_anchor_preimage' if change in {'missing', 'duplicate'} else 'candidate_template_fixture_anchor'
    with pytest.raises(RuntimeError, match=expected):
        patch.admit(manifest, ROOT, lambda root, name: (root / name).read_bytes())
    assert manifest == before
