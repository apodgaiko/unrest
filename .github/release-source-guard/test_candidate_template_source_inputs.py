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


def test_exact_compatibility_inputs_change_only_three_pins():
    require_inputs()
    manifest = baseline()
    expected = deepcopy(manifest)
    expected['product_pins'].update(patch.POST)
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


def test_product_delta_keeps_original_native_git_owner():
    require_inputs()
    import ast
    source = ROOT / 'src/unrest_harness/experimental_candidate.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == patch.POST[source.relative_to(ROOT).as_posix()]
    module = ast.parse(source.read_bytes())
    owner = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == '_Observation')
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'git')
    assert hashlib.sha256(ast.dump(method, include_attributes=False).encode()).hexdigest() == 'cef37191574dcc383fc345438ac524c94c13cba166cb6bdd9314b0df6a4bfa8e'
    assert method.lineno == 147
    assert next(n for n in ast.walk(method) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'subprocess.Popen').lineno == 151
