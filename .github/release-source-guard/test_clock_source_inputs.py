"""Exact clock amendment admission retains the original oracle and owners."""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('clock_inputs_test', ROOT / 'clock_source_inputs.py')
assert SPEC is not None and SPEC.loader is not None
clock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(clock)


def test_original_template_keeps_preimages_and_176_anchors():
    template = json.loads((ROOT / 'finite/source-template.json').read_bytes())
    assert len(template['anchor_inventory']) == 176
    for name, pin in clock.PRE.items():
        assert template['product_pins'][name] == pin
    assert 'tests/test_waiting_elapsed.py' not in template['product_pins']
    anchors = [row for row in template['anchor_inventory']
               if row['path'] == 'src/unrest_harness/coordinator.py']
    assert {row['line'] for row in anchors} == set(clock.OWNERS)
    for row in anchors:
        owner, expression, _ = clock.OWNERS[row['line']]
        assert row['owner'] == owner and row['expression_ast_sha256'] == expression
        assert row['source_sha256'] == clock.PRE[row['path']]


@pytest.fixture
def baseline(tmp_path, monkeypatch):
    # A source-free capsule has no product checkout. Translate only the fixture
    # reference hashes and readonly-mount flag; real IO/custody checks still run.
    root = tmp_path / 'source'
    root.mkdir()
    pins = {}
    for name in clock.PRE:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(('original fixture ' + name).encode())
        path.chmod(0o644)
        pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(clock, 'PRE', pins)
    original = clock.os.statvfs
    monkeypatch.setattr(clock.os, 'statvfs', lambda path: SimpleNamespace(f_flag=os.ST_RDONLY)
                        if Path(path).is_relative_to(root) else original(path))
    manifest = json.loads((ROOT / 'finite/source-template.json').read_bytes())
    manifest['product_pins'].update(pins)
    return root, manifest


def test_original_mode_does_not_change_any_manifest_field(baseline):
    root, manifest = baseline
    before = copy.deepcopy(manifest)
    assert clock.admit(manifest, root) == {'mode': 'original', 'remapped': []}
    assert manifest == before


@pytest.mark.parametrize('change', ['bytes', 'mode', 'link', 'hardlink', 'mixed_regression',
                                     'baseline_pin', 'rebased', 'writable', 'lost'])
def test_unapproved_clock_input_denied_without_manifest_mutation(baseline, monkeypatch, change):
    root, manifest = baseline
    source = root / 'src/unrest_harness/coordinator.py'
    if change == 'bytes':
        source.write_bytes(b'unknown product change')
    elif change == 'mode':
        source.chmod(0o777)
    elif change == 'link':
        source.rename(source.with_suffix('.retired'))
        source.symlink_to(source.with_suffix('.retired'))
    elif change == 'hardlink':
        os.link(source, root / 'alias')
    elif change == 'mixed_regression':
        path = root / 'tests/test_waiting_elapsed.py'
        path.parent.mkdir()
        path.write_bytes(b'cannot select clock repair by fixture presence')
    elif change == 'baseline_pin':
        manifest['product_pins']['src/unrest_harness/coordinator.py'] = 'a' * 64
    elif change == 'rebased':
        manifest['product_pins']['tests/test_waiting_elapsed.py'] = clock.POST['tests/test_waiting_elapsed.py']
    elif change == 'writable':
        monkeypatch.setattr(clock.os, 'statvfs', lambda path: SimpleNamespace(f_flag=0))
    elif change == 'lost':
        source.unlink()
    before = copy.deepcopy(manifest)
    with pytest.raises((RuntimeError, FileNotFoundError)):
        clock.admit(manifest, root)
    assert manifest == before


def test_prepare_uses_exact_helper_pin_before_baseline_scan():
    tree = ast.parse((ROOT / 'prepare_source.py').read_bytes())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'admit_clock')
    pins = [node.value for node in ast.walk(function) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and len(node.value) == 64]
    assert pins == [hashlib.sha256((ROOT / 'clock_source_inputs.py').read_bytes()).hexdigest()]
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    calls = [index for index, node in enumerate(main.body)
             if isinstance(node, ast.Expr) and ast.unparse(node) == 'admit_clock(manifest)']
    scan = next(index for index, node in enumerate(main.body)
                if isinstance(node, ast.For) and ast.unparse(node.iter) == "manifest['product_pins'].items()")
    assert len(calls) == 1 and calls[0] < scan
