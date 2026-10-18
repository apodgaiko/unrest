"""Checkout integration checks, explicitly run in the Linux host prerequisite."""
from pathlib import Path
import hashlib
import ast

ROOT = Path(__file__).resolve().parents[2]


def test_clock_and_projection_controls_precede_unchanged_original_tuple():
    workflow = (ROOT / '.github/workflows/v046-source-readiness.yml').read_text()
    command = ('env -u CODEX_PATH uv run --locked pytest -q tests/test_waiting_elapsed.py '
               '.github/release-source-guard/test_primary_dependency_integration.py')
    assert workflow.count(command) == 1
    assert workflow.index('Ordinary waiting checkpoint regression') < workflow.index('TEST primary affected source seams')
    original = ('env -u CODEX_PATH uv run pytest -q '
                'tests/test_server.py::test_composed_restart_stop_replacement_and_cancel_are_distinct '
                'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix[claude] '
                'tests/contracts/test_lean_provider_security.py::test_installed_supported_provider_matrix[codex] '
                'tests/test_distribution_check.py::test_checker_builds_and_executes_15_cases_with_extracted_provenance')
    assert workflow.count(original) == 2


def test_exact_clock_source_and_regression_bytes():
    expected = {
        'src/unrest_harness/coordinator.py': 'da8db10811775708fd4a0dc1f6bc6ccbe0cfc474ebe3b8c2991804d5a39b9406',
        'src/unrest_harness/supervision.py': '8a6983b504b95748da57305e6bb76f136fd3ad8d752b0657fc0d22669e689d23',
        'tests/test_waiting_elapsed.py': 'aedd05b7d39ea23c265dbdb13dc1f37678560fb4d02a4ff428090f8630ea173a',
        'docs/v5/08-mcp-surface.md': '16a9ec8c470501f33f20bcbae80c1fffb87121b7498666b6882c92c0c6dc17fd',
    }
    for name, digest in expected.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest


def test_primary_operation_entry_executes_exact_legacy_base():
    support = ROOT / '.github/release-source-guard'
    tree = ast.parse((support / 'primary_operations.py').read_bytes())
    checks = [node for node in tree.body if isinstance(node, ast.If)]
    assert len(checks) == 1
    expected = next(node.value for node in ast.walk(checks[0].test)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) == 64)
    assert hashlib.sha256((support / 'finite/source_operations.py').read_bytes()).hexdigest() == expected
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    assert [node.name for node in cls.body if isinstance(node, ast.FunctionDef)] == ['inputs', 'dependency']


def test_exact_clock_admission_only_relocates_three_equivalent_owners(monkeypatch):
    import copy
    import json
    import os
    from types import SimpleNamespace
    import clock_source_inputs
    support = ROOT / '.github/release-source-guard'
    manifest = json.loads((support / 'finite/source-template.json').read_bytes())
    original = copy.deepcopy(manifest)
    actual_statvfs = clock_source_inputs.os.statvfs
    monkeypatch.setattr(clock_source_inputs.os, 'statvfs', lambda path: SimpleNamespace(f_flag=os.ST_RDONLY)
                        if Path(path).is_relative_to(ROOT) else actual_statvfs(path))
    result = clock_source_inputs.admit(manifest, ROOT)
    assert result['mode'] == 'exact-waiting-clock' and len(result['remapped']) == 3
    assert len(manifest['anchor_inventory']) == 176
    changed = [(old, new) for old, new in zip(original['anchor_inventory'], manifest['anchor_inventory'])
               if old != new]
    assert len(changed) == 3
    for old, new in changed:
        assert {key: value for key, value in old.items() if key not in {'line', 'source_sha256'}} == {
            key: value for key, value in new.items() if key not in {'line', 'source_sha256'}}
        assert new['source_sha256'] == clock_source_inputs.POST['src/unrest_harness/coordinator.py']
        assert old['line'] != new['line']
    for key in original.keys() - {'anchor_inventory', 'product_pins'}:
        assert manifest[key] == original[key]
    assert {name for name in manifest['product_pins'] if manifest['product_pins'][name]
            != original['product_pins'].get(name)} == set(clock_source_inputs.POST)


def test_primary_inputs_require_actual_dependency_even_without_legacy_tree():
    import pytest
    support = ROOT / '.github/release-source-guard'
    body = (support / 'primary_operations.py').read_text()
    # Execute the production subclass with its exact legacy entry already checked above.
    cls = next(node for node in ast.parse(body).body if isinstance(node, ast.ClassDef))
    calls = []
    class Legacy:
        def inputs(self):
            calls.append('legacy')
            return 'validated-source'
    namespace = {'_LegacyOperations': Legacy}
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(support / 'primary_operations.py'), 'exec'),
         {'hashlib': hashlib, '_BASE': support / 'finite/source_operations.py', 'Path': Path}, namespace)
    operation = namespace['Operations']()
    operation.spec = {'trees': []}
    operation.refuse = lambda code: (_ for _ in ()).throw(RuntimeError(code))
    with pytest.raises(RuntimeError, match='primary_dependency_support_missing'):
        operation.inputs()
    assert calls == ['legacy']
    operation.dependency = lambda site: calls.append(site)
    assert operation.inputs() == 'validated-source'
    assert calls == ['legacy', 'legacy', '/source/.venv/lib/python3.13/site-packages']


def test_dependency_domains_preserve_standalone_inventory():
    tree = ast.parse((ROOT / '.github/release-source-guard/producer_setup.py').read_bytes())
    fields = {key.value: value for node in ast.walk(tree) if isinstance(node, ast.Dict)
              for key, value in zip(node.keys, node.values)
              if isinstance(key, ast.Constant) and key.value in {'shared_trees', 'trees'}}
    env = {'Path': Path, 'dependency_site': Path('/opt/deps/lib/python3.13/site-packages'),
           'activation': type('Activation', (), {'tree': staticmethod(str)}),
           'operations': type('Operations', (), {'tree_identity': staticmethod(str)})}
    observed = {}
    for primary in (False, True):
        env['primary'] = primary
        observed[primary] = {key: eval(compile(ast.Expression(value), '<setup-domain>', 'eval'), env)
                             for key, value in fields.items()}
    assert set(observed[False]['shared_trees']) == {
        '/opt/deps/lib/python3.13/site-packages', '/usr/local/lib/python3.13'}
    assert observed[False]['trees'] == ['/opt/deps/lib/python3.13/site-packages']
    assert set(observed[True]['shared_trees']) == {'/usr/local/lib/python3.13'}
    assert observed[True]['trees'] == []
