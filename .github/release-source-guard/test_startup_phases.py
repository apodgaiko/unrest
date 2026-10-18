"""Closed phase telemetry preserves the complete original executable AST."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parent

class StripTelemetry(ast.NodeTransformer):
    def visit_ClassDef(self, node):
        if node.name == 'DiagnosticTrace':
            return None
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name == '_diagnostic_mark':
            return None
        return self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call):
            function = node.value.func
            if ((isinstance(function, ast.Name) and function.id == '_diagnostic_mark')
                    or (isinstance(function, ast.Attribute) and function.attr == '_diagnostic_mark')
                    or (isinstance(function, ast.Attribute) and isinstance(function.value, ast.Attribute)
                        and function.value.attr == 'diagnostic_trace')):
                return None
            if (isinstance(function, ast.Attribute) and function.attr == 'append'
                    and node.value.args and isinstance(node.value.args[0], ast.Dict)
                    and any(isinstance(k, ast.Constant) and k.value == 'kind'
                            and isinstance(v, ast.Constant) and v.value in {
                                'diagnostic_stop', 'diagnostic_resume'}
                            for k, v in zip(node.value.args[0].keys, node.value.args[0].values))):
                return None
        return self.generic_visit(node)

    def diagnostic_target(self, node):
        return (isinstance(node, ast.Name) and node.id.startswith('diagnostic_')
                or isinstance(node, ast.Attribute) and node.attr in {'diagnostic_schedule', 'diagnostic_trace', 'diagnostic_inputs'}
                or isinstance(node, ast.Subscript) and self.diagnostic_target(node.value))

    def visit_Assign(self, node):
        if all(self.diagnostic_target(target) for target in node.targets):
            return None
        return self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self.diagnostic_target(node.target):
            return None
        return self.generic_visit(node)

    def visit_Dict(self, node):
        retained = [(k, v) for k, v in zip(node.keys, node.values)
                    if not (isinstance(k, ast.Constant) and k.value in {'diagnostic_schedule', 'diagnostic_trace'})]
        node.keys, node.values = [k for k, v in retained], [v for k, v in retained]
        return self.generic_visit(node)

BASELINE_AST_SHA256 = {'finite/source_operations.py': '63eba8a5c40c2500b26b26cf0731cee0f8f21fd562334a60664d443c6e392622', 'finite/runtime_guard.py': '3b26232fb8c8d033a984e5c0ba0fa1760600cb7b846af728b2fbbeb39ccd6fa4', 'finite/source_activation.py': 'fd49c0f30096da8163142b0f8f884d56a80dbf9f5b38b757f22486ec1f5efab7', 'linux_supervisor.py': '2fb9fb8012c9161fe64ad70dca851abdd65a2e86dca48701d3f5b2d2fabef99f', 'linux_trace.py': '344558174ec335476ac8f76fa0afdf4ee667a497825150e4388fdb8ca95f5b9c', 'primary_source_authority.py': 'b36a24d13b548d143379dacd844680f089a41e5f2666c9a9944eeb29607a1540'}


def test_only_closed_telemetry_changes_original_executable_trees():
    for name, expected in BASELINE_AST_SHA256.items():
        tree = StripTelemetry().visit(ast.parse((ROOT / name).read_bytes()))
        assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() == expected


def test_phase_record_contains_only_closed_values(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('phase_guard', ROOT / 'finite/runtime_guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard._STATE = {'events': str(tmp_path)}
    guard._diagnostic_mark('inner_enter')
    guard._diagnostic_mark('inner_return')
    rows = [json.loads(line) for path in tmp_path.glob('*.jsonl')
            for line in path.read_text().splitlines()]
    assert len(rows) == 2
    fields = {'kind', 'phase', 'monotonic_ns', 'process_cpu_ns', 'thread_cpu_ns', 'thread_id',
              'function_code_sha256', 'location_sha256', 'voluntary_switches',
              'involuntary_switches', 'minor_faults', 'major_faults', 'block_inputs',
              'block_outputs', 'owner_pid', 'parent_pid', 'case'}
    assert all(set(row) == fields for row in rows)
    assert rows[1]['monotonic_ns'] > rows[0]['monotonic_ns']
    for row in rows:
        assert row['kind'] == 'startup_phase' and row['case'] is None
        assert row['phase'] in {'inner_enter', 'inner_return'}
        for key in fields - {'kind', 'phase', 'case', 'function_code_sha256', 'location_sha256'}:
            assert type(row[key]) is int and row[key] >= 0
        for key in ('function_code_sha256', 'location_sha256'):
            assert len(row[key]) == 64 and int(row[key], 16) >= 0


def load_trace():
    spec = importlib.util.spec_from_file_location('bounded_trace', ROOT / 'linux_trace.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stressed_trace():
    module = load_trace()
    diagnostic = module.DiagnosticTrace()
    # The compartment admits at most 128 simultaneous tasks. Exercise each
    # numeric event column repeatedly without storing any per-event rows.
    for pid in range(1, 129):
        for event in range(1000):
            diagnostic.stop(pid, 133, event % 8)
            diagnostic.resume(pid, 7 if event % 2 else 24)
    return diagnostic.export()


def test_aggregate_size_independent_of_stop_count():
    value = stressed_trace()
    assert len(value['rows']) == 128
    assert len(value['columns']) == 15
    assert all(len(row) == 15 and row[1:3] == [1000, 1000] for row in value['rows'])
    assert all(all(type(number) is int and number >= 0 for number in row) for row in value['rows'])
    assert len(json.dumps(value).encode()) < 32768


def test_original_control_records_plus_maximum_diagnostics_stay_bounded():
    import sys
    import pytest
    if sys.platform != 'linux' or not Path('/work').is_dir():
        pytest.skip('original kernel controls are generated inside the Linux compartment')
    controls = sorted(Path('/work').glob('trace-control-*.json'))
    assert len(controls) == 9
    diagnostic = stressed_trace()
    for path in controls:
        original = json.loads(path.read_bytes())
        before = json.dumps(original['records'])
        original['diagnostic_trace'] = diagnostic
        assert len(json.dumps(original, sort_keys=True).encode()) < 131072
        assert json.dumps(original['records']) == before


def test_ast_proof_rejects_original_wait_or_admission_mutation():
    original = (ROOT / 'linux_trace.py').read_text()
    for before, after in [('os.waitpid(candidate, os.WNOHANG | 0x40000000)',
                           'os.waitpid(candidate, os.WNOHANG)'),
                          ('accepted = len(matches) == 1', 'accepted = True')]:
        assert before in original
        tree = StripTelemetry().visit(ast.parse(original.replace(before, after)))
        assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() != BASELINE_AST_SHA256['linux_trace.py']


def test_inner_diagnostics_are_selective_and_finite(monkeypatch):
    import sys
    import types
    import pytest
    rows = []
    monkeypatch.setitem(sys.modules, 'runtime_guard', types.SimpleNamespace(_diagnostic_mark=rows.append))
    import os
    # The synthetic compartment deliberately has no /source registration tree.
    # Execute only the actual diagnostic helper, never the original registrations.
    tree = ast.parse((ROOT / 'finite/source_operations.py').read_bytes())
    nodes = [node for node in tree.body if (isinstance(node, ast.FunctionDef)
             and node.name == '_diagnostic_mark') or (isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == 'diagnostic_seen'
                     for target in node.targets))]
    assert len(nodes) == 2
    namespace = {'os': os, 'sys': sys}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<closed-diagnostic-helper>', 'exec'), namespace)
    module = types.SimpleNamespace(**namespace)
    owner = types.SimpleNamespace(diagnostic_inputs=False)
    phases = ('operation_inputs_enter', 'operation_input_files_end', 'operation_input_trees_end')
    for _ in range(1000):
        for phase in phases:
            module._diagnostic_mark(owner, phase)
    assert rows == []
    owner.diagnostic_inputs = True
    for _ in range(1000):
        for phase in phases:
            module._diagnostic_mark(owner, phase)
    assert rows == list(phases)
    assert len(module.diagnostic_seen) == 3
    with pytest.raises(ValueError):
        module._diagnostic_mark(owner, 'unknown')


def test_outer_diagnostic_marks_have_finite_cardinality(tmp_path):
    spec = importlib.util.spec_from_file_location('bounded_phase_guard', ROOT / 'finite/runtime_guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard._STATE = {'events': str(tmp_path)}
    for _ in range(1000):
        for phase in sorted(guard.diagnostic_phases):
            guard._diagnostic_mark(phase)
    rows = [json.loads(line) for path in tmp_path.glob('*.jsonl') for line in path.read_text().splitlines()]
    assert len(rows) == len(guard.diagnostic_phases)
    assert {row['phase'] for row in rows} == guard.diagnostic_phases
    assert len(json.dumps(rows).encode()) < 32768
    assert all(row['kind'] == 'startup_phase' for row in rows)
    import pytest
    with pytest.raises(ValueError, match='unknown startup diagnostic phase'):
        guard._diagnostic_mark('unknown')
