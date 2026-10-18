"""Closed phase telemetry preserves the complete original executable AST."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parent

class StripTelemetry(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        if node.name == '_diagnostic_mark':
            return None
        return self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call):
            function = node.value.func
            if ((isinstance(function, ast.Name) and function.id == '_diagnostic_mark')
                    or (isinstance(function, ast.Attribute) and function.attr == '_diagnostic_mark')):
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
                or isinstance(node, ast.Attribute) and node.attr == 'diagnostic_schedule'
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
                    if not (isinstance(k, ast.Constant) and k.value == 'diagnostic_schedule')]
        node.keys, node.values = [k for k, v in retained], [v for k, v in retained]
        return self.generic_visit(node)

BASELINE_AST_SHA256 = {'finite/runtime_guard.py': '3b26232fb8c8d033a984e5c0ba0fa1760600cb7b846af728b2fbbeb39ccd6fa4', 'finite/source_activation.py': 'fd49c0f30096da8163142b0f8f884d56a80dbf9f5b38b757f22486ec1f5efab7', 'linux_supervisor.py': '2fb9fb8012c9161fe64ad70dca851abdd65a2e86dca48701d3f5b2d2fabef99f', 'linux_trace.py': '344558174ec335476ac8f76fa0afdf4ee667a497825150e4388fdb8ca95f5b9c', 'primary_source_authority.py': 'b36a24d13b548d143379dacd844680f089a41e5f2666c9a9944eeb29607a1540'}


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
