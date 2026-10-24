"""Closed phase telemetry preserves the complete original executable AST."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

from test_root_allocation import restore_primary_allocation
from test_producer_startup import restore_producer_profile, restore_primary_cache, restore_bootstrap_cache, restore_query_route, restore_dependency_diagnostic

ROOT = Path(__file__).parent

class StripTelemetry(ast.NodeTransformer):
    def visit_If(self, node):
        if ast.unparse(node.test) == "state.get('primary_snapshot_observer') is not None":
            assert ast.unparse(node) == "if state.get('primary_snapshot_observer') is not None:\n    state['primary_snapshot_observer'](frame, event, value)"
            return None
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        if node.name == 'DiagnosticTrace':
            return None
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.name in {'_diagnostic_mark', 'record_channel_diagnostic', 'diagnostic_summary'}:
            return None
        return self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call):
            function = node.value.func
            if (isinstance(function, ast.Attribute) and function.attr == 'record_channel_diagnostic'
                    and isinstance(function.value, ast.Name) and function.value.id == 'self'):
                return ast.Expr(value=ast.Call(
                    func=ast.Attribute(value=ast.Attribute(value=ast.Name(id='self', ctx=ast.Load()),
                                                          attr='channel_diagnostics', ctx=ast.Load()),
                                       attr='append', ctx=ast.Load()),
                    args=[ast.Call(func=ast.Attribute(value=ast.Name(id='self', ctx=ast.Load()),
                                                     attr='channel_snapshot', ctx=ast.Load()),
                                   args=node.value.args, keywords=[])], keywords=[]))
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
                or isinstance(node, ast.Attribute) and node.attr in {'diagnostic_schedule', 'diagnostic_trace', 'diagnostic_inputs', 'channel_diagnostic_hash', 'channel_diagnostic_summary'}
                or isinstance(node, ast.Subscript) and self.diagnostic_target(node.value))

    def visit_Assign(self, node):
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == 'state'
                and isinstance(node.targets[0].slice, ast.Constant)
                and node.targets[0].slice.value == 'diagnostic_success'):
            return None
        if all(self.diagnostic_target(target) for target in node.targets):
            return None
        return self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self.diagnostic_target(node.target):
            return None
        return self.generic_visit(node)

    def visit_Dict(self, node):
        retained = [(k, v) for k, v in zip(node.keys, node.values)
                    if not (isinstance(k, ast.Constant) and k.value in {'diagnostic_schedule', 'diagnostic_trace', 'receipt_channel_diagnostic_summary'})]
        node.keys, node.values = [k for k, v in retained], [v for k, v in retained]
        return self.generic_visit(node)

def restore_before_numeric_wait(tree):
    """Remove exactly the approved observation immediately before numeric wait."""
    expected = ast.parse("if getattr(self, 'before_numeric_wait', None) is not None:\n    self.before_numeric_wait(self, candidate)").body[0]
    loop = next(n for n in ast.walk(tree) if isinstance(n, ast.For)
                and ast.unparse(n.target) == 'candidate')
    ordered = ast.parse("if (getattr(self, 'defer_numeric_wait', None) is not None\n        and self.defer_numeric_wait(self, candidate)):\n    continue").body[0]
    assert ast.dump(loop.body[0], include_attributes=False) == ast.dump(ordered, include_attributes=False)
    references = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == 'defer_numeric_wait']
    assert len(references) == 1
    loop.body.pop(0)
    assert ast.dump(loop.body[0], include_attributes=False) == ast.dump(expected, include_attributes=False)
    assert ast.unparse(loop.body[1]) == 'pid, raw = os.waitpid(candidate, os.WNOHANG | 1073741824)'
    references = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                  and n.attr == 'before_numeric_wait']
    assert len(references) == 1
    loop.body.pop(0)
    return tree


def restore_absent_peer_candidate(tree):
    """Normalize only a missing historical payload-peer candidate observation."""
    handle = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle')
    loops = [n for n in ast.walk(handle) if isinstance(n, ast.For)
             and ast.unparse(n.target) == 'pid' and ast.unparse(n.iter) == 'self.registered']
    assert len(loops) == 1
    block = loops[0].body[0]
    assert isinstance(block, ast.Try) and len(block.handlers) == 1
    assert ast.unparse(block) == ('try:\n    peers = self.observe(pid)\n'
        'except (RuntimeError, FileNotFoundError):\n    continue')
    block.handlers[0].type = ast.Name(id='RuntimeError', ctx=ast.Load())
    return tree


def restore_response_channel(tree):
    handle = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle')
    nodes = [n for n in handle.body if isinstance(n, ast.If) and ast.unparse(n.test) == "kind == 'source_response_output'"]
    assert len(nodes) == 1
    assert ast.unparse(nodes[0]) == "if kind == 'source_response_output':\n    callback = getattr(self, 'source_response_output', None)\n    if callback is None:\n        raise RuntimeError('source_response_observer_missing')\n    return callback(request)"
    handle.body.remove(nodes[0])
    return tree


def restore_environment_name_grammar(tree):
    """Normalize only the explicit legal-empty-name parser correction."""
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                    and n.name == 'admit_exec')
    matches = [n for n in ast.walk(function) if isinstance(n, ast.If)
               and ast.unparse(n.test) == 'not separator or key in environment']
    assert len(matches) == 1
    assert ast.unparse(matches[0]) == (
        "if not separator or key in environment:\n"
        "    raise RuntimeError('invalid or duplicate exec environment entry')")
    matches[0].test = ast.parse('not separator or not key or key in environment', mode='eval').body
    return tree


def restore_launch_image_observation(tree):
    """Require the exact cwd-aware image observation; preserve the original AST."""
    expected = ast.parse('checked_source(\n                        Path(state["guard"]).with_name("launch_image.py"),\n                        state["direct_support"]["files"][str(Path(state["guard"]).with_name("launch_image.py"))],\n                    )["resolve"](argv[0], kwargs.get("cwd"), kwargs.get("env"))', mode='eval').body
    matches = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Name) and n.func.id == 'digest'
               and len(n.args) == 1
               and ast.dump(n.args[0], include_attributes=False) == ast.dump(expected, include_attributes=False)]
    assert len(matches) == 1
    matches[0].args[0] = ast.parse("shutil.which(argv[0], path=dict(os.environ if kwargs.get('env') is None else kwargs['env']).get('PATH')) or argv[0]", mode='eval').body
    return tree



def restore_controlled_postimage_class(tree):
    """Normalize only the exact reviewed original-fixture resolver output."""
    assignments = [n for n in tree.body if isinstance(n, ast.Assign)
                   and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                   and n.targets[0].id == 'ORDINARY_DIRECT']
    assert len(assignments) == 1
    value = assignments[0].value
    assert isinstance(value, ast.Call) and ast.unparse(value.func) == 'frozenset'
    assert len(value.args) == 1 and not value.keywords and isinstance(value.args[0], ast.Set)
    members = value.args[0].elts
    assert isinstance(members[0], ast.Constant) and members[0].value == 'canonical-backend'
    assert isinstance(members[1], ast.Constant) and members[1].value == 'source-controlled-backend-postimage'
    assert sum(isinstance(n, ast.Constant) and n.value == 'source-controlled-backend-postimage'
               for n in ast.walk(tree)) == 1
    members.pop(1)
    return tree



ACP_POST_ADMISSION_HOOK = b"        if registration['class'] == 'controlled-acp':\n            path = Path(state['guard']).with_name('stdlib_acp.py')\n            selected = checked_source(path, state['direct_support']['files'][str(path)])[\n                'after_admission'](registration, argv, cwd, environment, state, append, refuse)\n            if selected is not None:\n                return selected\n"

ORDERS_TOKEN_HOOK = b'        if registration["class"] == "source-orders-custody-git":\n            orders_path = Path(state["guard"]).with_name("orders_git.py")\n            checked_source(orders_path, state["direct_support"]["files"][str(orders_path)])[\n                "bind_launch"](registration, child_argv, kwargs.get("cwd"), kwargs.get("env"),\n                               state, launch_token, append, refuse)\n'

def restore_stdlib_acp_bytes(body):
    assert body.count(ORDERS_TOKEN_HOOK) == 1
    body = body.replace(ORDERS_TOKEN_HOOK, b'', 1)
    assert body.count(ACP_POST_ADMISSION_HOOK) == 1
    body = body.replace(ACP_POST_ADMISSION_HOOK, b'', 1)
    new = b'                "source-canonical-stdlib-backend", "source-canonical-stdlib-acp",\n'
    old = b'                "source-canonical-stdlib-backend",\n'
    assert body.count(new) == 1
    return body.replace(new, old, 1)


def restore_stdlib_ready_class(tree):
    import textwrap
    token = ast.parse(textwrap.dedent(ORDERS_TOKEN_HOOK.decode())).body[0]
    parents = [(node, i) for node in ast.walk(tree)
               for field, value in ast.iter_fields(node) if field == 'body' and isinstance(value, list)
               for i, child in enumerate(value)
               if ast.dump(child, include_attributes=False) == ast.dump(token, include_attributes=False)]
    assert len(parents) == 1
    parent, index = parents[0]
    parent.body.pop(index)
    expected = ast.parse(textwrap.dedent(ACP_POST_ADMISSION_HOOK.decode())).body[0]
    parents = [(node, i, child) for node in ast.walk(tree)
               for field, value in ast.iter_fields(node) if field == 'body' and isinstance(value, list)
               for i, child in enumerate(value)
               if ast.dump(child, include_attributes=False) == ast.dump(expected, include_attributes=False)]
    assert len(parents) == 1
    parent, index, _ = parents[0]
    parent.body.pop(index)
    acp = [n for n in ast.walk(tree) if isinstance(n, ast.Constant)
           and n.value == 'source-canonical-stdlib-acp']
    assert len(acp) == 1
    tuples = [n for n in ast.walk(tree) if isinstance(n, ast.Tuple) and acp[0] in n.elts]
    assert len(tuples) == 1 and tuples[0].elts.index(acp[0]) == 2
    tuples[0].elts.remove(acp[0])
    constants = [n for n in ast.walk(tree) if isinstance(n, ast.Constant)
                 and n.value == 'source-canonical-stdlib-backend']
    assert len(constants) == 1
    tuples = [n for n in ast.walk(tree) if isinstance(n, ast.Tuple)
              and constants[0] in n.elts]
    assert len(tuples) == 1
    members = tuples[0].elts
    assert ast.literal_eval(members[0]) == 'canonical-backend'
    assert members[1] is constants[0]
    assert ast.literal_eval(members[2]) == 'controlled-acp'
    members.pop(1)
    return tree



def restore_empty_receipt(tree):
    expected = ast.parse("""
if not state['buffer']:
    if receipt_lifecycle.empty_exit(self, state, events):
        self.record_channel_diagnostic(state, 'owned_empty_reaped')
        stream.close()
        del self.clients[stream]
    else:
        state['pending_reason'] = 'actual_parent_wait_record_still_pending'
    continue
""").body[0]
    capture = ast.parse('receipt_lifecycle.capture(self, stream, self.clients[stream], kernel.identity)').body[0]
    removed = [0, 0, 0]
    class Restore(ast.NodeTransformer):
        def visit_Import(self, node):
            if ast.dump(node) == ast.dump(ast.parse('import receipt_lifecycle').body[0]):
                removed[0] += 1
                return None
            return node
        def visit_Expr(self, node):
            if ast.dump(node) == ast.dump(capture):
                removed[1] += 1
                return None
            return self.generic_visit(node)
        def visit_If(self, node):
            if ast.dump(node) == ast.dump(expected):
                removed[2] += 1
                return None
            return self.generic_visit(node)
    tree = Restore().visit(tree)
    assert removed == [1, 1, 1]
    return tree

BASELINE_AST_SHA256 = {'finite/source_operations.py': 'a5d9f2958f8aa4dd57922407f3112d6917544cc87b22942febe254172bd50209', 'finite/runtime_guard.py': '3b26232fb8c8d033a984e5c0ba0fa1760600cb7b846af728b2fbbeb39ccd6fa4', 'finite/source_activation.py': 'fd49c0f30096da8163142b0f8f884d56a80dbf9f5b38b757f22486ec1f5efab7', 'linux_supervisor.py': '2fb9fb8012c9161fe64ad70dca851abdd65a2e86dca48701d3f5b2d2fabef99f', 'linux_trace.py': '344558174ec335476ac8f76fa0afdf4ee667a497825150e4388fdb8ca95f5b9c', 'primary_source_authority.py': 'b36a24d13b548d143379dacd844680f089a41e5f2666c9a9944eeb29607a1540'}


def test_only_closed_telemetry_changes_original_executable_trees():
    for name, expected in BASELINE_AST_SHA256.items():
        tree = ast.parse((ROOT / name).read_bytes())
        if name == 'finite/runtime_guard.py':
            tree = restore_stdlib_ready_class(restore_launch_image_observation(tree))
        if name == 'finite/source_operations.py':
            tree = restore_dependency_diagnostic(restore_query_route(tree))
        if name == 'linux_supervisor.py':
            tree = restore_absent_peer_candidate(restore_response_channel(restore_empty_receipt(tree)))
        if name == 'linux_trace.py':
            tree = restore_before_numeric_wait(restore_primary_allocation(restore_environment_name_grammar(tree)))
        if name == 'primary_source_authority.py':
            tree = restore_bootstrap_cache(restore_producer_profile(tree))
        if name == 'finite/source_activation.py':
            tree = restore_controlled_postimage_class(restore_primary_cache(tree))
        tree = StripTelemetry().visit(tree)
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
        tree = StripTelemetry().visit(restore_primary_allocation(restore_environment_name_grammar(ast.parse(original.replace(before, after)))))
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


def test_bounded_channel_telemetry_cannot_hide_receipt_or_deadline_mutation():
    original = (ROOT / 'linux_supervisor.py').read_text()
    for before, after in [('self.receipts.append(result)', 'self.receipts.append({})'),
                          ('self.ledger.admit(stream, request)', '{}'),
                          ('len(encoded) > 16384', 'len(encoded) > 32768')]:
        assert before in original
        tree = StripTelemetry().visit(ast.parse(original.replace(before, after)))
        assert hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest() != BASELINE_AST_SHA256['linux_supervisor.py']
