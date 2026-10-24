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

ROLE_TOKEN_HOOK = b'        if registration["class"] in {"source-owned-role:worker", "source-owned-role:validator",\n                                     "source-owned-role:terminal-reviewer"}:\n            role_path = Path(state["guard"]).with_name("role_routes.py")\n            checked_source(role_path, state["direct_support"]["files"][str(role_path)])[\n                "bind_launch"](registration, child_argv, kwargs.get("cwd"),\n                               inherited_environment() if kwargs.get("env") is None else dict(kwargs["env"]),\n                               code, state, launch_token, append, refuse)\n'


CLOSED_BOOTSTRAP_HOOK = b"""    leaf_path = Path(__file__).with_name('closed_bootstrap_leaf.py')
    if (command_class in {'source-canonical-stdlib-backend', 'source-canonical-stdlib-acp'}
            and case in (
                'tests/test_experimental_bootstrap.py::test_actual_sequential_initialize_and_session_share_cutoff',
                'tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout')
            and str(leaf_path) in support['files']):
        leaf = checked_source(leaf_path, support['files'][str(leaf_path)])['select'](
            sys.modules[__name__], state, sys._getframe())
        if leaf is not None:
            _CLOSED_LEAF = state['closed_bootstrap_leaf'] = leaf
            leaf.install()
            return
"""


def restore_closed_bootstrap_bytes(body):
    replacements = (
        (b'_CLOSED_LEAF = None\n', b''),
        (b'    global _STATE, _CLOSED_LEAF\n', b'    global _STATE\n'),
        (b"    leaf = _STATE.get('closed_bootstrap_leaf')\n    if leaf is not None:\n        leaf.validate_ready()\n", b''),
        (b"        if leaf is None and (owner is not _STATE.get('operation_profile_owner')", b"        if (owner is not _STATE.get('operation_profile_owner')"),
        (b'    if _CLOSED_LEAF is not None:\n        _CLOSED_LEAF.audit(event, args)\n        return\n', b''),
        (CLOSED_BOOTSTRAP_HOOK, b''),
    )
    for current, previous in replacements:
        assert body.count(current) == 1
        body = body.replace(current, previous, 1)
    return body


def restore_stdlib_acp_bytes(body):
    body = restore_closed_bootstrap_bytes(body)
    delayed = b'                "source-delayed-bootstrap",\n'
    assert body.count(delayed) == 1
    body = body.replace(delayed, b'', 1)
    assert body.count(ROLE_TOKEN_HOOK) == 1
    body = body.replace(ROLE_TOKEN_HOOK, b'', 1)
    assert body.count(ORDERS_TOKEN_HOOK) == 1
    body = body.replace(ORDERS_TOKEN_HOOK, b'', 1)
    assert body.count(ACP_POST_ADMISSION_HOOK) == 1
    body = body.replace(ACP_POST_ADMISSION_HOOK, b'', 1)
    new = b'                "source-canonical-stdlib-backend", "source-canonical-stdlib-acp",\n'
    old = b'                "source-canonical-stdlib-backend",\n'
    assert body.count(new) == 1
    return body.replace(new, old, 1)


def restore_stdlib_ready_class(tree):
    delayed = [n for n in ast.walk(tree) if isinstance(n, ast.Constant)
               and n.value == 'source-delayed-bootstrap']
    assert len(delayed) == 1
    owners = [n for n in ast.walk(tree) if isinstance(n, ast.Tuple) and delayed[0] in n.elts]
    assert len(owners) == 1 and owners[0].elts.index(delayed[0]) == 3
    assert [ast.literal_eval(n) for n in owners[0].elts[:3]] == [
        'canonical-backend', 'source-canonical-stdlib-backend', 'source-canonical-stdlib-acp']
    owners[0].elts.remove(delayed[0])
    import textwrap
    role = ast.parse(textwrap.dedent(ROLE_TOKEN_HOOK.decode())).body[0]
    matches = [(node, i) for node in ast.walk(tree)
               for field, value in ast.iter_fields(node) if field == 'body' and isinstance(value, list)
               for i, child in enumerate(value)
               if ast.dump(child, include_attributes=False) == ast.dump(role, include_attributes=False)]
    assert len(matches) == 1
    matches[0][0].body.pop(matches[0][1])
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


def restore_closed_bootstrap_leaf(tree):
    """Remove only the exact new closed-leaf branches; retain the old oracle."""
    pieces = [
        "_CLOSED_LEAF = None",
        "leaf = _STATE.get('closed_bootstrap_leaf')",
        "if leaf is not None:\n    leaf.validate_ready()",
        "if _CLOSED_LEAF is not None:\n    _CLOSED_LEAF.audit(event, args)\n    return",
        "leaf_path = Path(__file__).with_name('closed_bootstrap_leaf.py')",
        """if (command_class in {'source-canonical-stdlib-backend', 'source-canonical-stdlib-acp'}
            and case in (
                'tests/test_experimental_bootstrap.py::test_actual_sequential_initialize_and_session_share_cutoff',
                'tests/test_experimental_bootstrap.py::test_startup_subtracts_from_actual_inference_timeout')
            and str(leaf_path) in support['files']):
        leaf = checked_source(leaf_path, support['files'][str(leaf_path)])['select'](
            sys.modules[__name__], state, sys._getframe())
        if leaf is not None:
            _CLOSED_LEAF = state['closed_bootstrap_leaf'] = leaf
            leaf.install()
            return""",
    ]
    expected = [ast.dump(ast.parse(body).body[0], include_attributes=False) for body in pieces]
    counts = [0] * len(expected)
    condition = ast.parse("""owner is not _STATE.get('operation_profile_owner')
        or getattr(method, '__func__', None) is not _STATE.get('operation_profile_function')
        or method.__func__.__code__ is not _STATE.get('operation_profile_code')
        or method.__func__.__globals__ is not _STATE.get('operation_profile_globals')
        or _STATE.get('operation_profile_sources') != frozenset(
            method.__func__.__globals__['SOURCE_FRAME_PATHS'])""".replace('\n', ' '), mode='eval').body
    globals_restored = []
    checks_restored = []
    class Restore(ast.NodeTransformer):
        def visit(self, node):
            current = ast.dump(node, include_attributes=False)
            if current in expected:
                counts[expected.index(current)] += 1
                return None
            return super().visit(node)
        def visit_Global(self, node):
            if node.names == ['_STATE', '_CLOSED_LEAF']:
                globals_restored.append(True)
                return ast.Global(names=['_STATE'])
            return node
        def visit_If(self, node):
            if (isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.And)
                    and len(node.test.values) == 2
                    and ast.unparse(node.test.values[0]) == 'leaf is None'):
                assert ast.dump(node.test.values[1], include_attributes=False) == ast.dump(condition, include_attributes=False)
                node.test = node.test.values[1]
                checks_restored.append(True)
            return self.generic_visit(node)
    tree = Restore().visit(tree)
    assert counts == [1] * len(expected) and len(globals_restored) == len(checks_restored) == 1
    return tree


BASELINE_AST_SHA256 = {'finite/source_operations.py': 'a5d9f2958f8aa4dd57922407f3112d6917544cc87b22942febe254172bd50209', 'finite/runtime_guard.py': '3b26232fb8c8d033a984e5c0ba0fa1760600cb7b846af728b2fbbeb39ccd6fa4', 'finite/source_activation.py': 'fd49c0f30096da8163142b0f8f884d56a80dbf9f5b38b757f22486ec1f5efab7', 'linux_supervisor.py': '2fb9fb8012c9161fe64ad70dca851abdd65a2e86dca48701d3f5b2d2fabef99f', 'linux_trace.py': '344558174ec335476ac8f76fa0afdf4ee667a497825150e4388fdb8ca95f5b9c', 'primary_source_authority.py': 'b36a24d13b548d143379dacd844680f089a41e5f2666c9a9944eeb29607a1540'}


def restore_exact_listener_acquisition(tree):
    method = ast.unparse(ast.parse("""
    def observe_listener(self, entry):
        pid = entry['pid']
        saved = self.registered[pid]['identity']
        if kernel.identity(pid) != saved:
            raise RuntimeError('stale_or_reused_ownership')
        current = sockets.socket_descriptor(pid, entry['fd'])
        if kernel.identity(pid) != saved:
            raise RuntimeError('stale_or_reused_ownership')
        return current
    """.strip()).body[0])
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Supervisor')
    actual = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == 'observe_listener')
    assert ast.unparse(actual) == method
    owner.body.remove(actual)
    source = ast.unparse(tree)
    assert source.count('current = self.observe_listener(entry)') == 1
    return ast.parse(source.replace('current = self.observe_listener(entry)',
        "current = next((s for s in self.observe(entry['pid']) if s['fd'] == entry['fd']), None)"))


def test_only_closed_telemetry_changes_original_executable_trees():
    for name, expected in BASELINE_AST_SHA256.items():
        tree = ast.parse((ROOT / name).read_bytes())
        if name == 'finite/runtime_guard.py':
            tree = restore_closed_bootstrap_leaf(tree)
            tree = restore_stdlib_ready_class(restore_launch_image_observation(tree))
        if name == 'finite/source_operations.py':
            tree = restore_dependency_diagnostic(restore_query_route(tree))
        if name == 'linux_supervisor.py':
            tree = restore_connected_acquisition(tree)
            tree = restore_exact_listener_acquisition(restore_absent_peer_candidate(restore_response_channel(restore_empty_receipt(tree))))
        if name == 'linux_trace.py':
            tree = restore_before_numeric_wait(restore_primary_allocation(restore_environment_name_grammar(tree)))
        if name == 'primary_source_authority.py':
            source = ast.unparse(tree)
            assert source.count('from journal_supervisor import launch_events') == 1
            assert source.count('events = launch_events(self.supervisor)') == 1
            source = source.replace('from journal_supervisor import launch_events', '')
            source = source.replace('events = launch_events(self.supervisor)', 'events = self.supervisor.events()')
            tree = restore_bootstrap_cache(restore_producer_profile(ast.parse(source)))
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


def test_listener_acquisition_normalization_cannot_hide_authority_drift():
    import pytest
    source = (ROOT / 'linux_supervisor.py').read_text()
    for before, after in [
        ("current = sockets.socket_descriptor(pid, entry['fd'])", "current = entry"),
        ("saved = self.registered[pid]['identity']", "saved = kernel.identity(pid)"),
        ("if kernel.identity(pid) != saved:", "if False:"),
        ("current = self.observe_listener(entry)", "current = entry"),
    ]:
        assert before in source
        with pytest.raises((AssertionError, StopIteration)):
            restore_exact_listener_acquisition(ast.parse(source.replace(before, after)))


def restore_connected_acquisition(tree):
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Supervisor')
    methods = [n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'observe_connection']
    assert len(methods) == 1
    expected = ast.parse("""def observe_connection(self, pid):
        saved = self.registered[pid]['identity']
        if kernel.identity(pid) != saved:
            raise RuntimeError('stale_or_reused_ownership')
        rows = sockets.connected_sockets(pid)
        if kernel.identity(pid) != saved:
            raise RuntimeError('stale_or_reused_ownership')
        return rows
""").body[0]
    assert ast.dump(methods[0], include_attributes=False) == ast.dump(expected, include_attributes=False)
    owner.body.remove(methods[0])
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == 'observe_connection']
    assert len(calls) == 2
    assert {ast.unparse(n.args[0]) for n in calls} == {"listener['pid']", "request['pid']"}
    for call in calls:
        assert ast.unparse(call.func.value) == 'self' and len(call.args) == 1 and not call.keywords
        call.func.attr = 'observe'
    return tree


def test_connected_acquisition_normalization_cannot_hide_authority_drift():
    import pytest
    source = (ROOT / 'linux_supervisor.py').read_text()
    for before, after in [
        ('rows = sockets.connected_sockets(pid)', 'rows = []'),
        ("saved = self.registered[pid]['identity']", 'saved = kernel.identity(pid)'),
        ("if kernel.identity(pid) != saved:", 'if False:'),
        ('self.observe_connection(request["pid"])', 'self.observe_connection(listener["pid"])'),
    ]:
        assert before in source
        with pytest.raises((AssertionError, StopIteration)):
            restore_connected_acquisition(ast.parse(source.replace(before, after)))


def test_closed_leaf_byte_and_ast_inverses_preserve_the_same_original_tree():
    body = (ROOT / 'finite/runtime_guard.py').read_bytes()
    original_bytes = restore_closed_bootstrap_bytes(body)
    original_tree = restore_closed_bootstrap_leaf(ast.parse(body))
    assert ast.dump(ast.parse(original_bytes), include_attributes=False) == ast.dump(original_tree, include_attributes=False)


def test_closed_leaf_inverses_refuse_changed_or_duplicate_branches():
    import pytest
    body = (ROOT / 'finite/runtime_guard.py').read_bytes()
    for before, after in [
            (b"leaf.validate_ready()", b"leaf.install()"),
            (b"_CLOSED_LEAF.audit(event, args)", b"_CLOSED_LEAF.audit(event, ())"),
            (b"and case in (", b"or case in ("),
            (b"_CLOSED_LEAF = None\n", b"_CLOSED_LEAF = None\n_CLOSED_LEAF = None\n")]:
        assert body.count(before) == 1
        changed = body.replace(before, after)
        with pytest.raises(AssertionError):
            restore_closed_bootstrap_bytes(changed)
        with pytest.raises(AssertionError):
            restore_closed_bootstrap_leaf(ast.parse(changed))
