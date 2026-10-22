"""All and only the original nine controlled approval scenarios are admitted."""
import ast
from pathlib import Path

import pytest

from finite import approval_routes as routes


@pytest.mark.parametrize('mode', routes.MODES)
def test_each_original_mode_is_derived_from_its_exact_case(mode):
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']') == mode
    assert routes.selected_mode(routes.PREFIX + '[' + mode + ']-foreign') is None


@pytest.mark.parametrize('case', [None, '', 'foreign', routes.PREFIX, routes.PREFIX + '[new]',
                                   routes.PREFIX + '[success] extra'])
def test_other_cases_gain_no_controlled_approval_launch(case):
    assert routes.selected_mode(case) is None
    assert routes.select([], None, None, {'case': case}, None, None) is None


def test_original_mode_parameters_and_backend_identity_gates_remain_closed():
    path = Path(routes.__file__)
    source = path.read_text()
    tree = ast.parse(source)
    assert source.count('scenario["mode"] != mode') == 1
    assert source.count('env["CONTROLLED_APPROVAL_MODE"] != mode') == 1
    assert 'backend_path.read_bytes() != backend_body' in source
    assert 'backend.read_bytes() != body' in source
    assert 'sha(backend) != local["backend_digest"]' in source
    assert not any(isinstance(n, ast.Call) and ast.unparse(n.func) in {'subprocess.Popen', 'os.system'}
                   for n in ast.walk(tree))


@pytest.mark.parametrize('boundary, mode', routes.DURABLE_MODES.items())
def test_exact_durable_boundaries_derive_original_modes(boundary, mode):
    from finite.approval_run_owner import boundary as select_boundary
    case = routes.DURABLE_PREFIX + '[' + boundary + ']'
    assert routes.selected_mode(case) == mode
    assert select_boundary(case) == boundary
    assert select_boundary(case + '-foreign') is None


def test_closed_bulk_diagnostic_keeps_existing_budget_and_original_deadlines():
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES, TEST_SEAM_ROOT_SECONDS, root_seconds
    from test_primary_source_entry import inputs, COMMAND
    from primary_source_inputs import test_plan as make_plan
    text, _ = inputs()
    assert len(TEST_APPROVAL_CLOSURE_CASES) == 33
    script = (COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES)).encode()
    plan = make_plan(script, text, 'TEST-positive')
    assert plan['timeout_seconds'] == root_seconds(plan) == TEST_SEAM_ROOT_SECONDS == 600
    assert plan['source_checkpoint_ready'] is False
    with pytest.raises(RuntimeError):
        make_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_CLOSURE_CASES[:-1])).encode(), text, 'TEST-positive')


def test_approval_inventory_pipe_keeps_original_descriptor_custody(monkeypatch):
    import owned_multiprocess_authority as owned
    import approval_pipe_custody as pipe
    authority = object.__new__(owned.SourceAuthority)
    marker = object()
    monkeypatch.setattr(owned.OriginalSourceAuthority, 'pipe_binding', lambda *args: marker)
    monkeypatch.setattr(pipe, 'binding', lambda *args: pytest.fail('original result bypassed'))
    assert authority.pipe_binding(42) is marker


def test_unrelated_class_gets_no_approval_inventory_descriptor():
    import approval_pipe_custody as pipe
    from types import SimpleNamespace
    assert pipe.binding(SimpleNamespace(bound={42: {'registration': {'class': 'foreign'}}}), 42) is None


def approval_pipe_fixture(monkeypatch):
    import approval_pipe_custody as pipe
    from types import SimpleNamespace
    import copy
    original_read = Path.read_bytes
    import hashlib
    bodies = {Path('/source', pipe.SOURCE): b'synthetic original ACP caller',
              Path('/source', pipe.TEST): b'synthetic original approval cases'}
    monkeypatch.setattr(pipe, 'PIN', hashlib.sha256(bodies[Path('/source', pipe.SOURCE)]).hexdigest())
    monkeypatch.setattr(pipe, 'TEST_PIN', hashlib.sha256(bodies[Path('/source', pipe.TEST)]).hexdigest())
    monkeypatch.setattr(Path, 'read_bytes', lambda p: bodies[p] if p in bodies else original_read(p))
    monkeypatch.setattr(pipe, 'identity', lambda pid: {'ppid': 7})
    row = {'kind': 'exact_controlled_approval_registration', 'owner_pid': 7,
           'class': 'source-approval-mcp', 'source_binding': {'path': '/source/' + pipe.SOURCE,
           'line': 2191, 'sha256': pipe.PIN}, 'argv_sha256': 'a' * 64,
           'case': routes.PREFIX + '[success]', 'native_provider': False,
           'pipe_device': 1, 'pipe_inode': 2}
    rows = [copy.deepcopy(row), copy.deepcopy(row)]
    selected = {key: row[key] for key in ('class', 'source_binding', 'argv_sha256')}
    authority = SimpleNamespace(bound={42: {'registration': selected}},
                                manifest={'product_pins': {pipe.SOURCE: pipe.PIN, pipe.TEST: pipe.TEST_PIN}},
                                supervisor=SimpleNamespace(events=lambda: rows))
    return pipe, authority, rows


def test_only_two_identical_original_approval_registrations_bind_pipe(monkeypatch):
    pipe, authority, rows = approval_pipe_fixture(monkeypatch)
    assert pipe.binding(authority, 42) == rows[0]


@pytest.mark.parametrize('mutation', ['one', 'extra', 'different', 'foreign_case', 'native',
                                       'negative_fd', 'bool_fd', 'source_pin', 'argv', 'parent'])
def test_approval_pipe_registration_mutations_refuse(monkeypatch, mutation):
    pipe, authority, rows = approval_pipe_fixture(monkeypatch)
    if mutation == 'one':
        rows.pop()
    elif mutation == 'extra':
        rows.append(dict(rows[0]))
    elif mutation == 'different':
        rows[1]['pipe_inode'] = 9
    elif mutation == 'source_pin':
        authority.manifest['product_pins'][pipe.SOURCE] = '0' * 64
    else:
        key, value = {'foreign_case': ('case', 'foreign'), 'native': ('native_provider', True),
                      'negative_fd': ('pipe_inode', -1), 'bool_fd': ('pipe_inode', True),
                      'argv': ('argv_sha256', 'b' * 64), 'parent': ('owner_pid', 8)}[mutation]
        for row in rows:
            row[key] = value
    with pytest.raises(RuntimeError):
        pipe.binding(authority, 42)


def test_approval_stall_capture_is_diagnostic_only_and_exact_selection():
    from finite.approval_stall_diagnostic import case_seconds
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES
    profile = {'source_mode': 'TEST-positive',
               'orig_argv': ['python', 'pytest', '-q', *TEST_APPROVAL_CLOSURE_CASES]}
    case = routes.PREFIX + '[success]'
    assert case_seconds(profile, case) == 60
    assert case_seconds(profile, routes.DURABLE_PREFIX + '[crash]') == 120
    assert case_seconds({**profile, 'source_mode': 'SOURCE'}, case) is None
    assert case_seconds({**profile, 'source_mode': 'TEST-poison'}, case) is None
    assert case_seconds({**profile, 'orig_argv': profile['orig_argv'][:-1]}, case) is None
    assert case_seconds(profile, 'foreign') is None


@pytest.mark.parametrize('kind, mode', [('foreign', 'success'), ('source-approval-relay', None)])
def test_owned_cwd_grants_nothing_to_foreign_case_or_class(kind, mode):
    from finite.approval_owned_cwd import prepare
    assert not prepare({'registration': {'class': kind}}, {}, {}, mode, None)


def test_owned_cwd_rejects_outside_or_non_workspace_directories(tmp_path):
    from finite.approval_owned_cwd import directory
    for path in (tmp_path, tmp_path / 'pytest', tmp_path / 'pytest/case/other'):
        path.mkdir(parents=True, exist_ok=True)
        with pytest.raises(RuntimeError):
            directory(path, tmp_path)


def test_missing_owned_cwd_kernel_record_poison_is_retained(monkeypatch):
    import approval_owned_cwd_custody as host
    from types import SimpleNamespace
    monkeypatch.setattr(host, 'identity', lambda pid: {'ppid': 7})
    poison = []
    authority = SimpleNamespace(bound={42: {'registration': {'class': 'source-approval-relay'},
                                              'token': 'owned'}},
                                supervisor=SimpleNamespace(registered={7: {'identity': {}}},
                                    events=lambda: [], poison=poison.append))
    trace = SimpleNamespace(poison=[])
    with pytest.raises(RuntimeError, match='cardinality'):
        host.check(authority, trace, 42, [])
    assert trace.poison == poison == ['approval_owned_cwd_kernel_binding']


def test_approval_diagnostic_has_no_checkout_only_imports():
    from finite import approval_stall_diagnostic as diagnostic
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES
    import hashlib
    import json
    assert diagnostic.SELECTION_SHA256 == hashlib.sha256(json.dumps(['-q', *TEST_APPROVAL_CLOSURE_CASES]).encode()).hexdigest()
    tree = ast.parse(Path(diagnostic.__file__).read_bytes())
    assert all(n.module == '__future__' for n in ast.walk(tree) if isinstance(n, ast.ImportFrom))
    assert {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names} == {'hashlib', 'json'}


def test_exact_approval_watchdog_survives_call_and_closes_after_teardown():
    from primary_source_entry import Observer
    from types import SimpleNamespace
    calls = []
    case = routes.PREFIX + '[success]'
    owner = SimpleNamespace(startup_stall_timer=SimpleNamespace(cancel=lambda: calls.append('cancel')),
                            startup_stall_token=object(), approval_stall_case=case,
                            retain_failure=lambda report: None,
                            guard=SimpleNamespace(append=lambda row: calls.append(row['phase'])),
                            session=None, custodian=None)
    report = SimpleNamespace(when='call', nodeid=case, failed=False, outcome='passed')
    Observer.pytest_runtest_logreport(owner, report)
    assert calls == ['call'] and owner.startup_stall_timer is not None
    report.when = 'teardown'
    Observer.pytest_runtest_logreport(owner, report)
    assert calls == ['call', 'cancel', 'teardown'] and owner.startup_stall_timer is None


def test_unrelated_watchdog_keeps_original_call_cancellation():
    from primary_source_entry import Observer
    from types import SimpleNamespace
    calls = []
    owner = SimpleNamespace(startup_stall_timer=SimpleNamespace(cancel=lambda: calls.append('cancel')),
                            startup_stall_token=object(), approval_stall_case=None,
                            retain_failure=lambda report: None,
                            guard=SimpleNamespace(append=lambda row: None), session=None, custodian=None)
    Observer.pytest_runtest_logreport(owner, SimpleNamespace(when='call', nodeid='original', failed=False, outcome='passed'))
    assert calls == ['cancel'] and owner.startup_stall_timer is None


def test_actual_mcp_and_foreign_callers_cannot_omit_server_configuration():
    from finite import approval_json_setup as setup
    from types import SimpleNamespace
    for kind in ['source-approval-mcp', 'source-run-worker', 'foreign', 'source-approval-adapter']:
        assert setup.select(SimpleNamespace(_STATE={'class': kind}), {}) is None


@pytest.mark.parametrize('change', ['class', 'case', 'token', 'argv', 'binding', 'mode', 'phase', 'setup'])
def test_json_approval_setup_selection_refuses_context_mutations(change):
    from finite import approval_json_setup as setup
    import os
    kind = 'source-approval-adapter'
    source, line, pin = setup.BINDINGS[kind]
    target = '/source/tests/fixtures/approval_recovery_acp.py'
    case = routes.PREFIX + '[drop_ack]'
    state = {'class': kind, 'case': case, 'token': 'exact', 'phase': 'READY', 'checkout': '/source',
             'runtime': {'paths': ['python']}, 'product_pins': {source: pin}}
    endpoint = {'token': 'exact', 'identity': {'pid': os.getpid()}}
    payload = {'class': kind, 'case': case, 'token': 'exact', 'mode': 'script', 'target': target,
               'path0': '/source/tests/fixtures', 'orig_argv': ['python', target, '/work/scenario'],
               'sys_argv': [target, '/work/scenario'], 'isolated': False,
               'source_binding': {'path': '/source/' + source, 'line': line, 'sha256': pin}}
    assert setup.eligible(state, endpoint, payload, 'drop_ack')
    if change in {'class', 'case', 'token', 'mode'}:
        payload[change] = 'foreign'
    elif change == 'argv':
        payload['orig_argv'].append('foreign')
    elif change == 'binding':
        payload['source_binding']['line'] += 1
    elif change == 'phase':
        state['phase'] = 'INSTALLING'
    else:
        state['setup_mode'] = 'dependency-source-negative'
    assert not setup.eligible(state, endpoint, payload, 'drop_ack')


def test_json_setup_keeps_original_mock_fallback_and_dependency_body():
    from test_mock_backend_setup import test_unknown_contexts_and_all_negative_controls_retain_original_setup_body
    test_unknown_contexts_and_all_negative_controls_retain_original_setup_body()


@pytest.mark.parametrize('kind', ['source-approval-adapter', 'source-approval-relay', 'source-approval-python-backend'])
def test_current_json_script_and_generated_bytes_match_without_server_import(tmp_path, kind):
    from finite import approval_json_setup as setup
    import sys
    root = Path(__file__).resolve().parent
    if root.name == 'release-source-guard':
        root = root.parent.parent
    else:
        pytest.skip('original product source is absent from the synthetic control compartment')
    assert (root / 'tests/fixtures/approval_recovery_acp.py').is_file()
    native = tmp_path / 'controlled-backend'
    native.write_bytes(f'#!{sys.executable}\n'.encode() + (root / 'tests/fixtures/approval_native_backend.py').read_bytes())
    if kind == 'source-approval-adapter':
        target = root / 'tests/fixtures/approval_recovery_acp.py'
        argument = tmp_path / 'scenario.json'
        argument.write_text('{}')
    elif kind == 'source-approval-python-backend':
        target, argument = native, 'app-server'
    else:
        directory = tmp_path / 'unrest-approval-abcdefgh'
        directory.mkdir()
        target, argument = directory / 'backend', 'app-server'
        import hashlib
        digest = hashlib.sha256(native.read_bytes()).hexdigest()
        target.write_text(f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(root / "src")!r})\n'
                          'from unrest_harness.approval_relay import main\n'
                          f'main({str(directory / "control")!r}, {"a" * 64!r}, {str(native)!r}, {digest!r})\n')
    state = {'class': kind, 'checkout': str(root), 'owned_root': str(tmp_path), 'product_pins': dict(setup.PURE)}
    payload = {'target': str(target), 'sys_argv': [str(target), str(argument)]}
    assert setup.script_identity(state, payload) is not None
    state['product_pins']['src/unrest_harness/approval_native.py'] = 'foreign'
    assert setup.script_identity(state, payload) is None


def test_stall_snapshot_uses_original_output_descriptor_not_pytest_capture(monkeypatch):
    from primary_source_entry import Observer, diagnostic_output_identity
    from types import SimpleNamespace
    import tempfile
    import sys
    token, case = object(), routes.PREFIX + '[success]'
    with tempfile.TemporaryFile() as output:
        owner = SimpleNamespace(startup_stall_token=token, guard=SimpleNamespace(_STATE={'case': case}),
                                stack_output_fd=output.fileno(),
                                stack_output_identity=diagnostic_output_identity(output.fileno()))
        monkeypatch.setattr(sys, '__stderr__', SimpleNamespace(write=lambda value: pytest.fail('captured stderr used')))
        assert Observer.retain_stall_snapshot(owner, token, case, None)
        output.seek(0)
        assert b'[retained task snapshot]' in output.read()


def test_stall_snapshot_does_not_write_reused_descriptor(monkeypatch):
    from primary_source_entry import Observer
    from types import SimpleNamespace
    import tempfile
    token, case = object(), routes.PREFIX + '[success]'
    with tempfile.TemporaryFile() as output:
        owner = SimpleNamespace(startup_stall_token=token, guard=SimpleNamespace(_STATE={'case': case}),
                                stack_output_fd=output.fileno(), stack_output_identity=('foreign',))
        assert not Observer.retain_stall_snapshot(owner, token, case, None)
        assert output.tell() == 0


def test_remaining_original_approval_cases_reuse_sealed_prefix_without_source_certificate():
    from primary_policy import TEST_APPROVAL_CLOSURE_CASES, TEST_APPROVAL_REMAINING_CASES, root_seconds
    from primary_source_inputs import test_plan as make_plan
    from test_primary_source_entry import inputs, COMMAND
    from finite.approval_stall_diagnostic import case_seconds
    text, _ = inputs()
    assert TEST_APPROVAL_REMAINING_CASES == (TEST_APPROVAL_CLOSURE_CASES[0], *TEST_APPROVAL_CLOSURE_CASES[20:])
    plan = make_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_REMAINING_CASES)).encode(), text, 'TEST-positive')
    assert not plan['source_checkpoint_ready'] and root_seconds(plan) == 600
    profile = {'source_mode': 'TEST-positive', 'orig_argv': ['python', 'pytest', '-q', *TEST_APPROVAL_REMAINING_CASES]}
    assert case_seconds(profile, routes.DURABLE_PREFIX + '[success]') == 120
    assert case_seconds(profile, routes.PREFIX + '[success]') is None


def test_constructor_diagnostic_does_not_capture_message_or_change_exception():
    import hashlib
    import json
    path = Path(__file__).parent / 'finite/child_relative.py'
    tree = ast.parse(path.read_bytes())
    handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
                and node.name == 'error' and 'approval_owned_cwd_constructor_error' in ast.unparse(node)]
    assert len(handlers) == 1
    function = ast.parse('def handler(error, emit, token, registration):\n    pass').body[0]
    function.body = handlers[0].body
    namespace = {'hashlib': hashlib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), '<diagnostic-control>', 'exec'), namespace)
    records = []
    try:
        exec(compile('raise ValueError("PRIVATE-BODY-CANARY")', 'PRIVATE-PATH-CANARY', 'exec'))
    except ValueError as original:
        with pytest.raises(ValueError) as caught:
            namespace['handler'](original, records.append, 'actual-token', {'class': 'source-approval-relay'})
        assert caught.value is original
    body = json.dumps(records)
    assert 'PRIVATE-BODY-CANARY' not in body and 'PRIVATE-PATH-CANARY' not in body
    assert records[0]['error_class'] == 'ValueError' and records[0]['errno'] is None
    assert records[0]['frames']


def orphan_owner(monkeypatch):
    from types import SimpleNamespace
    import approval_orphan_custody as custody
    import hashlib
    birth = {'pid': 54, 'ppid': 49, 'pgid': 49, 'sid': 49, 'uid': 20000,
             'start_ticks': 28529, 'boot_id': 'original', 'clock_ticks_per_second': 100}
    parent = {**birth, 'pid': 49, 'ppid': 22, 'start_ticks': 27655}
    case = custody.DURABLE_PREFIX + '[crash]'
    events = [{'kind': 'registered', 'pid': 54, 'owner_pid': 49,
               'class': 'source-approval-adapter', 'case': case, 'token': 'owned'},
              {'kind': 'ready', 'owner_pid': 54, 'token': 'owned'},
              {'kind': 'registered', 'pid': 49, 'class': 'source-run-worker', 'case': case}]
    rows = [{'kind': 'tracer_terminal_wait', 'pid': 49, 'raw': 9, 'normalized': -9,
             'identity': {key: value for key, value in
                          {**parent, 'pgid': 9, 'sid': 9, 'uids': [20000] * 4}.items()
                          if key != 'uid'}},
            {'kind': 'kernel_exit', 'pid': 49, 'raw': 9}]
    pin = hashlib.sha256(b'original source').hexdigest()
    monkeypatch.setattr(custody, 'PINS', {'original.py': pin})
    monkeypatch.setattr(custody.Path, 'read_bytes', lambda self: b'original source')
    owner = SimpleNamespace(events=lambda: events,
                            registered={54: {'identity': birth, 'token': 'owned'},
                                        49: {'identity': parent, 'token': 'parent'}},
                            owned_trace=SimpleNamespace(records=rows),
                            manifest={'product_pins': {'original.py': pin}})
    return custody, owner, birth, {**birth, 'ppid': custody.os.getpid()}, events, rows


def test_reparenting_proof_retains_original_birth_and_actual_parent_status(monkeypatch):
    custody, owner, birth, current, events, rows = orphan_owner(monkeypatch)
    result = custody.proof(owner, 54, birth, current, 'payload')
    assert result['original_birth'] == birth and result['current_identity'] == current
    assert result['parent_terminal'] is rows[0] and result['parent_kernel_exit'] is rows[1]
    assert result['new_effect_authority'] is False
    assert owner.registered[54]['identity'] == birth
    assert custody.proof(owner, 54, birth, birth, 'payload') is None


@pytest.mark.parametrize('drift', ['birth', 'uid', 'group', 'parent', 'case', 'class',
                                 'ready', 'token', 'pin', 'missing_exit', 'missing_wait',
                                 'status', 'normal_exit', 'parent_birth', 'duplicate',
                                 'connect', 'listen', 'pair', 'ready_method', 'plan'])
def test_unknown_or_new_effects_never_gain_reparented_cleanup(monkeypatch, drift):
    custody, owner, birth, current, events, rows = orphan_owner(monkeypatch)
    method = 'payload'
    if drift in ('birth', 'uid', 'group', 'parent'):
        key = {'birth': 'start_ticks', 'uid': 'uid', 'group': 'pgid', 'parent': 'ppid'}[drift]
        current[key] = -1
    elif drift in ('case', 'class', 'token'):
        events[0][drift] = 'foreign'
    elif drift == 'ready':
        events.pop(1)
    elif drift == 'pin':
        owner.manifest['product_pins']['original.py'] = 'foreign'
    elif drift == 'missing_exit':
        rows.pop(1)
    elif drift == 'missing_wait':
        rows.pop(0)
    elif drift == 'status':
        rows[1]['raw'] = 15
    elif drift == 'normal_exit':
        rows[0].update(raw=0, normalized=0)
        rows[1]['raw'] = 0
    elif drift == 'parent_birth':
        rows[0]['identity']['start_ticks'] = -1
    elif drift == 'duplicate':
        rows.append(dict(rows[0]))
    else:
        method = {'ready_method': 'ready', 'pair': 'pair'}.get(drift, drift)
    assert custody.proof(owner, 54, birth, current, method) is None


def test_reparented_ledger_still_runs_original_peer_nonce_token_and_replay_checks(monkeypatch):
    from types import SimpleNamespace
    import socket
    custody, owner, birth, current, events, rows = orphan_owner(monkeypatch)
    ledger = custody.ApprovalLedger('a' * 64, 20000)
    ledger.supervisor = owner
    ledger.registered[54] = ('b' * 32, birth)
    monkeypatch.setattr(custody.receipts._identity, 'identity', lambda pid: current)
    monkeypatch.setattr(socket, 'SO_PEERCRED', 17, raising=False)
    stream = SimpleNamespace(family=socket.AF_UNIX,
                             getsockopt=lambda *args: custody.receipts.struct.pack('3i', 54, 20000, 20000))
    request = {'pid': 54, 'identity': birth, 'token': 'b' * 32,
               'nonce': 'a' * 64, 'id': 'c' * 32, 'kind': 'payload'}
    result = ledger.admit(stream, request)
    assert result['birth'] == birth and result['reparented_cleanup']['current_identity'] == current
    assert ledger.registered[54][1] == birth and request['identity'] == birth
    with pytest.raises(custody.receipts.ReceiptRefused, match='replay'):
        ledger.admit(stream, request)


@pytest.mark.parametrize('field', ['nonce', 'token', 'pid', 'identity', 'id'])
def test_reparenting_does_not_bypass_original_receipt_identity_checks(monkeypatch, field):
    from types import SimpleNamespace
    import socket
    custody, owner, birth, current, events, rows = orphan_owner(monkeypatch)
    ledger = custody.ApprovalLedger('a' * 64, 20000)
    ledger.supervisor = owner
    ledger.registered[54] = ('b' * 32, birth)
    monkeypatch.setattr(custody.receipts._identity, 'identity', lambda pid: current)
    monkeypatch.setattr(socket, 'SO_PEERCRED', 17, raising=False)
    stream = SimpleNamespace(family=socket.AF_UNIX,
                             getsockopt=lambda *args: custody.receipts.struct.pack('3i', 54, 20000, 20000))
    request = {'pid': 54, 'identity': birth, 'token': 'b' * 32,
               'nonce': 'a' * 64, 'id': 'c' * 32, 'kind': 'payload'}
    request[field] = {'pid': 55, 'identity': {**birth, 'start_ticks': -1}}.get(field, 'foreign')
    with pytest.raises(custody.receipts.ReceiptRefused):
        ledger.admit(stream, request)
    assert ledger.poison and not ledger.seen and ledger.registered[54][1] == birth


def test_orphan_supervisor_delegates_actual_snapshot_without_mutating_birth(monkeypatch):
    custody, owner, birth, current, events, rows = orphan_owner(monkeypatch)
    supervisor = custody.ApprovalSupervisor.__new__(custody.ApprovalSupervisor)
    supervisor.__dict__.update(vars(owner))
    calls = []
    monkeypatch.setattr(custody.kernel, 'identity', lambda pid: current)
    monkeypatch.setattr(custody.Supervisor, 'authenticate',
                        lambda owner, request, events: calls.append((owner, request, events)) or 'checked')
    request = {'pid': 54, 'identity': birth, 'kind': 'payload'}
    assert supervisor.authenticate(request, events) == 'checked'
    selected, delegated, actual_events = calls[0]
    assert selected.registered[54]['identity'] == current and delegated['identity'] == current
    assert actual_events is events and supervisor.registered[54]['identity'] == birth
    assert request['identity'] == birth


def exit_observer():
    from types import SimpleNamespace
    from approval_exit_observation import CASES
    case = sorted(CASES)[0]
    authority = SimpleNamespace(
        bound={54: {'registration': {'class': 'source-approval-adapter'}}}, pipe_records=[],
        supervisor=SimpleNamespace(events=lambda: [
            {'kind': 'registered', 'pid': 54, 'case': case}]))
    trace = SimpleNamespace(records=[{'kind': 'kernel_exit', 'pid': 54, 'raw': 15},
                                    {'kind': 'tracer_terminal_wait', 'pid': 54, 'raw': 15}])
    return authority, trace


def test_exit_observation_separates_kernel_exit_from_actual_numeric_wait(monkeypatch):
    import approval_exit_observation as observation
    authority, trace = exit_observer()
    monkeypatch.setattr(observation, 'snapshot', lambda pid: {'pid': pid, 'ppid': 1})
    monkeypatch.setattr(observation, 'process_absent', lambda pid: True)
    original = [dict(row) for row in trace.records]
    observation.collect(authority, trace)
    assert trace.records == original
    before, after = authority.pipe_records
    assert before['numeric_wait_observed'] is False and before['current_identity']['ppid'] == 1
    assert after['numeric_wait_observed'] is True and after['raw'] == 15
    assert after['process_absent_after_actual_wait'] is True
    assert all(row['eligible_certificate'] is False for row in authority.pipe_records)
    observation.collect(authority, trace)
    assert len(authority.pipe_records) == 2


def test_absent_process_does_not_fabricate_a_wait_or_remove_trace_failure(monkeypatch):
    import approval_exit_observation as observation
    authority, trace = exit_observer()
    trace.records.pop()
    def missing(pid):
        raise FileNotFoundError('private message')
    monkeypatch.setattr(observation, 'snapshot', missing)
    observation.collect(authority, trace)
    assert len(authority.pipe_records) == 1
    record = authority.pipe_records[0]
    assert record['numeric_wait_observed'] is False
    assert record['unavailable'] == 'FileNotFoundError' and 'private message' not in str(record)
    assert 'current_identity' not in record and 'process_absent_after_actual_wait' not in record


def test_foreign_or_unregistered_exit_has_no_controlled_proof(monkeypatch):
    import approval_exit_observation as observation
    authority, trace = exit_observer()
    authority.bound[54]['registration']['class'] = 'foreign'
    observation.collect(authority, trace)
    assert authority.pipe_records == []
    trace.records.clear()
    with pytest.raises(RuntimeError, match='trace_rewound'):
        observation.collect(authority, trace)



def worker_setup_context():
    from finite import approval_worker_setup as setup
    import os
    vector = ['/source/.venv/bin/python', '-m', setup.MODULE,
              '--project-root', '/work/owned/run-home', '--run-id', 'run-original',
              '--executor', setup.EXECUTOR, '--custody-root-id', 'owned-original', '--generation', '1']
    state = {'class': 'source-run-worker', 'source_selection': 'primary-source',
             'setup_mode': 'source', 'phase': 'READY', 'case': sorted(setup.CASES)[0],
             'token': 'owned', 'runtime': {'paths': [vector[0]]}, 'owned_root': '/work/owned'}
    endpoint = {'token': 'owned', 'identity': {'pid': os.getpid()}}
    payload = {'class': state['class'], 'mode': 'module', 'target': setup.MODULE,
               'case': state['case'], 'token': 'owned', 'source_binding': dict(setup.BINDING),
               'orig_argv': vector, 'sys_argv': [setup.MODULE, *vector[3:]],
               'path0': vector[4], 'isolated': False}
    return setup, state, endpoint, payload


def test_only_exact_controlled_worker_delegates_sdk_setup_to_actual_mcp_child():
    setup, state, endpoint, payload = worker_setup_context()
    for case in setup.CASES:
        state['case'] = payload['case'] = case
        assert setup.eligible(state, endpoint, payload)
    assert setup.select(type('Guard', (), {'_STATE': state})(), endpoint) is None


@pytest.mark.parametrize('drift', ['class', 'selection', 'case', 'phase', 'mode', 'target',
                                 'token', 'endpoint_token', 'peer', 'binding', 'runtime',
                                 'executor', 'flags', 'generation', 'sys_argv', 'cwd',
                                 'isolated', 'profile-timing', 'dependency-source-negative',
                                 'dependency-launch-negative'])
def test_other_workers_or_changed_entry_keep_original_sdk_setup(drift):
    setup, state, endpoint, payload = worker_setup_context()
    if drift == 'class':
        state['class'] = payload['class'] = 'source-approval-mcp'
    elif drift == 'selection':
        state['source_selection'] = 'foreign'
    elif drift in ('case', 'phase'):
        state[drift] = 'foreign'
    elif drift in ('mode', 'target', 'token', 'sys_argv', 'isolated'):
        payload[drift] = 'foreign'
    elif drift == 'endpoint_token':
        endpoint['token'] = 'foreign'
    elif drift == 'peer':
        endpoint['identity']['pid'] += 1
    elif drift == 'binding':
        payload['source_binding']['sha256'] = 'foreign'
    elif drift == 'runtime':
        payload['orig_argv'][0] = '/foreign/python'
    elif drift == 'executor':
        payload['orig_argv'][8] = 'foreign:execute'
    elif drift == 'flags':
        payload['orig_argv'][7] = '--foreign'
    elif drift == 'generation':
        payload['orig_argv'][12] = '0'
    elif drift == 'cwd':
        payload['orig_argv'][4] = payload['path0'] = '/foreign'
        payload['sys_argv'] = [setup.MODULE, *payload['orig_argv'][3:]]
    else:
        state['setup_mode'] = drift
    assert not setup.eligible(state, endpoint, payload)


def test_exact_worker_configuration_matches_original_helper_without_launch(tmp_path, monkeypatch):
    from types import SimpleNamespace
    root = Path(__file__).parent.parent.parent
    if not (root / 'tests/fixtures/approval_run_executor.py').is_file():
        pytest.skip('product source is exercised by the real controlled worker lane')
    monkeypatch.syspath_prepend(str(root))
    import tests.fixtures.approval_run_executor as executor
    from tests.test_provider_review import config_at
    actual = []
    class StopBeforeEffects(Exception):
        pass
    def capture(config):
        actual.append(config)
        raise StopBeforeEffects()
    monkeypatch.setattr(executor, 'ProjectStore', capture)
    monkeypatch.setenv('CONTROLLED_RUN_ROOT', str(tmp_path))
    context = SimpleNamespace(run_id='run', control=SimpleNamespace(
        inspect_run=lambda run_id: SimpleNamespace(state='running')))
    with pytest.raises(StopBeforeEffects):
        executor.execute('advance_project', {}, context)
    assert len(actual) == 1 and actual[0] == config_at(tmp_path)


def test_type_only_transition_keeps_every_other_runtime_statement_and_line(monkeypatch):
    import hashlib
    import json
    import approval_import_source_inputs as transition
    before = 'from typing import Any\nfrom fastmcp import Context\n\ndef work(ctx: Context):\n    return True\n'
    after = 'from typing import TYPE_CHECKING, Any\n# type-only context\n\ndef work(ctx: Context):\n    return True\n\nif TYPE_CHECKING:\n    from fastmcp import Context\n'
    tree = ast.parse(before)
    monkeypatch.setattr(transition, 'SOURCE_AST', hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest())
    lines = [(type(node).__name__,node.name,node.lineno) for node in ast.walk(tree)
             if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))]
    monkeypatch.setattr(transition, 'DEFINITION_LINES',hashlib.sha256(json.dumps(lines).encode()).hexdigest())
    transition.verify_source(after)
    for changed in (after.replace('return True','return False'),
                    after.replace('TYPE_CHECKING, Any','TYPE_CHECKING as other, Any'),
                    after.replace('def work','\ndef work')):
        with pytest.raises(RuntimeError):
            transition.verify_source(changed)


def test_fixture_transition_does_not_change_assertions_or_executor_behavior(monkeypatch):
    import hashlib
    import approval_import_source_inputs as transition
    before = 'from tests.test_provider_review import config_at\ndef execute(root):\n    assert root\n    store = ProjectStore(config_at(root))\n    return store\n'
    after = 'from unrest_harness.config import HarnessConfig\ndef execute(root):\n    assert root\n    store = ProjectStore(HarnessConfig(root=root))\n    return store\n'
    monkeypatch.setattr(transition,'FIXTURE_AST',hashlib.sha256(ast.dump(ast.parse(before),include_attributes=False).encode()).hexdigest())
    monkeypatch.setattr(transition,'CONSTRUCTOR',ast.dump(ast.parse('HarnessConfig(root=root)',mode='eval').body,include_attributes=False))
    transition.verify_fixture(after)
    for changed in (after.replace('assert root','assert True'),
                    after.replace('root=root','root=None'),
                    after.replace('return store','return None')):
        with pytest.raises(RuntimeError):
            transition.verify_fixture(changed)


def test_transition_refuses_wrong_preimage_before_read_or_partial_mutation():
    from copy import deepcopy
    import approval_import_source_inputs as transition
    manifest = {'product_pins':dict(transition.PRE),'anchor_inventory':[]}
    manifest['product_pins']['src/unrest_harness/approval_recovery.py']='foreign'
    before=deepcopy(manifest)
    with pytest.raises(RuntimeError,match='preimage'):
        transition.admit(manifest,None,lambda *args:pytest.fail('source must not be read'))
    assert manifest==before


def test_orphan_install_composes_existing_instance_ready_hook(monkeypatch):
    from types import MethodType
    custody, source, birth, current, events, rows = orphan_owner(monkeypatch)
    owner = custody.JournalSupervisor.__new__(custody.JournalSupervisor)
    owner.__dict__.update(vars(source))
    owner.ledger = custody.receipts.ReceiptLedger('a' * 64, 20000)
    ordinary = []
    def ready_snapshot(actual, request, events):
        assert actual is owner
        ordinary.append(request)
        return 'original READY wrapper'
    owner.authenticate = MethodType(ready_snapshot, owner)
    custody.install(owner)
    monkeypatch.setattr(custody.kernel, 'identity', lambda pid: current)
    authenticated = []
    monkeypatch.setattr(custody.Supervisor, 'authenticate', lambda actual, request, events:
                        authenticated.append((actual,request,events)) or 'actual original authentication')
    request = {'pid':54,'identity':birth,'kind':'payload'}
    assert owner.authenticate(request, events) == 'actual original authentication'
    assert ordinary == [] and authenticated[0][1]['identity'] == current
    assert owner.registered[54]['identity'] == birth and request['identity'] == birth
    assert owner.authenticate({**request,'kind':'connect'}, events) == 'original READY wrapper'
    assert len(ordinary) == 1
    monkeypatch.setattr(custody.kernel, 'identity', lambda pid: birth)
    assert owner.authenticate(request, events) == 'original READY wrapper'
    assert len(ordinary) == 2


def adoptive_context(monkeypatch):
    from types import SimpleNamespace
    import approval_adoptive_reap as adoption
    birth = {'pid':54,'ppid':49,'uid':20000,'start_ticks':10}
    current = {**birth,'ppid':adoption.os.getpid()}
    authority = SimpleNamespace(bound={54:{'registration':{'class':'source-approval-adapter'}}},
                                pipe_records=[],supervisor=SimpleNamespace(
                                    registered={54:{'identity':birth,'token':'owned'}}))
    trace = SimpleNamespace(active=set(), records=[
        {'kind':'tracer_terminal_wait','pid':49,'raw':9,'normalized':-9},
        {'kind':'tracer_terminal_wait','pid':54,'raw':256,'normalized':1}])
    monkeypatch.setattr(adoption,'identity',lambda pid:current)
    monkeypatch.setattr(adoption,'proof',lambda *args:{'case':'exact controlled case'})
    monkeypatch.setattr(adoption,'zombie',lambda pid:True)
    calls=[]
    monkeypatch.setattr(adoption.os,'waitpid',lambda pid,flags:calls.append((pid,flags)) or (pid,256))
    return adoption,authority,trace,birth,current,calls


def test_adoptive_cleanup_records_only_a_real_matching_nonblocking_parent_wait(monkeypatch):
    adoption,authority,trace,birth,current,calls=adoptive_context(monkeypatch)
    original=[dict(row) for row in trace.records]
    adoption.reap(authority,trace)
    assert calls==[(54,adoption.os.WNOHANG)] and trace.records==original
    record=authority.pipe_records[0]
    assert record['pid']==54 and record['raw']==256 and record['normalized']==1
    assert record['original_birth']==birth and record['current_identity']==current
    assert record['source_checkpoint_ready'] is False
    adoption.reap(authority,trace)
    assert len(calls)==1 and len(authority.pipe_records)==1


@pytest.mark.parametrize('drift',['original_parent_alive','active','missing_parent_terminal',
                                 'foreign_class','birth_proof','not_zombie','pending_wait'])
def test_unproved_or_still_owned_children_gain_no_adoptive_wait(monkeypatch,drift):
    adoption,authority,trace,birth,current,calls=adoptive_context(monkeypatch)
    if drift=='original_parent_alive':
        current['ppid']=49
    elif drift=='active':
        trace.active.add(54)
    elif drift=='missing_parent_terminal':
        trace.records.pop(0)
    elif drift=='foreign_class':
        authority.bound[54]['registration']['class']='foreign'
    elif drift=='birth_proof':
        monkeypatch.setattr(adoption,'proof',lambda *args:None)
    elif drift=='not_zombie':
        monkeypatch.setattr(adoption,'zombie',lambda pid:False)
    else:
        monkeypatch.setattr(adoption.os,'waitpid',lambda pid,flags:calls.append((pid,flags)) or (0,0))
    adoption.reap(authority,trace)
    assert authority.pipe_records==[]
    assert calls==([] if drift!='pending_wait' else [(54,adoption.os.WNOHANG)])


def test_adoptive_wait_status_drift_remains_a_recorded_failure(monkeypatch):
    adoption,authority,trace,birth,current,calls=adoptive_context(monkeypatch)
    monkeypatch.setattr(adoption.os,'waitpid',lambda pid,flags:(pid,9))
    with pytest.raises(RuntimeError,match='actual_wait_status_drift'):
        adoption.reap(authority,trace)
    assert authority.pipe_records[0]['raw']==9
    assert authority.pipe_records[0]['source_checkpoint_ready'] is False


def test_appended_regression_updates_only_exact_existing_anchor_file_pin():
    from copy import deepcopy
    import approval_import_source_inputs as transition
    row=deepcopy(transition.TEST_ANCHOR)
    manifest={'anchor_inventory':[row]}
    transition.admit_test_anchor(manifest)
    assert row == {**transition.TEST_ANCHOR, 'source_sha256':transition.POST[row['path']], 'line':734}
    for key,value in [('line',731),('route','subprocess.Popen'),('owner','another'),
                      ('expression_ast_sha256','0'*64),('source_sha256','0'*64)]:
        changed=deepcopy(transition.TEST_ANCHOR)
        changed[key]=value
        with pytest.raises(RuntimeError,match='original_anchor_drift'):
            transition.admit_test_anchor({'anchor_inventory':[changed]})


def test_cleanup_diagnostic_is_passive_bounded_and_composes_prior_observer():
    from types import SimpleNamespace
    from finite.approval_cleanup_diagnostic import install
    rows, prior = [], []
    guard=SimpleNamespace(_STATE={'primary_snapshot_observer':lambda *args:prior.append(args)},append=rows.append)
    observe=install(guard)
    def frame(path,name):
        return SimpleNamespace(f_code=SimpleNamespace(co_filename=path,co_name=name),f_lineno=1)
    inactive=frame('/source/src/unrest_harness/run_worker.py','other')
    observe(inactive,'call',None)
    assert not rows and len(prior)==1
    selected=frame('/source/src/unrest_harness/run_worker.py','_cancel')
    observe(selected,'call',None)
    observe(selected,'call',None)
    assert len(rows)==1 and rows[0]['eligible_certificate'] is False
    assert rows[0]['trigger']==['/source/src/unrest_harness/run_worker.py','_cancel',1]
    for index in range(40):
        observe(frame('/synthetic/'+str(index),'close'),'call',None)
    assert len(rows)==16
    assert all(set(r)=={'kind','trigger','threads','tasks','diagnostic_only','eligible_certificate'} for r in rows)


def test_pending_adoption_retries_kernel_parenthood_without_fabricated_trace_progress(monkeypatch):
    adoption,authority,trace,birth,current,calls=adoptive_context(monkeypatch)
    now=[0.0]
    monkeypatch.setattr(adoption.time,'monotonic',lambda:now[0])
    current['ppid']=49
    adoption.reap(authority,trace)
    assert calls==[]
    original=[dict(row) for row in trace.records]
    current['ppid']=adoption.os.getpid()
    now[0]=0.01
    adoption.reap(authority,trace)
    assert calls==[]
    now[0]=0.03
    adoption.reap(authority,trace)
    assert calls==[(54,adoption.os.WNOHANG)] and trace.records==original
    adoption.reap(authority,trace)
    assert len(calls)==1


def test_pre_wait_observation_preserves_the_entire_original_tracer_algorithm():
    import hashlib
    from test_startup_phases import restore_before_numeric_wait
    original=restore_before_numeric_wait(ast.parse((Path(__file__).parent/'linux_trace.py').read_bytes()))
    assert hashlib.sha256(ast.dump(original,include_attributes=False).encode()).hexdigest()=='207f3b1427331f5f71829aeb61b3c6e86deb1df08776d03d85fafef012c16035'


def test_pre_wait_snapshot_is_bound_to_known_exited_controlled_child(monkeypatch):
    from types import SimpleNamespace
    import approval_exit_observation as observation
    case=next(iter(observation.CASES))
    rows=[{'kind':'registered','pid':54,'case':case}]
    current={'pid':54,'ppid':1,'uids':[20000]*4}
    authority=SimpleNamespace(_approval_exited={54},bound={54:{'registration':{'class':'source-approval-adapter'}}},
                              supervisor=SimpleNamespace(events=lambda:rows))
    trace=SimpleNamespace(records=[{'kind':'observed'}])
    monkeypatch.setattr(observation,'snapshot',lambda pid:dict(current))
    observation.before_wait(authority,trace,54)
    assert authority._approval_pre_wait[54]=={'identity':current,'trace_record_count':1}
    current['ppid']=49
    observation.before_wait(authority,trace,54)
    assert authority._approval_pre_wait[54]['identity']['ppid']==49
    observation.before_wait(authority,trace,55)
    assert 55 not in authority._approval_pre_wait


@pytest.mark.parametrize('before,after', [
    ('self.before_numeric_wait(self, candidate)', 'self.before_numeric_wait(self, self.child)'),
    ('self.before_numeric_wait(self, candidate)', 'self.before_numeric_wait(self, candidate); self.active.clear()'),
    ('os.waitpid(candidate, os.WNOHANG | 0x40000000)', 'os.waitpid(candidate, 0)'),
    ("if getattr(self, 'before_numeric_wait', None) is not None:", "if getattr(self, 'before_numeric_wait', None) is None:"),
])
def test_pre_wait_normalization_rejects_callback_or_wait_mutation(before,after):
    from test_startup_phases import restore_before_numeric_wait
    source=(Path(__file__).parent/'linux_trace.py').read_text()
    assert before in source
    with pytest.raises(AssertionError):
        restore_before_numeric_wait(ast.parse(source.replace(before,after)))


def test_expiry_fixture_delta_preserves_all_previous_test_bytes(monkeypatch):
    import hashlib
    import approval_import_source_inputs as transition
    before = (b'async def install_pending(owner):\n' + transition.SETTLEMENT_BEFORE
              + b'    assert owner.event is None\n'
              + b'    deadline=time.monotonic() + 0.2\n')
    body = before.replace(transition.SETTLEMENT_BEFORE, transition.SETTLEMENT_AFTER)
    pin = hashlib.sha256(before).hexdigest()
    monkeypatch.setattr(transition, 'TEST_BASE_SIZE', len(before))
    monkeypatch.setattr(transition, 'TEST_BASE_SHA256', pin)
    monkeypatch.setattr(transition, 'PRE', {'tests/test_approval_recovery.py': pin})
    transition.verify_test(body)
    for changed in (body.replace(b'owner.remaining()', b'30', 1),
                    body.replace(b'assert owner.event is None', b'assert True', 1),
                    body.replace(b'deadline=time.monotonic() + 0.2',
                                 b'deadline=time.monotonic() + 20', 1),
                    body.replace(transition.SETTLEMENT_AFTER,
                                 transition.SETTLEMENT_AFTER + b'    pass\n', 1)):
        with pytest.raises(RuntimeError):
            transition.verify_test(changed)


def test_real_expiry_stall_probe_keeps_source_deadline_and_exact_diagnostic_scope():
    from finite.approval_stall_diagnostic import case_seconds
    from primary_policy import TEST_APPROVAL_REMAINING_CASES
    profile = {'source_mode': 'TEST-positive',
               'orig_argv': ['python', 'pytest', '-q', *TEST_APPROVAL_REMAINING_CASES]}
    case = 'tests/test_approval_recovery.py::test_real_deadline_timer_erases_memory_and_cleans_reader'
    assert case_seconds(profile, case) == 20
    assert case_seconds({**profile, 'source_mode': 'SOURCE'}, case) is None
    assert case_seconds({**profile, 'orig_argv': profile['orig_argv'][:-1]}, case) is None
    assert case_seconds(profile, case + '-foreign') is None


def test_approval_preparer_binds_current_helper_before_exec():
    import hashlib
    folder = Path(__file__).parent
    source = folder.joinpath('prepare_source.py').read_bytes()
    function = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'admit_approval_imports')
    body = folder.joinpath('approval_import_source_inputs.py').read_bytes()
    namespace = {'CLOCK_READER': lambda *args: body, 'Path': Path,
                 'ROOT': Path('/source'), 'hashlib': hashlib}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '/guard/prepare_source.py', 'exec'), namespace)
    with pytest.raises(RuntimeError, match='approval_import_preimage'):
        namespace['admit_approval_imports']({'product_pins': {}, 'anchor_inventory': []})
    namespace['CLOCK_READER'] = lambda *args: body + b'\n'
    with pytest.raises(RuntimeError, match='approval_import_support_drift'):
        namespace['admit_approval_imports']({'product_pins': {}, 'anchor_inventory': []})
