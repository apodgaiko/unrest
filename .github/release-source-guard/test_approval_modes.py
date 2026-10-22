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
