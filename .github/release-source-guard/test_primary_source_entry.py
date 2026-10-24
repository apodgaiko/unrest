"""SOURCE entry policy boundaries; hosted probes exercise the actual bridge."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from ci_commands import REGISTRY
from checkpoint_receipt import COMMAND, DEFINITION_FIELDS
from primary_policy import SOURCE, SOURCE_BUDGET, TEST_CASE, plan, public_plan, sha
from primary_source_inputs import test_plan as make_test_plan
from primary_source_inputs import require_full_input
from primary_source_inputs import python_flags
from test_ci_commands import workflow


def inputs():
    registry = json.loads(REGISTRY.read_bytes())
    text = workflow(registry)
    definition = {name: 'a' * (40 if name in {'head_sha', 'source_tree'} else 64)
                  for name in DEFINITION_FIELDS}
    definition.update(workflow_sha256=sha(text.encode()), source_command_sha256=sha(COMMAND.encode()))
    return text, {'schema': 'unrest.v046.primary-source-input.v1', 'definition': definition,
                  'source_carrier_sha256': 'b' * 64, 'selected_carrier': 'b' * 64,
                  'package_closure_sha256': 'c' * 64, 'final_closure_sha256': 'd' * 64,
                  'source_checkpoint_ready': True}


def test_source_command_stays_literal_and_has_separate_finite_budgets():
    text, value = inputs()
    result = plan(COMMAND.encode(), text, value)
    assert result['duty'] == SOURCE
    assert result['commands'] == [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']]
    assert result['timeout_seconds'] == SOURCE_BUDGET['root_seconds'] > 180
    assert result['source_budget'] == {'root_seconds': 7200, 'collection_seconds': 300, 'drain_seconds': 60}
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert public_plan(result)['command_count'] == 1


@pytest.mark.parametrize('field', ['source_carrier_sha256', 'package_closure_sha256',
                                   'final_closure_sha256', 'selected_carrier', 'definition'])
def test_partial_readiness_never_activates_whole_source(field):
    text, value = inputs()
    value.pop(field)
    with pytest.raises(RuntimeError):
        plan(COMMAND.encode(), text, value)


def test_no_readiness_or_filtered_full_script_can_activate_source():
    text, value = inputs()
    with pytest.raises(RuntimeError):
        plan(COMMAND.encode(), text)
    with pytest.raises(RuntimeError):
        plan((COMMAND + ' tests/test_server.py').encode(), text, value)
    for change in ({'source_checkpoint_ready': False}, {'selected_carrier': None},
                   {'definition': {**value['definition'], 'workflow_sha256': '0' * 64}}):
        with pytest.raises(RuntimeError):
            require_full_input({**value, **change}, COMMAND.encode(), text)


def test_test_identity_never_becomes_original_source_duty():
    text, value = inputs()
    script = (COMMAND + ' ' + TEST_CASE).encode()
    for mode in ('TEST-positive', 'TEST-poison'):
        result = make_test_plan(script, text, mode)
        assert result['duty'] != SOURCE and result['source_mode'] == mode
        assert result['source_checkpoint_ready'] is False and result['timeout_seconds'] == 180
        public_plan(result)
        with pytest.raises(RuntimeError):
            plan(script, text, value)
    with pytest.raises(RuntimeError):
        make_test_plan(COMMAND.encode(), text, 'TEST-positive')
    with pytest.raises(RuntimeError):
        make_test_plan(script, text, 'SOURCE')


def test_source_bootstrap_profiles_preserve_isolated_and_no_site_flags():
    assert python_flags(['/python', '-I', '-S', '-c', 'body'], {}) == [1, 1, 0]
    assert python_flags(['/python', '-B', '-c', 'body'], {}) == [0, 0, 1]
    assert python_flags(['/python', '-c', 'body'], {'PYTHONDONTWRITEBYTECODE': '1'}) == [0, 0, 1]
    with pytest.raises(RuntimeError):
        python_flags(['/python', '-X', '-c', 'body'], {})


def test_input_binding_is_not_satisfied_by_a_foreign_script_or_workflow():
    text, value = inputs()
    for script, workflow_text in ((COMMAND.encode() + b' -x', text), (COMMAND.encode(), text + '\n')):
        with pytest.raises(RuntimeError):
            require_full_input(copy.deepcopy(value), script, workflow_text)


def test_source_temp_root_and_env_addition_do_not_broaden_focused_policy():
    from primary_policy import environment, command_environment
    root = environment(source=True)
    assert root['TMPDIR'] == '/work/owned/tmp'
    assert environment()['TMPDIR'] == '/work/tmp'
    value = {**root, 'PWD': '/source', 'SHLVL': '1', '_': '/usr/bin/env'}
    assert command_environment(value, root, source=True)
    assert not command_environment(value, root)
    for change in ({'_': '/foreign/env'}, {'OPENAI_API_KEY': 'forbidden'}, {'PYTHONPATH': '/foreign'}):
        assert not command_environment({**value, **change}, root, source=True)


def test_affected_seams_are_one_closed_original_parameter_tuple():
    from primary_policy import TEST_SEAM_CASES
    text, value = inputs()
    script = (COMMAND + ' ' + ' '.join(TEST_SEAM_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['commands'][0][7:] == list(TEST_SEAM_CASES)
    assert result['source_checkpoint_ready'] is False
    assert result['selected_carrier'] is None
    public_plan(result)
    for selection in (TEST_SEAM_CASES[:1], TEST_SEAM_CASES[::-1],
                      (*TEST_SEAM_CASES, '-k', 'installed'),
                      (*TEST_SEAM_CASES, 'tests/test_server.py')):
        with pytest.raises(RuntimeError, match='primary_source_test_script'):
            make_test_plan((COMMAND + ' ' + ' '.join(selection)).encode(), text, 'TEST-positive')
    with pytest.raises(RuntimeError):
        plan(script, text, value)


@pytest.mark.parametrize('change', ['valid', 'unknown', 'stale', 'extra', 'write', 'uid'])
def test_owned_role_inventory_pipe_requires_exact_source_and_kernel_identity(monkeypatch, change):
    from types import SimpleNamespace
    import os
    import stat
    import primary_source_authority as authority
    binding = {'path': '/source/src/unrest_harness/acp_runner.py', 'sha256': 'a' * 64}
    registration = {'class': 'source-owned-role:worker', 'source_binding': binding,
                    'argv_sha256': 'b' * 64}
    event = {'kind': 'concrete_owned_role_registration', 'owner_pid': 10, 'role': 'worker',
             'source_binding': binding, 'argv_sha256': 'b' * 64, 'pipe_device': 2, 'pipe_inode': 3}
    rows = [dict(event), dict(event)]
    flags = os.O_RDONLY
    info = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_uid=20000, st_dev=2, st_ino=3)
    if change == 'unknown':
        registration['class'] = 'other'
    elif change == 'stale':
        rows[0]['pipe_inode'] = 4
    elif change == 'write':
        flags = os.O_WRONLY
    elif change == 'uid':
        info.st_uid = 20001

    instance = object.__new__(authority.SourceAuthority)
    instance.bound = {11: {'registration': registration}}
    instance.pipe_records = []
    instance.supervisor = SimpleNamespace(events=lambda: rows)
    row = {'fd': 7, 'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
           'uid': info.st_uid, 'access': flags & os.O_ACCMODE, 'close_on_exec': False}
    monkeypatch.setattr(instance, 'census', lambda pid: [row, row] if change == 'extra' else [row])
    monkeypatch.setattr(authority, 'identity', lambda pid: {'ppid': 10})
    if change == 'valid':
        assert instance.descriptors(11) == [{'fd': 7, 'device': 2, 'inode': 3,
                                              'mode': info.st_mode, 'uid': 20000, 'access': os.O_RDONLY}]
    elif change == 'unknown':
        assert instance.descriptors(11) == []
    else:
        with pytest.raises(RuntimeError, match='primary_source_role_pipe_'):
            instance.descriptors(11)


def test_exact_startup_diagnosis_is_bounded_and_cannot_certify_full():
    from primary_policy import TEST_STARTUP_CASES, root_seconds
    text, value = inputs()
    assert len(TEST_STARTUP_CASES) == 9 and len(set(TEST_STARTUP_CASES)) == 9
    assert all('test_startup_failure_attribution_and_owned_cleanup[' in case
               for case in TEST_STARTUP_CASES)
    script = (COMMAND + ' ' + ' '.join(TEST_STARTUP_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert result['duty'] == 'TEST-source-positive'
    assert root_seconds(result) == result['timeout_seconds'] == 180
    with pytest.raises(RuntimeError):
        plan(script, text, value)
    with pytest.raises(RuntimeError):
        make_test_plan(script + b' --maxfail=1', text, 'TEST-positive')
    with pytest.raises(RuntimeError):
        make_test_plan((COMMAND + ' ' + ' '.join(TEST_STARTUP_CASES[:-1])).encode(), text, 'TEST-positive')


def test_diagnostic_workflow_leaves_primary_release_workflow_unchanged():
    import yaml
    from primary_policy import TEST_RELEASE_BUILD_PREFLIGHT_CASES
    path = Path(__file__).parent.parent / 'workflows/v046-source-readiness.yml'
    document = yaml.safe_load(path.read_text())
    job = document['jobs']['startup-cancellation-diagnosis']
    ref = 'refs/heads/codex/source-guard-structured-20261018-source-composition-startup-cancel-20261021'
    assert job['if'] == "${{ github.ref == '" + ref + "' }}"
    postimage_ref = 'refs/heads/codex/source-guard-structured-20261018-source-composition-postimages-20261022'
    assert document['jobs']['compartment-controls']['if'] == (
        "${{ github.ref != '" + ref + "' && github.ref != '" + postimage_ref + "' }}")
    steps = job['steps']
    call = next(step for step in steps if step.get('shell'))
    assert call['run'] == COMMAND + ' ' + ' '.join(TEST_RELEASE_BUILD_PREFLIGHT_CASES)
    assert call['shell'] == 'python3 .github/release-source-guard/ci_shell.py --source-test TEST-positive {0}'
    assert steps[-1]['if'] == 'always()'


def test_complete_cleanup_diagnosis_uses_existing_ten_minute_bound_only():
    from primary_policy import TEST_CLEANUP_CASES, root_seconds
    text, value = inputs()
    assert len(TEST_CLEANUP_CASES) == len(set(TEST_CLEANUP_CASES)) == 51
    assert all(case.startswith('tests/test_acp_cleanup.py::') for case in TEST_CLEANUP_CASES)
    script = (COMMAND + ' ' + ' '.join(TEST_CLEANUP_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['timeout_seconds'] == root_seconds(result) == 600
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    with pytest.raises(RuntimeError):
        plan(script, text, value)


def test_exact_readiness_diagnosis_retains_all_original_modes_and_no_full_certificate():
    from primary_policy import TEST_READINESS_CASES, root_seconds
    text, value = inputs()
    prefix = 'tests/test_acp_runner.py::test_readiness_attributes_local_child_and_drains['
    assert TEST_READINESS_CASES == tuple(prefix + mode + ']' for mode in (
        'early_exit', 'never_ready', 'ready', 'cancel'))
    script = (COMMAND + ' ' + ' '.join(TEST_READINESS_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert root_seconds(result) == result['timeout_seconds'] == 180
    with pytest.raises(RuntimeError):
        plan(script, text, value)
    for altered in [script + b' --maxfail=1',
                    (COMMAND + ' ' + ' '.join(TEST_READINESS_CASES[:-1])).encode(),
                    script.replace(b'[never_ready]', b'[foreign]')]:
        with pytest.raises(RuntimeError):
            make_test_plan(altered, text, 'TEST-positive')


def test_exact_inventory_diagnosis_cannot_certify_full_source():
    from primary_policy import TEST_INVENTORY_CASES, root_seconds
    text, value = inputs()
    prefix = 'tests/test_acp_runner.py::test_real_mcp_inventory_fd_redacts_before_crash_and_restart['
    assert TEST_INVENTORY_CASES == tuple(prefix + mode + ']' for mode in ('worker', 'terminal-reviewer'))
    script = (COMMAND + ' ' + ' '.join(TEST_INVENTORY_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert root_seconds(result) == result['timeout_seconds'] == 180
    with pytest.raises(RuntimeError):
        plan(script, text, value)
    for altered in [script + b' --maxfail=1',
                    (COMMAND + ' ' + TEST_INVENTORY_CASES[0]).encode(),
                    script.replace(b'[worker]', b'[foreign]')]:
        with pytest.raises(RuntimeError):
            make_test_plan(altered, text, 'TEST-positive')


def test_exact_stream_diagnosis_keeps_both_original_modes_and_cannot_certify_full():
    from primary_policy import TEST_STREAM_CASES, root_seconds
    text, value = inputs()
    prefix = 'tests/test_acp_runner.py::test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained['
    assert TEST_STREAM_CASES == tuple(prefix + mode + ']' for mode in ('worker', 'terminal-reviewer'))
    script = (COMMAND + ' ' + ' '.join(TEST_STREAM_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert root_seconds(result) == result['timeout_seconds'] == 180
    with pytest.raises(RuntimeError):
        plan(script, text, value)
    for altered in [script + b' --maxfail=1',
                    (COMMAND + ' ' + TEST_STREAM_CASES[0]).encode(),
                    script.replace(b'[worker]', b'[foreign]')]:
        with pytest.raises(RuntimeError):
            make_test_plan(altered, text, 'TEST-positive')


def test_cleanup_success_diagnosis_is_exact_and_keeps_source_deadlines():
    from primary_policy import TEST_CLEANUP_SUCCESS_CASES, root_seconds
    text, value = inputs()
    assert len(TEST_CLEANUP_SUCCESS_CASES) == 4
    assert TEST_CLEANUP_SUCCESS_CASES[0] == 'tests/test_acp_runner.py::test_run_node_with_mock_agent'
    assert TEST_CLEANUP_SUCCESS_CASES[1:] == tuple(
        'tests/test_acp_cleanup.py::test_recorded_transport_failures[success-' + role + ']'
        for role in ('work', 'validate', 'terminal_reviewer'))
    script = (COMMAND + ' ' + ' '.join(TEST_CLEANUP_SUCCESS_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['timeout_seconds'] == root_seconds(result) == 180
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    with pytest.raises(RuntimeError):
        plan(script, text, value)


def test_exact_cleanup_fixture_diagnosis_retains_all_startup_and_inflight_cases():
    from primary_policy import TEST_CLEANUP_FIXTURE_CASES, TEST_STARTUP_CASES, root_seconds
    text, value = inputs()
    assert TEST_CLEANUP_FIXTURE_CASES[:9] == TEST_STARTUP_CASES
    assert TEST_CLEANUP_FIXTURE_CASES[9:] == (
        'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[False]',
        'tests/test_acp_cleanup.py::test_inflight_terminal_registration_before_inventory[True]')
    script = (COMMAND + ' ' + ' '.join(TEST_CLEANUP_FIXTURE_CASES)).encode()
    result = make_test_plan(script, text, 'TEST-positive')
    assert result['timeout_seconds'] == root_seconds(result) == 180
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    with pytest.raises(RuntimeError):
        plan(script, text, value)
    with pytest.raises(RuntimeError):
        make_test_plan(script + b' --maxfail=1', text, 'TEST-positive')
    with pytest.raises(RuntimeError):
        make_test_plan((COMMAND + ' ' + ' '.join(TEST_CLEANUP_FIXTURE_CASES[:-1])).encode(), text, 'TEST-positive')


def test_terminal_order_diagnostic_is_closed_and_never_source_certification():
    from primary_policy import TEST_TERMINAL_ORDER_CASES, root_seconds, SOURCE_BUDGET
    text, value = inputs()
    assert len(TEST_TERMINAL_ORDER_CASES) == len(set(TEST_TERMINAL_ORDER_CASES)) == 18
    script = (COMMAND + ' ' + ' '.join(TEST_TERMINAL_ORDER_CASES)).encode()
    plan = make_test_plan(script, text, 'TEST-positive')
    assert plan['source_checkpoint_ready'] is False and plan['selected_carrier'] is None
    assert plan['source_budget'] == SOURCE_BUDGET
    assert plan['timeout_seconds'] == root_seconds(plan) == 600
    for changed in (TEST_TERMINAL_ORDER_CASES[:-1], (*TEST_TERMINAL_ORDER_CASES,'foreign')):
        with pytest.raises(RuntimeError):
            make_test_plan((COMMAND + ' ' + ' '.join(changed)).encode(),text,'TEST-positive')


def test_completion_pipe_diagnostic_is_exact_and_never_certifies_source():
    from primary_policy import TEST_COMPLETION_PIPE_CASES, root_seconds, SOURCE_BUDGET
    from primary_source_inputs import test_plan as make_test_plan
    assert len(TEST_COMPLETION_PIPE_CASES) == len(set(TEST_COMPLETION_PIPE_CASES)) == 16
    script = (COMMAND + ' ' + ' '.join(TEST_COMPLETION_PIPE_CASES)).encode()
    result = make_test_plan(script, 'workflow', 'TEST-positive')
    assert result['timeout_seconds'] == root_seconds(result) == 600
    assert result['source_checkpoint_ready'] is False and result['selected_carrier'] is None
    assert SOURCE_BUDGET == {'root_seconds': 7200, 'collection_seconds': 300, 'drain_seconds': 60}
    for changed in (TEST_COMPLETION_PIPE_CASES[:-1], (*TEST_COMPLETION_PIPE_CASES, 'foreign')):
        with pytest.raises(RuntimeError):
            make_test_plan((COMMAND + ' ' + ' '.join(changed)).encode(), 'workflow', 'TEST-positive')


@pytest.mark.parametrize(
    "mode,case,armed",
    [
        ("TEST-positive", "exact-finite-case", True),
        ("TEST-positive", "foreign-case", False),
        ("SOURCE", "exact-finite-case", False),
    ],
)
def test_finite_stall_snapshot_is_diagnostic_only_and_never_forces_exit(
    monkeypatch, mode, case, armed
):
    import primary_source_entry as entry
    from types import SimpleNamespace

    timers = []

    class Timer:
        def __init__(self, seconds, callback):
            self.seconds, self.callback = seconds, callback
            timers.append(self)

        def start(self):
            pass

    monkeypatch.setattr(entry.threading, "Timer", Timer)
    observed = []
    obj = object.__new__(entry.Observer)
    obj.profile = {"source_mode": mode}
    path = "/guard/finite/orders_git_data.py"
    obj.manifest = {"direct_support": {"files": {path: "exact-pin"}}}

    def checked(actual, pin):
        assert (actual, pin) == (path, "exact-pin")
        return {"CASES": {"exact-finite-case": "cohort"}}

    obj.guard = SimpleNamespace(checked_source=checked)
    obj.retain_stall_snapshot = lambda *args: observed.append(args)
    obj.pytest_runtest_call(SimpleNamespace(nodeid=case, funcargs={}))
    assert bool(timers) is armed
    if armed:
        assert timers[0].seconds == 10
        timers[0].callback()
        assert observed == [(obj.startup_stall_token, case, None)]


def test_startup_reproduction_retains_original_capacity_case_and_deadlines():
    import yaml
    from primary_policy import TEST_GIT_OVERHEAD_CASES, TEST_COHORT_STARTUP_CASES, TEST_APPROVAL_STARTUP_COST_CASES, TEST_CONTROLLED_CANCEL_CASES, TEST_RECORDED_CLEANUP_GROUPS, TEST_CONTROLLED_REGISTRATION_CASES, TEST_JOURNAL_CONTEXT_CASES, TEST_INITIALIZATION_CASES, root_seconds
    from primary_source_inputs import test_plan
    case='tests/test_experimental_finite_orders.py::test_actual_capacity_and_parking[2-1]'
    assert TEST_GIT_OVERHEAD_CASES == (case,)
    script=(COMMAND+' '+case).encode()
    plan=test_plan(script,'diagnostic','TEST-positive')
    assert plan['timeout_seconds']==root_seconds(plan)==600
    assert plan['source_checkpoint_ready'] is False
    workflow=yaml.safe_load((Path(__file__).parent.parent/'workflows/v046-source-readiness.yml').read_text())
    assert workflow['jobs']['controlled-backend-postimage-diagnosis']['strategy']['matrix']['include']==[
        {'group':'postimages-1','cases':' '.join(TEST_APPROVAL_STARTUP_COST_CASES)},
        {'group':'postimages-2','cases':' '.join(TEST_CONTROLLED_CANCEL_CASES)}] + [
        {'group':f'postimages-{i}','cases':' '.join(cases)}
        for i,cases in enumerate(TEST_RECORDED_CLEANUP_GROUPS,3)] + [
        {'group':'postimages-7','cases':' '.join(TEST_CONTROLLED_REGISTRATION_CASES)},
        {'group':'postimages-8','cases':' '.join(TEST_JOURNAL_CONTEXT_CASES)},
        {'group':'postimages-9','cases':' '.join(TEST_INITIALIZATION_CASES)}]
    assert len(TEST_RECORDED_CLEANUP_GROUPS) == 4
    for fault,cases in zip(('deep_json','array_id','object_id','success'), TEST_RECORDED_CLEANUP_GROUPS):
        assert cases == tuple('tests/test_acp_cleanup.py::test_recorded_transport_failures[' + fault + '-' + role + ']'
                              for role in ('work','validate','terminal_reviewer'))
        cleanup = test_plan((COMMAND + ' ' + ' '.join(cases)).encode(), 'diagnostic', 'TEST-positive')
        assert cleanup['timeout_seconds'] == root_seconds(cleanup) == 180
        assert cleanup['source_checkpoint_ready'] is False
    observed = test_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_STARTUP_COST_CASES)).encode(), 'diagnostic', 'TEST-positive')
    assert observed['timeout_seconds'] == root_seconds(observed) == 180
    assert observed['source_checkpoint_ready'] is False
    cancellation = test_plan((COMMAND + ' ' + ' '.join(TEST_CONTROLLED_CANCEL_CASES)).encode(), 'diagnostic', 'TEST-positive')
    assert cancellation['timeout_seconds'] == root_seconds(cancellation) == 180
    assert cancellation['source_checkpoint_ready'] is False
    assert TEST_CONTROLLED_CANCEL_CASES == tuple(
        'tests/test_controlled_python_acp.py::test_cancel_at_actual_boundary[' + stage + ']'
        for stage in ('backend_registered', 'adapter_registered', 'auth', 'forwarding'))
    for suffix in (' --maxfail=1', ' -k success'):
        with pytest.raises(RuntimeError):
            test_plan((COMMAND + ' ' + ' '.join(TEST_APPROVAL_STARTUP_COST_CASES) + suffix).encode(), 'diagnostic', 'TEST-positive')
    assert TEST_COHORT_STARTUP_CASES == (case,
        'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[claude]',
        'tests/test_acp_runner.py::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success[codex]')
    selected = (COMMAND + ' ' + ' '.join(TEST_COHORT_STARTUP_CASES)).encode()
    narrowed = test_plan(selected, 'diagnostic', 'TEST-positive')
    assert root_seconds(narrowed) == narrowed['timeout_seconds'] == 600
    with pytest.raises(RuntimeError):
        test_plan(selected + b' --maxfail=1', 'diagnostic', 'TEST-positive')


def test_guard_overhead_sampling_is_bounded_passive_and_contains_no_locals(monkeypatch):
    import json
    import sys
    from types import SimpleNamespace
    import primary_source_entry as entry

    import io
    output = io.StringIO()
    monkeypatch.setattr(entry.sys, "__stderr__", output)
    obj = object.__new__(entry.Observer)
    token, case = object(), 'exact-diagnostic'
    obj.startup_stall_token, obj.overhead_thread = token, 13
    obj.guard = SimpleNamespace(_STATE={'case': case})
    snapshots, pauses = [], []
    obj.retain_stall_snapshot = lambda *args: snapshots.append(args)
    secret = 'private-locals-must-not-be-retained'
    frame = sys._getframe()
    monkeypatch.setattr(entry.sys, '_current_frames', lambda: {13: frame})
    monkeypatch.setattr(entry.time, 'sleep', lambda seconds: pauses.append(seconds))
    obj.retain_guard_overhead(token, case, None)
    assert snapshots == [(token, case, None)]
    assert pauses == [.01] * 400
    text = output.getvalue()
    assert secret not in text
    data = json.loads(text.split('[retained guard overhead]\n', 1)[1])
    assert data['samples'] == 400 and data['passive_only'] is True
    assert data['test_deadlines_unchanged'] is True
    assert len(data['top_stacks']) == 1 and data['top_stacks'][0]['count'] == 400
    assert len(data['top_stacks'][0]['stack']) <= 24
    assert all(len(location) == 3 for location in data['top_stacks'][0]['stack'])


def test_guard_overhead_sampling_stops_at_case_boundary(monkeypatch):
    from types import SimpleNamespace
    import primary_source_entry as entry

    import io
    output = io.StringIO()
    monkeypatch.setattr(entry.sys, "__stderr__", output)
    obj = object.__new__(entry.Observer)
    obj.startup_stall_token = object()
    obj.guard = SimpleNamespace(_STATE={'case': 'next-case'})
    obj.retain_stall_snapshot = lambda *args: None
    monkeypatch.setattr(entry.sys, '_current_frames', lambda: pytest.fail('stale sampling'))
    monkeypatch.setattr(entry.time, 'sleep', lambda seconds: pytest.fail('stale waiting'))
    obj.retain_guard_overhead(object(), 'old-case', None)
    assert '"samples":0' in output.getvalue()


@pytest.mark.parametrize('mode,armed', [('TEST-positive', True), ('SOURCE', False)])
def test_overhead_sampler_arms_only_exact_diagnostic_case(monkeypatch, mode, armed):
    import primary_source_entry as entry
    from primary_policy import TEST_GIT_OVERHEAD_CASES
    from types import SimpleNamespace
    case, = TEST_GIT_OVERHEAD_CASES
    timers = []

    class Timer:
        def __init__(self, seconds, callback):
            assert seconds == 10
            self.callback = callback
            timers.append(self)

        def start(self):
            pass

    monkeypatch.setattr(entry.threading, 'Timer', Timer)
    obj = object.__new__(entry.Observer)
    obj.profile = {'source_mode': mode}
    path = '/guard/finite/orders_git_data.py'
    obj.manifest = {'direct_support': {'files': {path: 'exact-pin', '/guard/finite/guard_cost_profile.py': 'profile-pin'}}}
    monkeypatch.setattr(entry, 'load', lambda *args: SimpleNamespace(
        CostProfile=lambda prefix: SimpleNamespace(start=lambda: True)))
    obj.guard = SimpleNamespace(checked_source=lambda actual, pin: {'CASES': {case: 'cohort'}})
    seen = []
    obj.retain_guard_overhead = lambda *args: seen.append(args)
    obj.pytest_runtest_call(SimpleNamespace(nodeid=case, funcargs={}))
    assert bool(timers) is armed
    if armed:
        timers[0].callback()
        assert seen == [(obj.startup_stall_token, case, None)]


def test_overhead_sampler_needs_no_host_policy_import_inside_compartment():
    import ast
    tree = ast.parse((Path(__file__).parent / 'primary_source_entry.py').read_bytes())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Observer')
    call = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                and node.name == 'pytest_runtest_call')
    assert not any(isinstance(node, ast.ImportFrom) and node.module == 'primary_policy'
                   for node in ast.walk(call))


def test_cost_diagnostic_loads_real_helper_from_declared_finite_manifest(monkeypatch):
    import hashlib
    import primary_source_entry as entry
    from primary_policy import TEST_GIT_OVERHEAD_CASES
    from types import SimpleNamespace
    finite = Path(__file__).parent / 'finite'
    declared = {'/guard/finite/' + p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in finite.glob('*.py')}
    case, = TEST_GIT_OVERHEAD_CASES
    obj = object.__new__(entry.Observer)
    obj.profile = {'source_mode': 'TEST-positive'}
    obj.manifest = {'direct_support': {'files': declared}}
    obj.guard = SimpleNamespace(checked_source=lambda actual, pin: {'CASES': {case: 'cohort'}})
    loaded = []

    def load(name, path, pin):
        assert path in declared and pin == declared[path]
        source = finite / Path(path).name
        assert source.is_file() and hashlib.sha256(source.read_bytes()).hexdigest() == pin
        namespace = {'__file__': path, '__name__': name}
        exec(compile(source.read_bytes(), path, 'exec', dont_inherit=True), namespace)
        loaded.append(path)
        return SimpleNamespace(**namespace)

    class Timer:
        def __init__(self, *args):
            pass

        def start(self):
            pass

    monkeypatch.setattr(entry, 'load', load)
    monkeypatch.setattr(entry.threading, 'Timer', Timer)
    try:
        obj.pytest_runtest_call(SimpleNamespace(nodeid=case, funcargs={}))
        assert loaded == ['/guard/finite/guard_cost_profile.py']
    finally:
        if hasattr(obj, 'metadata_monitor'):
            report = obj.metadata_monitor.stop()
            assert report['complete'] and report['existing_profile_identity_retained']
