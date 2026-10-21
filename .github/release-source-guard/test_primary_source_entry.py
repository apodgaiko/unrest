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
    from primary_policy import TEST_INVENTORY_CASES
    path = Path(__file__).parent.parent / 'workflows/v046-source-readiness.yml'
    document = yaml.safe_load(path.read_text())
    job = document['jobs']['startup-cancellation-diagnosis']
    ref = 'refs/heads/codex/source-guard-structured-20261018-source-composition-startup-cancel-20261021'
    assert job['if'] == "${{ github.ref == '" + ref + "' }}"
    assert document['jobs']['compartment-controls']['if'] == "${{ github.ref != '" + ref + "' }}"
    steps = job['steps']
    call = next(step for step in steps if step.get('shell'))
    assert call['run'] == COMMAND + ' ' + ' '.join(TEST_INVENTORY_CASES)
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
