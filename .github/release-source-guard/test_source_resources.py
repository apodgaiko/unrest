"""Storage capacity is finite and bound to the original full source command."""
from copy import deepcopy

import pytest
import ci_shell
from test_source_root import config


def spec():
    return {'duty': 'v0.4.7 source suite', 'source_mode': 'SOURCE',
            'commands': [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q']]}


def test_only_full_source_changes_workspace_capacity():
    original = deepcopy(ci_shell.TMPFS)
    mounts, memory = ci_shell.resources(spec())
    assert memory == 3 * 1024 ** 3
    assert mounts['/work'] == 'rw,exec,nosuid,nodev,size=2g,uid=20000,gid=20000,mode=0711'
    assert {k: v for k, v in mounts.items() if k != '/work'} == {k: v for k, v in original.items() if k != '/work'}
    assert ci_shell.TMPFS == original
    assert ci_shell.resources({'duty': 'Build wheel and source distribution'}) == (original, 1073741824)
    current, origins = config()
    current['HostConfig'].update(Tmpfs=mounts, Memory=memory)
    ci_shell.validate(current, 'sha256:owned', origins, spec())
    with pytest.raises(RuntimeError, match='configuration'):
        ci_shell.validate(current, 'sha256:owned', origins)


@pytest.mark.parametrize('field', ['duty', 'source_mode', 'commands'])
def test_scope_contradictions_do_not_expand_capacity(field):
    value = spec()
    value[field] = 'foreign'
    with pytest.raises(RuntimeError, match='resource_scope'):
        ci_shell.resources(value)


@pytest.mark.parametrize('change', ['memory', 'workspace', 'network', 'capability', 'uid', 'extra_mount'])
def test_inspected_source_resources_refuse_drift(change):
    current, origins = config()
    mounts, memory = ci_shell.resources(spec())
    current['HostConfig'].update(Tmpfs=mounts, Memory=memory)
    if change == 'memory':
        current['HostConfig']['Memory'] += 1
    elif change == 'workspace':
        mounts['/work'] = mounts['/work'].replace('2g', '4g')
    elif change == 'uid':
        mounts['/work'] = mounts['/work'].replace('uid=20000', 'uid=0')
    elif change == 'network':
        current['HostConfig']['NetworkMode'] = 'host'
    elif change == 'capability':
        current['HostConfig']['CapAdd'].append('SYS_ADMIN')
    else:
        mounts['/extra'] = 'rw'
    with pytest.raises(RuntimeError, match='configuration'):
        ci_shell.validate(current, 'sha256:owned', origins, spec())


def test_only_closed_positive_source_fixtures_receive_executable_mount():
    from primary_policy import TEST_CANDIDATE_FIXTURE_CASES
    value = {'duty': 'TEST-source-positive', 'source_mode': 'TEST-positive',
             'commands': [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q',
                           *TEST_CANDIDATE_FIXTURE_CASES]]}
    mounts, memory = ci_shell.resources(value)
    assert 'exec' in mounts['/work'].split(',') and memory == 1073741824
    assert ci_shell.TMPFS['/work'].startswith('rw,nosuid,nodev,')
    for key in ('commands', 'duty'):
        changed = deepcopy(value)
        changed[key] = 'foreign'
        with pytest.raises(RuntimeError, match='fixture_mount_scope'):
            ci_shell.resources(changed)
    mounts, _ = ci_shell.resources({'source_mode': 'TEST-poison'})
    assert mounts == ci_shell.TMPFS


def test_only_exact_full_sized_journal_diagnostic_matches_source_memory_cap():
    from startup_journal_control import TEST_JOURNAL_CONTEXT_CASES, selected
    from primary_source_inputs import test_plan
    script = 'env -u CODEX_PATH uv run pytest -q ' + ' '.join(TEST_JOURNAL_CONTEXT_CASES)
    value = test_plan(script.encode(), 'diagnostic', 'TEST-positive')
    assert selected(value)
    mounts, memory = ci_shell.resources(value)
    assert memory == ci_shell.resources(spec())[1] == 3 * 1024 ** 3
    assert mounts['/work'] == ci_shell.TMPFS['/work'].replace('rw,', 'rw,exec,', 1)
    current, origins = config()
    current['HostConfig'].update(Tmpfs=mounts, Memory=memory)
    ci_shell.validate(current, 'sha256:owned', origins, value)
    for key in ('script_sha256', 'source_checkpoint_ready', 'selected_carrier'):
        changed = deepcopy(value)
        changed[key] = {'script_sha256': '0' * 64, 'source_checkpoint_ready': True,
                        'selected_carrier': 'foreign'}[key]
        assert not selected(changed)
        assert ci_shell.resources(changed)[1] == 1073741824
        with pytest.raises(RuntimeError, match='configuration'):
            ci_shell.validate(current, 'sha256:owned', origins, changed)


def test_exact_initialization_probe_matches_full_memory_without_other_scope_changes():
    from primary_policy import TEST_INITIALIZATION_CASES
    from primary_source_inputs import test_plan
    script = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(TEST_INITIALIZATION_CASES)).encode()
    value = test_plan(script, 'diagnostic', 'TEST-positive')
    mounts, memory = ci_shell.resources(value)
    assert memory == 3 * 1024 ** 3 and value['timeout_seconds'] == 180
    assert mounts['/work'] == ci_shell.TMPFS['/work'].replace('rw,', 'rw,exec,', 1)
    current, origins = config()
    current['HostConfig'].update(Tmpfs=mounts, Memory=memory)
    ci_shell.validate(current, 'sha256:owned', origins, value)
    for key, drift in [('script_sha256', '0' * 64), ('source_checkpoint_ready', True),
                       ('selected_carrier', 'foreign')]:
        changed = deepcopy(value)
        changed[key] = drift
        assert ci_shell.resources(changed)[1] == 1073741824
        with pytest.raises(RuntimeError, match='configuration'):
            ci_shell.validate(current, 'sha256:owned', origins, changed)
