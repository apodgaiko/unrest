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
    assert mounts['/work'] == 'rw,nosuid,nodev,size=2g,uid=20000,gid=20000,mode=0711'
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
