"""Token joins distinguish reused logical argv without weakening pipe custody."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from role_pipe_custody import binding
from owned_multiprocess_authority import SourceAuthority


@pytest.fixture
def example(monkeypatch):
    import primary_source_authority
    monkeypatch.setattr(primary_source_authority, 'identity', lambda pid: {'ppid': 20})
    source = {'path': '/source/src/unrest_harness/acp_runner.py', 'line': 100, 'sha256': 'a' * 64}
    current = {'kind': 'concrete_owned_role_registration', 'owner_pid': 20, 'parent_pid': 8,
               'case': 'tests/test_acp_cleanup.py::test_saved_review_observer_compatibility[cancel]',
               'role': 'terminal-reviewer', 'source_binding': source, 'argv_sha256': 'b' * 64,
               'pipe_device': 15, 'pipe_inode': 194537}
    launch = {'kind': 'actual_launch_binding', 'owner_pid': 20, 'parent_pid': 8,
              'token': 'c' * 32, 'case': current['case'], 'cwd': '/owned/current',
              'bootstrap_sha256': 'd' * 64, 'transformed_argv_sha256': 'e' * 64,
              'environment_sha256': 'f' * 64}
    admitted = {key: launch[key] for key in ('owner_pid', 'parent_pid', 'token', 'case')}
    admitted.update(kind='admitted', **{'class': 'source-owned-role:terminal-reviewer'},
                    source_binding=source, argv_sha256=current['argv_sha256'])
    side = {**launch, **admitted, 'kind': 'owned_role_launch_binding',
            'pipe_device': current['pipe_device'], 'pipe_inode': current['pipe_inode']}
    earlier = {**current, 'pipe_inode': 192335,
               'case': 'tests/test_acp_cleanup.py::test_cleanup_faults_and_repeated_cancellation[reader-terminal_reviewer]'}
    rows = [dict(earlier), dict(earlier), dict(current), side, launch, admitted, dict(current)]
    authority = SourceAuthority.__new__(SourceAuthority)
    authority.bound = {363: {**launch, 'registration': admitted}}
    authority.supervisor = SimpleNamespace(events=lambda: rows)
    return authority, rows, current


def test_actual_four_row_history_collision_preserves_original_exact_pair(example):
    authority, rows, current = example
    from primary_source_authority import SourceAuthority as Original
    with pytest.raises(RuntimeError, match='primary_source_role_pipe_binding'):
        Original.pipe_binding(authority, 363)
    before, supervisor = deepcopy(rows), authority.supervisor
    assert authority.pipe_binding(363) == current
    assert rows == before and authority.supervisor is supervisor
    assert authority.bound[363]['transformed_argv_sha256'] != current['argv_sha256']


def test_same_case_repeated_launch_and_interleaved_other_owner(example):
    authority, rows, current = example
    rows[0]['case'] = rows[1]['case'] = current['case']
    rows.insert(4, {**rows[3], 'token': '1' * 32, 'owner_pid': 30})
    assert binding(authority, 363) == current


@pytest.mark.parametrize('kind', ['owned_role_launch_binding', 'actual_launch_binding', 'admitted'])
@pytest.mark.parametrize('change', ['missing', 'duplicate', 'cross_owner', 'cross_token'])
def test_launch_join_is_unique_current_and_fail_closed(example, kind, change):
    authority, rows, _ = example
    index = next(i for i, row in enumerate(rows) if row['kind'] == kind)
    if change == 'missing':
        rows.pop(index)
    elif change == 'duplicate':
        rows.append(dict(rows[index]))
    elif change == 'cross_owner':
        rows[index] = {**rows[index], 'owner_pid': 30}
    else:
        rows[index] = {**rows[index], 'token': '1' * 32}
    with pytest.raises(RuntimeError, match='owned_role_token'):
        binding(authority, 363)


@pytest.mark.parametrize('field', ['cwd', 'case', 'source_binding', 'argv_sha256', 'bootstrap_sha256',
                                    'transformed_argv_sha256', 'environment_sha256', 'class',
                                    'pipe_device', 'pipe_inode'])
def test_crossed_sidecar_never_authorizes_a_pipe(example, field):
    authority, rows, _ = example
    rows[3][field] = -1 if field.startswith('pipe_') else 'different'
    with pytest.raises(RuntimeError):
        binding(authority, 363)


def test_late_sidecar_rejected(example):
    authority, rows, _ = example
    rows.append(rows.pop(3))
    with pytest.raises(RuntimeError, match='owned_role_token_join'):
        binding(authority, 363)


@pytest.mark.parametrize('change', ['missing', 'unequal', 'duplicate', 'wrong_pipe', 'malformed_historical', 'missing_kind'])
def test_original_current_pair_and_malformed_history_stay_fail_closed(example, change):
    authority, rows, current = example
    if change == 'missing':
        rows.pop()
    elif change == 'unequal':
        rows[-1]['parent_pid'] += 1
    elif change == 'duplicate':
        rows.append(dict(current))
    elif change == 'wrong_pipe':
        rows[2]['pipe_inode'] += 1
        rows[-1]['pipe_inode'] += 1
    elif change == 'malformed_historical':
        del rows[0]['pipe_inode']
    else:
        rows.append({})
    with pytest.raises((RuntimeError, KeyError)):
        binding(authority, 363)


def test_binder_records_distinct_original_and_transformed_argv(example):
    import hashlib
    import json
    from finite.role_routes import bind_launch
    _, rows, current = example
    registration = {**rows[5], 'python': True, 'pipe_device': 15, 'pipe_inode': 194537}
    actual = ['/python', '-c', 'bootstrap']
    output = []
    def refuse(reason):
        raise RuntimeError(reason)
    bind_launch(registration, actual, '/owned/current', {'A': 'B'}, 'bootstrap',
                {'case': current['case']}, 'c' * 32, output.append, refuse)
    assert len(output) == 1
    assert output[0]['argv_sha256'] == current['argv_sha256']
    assert output[0]['transformed_argv_sha256'] == hashlib.sha256(json.dumps(actual).encode()).hexdigest()
    assert output[0]['argv_sha256'] != output[0]['transformed_argv_sha256']


@pytest.mark.parametrize('malformed', [None, [], 'row', 7, {}])
def test_malformed_journal_values_preserve_original_error(example, malformed):
    from primary_source_authority import SourceAuthority as Original
    authority, rows, _ = example
    rows.append(malformed)
    with pytest.raises((TypeError, KeyError)) as original:
        Original.pipe_binding(authority, 363)
    with pytest.raises(type(original.value)) as current:
        binding(authority, 363)
    assert current.value.args == original.value.args


def test_malformed_unrelated_role_is_still_ignored_by_original_comparison(example):
    authority, rows, current = example
    rows.insert(0, {**current, 'role': []})
    assert binding(authority, 363) == current
