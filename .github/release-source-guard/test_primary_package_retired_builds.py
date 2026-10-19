"""Only the current consumed TempDir lineage can restore an output ancestor."""
import copy
import stat

import pytest

from primary_package_retired_builds import names, checked_view, HELPERS, sha


def evidence():
    final = {'identity': [5, 12, stat.S_IFDIR | 0o755, 20000, 20000, 2, 20, 20],
             'type': stat.S_IFDIR, 'mode': 0o755, 'uid': 20000, 'gid': 20000,
             'links': 2, 'empty': True, 'leaf_count': 0}
    parent = {**final, 'identity': [5, 12, stat.S_IFDIR | 0o755, 20000, 20000, 3, 10, 10],
              'links': 3, 'empty': False, 'leaf_count': 1}
    root = {**parent, 'type': stat.S_IFDIR, 'mode': 0o755}
    ledger = [{'helper': helper, 'pid': i + 20, 'root': '/work/cache/builds-v0/.tmp' + str(i),
               'root_metadata': copy.deepcopy(root), 'parent_metadata': copy.deepcopy(parent)}
              for i, helper in enumerate(sorted(HELPERS))]
    return ledger, final


def test_only_exact_consumed_names_are_retained():
    ledger, final = evidence()
    result = names(ledger, final, preexisting=False)
    assert result == {sha(row['root'].removeprefix('/work/cache/').encode()):
                      row['root'].removeprefix('/work/cache/') for row in ledger}
    assert 'builds-v0' not in result.values()


@pytest.mark.parametrize('change', ['preexisting', 'missing', 'duplicate', 'unknown-helper',
    'foreign-path', 'prefix-only', 'parent-inode', 'parent-device', 'owner', 'group',
    'mode', 'symlink', 'hardlink', 'nonempty', 'child-owner', 'child-mode', 'observed-empty'])
def test_unknown_foreign_replaced_or_unbound_directory_stays_denied(change):
    ledger, final = evidence()
    preexisting = change == 'preexisting'
    if change == 'missing':
        ledger.pop()
    elif change == 'duplicate':
        ledger[0] = copy.deepcopy(ledger[1])
    elif change == 'unknown-helper':
        ledger[0]['helper'] = 'foreign'
    elif change == 'foreign-path':
        ledger[0]['root'] = '/work/cache/foreign/.tmp0'
    elif change == 'prefix-only':
        ledger[0]['root'] = '/work/cache/builds-v0/foreign'
    elif change == 'parent-inode':
        ledger[0]['parent_metadata']['identity'][1] += 1
    elif change == 'parent-device':
        ledger[0]['parent_metadata']['identity'][0] += 1
    elif change == 'owner':
        final['uid'] = 0
    elif change == 'group':
        final['gid'] = 0
    elif change == 'mode':
        final['mode'] = 0o777
    elif change == 'symlink':
        final['type'] = stat.S_IFLNK
    elif change == 'hardlink':
        final['links'] = 3
    elif change == 'nonempty':
        final['empty'] = False
    elif change == 'child-owner':
        ledger[0]['root_metadata']['uid'] = 0
    elif change == 'child-mode':
        ledger[0]['root_metadata']['mode'] = 0o700
    elif change == 'observed-empty':
        ledger[0]['parent_metadata']['empty'] = True
    with pytest.raises(RuntimeError, match='package_retired_build_'):
        names(ledger, final, preexisting=preexisting)


@pytest.mark.parametrize('change', ['none', 'replacement', 'membership', 'foreign-spec'])
def test_original_complete_census_is_preserved_and_replacement_refused(monkeypatch, change):
    import primary_package_retired_builds as retired
    _, final = evidence()
    key = sha(b'builds-v0')
    current = {key: {'type': 'directory', 'identity': final['identity'][:4]},
               'unknown': {'type': 'directory', 'identity': [5, 66, stat.S_IFDIR, 20000]}}
    paths = {key: 'builds-v0', 'unknown': 'foreign'}
    if change == 'replacement':
        current[key]['identity'][1] += 1
    observed = copy.deepcopy(final)
    if change == 'membership':
        observed['leaf_count'] = 1
    monkeypatch.setattr(retired, 'metadata', lambda path: observed)
    calls = []
    def original(spec, external):
        calls.append((spec, external))
        return current, paths
    check = checked_view(original, final)
    if change == 'none':
        assert check({'cache': '/work/cache'}, set()) == (current, paths)
        assert 'unknown' in current
    else:
        with pytest.raises(RuntimeError, match='census_drift'):
            check({'cache': '/foreign' if change == 'foreign-spec' else '/work/cache'}, set())
    assert len(calls) == 1
