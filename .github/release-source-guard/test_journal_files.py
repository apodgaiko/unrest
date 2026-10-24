"""Acquisition equivalence: fresh names/full bytes, including filesystem errors."""
from __future__ import annotations

import os
from pathlib import Path, PosixPath
import sys

import pytest

from journal_files import CurrentFiles, default_policy


def original(root):
    return [(path, path.read_bytes()) for path in sorted(root.glob('*.jsonl'))]


def test_default_path_reuses_only_spelling_and_discovers_every_current_name(tmp_path):
    for name in ['é.jsonl', '.jsonl', '.hidden.jsonl', '20.jsonl', '1.jsonl', 'a.JSONL']:
        (tmp_path / name).write_bytes(name.encode())
    source = CurrentFiles()
    assert default_policy(tmp_path)
    assert list(source.acquire(tmp_path)) == original(tmp_path)
    old = dict(source.spelling)
    before = (tmp_path / '20.jsonl').stat()
    (tmp_path / '20.jsonl').write_bytes(b'changed')
    os.utime(tmp_path / '20.jsonl', ns=(before.st_atime_ns, before.st_mtime_ns))
    (tmp_path / '1.jsonl').unlink()
    (tmp_path / '0.jsonl').write_bytes(b'new')
    assert list(source.acquire(tmp_path)) == original(tmp_path)
    assert source.spelling['20.jsonl'] is old['20.jsonl']
    assert '1.jsonl' not in source.spelling
    other = tmp_path / 'other'
    other.mkdir()
    (other / '20.jsonl').write_bytes(b'other root')
    assert list(source.acquire(other)) == original(other)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_alias_targets_are_freshly_read_even_when_external_to_directory(tmp_path, kind):
    root = tmp_path / 'journal'
    root.mkdir()
    target = tmp_path / 'outside'
    target.write_bytes(b'before')
    alias = root / '1.jsonl'
    if kind == 'symlink':
        alias.symlink_to(target)
    else:
        os.link(target, alias)
    source = CurrentFiles()
    assert list(source.acquire(root)) == original(root)
    target.write_bytes(b'after!')
    assert list(source.acquire(root)) == original(root) == [(alias, b'after!')]


@pytest.mark.parametrize('kind', ['directory', 'dangling'])
def test_matching_unreadable_members_are_never_filtered_or_replaced_with_cache(tmp_path, kind):
    path = tmp_path / '1.jsonl'
    if kind == 'directory':
        path.mkdir()
    else:
        path.symlink_to(tmp_path / 'absent')
    with pytest.raises(OSError) as expected:
        original(tmp_path)
    with pytest.raises(type(expected.value)) as actual:
        list(CurrentFiles().acquire(tmp_path))
    assert actual.value.errno == expected.value.errno


@pytest.mark.parametrize('method', ['glob', 'read_bytes', 'open', '__fspath__', '__str__'])
def test_concrete_path_policy_override_forces_original_path(tmp_path, monkeypatch, method):
    path = tmp_path / '1.jsonl'
    path.write_bytes(b'current')
    prior = getattr(PosixPath, method)
    calls = []
    def observed(self, *args, **kwargs):
        calls.append(method)
        return prior(self, *args, **kwargs)
    monkeypatch.setattr(PosixPath, method, observed)
    source = CurrentFiles()
    assert not default_policy(tmp_path)
    assert list(source.acquire(tmp_path)) == original(tmp_path)
    assert calls and not source.spelling


def test_glob_audit_policy_edit_is_observed_without_duplicate_glob_audit(tmp_path, monkeypatch):
    (tmp_path / '1.jsonl').write_bytes(b'current')
    events, reads = [], []
    original_read = Path.read_bytes
    def changed(path):
        reads.append(path)
        return original_read(path)
    def audit(name, *args):
        events.append((name, args))
        if name == 'pathlib.Path.glob':
            monkeypatch.setattr(Path, 'read_bytes', changed)
    monkeypatch.setattr(sys, 'audit', audit)
    assert list(CurrentFiles().acquire(tmp_path)) == [(tmp_path / '1.jsonl', b'current')]
    assert [name for name, _ in events].count('pathlib.Path.glob') == 1
    assert reads == [tmp_path / '1.jsonl']


def test_glob_audit_exception_precedes_scan_or_read(tmp_path, monkeypatch):
    cause = RuntimeError('audit denied')
    def audit(*args):
        raise cause
    monkeypatch.setattr(sys, 'audit', audit)
    with pytest.raises(RuntimeError) as caught:
        list(CurrentFiles().acquire(tmp_path))
    assert caught.value is cause


def test_scan_error_is_suppressed_and_read_error_is_not(tmp_path, monkeypatch):
    source = CurrentFiles()
    assert list(source.acquire(tmp_path / 'absent')) == []
    path = tmp_path / '1.jsonl'
    path.write_bytes(b'original')
    source = CurrentFiles()
    assert list(source.acquire(tmp_path)) == original(tmp_path)
    path.unlink()
    path.mkdir()
    with pytest.raises(IsADirectoryError):
        list(source.acquire(tmp_path))


def test_concrete_comparator_override_retains_original_sort_order(tmp_path, monkeypatch):
    for name in ['1.jsonl', '2.jsonl']:
        (tmp_path / name).write_bytes(name.encode())
    monkeypatch.setattr(PosixPath, '__lt__', lambda left, right: str(left) > str(right))
    source = CurrentFiles()
    assert not default_policy(tmp_path)
    assert list(source.acquire(tmp_path)) == original(tmp_path)
    assert [path.name for path, _ in source.acquire(tmp_path)] == ['2.jsonl', '1.jsonl']
    assert not source.spelling


@pytest.mark.parametrize('method', ['__eq__', '__truediv__'])
def test_new_path_operation_override_cannot_reuse_or_redirect_spelling(tmp_path, monkeypatch, method):
    left, right = tmp_path / 'left', tmp_path / 'right'
    left.mkdir()
    right.mkdir()
    (left / '1.jsonl').write_bytes(b'left')
    (right / '1.jsonl').write_bytes(b'right')
    source = CurrentFiles()
    assert list(source.acquire(left)) == original(left)
    if method == '__eq__':
        monkeypatch.setattr(PosixPath, method, lambda *args: True)
    else:
        redirected = left / 'absent'
        monkeypatch.setattr(PosixPath, method, lambda *args: redirected)
    assert not default_policy(right)
    actual = list(source.acquire(right))
    expected = original(right)
    assert [(str(path), body) for path, body in actual] == [(str(path), body) for path, body in expected]
    assert actual[0][1] == b'right'


def test_scan_time_policy_edit_precedes_cache_root_comparison(tmp_path, monkeypatch):
    import journal_files as module
    left, right = tmp_path / 'left', tmp_path / 'right'
    left.mkdir()
    right.mkdir()
    (left / '1.jsonl').write_bytes(b'left')
    (right / '1.jsonl').write_bytes(b'right')
    source = CurrentFiles()
    assert list(source.acquire(left)) == original(left)
    scan, calls = os.scandir, []
    def audited_scan(path):
        calls.append(str(path))
        monkeypatch.setattr(PosixPath, '__eq__', lambda *args: True)
        return scan(path)
    # Model the synchronous os.scandir audit-hook boundary without leaving
    # a permanent process-global hook in the rest of this control suite.
    monkeypatch.setattr(os, 'scandir', audited_scan)
    monkeypatch.setattr(module, '_SCANDIR', audited_scan)
    assert default_policy(right)
    actual = list(source.acquire(right))
    assert calls == [str(right)]
    assert actual[0][1] == b'right'
    assert str(actual[0][0]) == str(right / '1.jsonl')
