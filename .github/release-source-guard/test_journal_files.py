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


@pytest.mark.parametrize('size', [0, 1, 8191, 8192, 65537, 1024 * 1024])
def test_unbuffered_current_regular_bytes_match_original_at_io_boundaries(tmp_path, size):
    path = tmp_path / '1.jsonl'
    body = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    path.write_bytes(body)
    assert list(CurrentFiles().acquire(tmp_path)) == original(tmp_path) == [(path, body)]
    path.write_bytes(body[:size // 2])
    assert list(CurrentFiles().acquire(tmp_path)) == original(tmp_path)


def read_from_descriptor(root, factory, candidate, monkeypatch):
    """Compare actual FileIO/BufferedReader behavior on finite OS descriptors.

    The test-only opener supplies the same real descriptor to either buffering
    mode. Production still requires its unchanged captured io.open identity.
    """
    import io
    import journal_files as module
    actual_open = io.open
    cleanups = []
    def selected_open(path, mode='r', *args, **kwargs):
        if os.fspath(path) == str(root / '1.jsonl') and mode == 'rb':
            fd, cleanup = factory()
            cleanups.append(cleanup)
            raw = io.FileIO(fd, 'rb', closefd=True)
            return raw if kwargs.get('buffering', -1) == 0 else io.BufferedReader(raw)
        return actual_open(path, mode, *args, **kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(io, 'open', selected_open)
            patch.setattr(module, '_IO_OPEN', selected_open)
            assert default_policy(root)
            try:
                rows = list(CurrentFiles().acquire(root)) if candidate else original(root)
                return ('bytes', [(str(path), body) for path, body in rows])
            except (OSError, InterruptedError) as error:
                return ('error', type(error), error.errno, error.args)
    finally:
        for cleanup in cleanups:
            cleanup()


@pytest.mark.parametrize('mode', ['empty-eof', 'data-eof', 'nonblocking-empty', 'nonblocking-data'])
def test_actual_fifo_eof_and_nonblocking_partial_reads_match_original(tmp_path, monkeypatch, mode):
    (tmp_path / '1.jsonl').write_bytes(b'path identity is tested separately')
    payload = b'current fifo bytes' * 32
    def descriptor():
        read, write = os.pipe()
        if mode.startswith('nonblocking'):
            os.set_blocking(read, False)
        if mode in ('data-eof', 'nonblocking-data'):
            assert os.write(write, payload) == len(payload)
        if mode.endswith('eof'):
            os.close(write)
            return read, lambda: None
        return read, lambda: os.close(write)
    expected = read_from_descriptor(tmp_path, descriptor, False, monkeypatch)
    assert read_from_descriptor(tmp_path, descriptor, True, monkeypatch) == expected
    assert expected[0] == 'bytes'
    assert expected[1][0][1] == (payload if 'data' in mode else None if mode == 'nonblocking-empty' else b'')


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux PTY closes with EIO after buffered output')
def test_actual_partial_data_followed_by_io_error_matches_original(tmp_path, monkeypatch):
    import pty
    (tmp_path / '1.jsonl').write_bytes(b'path identity is tested separately')
    def descriptor():
        master, slave = pty.openpty()
        try:
            assert os.write(slave, b'partial bytes before terminal EIO') == 33
        finally:
            os.close(slave)
        return master, lambda: None
    expected = read_from_descriptor(tmp_path, descriptor, False, monkeypatch)
    assert read_from_descriptor(tmp_path, descriptor, True, monkeypatch) == expected
    assert expected[0] == 'error' and expected[2] == 5


def test_actual_interrupted_blocking_read_preserves_original_exception(tmp_path, monkeypatch):
    import signal
    (tmp_path / '1.jsonl').write_bytes(b'path identity is tested separately')
    previous = signal.getsignal(signal.SIGALRM)
    def interrupt(signum, frame):
        raise InterruptedError('journal read interrupted')
    def descriptor():
        read, write = os.pipe()
        signal.setitimer(signal.ITIMER_REAL, .05)
        return read, lambda: os.close(write)
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    signal.signal(signal.SIGALRM, interrupt)
    try:
        expected = read_from_descriptor(tmp_path, descriptor, False, monkeypatch)
        assert read_from_descriptor(tmp_path, descriptor, True, monkeypatch) == expected
        assert expected[0] == 'error' and expected[1] is InterruptedError
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def test_unrecognized_io_policy_keeps_original_buffering_and_current_reads(tmp_path, monkeypatch):
    import io
    actual = io.open
    path = tmp_path / '1.jsonl'
    path.write_bytes(b'current')
    calls = []
    def changed(file, mode='r', *args, **kwargs):
        calls.append(kwargs.get('buffering', -1))
        return actual(file, mode, *args, **kwargs)
    monkeypatch.setattr(io, 'open', changed)
    assert not default_policy(tmp_path)
    assert list(CurrentFiles().acquire(tmp_path)) == [(path, b'current')]
    assert calls == [-1]


def test_changed_read_permissions_preserve_original_result_or_exception(tmp_path):
    path = tmp_path / '1.jsonl'
    path.write_bytes(b'current')
    reader = CurrentFiles()
    assert list(reader.acquire(tmp_path)) == original(tmp_path)
    def observe(call):
        try:
            return ('bytes', call())
        except OSError as error:
            return ('error', type(error), error.errno, error.args)
    path.chmod(0)
    try:
        assert observe(lambda: list(reader.acquire(tmp_path))) == observe(lambda: original(tmp_path))
    finally:
        path.chmod(0o600)
