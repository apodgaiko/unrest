"""Complete descriptor reads preserve all custody/race evidence without rewrapping FDs."""
import hashlib
import os

import pytest

import primary_dependency as dependency


def original_read(path, uid, gid):
    before = os.stat(path, follow_symlinks=False)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        assert dependency.key(os.fstat(descriptor)) == dependency.key(before)
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(dependency.LIMIT + 1)
        assert len(body) == before.st_size
        assert dependency.key(os.fstat(descriptor)) == dependency.key(before)
        assert dependency.key(os.stat(path, follow_symlinks=False)) == dependency.key(before)
    finally:
        os.close(descriptor)
    assert before.st_uid == uid and before.st_gid == gid
    return body, {'path': str(path), 'identity': dependency.key(before),
                  'sha256': hashlib.sha256(body).hexdigest()}


@pytest.mark.parametrize('size', [0, 1, 4095, 32769, 2 * 1024 * 1024])
def test_fresh_full_bytes_and_all_receipt_fields_match_prior_reader(tmp_path, size):
    path = tmp_path / 'member'
    path.write_bytes((b'0123456789abcdef' * ((size + 15) // 16))[:size])
    info = path.stat()
    expected = original_read(path, info.st_uid, info.st_gid)
    assert dependency.read(path, info.st_uid, info.st_gid) == expected
    path.write_bytes(b'x' * size)
    assert dependency.read(path, info.st_uid, info.st_gid) == original_read(path, info.st_uid, info.st_gid)


def test_short_native_reads_are_completed_without_buffered_descriptor_setup(tmp_path, monkeypatch):
    path = tmp_path / 'member'
    body = b'complete byte-current dependency' * 271
    path.write_bytes(body)
    info = path.stat()
    native = os.read
    requests = []
    def partial(fd, size):
        requests.append(size)
        return native(fd, min(size, 7))
    def forbidden(*args, **kwargs):
        raise AssertionError('a second buffered file object is unnecessary')
    monkeypatch.setattr(dependency.os, 'read', partial)
    monkeypatch.setattr(dependency.os, 'fdopen', forbidden)
    actual, receipt = dependency.read(path, info.st_uid, info.st_gid)
    assert actual == body and receipt['sha256'] == hashlib.sha256(body).hexdigest()
    assert requests[0] == len(body) + 1 and requests[-1] == 1
    assert all(a > b for a, b in zip(requests, requests[1:]))


@pytest.mark.parametrize('change', ['growth', 'truncate', 'replace', 'mode', 'hardlink'])
def test_concurrent_member_changes_refuse_instead_of_producing_a_receipt(tmp_path, monkeypatch, change):
    path = tmp_path / 'member'
    path.write_bytes(b'original')
    info = path.stat()
    native = os.read
    changed = False
    def mutate(fd, size):
        nonlocal changed
        if not changed:
            changed = True
            if change == 'growth':
                with path.open('ab') as stream:
                    stream.write(b'added')
            elif change == 'truncate':
                path.write_bytes(b'x')
            elif change == 'replace':
                other = tmp_path / 'replacement'
                other.write_bytes(b'original')
                os.replace(other, path)
            elif change == 'mode':
                path.chmod(0o400)
            else:
                os.link(path, tmp_path / 'alias')
        return native(fd, size)
    monkeypatch.setattr(dependency.os, 'read', mutate)
    with pytest.raises(RuntimeError, match='primary_dependency_read_race'):
        dependency.read(path, info.st_uid, info.st_gid)


def test_unsafe_source_or_declared_size_refuses_before_open(tmp_path, monkeypatch):
    path = tmp_path / 'member'
    path.write_bytes(b'content')
    info = path.stat()
    link = tmp_path / 'link'
    link.symlink_to(path)
    native = os.open
    opened = []
    def open_record(*args, **kwargs):
        opened.append(args[0])
        return native(*args, **kwargs)
    monkeypatch.setattr(dependency.os, 'open', open_record)
    with pytest.raises(RuntimeError, match='file_custody'):
        dependency.read(link, info.st_uid, info.st_gid)
    monkeypatch.setattr(dependency, 'LIMIT', 2)
    with pytest.raises(RuntimeError, match='file_custody'):
        dependency.read(path, info.st_uid, info.st_gid)
    with pytest.raises(RuntimeError, match='file_custody'):
        dependency.read(path, info.st_uid + 1, info.st_gid)
    assert opened == []
