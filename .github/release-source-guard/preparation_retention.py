"""Exclusive host evidence ownership before physical candidate acquisition."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile

from primary_custody import file_identity, read_regular
from phase_catalog import catalog
from structured_evidence import canonical, require, execution_identity

SUPPORT = Path(__file__).resolve().parent
OWNED = {}
LIMIT = 64 * 1024 * 1024


def acquire(runner, kind):
    require(kind in {'primary-preparation', 'primary-source-positive', 'primary-source-poison'}
            | {phase.output for phase in catalog().values()},
            'primary_retention_kind')
    require(runner.resolve(strict=True) == runner, 'primary_retention_runner')
    parent = os.open(runner, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptors = [parent]
    try:
        info = os.fstat(parent)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o022
                and file_identity(info) == file_identity(runner.lstat()), 'primary_retention_runner')
        os.mkdir(kind, mode=0o700, dir_fd=parent)
        root = os.open(kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=parent)
        descriptors.append(root)
        os.mkdir('raw', mode=0o700, dir_fd=root)
        raw = os.open('raw', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=root)
        descriptors.append(raw)
        path = runner / kind
        pins = [file_identity(os.fstat(fd))[:5] for fd in descriptors]
        require(all(pin[3] == os.getuid() for pin in pins)
                and all(stat.S_IMODE(pin[2]) == 0o700 for pin in pins[1:]),
                'primary_retention_owner')
        OWNED[path] = (descriptors, pins)
        check(path)
        return path
    except BaseException:
        OWNED.pop(runner / kind, None)
        for fd in reversed(descriptors):
            os.close(fd)
        raise


def check(root):
    descriptors, pins = OWNED[root]
    for path, fd, pin in zip((root.parent, root, root / 'raw'), descriptors, pins):
        require(file_identity(os.fstat(fd))[:5] == file_identity(path.lstat())[:5] == pin
                and path.resolve(strict=True) == path, 'primary_retention_identity')
    return descriptors


def release(root):
    descriptors, _ = OWNED.pop(root)
    for fd in reversed(descriptors):
        os.close(fd)


def write(fd, name, body):
    target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    with os.fdopen(target, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def retain(root, record, error, child=None):
    from preparation_diagnostics import failure
    record = {**record, 'host_identity': execution_identity(SUPPORT, 'primary-source' if root.name == 'primary-preparation' else root.name)}
    _, directory, raw = check(root)
    write(raw, 'preparation-status.json', canonical({**record, 'failure': failure(error),
                                                  'child_failure_sha256': child}))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name in sorted(os.listdir(raw)):
            body = read_regular(root / 'raw' / name, LIMIT)
            member = tarfile.TarInfo(name)
            member.mode, member.size = 0o600, len(body)
            archive.addfile(member, io.BytesIO(body))
    plaintext = buffer.getvalue()
    require(len(plaintext) <= LIMIT, 'primary_retention_bound')
    check(root)
    output = os.open('evidence.cms', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=directory)
    with os.fdopen(output, 'wb') as stream:
        encrypted = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc',
                                    '-outform', 'DER', str(SUPPORT / 'evidence-recipient.pem')],
                                   input=plaintext, stdout=stream, stderr=subprocess.DEVNULL,
                                   check=False)
    require(encrypted.returncode == 0, 'primary_encryption_failed')
    check(root)
    cipher = read_regular(root / 'evidence.cms', LIMIT, 0o600)
    write(directory, 'safe-provenance.json', canonical({
        **record, 'ciphertext_sha256': hashlib.sha256(cipher).hexdigest(),
        'plaintext_archive_sha256': hashlib.sha256(plaintext).hexdigest()}))
    shutil.rmtree(root / 'raw')
    release(root)
