"""Finite artifact overlays and host custody for the immutable source namespace."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any

OVERLAYS = {
    '/source/.venv': 'rw,exec,nosuid,nodev,size=256m,uid=20000,gid=20000,mode=0700',
    '/source/build': 'rw,nosuid,nodev,noexec,size=64m,uid=20000,gid=20000,mode=0700',
    '/source/dist': 'rw,nosuid,nodev,noexec,size=64m,uid=20000,gid=20000,mode=0700',
    '/source/src/unrest_harness.egg-info': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.pytest_cache': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.ruff_cache': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.mypy_cache': 'rw,nosuid,nodev,noexec,size=32m,uid=20000,gid=20000,mode=0700',
}
BASE = Path('/var/lib/unrest-source-custody')
OWNED: list[tuple[Path, Path]] = []
CONTAINERS: set[str] = set()


def layout(source: Path) -> None:
    for name in OVERLAYS:
        path = source / Path(name).relative_to('/source')
        path.mkdir(exist_ok=True)
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise RuntimeError('source_artifact_mountpoint')


def key(path: Path) -> list[int]:
    info = path.lstat()
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]


def inventory(source: Path) -> dict[str, Any]:
    if source.resolve(strict=True) != source:
        raise RuntimeError('source_snapshot_alias')
    rows = {}
    for path in [source, *sorted(source.rglob('*'))]:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise RuntimeError('source_snapshot_type')
        rows[str(path.relative_to(source))] = {
            'identity': key(path),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None}
    return {'physical_path': str(source), 'members': rows,
            'ancestors': {str(p): key(p) for p in source.parents}}


def verify_identity(source: Path, expected: dict[str, Any]) -> None:
    if inventory(source) != expected:
        raise RuntimeError('source_host_custody_drift')


def verify(source: Path, expected: dict[str, Any]) -> None:
    verify_identity(source, expected)
    if not os.statvfs(source).f_flag & os.ST_RDONLY:
        raise RuntimeError('source_host_mount_writable')
    for path in [source, *source.parents]:
        info = path.lstat()
        if info.st_uid != (20000 if path == source else 0) or info.st_mode & 0o022:
            raise RuntimeError('source_host_ancestor_custody')


def seal(source: Path, log: Path) -> Path:
    """Move to exclusive root custody, then seal the host mount before Docker."""
    def run(*argv: str) -> None:
        with log.open('ab') as stream:
            subprocess.run(['sudo', '-n', *argv], stdout=stream, stderr=subprocess.STDOUT, check=True)
    if BASE.exists():
        if BASE.resolve(strict=True) != BASE or key(BASE)[3] != 0 or BASE.stat().st_mode & 0o022:
            raise RuntimeError('source_host_base_custody')
    else:
        run('install', '-d', '-m', '0755', '-o', '0', '-g', '0', str(BASE))
    parent = BASE / secrets.token_hex(32)
    run('mkdir', '-m', '0755', str(parent))
    target = parent / 'source'
    # Register before any acquisition which could fail, including a partial mount.
    OWNED.append((target, log))
    before = inventory(source)['members']
    run('mv', '-T', str(source), str(target))
    if inventory(target)['members'] != before:
        raise RuntimeError('source_host_move_drift')
    run('chown', '--no-dereference', '-R', '0:0', str(target))
    if (target / '.git').exists():
        run('chown', '--no-dereference', '-R', '20000:20000', str(target / '.git'))
    # Git checks both worktree and .git ownership. The read-only host mount,
    # not mode normalization, seals their owner while retaining strict 0644 inputs.
    run('chown', '--no-dereference', '20000:20000', str(target))
    run('mount', '--bind', str(target), str(target))
    run('mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target))
    verify(target, inventory(target))
    return target


def release() -> None:
    for container in sorted(CONTAINERS):
        removed = subprocess.run(['docker', 'rm', '--force', container], capture_output=True, check=False)
        if removed.returncode:
            # Never unseal backing while a capsule may still refer to it.
            raise RuntimeError('source_container_cleanup_failed')
        CONTAINERS.remove(container)
    while OWNED:
        target, log = OWNED.pop()
        with (log.parent.parent / 'source-custody-cleanup.log').open('ab') as stream:
            # A failed unmount retains the sealed backing rather than deleting it.
            mounted = subprocess.run(['mountpoint', '-q', str(target)], check=False).returncode == 0
            if mounted:
                subprocess.run(['sudo', '-n', 'umount', str(target)], stdout=stream,
                               stderr=subprocess.STDOUT, check=True)
            subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(target.parent)],
                           stdout=stream, stderr=subprocess.STDOUT, check=True)


def mount_inventory() -> dict[str, dict[str, Any]]:
    result = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        separator = fields.index('-')
        point = fields[4]
        if point == '/' or point == '/source' or point.startswith('/source/'):
            if point in result:
                raise RuntimeError('source_duplicate_mount')
            result[point] = {'options': fields[5].split(','),
                             'filesystem': fields[separator + 1], 'device': fields[2], 'root': fields[3]}
    return result


def check_view(expected: dict[str, Any], mounts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    source = Path('/source')
    if (set(mounts) != {'/', '/source', *OVERLAYS}
            or any('ro' not in mounts[p]['options'] for p in ('/', '/source'))
            or any(mounts[p]['filesystem'] != 'tmpfs' or 'rw' not in mounts[p]['options']
                   for p in OVERLAYS)):
        raise RuntimeError('source_probe_mount_inventory')
    if mounts['/source']['root'] != expected['physical_path']:
        raise RuntimeError('source_probe_physical_mount')
    observations = {}
    for path in (Path('/'), source, source / 'src'):
        if not os.access(path, os.X_OK) or not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise RuntimeError('source_probe_ancestor')
        observations[str(path)] = key(path)
    for name, row in expected['members'].items():
        path = source / name
        if str(path) in OVERLAYS:
            continue
        if key(path) != row['identity'] or (row['sha256'] is not None
                and hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']):
            raise RuntimeError('source_probe_member_drift')
    return observations


def probe() -> dict[str, Any]:
    """Own-identity Linux observations before source code or guard activation."""
    if sys.platform != 'linux' or os.getuid() != 20000 or os.getgid() != 20000:
        raise RuntimeError('source_probe_identity')
    source = Path('/source')
    expected = json.loads(Path('/inputs/source-custody.json').read_bytes())
    mounts = mount_inventory()
    observations = check_view(expected, mounts)
    controls = []
    import copy
    for mutation in ('wrong-mount', 'writable-root', 'extra-overlay', 'source-byte',
                     'source-identity', 'host-snapshot-substitution'):
        other = copy.deepcopy(expected)
        inventory = copy.deepcopy(mounts)
        if mutation == 'wrong-mount':
            inventory['/source']['root'] += '-wrong'
        elif mutation == 'writable-root':
            inventory['/source']['options'] = ['rw']
        elif mutation == 'extra-overlay':
            inventory['/source/src'] = inventory['/source/.venv']
        elif mutation == 'source-byte':
            other['members']['pyproject.toml']['sha256'] = '0' * 64
        elif mutation == 'source-identity':
            other['members']['.']['identity'][1] += 1
        else:
            other['physical_path'] += '-substituted'
        try:
            check_view(other, inventory)
        except RuntimeError as error:
            controls.append({'case': mutation, 'refusal': str(error)})
        else:
            raise RuntimeError('source_probe_negative_accepted')
    denials = {}
    operations = {
        'write': lambda: os.close(os.open('/source/pyproject.toml', os.O_WRONLY | os.O_NOFOLLOW)),
        'create': lambda: (source / '.immutable-root-canary').mkdir(),
        'rename': lambda: (source / 'pyproject.toml').rename(source / '.immutable-rename-canary'),
        'mode': lambda: source.chmod(0o777),
        'ancestor_mode': lambda: Path('/').chmod(0o777),
        'root_rename': lambda: source.rename('/immutable-source-canary'),
    }
    import errno
    for name, operation in operations.items():
        try:
            operation()
        except OSError as error:
            if error.errno not in (errno.EROFS, errno.EACCES, errno.EPERM, errno.EBUSY):
                raise
            denials[name] = error.errno
        else:
            raise RuntimeError('source_probe_mutation_succeeded')
    artifacts = {}
    for name in OVERLAYS:
        path = Path(name) / '.immutable-artifact-canary'
        with path.open('xb') as stream:
            stream.write(b'finite-artifact\n')
        if path.read_bytes() != b'finite-artifact\n':
            raise RuntimeError('source_probe_artifact')
        path.unlink()
        artifacts[name] = key(Path(name))
    import _posixsubprocess
    runtime = Path(sys.executable).resolve(strict=True)
    return {'mounts': mounts, 'ancestors': observations, 'denials': denials,
            'artifacts': artifacts, 'source_identity': key(source),
            'host_manifest_sha256': hashlib.sha256(Path('/inputs/source-custody.json').read_bytes()).hexdigest(),
            'controls': controls,
            'runtime': {'stdlib_subprocess_sha256': hashlib.sha256(Path(subprocess.__file__).read_bytes()).hexdigest(),
                        'native_posixsubprocess_sha256': hashlib.sha256(Path(_posixsubprocess.__file__).read_bytes()).hexdigest(),
                        'use_posix_spawn': subprocess._USE_POSIX_SPAWN,
                        'use_vfork': subprocess._USE_VFORK,
                        'version': sys.version, 'implementation': sys.implementation.name,
                        'executable': str(runtime), 'sha256': hashlib.sha256(runtime.read_bytes()).hexdigest(),
                        'flags': list(sys.flags)},
            'source_uid': os.getuid(), 'source_checkpoint_ready': False}
