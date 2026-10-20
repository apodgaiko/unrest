"""Finite artifact overlays and host custody for the immutable source namespace."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
from typing import Any

OVERLAYS = {
    '/source/.wheel-venv': 'rw,exec,nosuid,nodev,size=256m,uid=20000,gid=20000,mode=0700',
    '/source/.venv': 'rw,exec,nosuid,nodev,size=256m,uid=20000,gid=20000,mode=0700',
    '/source/unrest_harness-0.4.7': 'rw,nosuid,nodev,noexec,size=128m,uid=20000,gid=20000,mode=0700',
    '/source/build': 'rw,nosuid,nodev,noexec,size=64m,uid=20000,gid=20000,mode=0700',
    '/source/dist': 'rw,nosuid,nodev,noexec,size=64m,uid=20000,gid=20000,mode=0700',
    '/source/src/unrest_harness.egg-info': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.pytest_cache': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.ruff_cache': 'rw,nosuid,nodev,noexec,size=8m,uid=20000,gid=20000,mode=0700',
    '/source/.mypy_cache': 'rw,nosuid,nodev,noexec,size=32m,uid=20000,gid=20000,mode=0700',
}
BASE = Path('/var/lib/unrest-source-custody')


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
    return {'physical_path': str(source),
            'host_mount_flags': os.statvfs(source).f_flag,
            'host_readonly': bool(os.statvfs(source).f_flag & os.ST_RDONLY), 'members': rows,
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


class Custody:
    def __init__(self, target: Path, log: Path, base_identity: list[int], source: Path,
                 members: dict[str, Any], parent_identity: list[int] | None = None,
                 phase: str = 'creating', pending: str | None = None,
                 owners: dict[str, list[list[int]]] | None = None) -> None:
        self.target = target
        self.log = log
        self.base_identity = base_identity
        self.source = source
        self.members = members
        self.parent_identity = parent_identity
        self.phase = phase
        self.pending = pending
        self.owners = owners


OWNED: list[Custody] = []
CONTAINERS: dict[str, dict[str, Any]] = {}


def host(log: Path, *argv: str) -> None:
    with log.open('ab') as stream:
        subprocess.run(['sudo', '-n', *argv], stdout=stream, stderr=subprocess.STDOUT, check=True)


def event(record: Custody, kind: str, **fields: Any) -> None:
    with record.log.open('a') as stream:
        stream.write(json.dumps({'source_custody': kind, 'target': str(record.target),
                                 'phase': record.phase, **fields}, sort_keys=True) + '\n')


def directory(path: Path, uid: int) -> list[int]:
    identity = key(path)
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(identity[2])
            or identity[3:5] != [uid, uid] or identity[2] & 0o022):
        raise RuntimeError('source_host_directory_custody')
    return identity


def same_directory(path: Path, expected: list[int], uid: int) -> None:
    if directory(path, uid)[:5] != expected[:5]:
        raise RuntimeError('source_host_directory_substitution')


def ancestors(record: Custody) -> None:
    same_directory(BASE, record.base_identity, 0)
    if record.target.parent.parent != BASE or record.parent_identity is None:
        raise RuntimeError('source_host_parent_unknown')
    same_directory(record.target.parent, record.parent_identity, 0)
    for path in BASE.parents:
        directory(path, 0)


def members_match(record: Custody, actual: dict[str, Any]) -> None:
    if actual.keys() != record.members.keys():
        raise RuntimeError('source_host_member_set')
    for name, expected in record.members.items():
        observed = actual[name]
        left, right = observed['identity'], expected['identity']
        # Directory link counts change only as recorded children are removed.
        count = 5 if stat.S_ISDIR(right[2]) else 6
        if (left[:3] != right[:3] or left[:count] != right[:count]
                and not (record.owners and name in record.owners
                         and left[3:5] in record.owners[name]
                         and left[:3] == right[:3] and left[5:count] == right[5:count])
                or observed['sha256'] != expected['sha256']
                or (observed['sha256'] is not None and left[5] != 1)):
            raise RuntimeError('source_host_member_drift')


def check_owned(record: Custody) -> None:
    ancestors(record)
    if set(p.name for p in record.target.parent.iterdir()) != {'source'}:
        raise RuntimeError('source_host_parent_members')
    members_match(record, inventory(record.target)['members'])


MOUNT_TOOL: dict[str, Any] | None = None


def mount_tool() -> str:
    global MOUNT_TOOL
    path = Path(shutil.which('mountpoint') or '').resolve(strict=True)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('source_mount_tool_custody')
    for parent in path.parents:
        directory(parent, 0)
    pin = {'path': str(path), 'identity': key(path),
           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    if MOUNT_TOOL is None:
        version = subprocess.check_output([str(path), '--version']).decode().strip()
        if not version.startswith('mountpoint from util-linux '):
            raise RuntimeError('source_mount_tool_version')
        MOUNT_TOOL = {**pin, 'version': version, 'not_mounted_exit': 32}
    if pin != {name: MOUNT_TOOL[name] for name in pin}:
        raise RuntimeError('source_mount_tool_drift')
    return str(path)


def mount_status(target: Path) -> bool:
    result = subprocess.run([mount_tool(), '-q', '--', str(target)], capture_output=True, check=False)
    # util-linux mountpoint: 32 is documented "not a mountpoint"; 1 is an error.
    if result.returncode == 0:
        return True
    if result.returncode == 32:
        return False
    raise RuntimeError('source_mount_query_failed')


def change_owners(record: Custody, names: list[str], uid: int, *argv: str) -> None:
    record.phase = 'chowning'
    record.owners = {name: [record.members[name]['identity'][3:5], [uid, uid]] for name in names}
    event(record, 'before_chown', owners=record.owners)
    host(record.log, 'chown', '--no-dereference', *argv)
    check_owned(record)
    for name in names:
        record.members[name]['identity'][3:5] = [uid, uid]
    record.owners = None
    check_owned(record)
    record.phase = 'chowned'


def seal(source: Path, log: Path) -> Path:
    """Acquire one exclusive snapshot; a failure retains its phase and identities."""
    if (source.name != 'source' or log.name != 'coordinator.log' or log.parent.name != 'raw'
            or source.parent != log.parent.parent or source.parent.resolve(strict=True) != source.parent
            or source.parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(source.parent.stat().st_mode) != 0o700
            or source.stat().st_uid != os.getuid()):
        raise RuntimeError('source_host_acquisition_scope')
    if BASE.exists():
        directory(BASE, 0)
    else:
        host(log, 'install', '-d', '-m', '0755', '-o', '0', '-g', '0', str(BASE))
    base_identity = directory(BASE, 0)
    for ancestor in BASE.parents:
        directory(ancestor, 0)
    before = inventory(source)['members']
    if source.stat().st_dev != base_identity[0] or any(
            row['sha256'] is not None and row['identity'][5] != 1 for row in before.values()):
        raise RuntimeError('source_host_nonexclusive_backing')
    record = Custody(BASE / secrets.token_hex(32) / 'source', log, base_identity, source, before)
    OWNED.append(record)
    event(record, 'before_create', base_identity=base_identity, source=str(source), members=before)
    try:
        host(log, 'mkdir', '-m', '0755', str(record.target.parent))
    finally:
        # The random name is reserved by this invocation under the checked root-only
        # base. Record creation even if the command fails after creating it.
        if record.target.parent.exists():
            record.parent_identity = directory(record.target.parent, 0)
    ancestors(record)
    if any(record.target.parent.iterdir()):
        raise RuntimeError('source_host_parent_not_empty')
    record.phase = 'created'
    event(record, 'created', parent_identity=record.parent_identity)
    record.phase = 'moving'
    event(record, 'before_move')
    host(log, 'mv', '-T', str(source), str(record.target))
    check_owned(record)
    if source.exists():
        raise RuntimeError('source_host_move_not_exclusive')
    record.phase = 'moved'
    names = list(record.members)
    change_owners(record, names, 0, '-R', '0:0', str(record.target))
    if '.git' in record.members:
        git_names = [name for name in names if name == '.git' or name.startswith('.git/')]
        change_owners(record, git_names, 20000, '-R', '20000:20000', str(record.target / '.git'))
    change_owners(record, ['.'], 20000, '20000:20000', str(record.target))
    record.phase = 'binding'
    event(record, 'before_bind')
    host(log, 'mount', '--bind', str(record.target), str(record.target))
    record.phase = 'bound'
    check_owned(record)
    if not mount_status(record.target):
        raise RuntimeError('source_host_bind_missing')
    record.phase = 'sealing'
    event(record, 'before_remount')
    host(log, 'mount', '-o', 'remount,bind,ro,nosuid,nodev', str(record.target))
    record.phase = 'sealed'
    check_owned(record)
    verify(record.target, inventory(record.target))
    event(record, 'sealed', source_identity=key(record.target), mounted=mount_status(record.target),
          mount_tool=MOUNT_TOOL)
    return record.target


def plan_capsule(argv: list[str], source: Path) -> list[str]:
    """Bind a create intent before Docker may acquire the named capsule."""
    name = argv[argv.index('--name') + 1]
    if name in CONTAINERS:
        raise RuntimeError('source_capsule_duplicate')
    record = next((row for row in OWNED if row.target == source and row.phase == 'sealed'), None)
    if source.is_relative_to(BASE) and record is None:
        raise RuntimeError('source_capsule_unowned_snapshot')
    token = secrets.token_hex(32)
    if record is not None:
        check_owned(record)
    CONTAINERS[name] = {'token': token, 'id': None, 'source': str(source), 'custody': record}
    return [*argv[:2], '--label=unrest.source-custody=' + token, *argv[2:]]


def run_preparer(argv: list[str], source: Path, log: Path) -> subprocess.CompletedProcess[bytes]:
    """The short source-bound setup capsule has the same ownership lifetime."""
    name = 'source-prepare-' + secrets.token_hex(16)
    command = plan_capsule([*argv[:2], '--name', name, *argv[2:]], source)
    initiating: BaseException | None = None
    try:
        with log.open('ab') as errors:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=errors, check=False)
        record = CONTAINERS[name]['custody']
        if record is not None:
            event(record, 'preparer_exit', exit_code=result.returncode)
        if result.returncode:
            initiating = subprocess.CalledProcessError(result.returncode, command, output=result.stdout)
        return result
    except BaseException as error:
        initiating = error
        raise
    finally:
        try:
            stop_capsule(name)
        except BaseException as cleanup:
            if initiating is not None:
                raise BaseExceptionGroup('source preparation and stop failed', [initiating, cleanup]) from None
            raise


def bind_capsule(config: dict[str, Any]) -> None:
    name = config['Name'].removeprefix('/')
    owned = CONTAINERS[name]
    if (owned['id'] is not None and config['Id'] != owned['id']
            or config['Config']['Labels'].get('unrest.source-custody') != owned['token']
            or not any(m['Destination'] == '/source' and m['Source'] == owned['source']
                       and m['Type'] == 'bind' and not m['RW'] for m in config['Mounts'])):
        raise RuntimeError('source_capsule_identity')
    owned['id'] = config['Id']
    if owned['custody'] is not None:
        event(owned['custody'], 'capsule_bound', capsule_id=config['Id'], authenticated=True)


def stop_capsule(name: str) -> None:
    if name not in CONTAINERS:
        return
    owned = CONTAINERS[name]
    # A successful exact-name listing distinguishes absence from daemon/query failure.
    listing = subprocess.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'],
                             capture_output=True, check=True)
    ids = listing.stdout.decode().splitlines()
    if len(ids) > 1 or ids and owned['id'] is not None and ids != [owned['id']]:
        raise RuntimeError('source_capsule_substitution')
    if ids:
        config, = json.loads(subprocess.check_output(['docker', 'inspect', ids[0]]))
        if (config['Id'] != ids[0] or config['Name'] != '/' + name
                or config['Config']['Labels'].get('unrest.source-custody') != owned['token']
                or not any(m['Destination'] == '/source' and m['Source'] == owned['source']
                           and m['Type'] == 'bind' and not m['RW'] for m in config['Mounts'])):
            raise RuntimeError('source_capsule_identity')
        owned['id'] = ids[0]
        subprocess.run(['docker', 'rm', '--force', ids[0]], capture_output=True, check=True)
        after = subprocess.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$'],
                               capture_output=True, check=True)
        if after.stdout.strip():
            raise RuntimeError('source_capsule_cleanup_residue')
    record = owned['custody']
    if record is not None:
        event(record, 'capsule_absent', capsule_id=owned['id'], authenticated=True)
    del CONTAINERS[name]


def reconcile_delete(record: Custody) -> None:
    if record.pending is None:
        return
    path = record.target / record.pending
    if not path.exists() and not path.is_symlink():
        del record.members[record.pending]
        record.pending = None


def release_one(record: Custody) -> None:
    if record.phase == 'creating' and record.parent_identity is None:
        same_directory(BASE, record.base_identity, 0)
        if record.target.parent.exists() or record.target.parent.is_symlink():
            raise RuntimeError('source_host_uncertain_creation')
        return
    ancestors(record)
    if record.phase in {'creating', 'created', 'moving'} and not record.target.exists():
        if inventory(record.source)['members'] != record.members:
            raise RuntimeError('source_host_partial_move_drift')
        if any(record.target.parent.iterdir()):
            raise RuntimeError('source_host_partial_parent_members')
    elif record.phase == 'parent_deleting':
        if record.target.exists() or record.target.is_symlink():
            raise RuntimeError('source_host_deleted_target_reappeared')
    else:
        reconcile_delete(record)
        if record.members:
            check_owned(record)
            mounted = mount_status(record.target)
            if (record.phase in {'bound', 'sealing', 'sealed'} and not mounted
                    or record.phase in {'unmounted', 'deleting'} and mounted
                    or record.phase not in {'binding', 'bound', 'sealing', 'sealed', 'unmounting',
                                            'unmounted', 'deleting'} and mounted):
                raise RuntimeError('source_host_mount_lifecycle')
            if mounted:
                record.phase = 'unmounting'
                event(record, 'before_unmount', mounted=True)
                host(record.log, 'umount', str(record.target))
            record.phase = 'unmounted'
            if mount_status(record.target):
                raise RuntimeError('source_host_unmount_residue')
            check_owned(record)
            record.phase = 'deleting'
            # Each deletion has a recorded pending identity, retained across failures.
            for name in sorted(record.members, key=lambda n: (len(Path(n).parts), n), reverse=True):
                ancestors(record)
                path = record.target / name
                for parent in [path, *path.parents]:
                    if not parent.is_relative_to(record.target):
                        break
                    relative = str(parent.relative_to(record.target))
                    if parent.resolve(strict=True) != parent or parent.is_symlink():
                        raise RuntimeError('source_host_delete_alias')
                    members_match(Custody(record.target, record.log, record.base_identity,
                                          record.source, {relative: record.members[relative]},
                                          owners=record.owners),
                                  {relative: {'identity': key(parent),
                                              'sha256': hashlib.sha256(parent.read_bytes()).hexdigest()
                                              if parent.is_file() else None}})
                record.pending = name
                event(record, 'before_delete', member=name, identity=record.members[name]['identity'])
                command = 'rmdir' if stat.S_ISDIR(record.members[name]['identity'][2]) else 'rm'
                host(record.log, command, '--', str(path))
                if path.exists() or path.is_symlink():
                    raise RuntimeError('source_host_delete_residue')
                del record.members[name]
                record.pending = None
    record.phase = 'parent_deleting'
    ancestors(record)
    if any(record.target.parent.iterdir()):
        raise RuntimeError('source_host_parent_residue')
    event(record, 'before_parent_delete')
    host(record.log, 'rmdir', '--', str(record.target.parent))
    same_directory(BASE, record.base_identity, 0)
    if record.target.parent.exists() or record.target.parent.is_symlink():
        raise RuntimeError('source_host_parent_delete_residue')
    record.phase = 'released'
    event(record, 'released', mounted=False, parent_exists=False, target_exists=False, residue=0)


def release() -> None:
    for name in sorted(CONTAINERS):
        stop_capsule(name)
    while OWNED:
        record = OWNED[-1]
        # An acknowledged parent deletion may fail only in its return/report path.
        if (record.phase in {'parent_deleting', 'released'}
                and not record.target.parent.exists() and not record.target.parent.is_symlink()):
            same_directory(BASE, record.base_identity, 0)
            record.phase = 'released'
            event(record, 'released', mounted=False, parent_exists=False, target_exists=False, residue=0)
        else:
            release_one(record)
        OWNED.remove(record)


def settle(initiating: BaseException | None = None) -> None:
    try:
        release()
    except BaseException as cleanup:
        if initiating is not None:
            raise BaseExceptionGroup('source operation and custody cleanup failed', [initiating, cleanup]) from None
        raise


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
        if name == '/source/dist':
            require_empty_dist(key(Path(name)))
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
            'pid': os.getpid(), 'source_uid': os.getuid(), 'source_gid': os.getgid(),
            'source_checkpoint_ready': False}


def retain_proof(result: dict[str, Any], identity: dict[str, Any], runtime: dict[str, Any]) -> None:
    """Keep the observed source setup in the existing typed primary stream."""
    path = Path('/receipts/producers/setup-controls.json')
    if not path.is_file():
        return
    proof = json.loads(path.read_bytes())
    if (proof['pid'] != identity['pid'] or proof['source_uid'] != 20000
            or proof['source_gid'] != 20000):
        raise RuntimeError('source_setup_owner_drift')
    result['primary_records'].append({
        'kind': 'immutable_source_root', 'pid': identity['pid'], 'identity': identity,
        'proof': proof, 'runtime_binding': {name: runtime[name] for name in (
            'primary', 'source_native', 'source_profile_gate', 'source_abi') if name in runtime}})


def require_empty_dist(expected: list[int]) -> list[int]:
    """An existing artifact mountpoint is not a preexisting build output."""
    path = Path('/source/dist')
    current = key(path)
    mount = mount_inventory().get('/source/dist')
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(current[2])
            or current[3:5] != [20000, 20000] or stat.S_IMODE(current[2]) != 0o700
            or current != expected or mount is None or mount['filesystem'] != 'tmpfs'
            or 'rw' not in mount['options'] or any(path.iterdir())):
        raise RuntimeError('primary_package_preexisting_output')
    return current
