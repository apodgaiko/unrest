"""Faults exercise the production acquisition/release state machine on real files.

Only privileged host syscalls, mount status, and Docker are modeled here. Actual
Linux cleanup evidence is retained by the same helper in the production log.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

import source_root as root


@pytest.fixture
def custody(tmp_path, monkeypatch):
    base = tmp_path / 'base'
    base.mkdir()
    tmp_path.chmod(0o700)
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'src').mkdir()
    (source / 'src/module.py').write_bytes(b'original module\n')
    (source / 'pyproject.toml').write_bytes(b'original project\n')
    (source / '.git').mkdir()
    (source / '.git/HEAD').write_bytes(b'original git\n')
    (tmp_path / 'raw').mkdir(mode=0o700)
    log = tmp_path / 'raw/coordinator.log'
    kernel = SimpleNamespace(base=base, source=source, log=log, owners={}, mounted=False,
                             readonly=False, fault=None, calls=[], query=None, containers={})
    for path in [source, *source.rglob("*")]:
        kernel.owners[path.stat().st_ino] = [path.stat().st_uid, path.stat().st_gid]
    original_key = root.key

    def key(path):
        value = original_key(path)
        if path.is_relative_to(base):
            value[3:5] = kernel.owners.get(value[1], [0, 0])
        elif path != source and not path.is_relative_to(source):
            value[3:5] = [0, 0]
            value[2] &= ~0o022
        return value

    def host(log, *argv):
        command = argv[0]
        operation = ('remount' if command == 'mount' and argv[1] == '-o' else
                     'bind' if command == 'mount' else command)
        kernel.calls.append(operation)
        if kernel.fault == (operation, 'before'):
            raise OSError('initiating ' + operation)
        target = Path(argv[-1])
        if command == 'mkdir':
            target.mkdir(mode=0o755)
        elif command == 'mv':
            shutil.move(argv[-2], argv[-1])
        elif command == 'chown':
            owner = [int(v) for v in argv[-2].split(':')]
            names = [target, *target.rglob('*')] if '-R' in argv else [target]
            for path in names:
                kernel.owners[path.stat().st_ino] = owner
        elif operation == 'bind':
            kernel.mounted = True
        elif operation == 'remount':
            kernel.readonly = True
        elif command == 'umount':
            kernel.mounted = False
            kernel.readonly = False
        elif command == 'rm':
            target.unlink()
        elif command == 'rmdir':
            target.rmdir()
        else:
            raise AssertionError(argv)
        if kernel.fault == (operation, 'after'):
            raise OSError('cleanup ' + operation)

    def mount_run(argv, **kwargs):
        assert argv[:3] == ['mountpoint', '-q', '--']
        return SimpleNamespace(returncode=kernel.query if kernel.query is not None else
                               0 if kernel.mounted else 32)

    def verify(path, expected):
        root.verify_identity(path, expected)
        assert kernel.mounted and kernel.readonly

    monkeypatch.setattr(root, 'BASE', base)
    monkeypatch.setattr(root, 'OWNED', [])
    monkeypatch.setattr(root, 'CONTAINERS', {})
    monkeypatch.setattr(root, 'key', key)
    monkeypatch.setattr(root, 'host', host)
    monkeypatch.setattr(root, 'mount_tool', lambda: 'mountpoint')
    monkeypatch.setattr(root.subprocess, 'run', mount_run)
    monkeypatch.setattr(root, 'verify', verify)
    kernel.seal = lambda: root.seal(source, log)
    return kernel


@pytest.mark.parametrize('operation', ['mkdir', 'mv', 'chown', 'bind', 'remount'])
@pytest.mark.parametrize('when', ['before', 'after'])
def test_custody_acquisition_fault_retains_retry(custody, operation, when):
    custody.fault = operation, when
    with pytest.raises(OSError):
        custody.seal()
    assert len(root.OWNED) == 1
    record = root.OWNED[0]
    assert record.phase in {'creating', 'moving', 'chowning', 'binding', 'sealing'}
    custody.fault = None
    root.release()
    assert root.OWNED == [] and list(custody.base.iterdir()) == [] and not custody.mounted
    if operation == 'mkdir' or operation == 'mv' and when == 'before':
        assert custody.source.is_dir()
    else:
        assert not custody.source.exists()


@pytest.mark.parametrize('operation', ['umount', 'rm', 'rmdir'])
@pytest.mark.parametrize('when', ['before', 'after'])
def test_custody_cleanup_fault_retains_retry(custody, operation, when):
    target = custody.seal()
    record = root.OWNED[0]
    custody.fault = operation, when
    with pytest.raises(OSError):
        root.release()
    assert root.OWNED == [record] and target.parent.exists()
    assert record.pending is not None if operation in {'rm', 'rmdir'} else record.phase == 'unmounting'
    custody.fault = None
    root.release()
    assert root.OWNED == [] and not target.parent.exists() and not custody.mounted


@pytest.mark.parametrize('code', [1, 2, 64, -9])
def test_custody_mount_query_error_retains_seal(custody, code):
    target = custody.seal()
    custody.query = code
    before = root.inventory(target)
    with pytest.raises(RuntimeError, match='source_mount_query_failed'):
        root.release()
    assert len(root.OWNED) == 1 and custody.mounted and custody.readonly
    assert root.inventory(target) == before and 'umount' not in custody.calls
    custody.query = None
    root.release()
    assert not target.parent.exists()


def test_custody_documented_absence_and_post_unmount_retry(custody):
    target = custody.seal()
    custody.fault = 'umount', 'after'
    with pytest.raises(OSError):
        root.release()
    assert root.OWNED and not custody.mounted
    custody.fault = None
    calls = custody.calls.count('umount')
    root.release()
    assert custody.calls.count('umount') == calls and not target.parent.exists()


@pytest.mark.parametrize('member', ['parent', 'target', 'source-file', 'symlink'])
def test_custody_substitution_never_deletes_replacement(custody, member):
    target = custody.seal()
    if member == 'parent':
        path = target.parent
    elif member in {'target', 'symlink'}:
        path = target
    else:
        path = target / 'src/module.py'
    old = path.with_name(path.name + '-retained')
    path.rename(old)
    if member == 'symlink':
        path.symlink_to(old, target_is_directory=True)
    elif old.is_dir():
        path.mkdir()
    else:
        path.write_bytes(old.read_bytes())
    before = root.key(path)
    with pytest.raises(RuntimeError):
        root.release()
    assert root.OWNED and root.key(path) == before and old.exists()
    assert custody.mounted and custody.readonly and 'umount' not in custody.calls
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        path.rmdir()
    old.rename(path)
    root.release()
    assert not target.parent.exists()


def test_custody_parent_delete_failure_after_complete_tree(custody, monkeypatch):
    target = custody.seal()
    host = root.host

    def fault(log, *argv):
        if argv[0] == 'rmdir' and Path(argv[-1]) == target.parent:
            host(log, *argv)
            raise OSError('after parent deletion')
        host(log, *argv)

    monkeypatch.setattr(root, 'host', fault)
    with pytest.raises(OSError):
        root.release()
    assert root.OWNED and root.OWNED[0].phase == 'parent_deleting'
    assert not target.parent.exists()
    monkeypatch.setattr(root, 'host', host)
    root.release()
    assert not root.OWNED


def test_custody_partial_delete_detects_other_member_mutation(custody):
    target = custody.seal()
    custody.fault = 'rm', 'after'
    with pytest.raises(OSError):
        root.release()
    remaining = next(target.rglob('HEAD'))
    remaining.write_bytes(b'changed')
    custody.fault = None
    with pytest.raises(RuntimeError, match='source_host_member_drift'):
        root.release()
    assert root.OWNED and remaining.read_bytes() == b'changed'
    remaining.write_bytes(b'original git\n')
    root.release()
    assert not root.OWNED


def test_custody_dual_error_keeps_initiating_and_cleanup(custody):
    custody.seal()
    custody.fault = 'umount', 'before'
    initiating = ValueError('original initiating failure')
    with pytest.raises(BaseExceptionGroup) as result:
        root.settle(initiating)
    assert result.value.exceptions[0] is initiating
    assert isinstance(result.value.exceptions[1], OSError)
    assert root.OWNED and custody.mounted
    custody.fault = None
    root.settle()
    assert not root.OWNED


@pytest.mark.parametrize('fault', ['stop', 'query', 'identity', 'mount', 'post-stop-query'])
def test_custody_capsule_failure_prevents_unsealing(custody, monkeypatch, fault):
    target = custody.seal()
    command = root.plan_capsule(['docker', 'create', '--name', 'owned-capsule'], target)
    owned = root.CONTAINERS['owned-capsule']
    assert '--label=unrest.source-custody=' + owned['token'] in command
    config = {'Id': 'a' * 64, 'Name': '/owned-capsule',
              'Config': {'Labels': {'unrest.source-custody': owned['token']}},
              'Mounts': [{'Type': 'bind', 'Destination': '/source', 'Source': str(target), 'RW': False}]}
    root.bind_capsule(config)
    if fault == 'identity':
        config['Config']['Labels']['unrest.source-custody'] = 'substitution'
    elif fault == 'mount':
        config['Mounts'][0]['Source'] += '-substitution'
    present = True
    calls = []

    def docker(argv, **kwargs):
        nonlocal present
        calls.append(argv)
        if argv[:2] == ['docker', 'ps']:
            if fault == 'query' or not present and fault == 'post-stop-query':
                raise subprocess.CalledProcessError(1, argv)
            return SimpleNamespace(stdout=(('a' * 64 + '\n').encode() if present else b''))
        assert argv == ['docker', 'rm', '--force', 'a' * 64]
        if fault == 'stop':
            raise subprocess.CalledProcessError(1, argv)
        present = False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(root.subprocess, 'check_output', lambda argv: json.dumps([config]).encode())
    mount_run = root.subprocess.run
    monkeypatch.setattr(root.subprocess, 'run', docker)
    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        root.release()
    assert root.OWNED and root.CONTAINERS and custody.mounted and custody.readonly
    assert 'umount' not in custody.calls
    if fault in {'identity', 'mount'}:
        assert not any(argv[:2] == ['docker', 'rm'] for argv in calls)
    fault = 'fixed'
    config['Config']['Labels']['unrest.source-custody'] = owned['token']
    config['Mounts'][0]['Source'] = str(target)
    root.stop_capsule('owned-capsule')
    assert not root.CONTAINERS
    monkeypatch.setattr(root.subprocess, 'run', mount_run)
    root.release()
    assert not root.OWNED and not target.parent.exists()


def test_custody_release_proof_records_actual_disappearance(custody):
    target = custody.seal()
    identity = root.key(target)
    assert stat.S_ISDIR(identity[2])
    root.release()
    records = [json.loads(line) for line in custody.log.read_text().splitlines()]
    assert records[0]['members']['src/module.py']['sha256']
    sealed = next(row for row in records if row['source_custody'] == 'sealed')
    assert sealed['source_identity'] == identity and sealed['mounted']
    assert records[-1] == {'source_custody': 'released', 'target': str(target), 'phase': 'released',
                           'mounted': False, 'target_exists': False, 'parent_exists': False, 'residue': 0}
    assert not target.exists() and not target.parent.exists() and not root.OWNED


def test_custody_unexpected_mount_absence_retains_ownership(custody):
    target = custody.seal()
    custody.query = 32
    with pytest.raises(RuntimeError, match='source_host_mount_lifecycle'):
        root.release()
    assert root.OWNED and target.exists() and custody.mounted
    assert 'umount' not in custody.calls and 'rm' not in custody.calls
    custody.query = None
    root.release()
    assert not root.OWNED


@pytest.mark.parametrize('substitution', [False, True])
def test_custody_partial_chown_retries_only_known_owners(custody, monkeypatch, substitution):
    host = root.host

    def partial(log, *argv):
        if argv[0] == 'chown':
            member = root.OWNED[0].target / 'src/module.py'
            custody.owners[member.stat().st_ino] = [12345, 12345] if substitution else [0, 0]
            raise OSError('partially changed ownership')
        host(log, *argv)

    monkeypatch.setattr(root, 'host', partial)
    with pytest.raises(OSError):
        custody.seal()
    assert root.OWNED[0].phase == 'chowning' and root.OWNED[0].owners
    monkeypatch.setattr(root, 'host', host)
    if substitution:
        with pytest.raises(RuntimeError, match='source_host_member_drift'):
            root.release()
        assert root.OWNED
        member = root.OWNED[0].target / 'src/module.py'
        custody.owners[member.stat().st_ino] = [0, 0]
    root.release()
    assert not root.OWNED and list(custody.base.iterdir()) == []


def test_custody_parent_delete_substitution_retains_new_object(custody, monkeypatch):
    target = custody.seal()
    host = root.host

    def before_parent(log, *argv):
        if argv[0] == 'rmdir' and Path(argv[-1]) == target.parent:
            raise OSError('before parent deletion')
        host(log, *argv)

    monkeypatch.setattr(root, 'host', before_parent)
    with pytest.raises(OSError):
        root.release()
    old = target.parent.with_name(target.parent.name + '-retained')
    target.parent.rename(old)
    target.parent.mkdir()
    with pytest.raises(RuntimeError):
        root.release()
    assert root.OWNED and target.parent.is_dir() and old.is_dir()
    target.parent.rmdir()
    old.rename(target.parent)
    monkeypatch.setattr(root, 'host', host)
    root.release()
    assert not root.OWNED


def test_custody_setup_loader_needs_no_module_registration():
    import importlib.util
    import sys
    name = 'own_unregistered_source_custody'
    assert name not in sys.modules
    spec = importlib.util.spec_from_file_location(name, root.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.OVERLAYS == root.OVERLAYS and module.OWNED == []
    assert name not in sys.modules


@pytest.mark.parametrize('outcome', ['success', 'process-error', 'stop-error', 'both-errors'])
def test_custody_preparer_is_owned_before_launch(custody, monkeypatch, outcome):
    target = custody.seal()
    seen = []
    stop = root.stop_capsule

    def run(argv, **kwargs):
        assert argv[:2] == ['docker', 'run']
        name = argv[argv.index('--name') + 1]
        assert root.CONTAINERS[name]['source'] == str(target)
        assert '--label=unrest.source-custody=' + root.CONTAINERS[name]['token'] in argv
        seen.append(name)
        if outcome in {'process-error', 'both-errors'}:
            raise OSError('preparer process failure')
        return SimpleNamespace(returncode=0, stdout=b'original setup output')

    def stopped(name):
        assert seen == [name] and name in root.CONTAINERS
        if outcome in {'stop-error', 'both-errors'}:
            raise RuntimeError('preparer stop failure')
        del root.CONTAINERS[name]

    mount_run = root.subprocess.run
    monkeypatch.setattr(root.subprocess, 'run', run)
    monkeypatch.setattr(root, 'stop_capsule', stopped)
    if outcome == 'success':
        assert root.run_preparer(['docker', 'run', '--rm'], target, custody.log).stdout == b'original setup output'
    elif outcome == 'both-errors':
        with pytest.raises(BaseExceptionGroup) as result:
            root.run_preparer(['docker', 'run', '--rm'], target, custody.log)
        assert isinstance(result.value.exceptions[0], OSError)
        assert isinstance(result.value.exceptions[1], RuntimeError)
    else:
        with pytest.raises(OSError if outcome == 'process-error' else RuntimeError):
            root.run_preparer(['docker', 'run', '--rm'], target, custody.log)
    assert custody.mounted and root.OWNED
    if outcome in {'stop-error', 'both-errors'}:
        assert len(root.CONTAINERS) == 1
        outcome = 'success'
        stopped(seen[0])
    assert not root.CONTAINERS
    monkeypatch.setattr(root, 'stop_capsule', stop)
    monkeypatch.setattr(root.subprocess, 'run', mount_run)
    root.release()
    assert not root.OWNED
