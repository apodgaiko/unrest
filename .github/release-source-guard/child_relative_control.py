"""Own source-free native prebody denial; no constructor or original-case claim."""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import tempfile
import uuid

from finite.linux_identity import identity
from linux_compartment import source_credentials
from linux_observation import process_identity
from linux_trace import OwnedTrace, install_observation_filter
from primary_policy import PYTHON


def digest(body):
    return hashlib.sha256(body).hexdigest()


def census():
    rows = []
    for fd in sorted(map(int, os.listdir('/proc/self/fd'))):
        try:
            value = os.fstat(fd)
        except OSError as error:
            import errno
            if error.errno == errno.EBADF:
                continue  # The closed listdir enumeration descriptor.
            raise
        rows.append({'fd': fd, 'device': value.st_dev, 'inode': value.st_ino,
                     'mode': value.st_mode, 'uid': value.st_uid, 'gid': value.st_gid,
                     'descriptor_flags': fcntl.fcntl(fd, fcntl.F_GETFD),
                     'status_flags': fcntl.fcntl(fd, fcntl.F_GETFL)})
    return rows


def run(binding, environment):
    if os.getpid() != 1 or os.geteuid() != 0 or binding['entry']['path'] != PYTHON:
        raise RuntimeError('child_relative_control_parent')
    guard_path = Path('/guard/finite/runtime_guard.py')
    spec = importlib.util.spec_from_file_location('_child_relative_control_bootstrap', guard_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    token = uuid.uuid4().hex
    before = census()
    root = Path(tempfile.mkdtemp(prefix='child-relative-control-', dir='/work'))
    os.chown(root, 20001, 20001)
    root.chmod(0o755)
    root_key = (root.stat().st_dev, root.stat().st_ino)
    body_root = root / 'body'
    body_root.mkdir(mode=0o700)
    os.chown(body_root, 20000, 20000)
    events = body_root / 'events'
    events.mkdir(mode=0o700)
    os.chown(events, 20000, 20000)
    marker = body_root / 'must-not-run'
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps({'events': str(events)}, sort_keys=True))
    os.chown(manifest, 20001, 20001)
    manifest.chmod(0o444)
    manifest_pin = digest(manifest.read_bytes())
    payload = {'token': token, 'class': 'child-relative-own-denial-control', 'case': None,
               'mode': 'inline', 'target': f'from pathlib import Path;Path({str(marker)!r}).write_text("ran")',
               'isolated': True, 'sys_argv': ['-c'], 'orig_argv': [], 'path0': '',
               'source_binding': {'path': '/guard/child_relative_control.py', 'line': 1,
                                  'sha256': digest(Path('/guard/child_relative_control.py').read_bytes())}}
    program = module.bootstrap(str(manifest), manifest_pin, str(guard_path),
                               digest(guard_path.read_bytes()), payload)
    argv = [PYTHON, '-I', '-S', '-c', program]
    directory = Path('/receipts/primary-startup')
    if directory.exists() or directory.is_symlink():
        raise RuntimeError('child_relative_control_namespace_exists')
    directory.mkdir(mode=0o755)
    os.chown(directory, 20001, 20001)
    directory_key = (directory.stat().st_dev, directory.stat().st_ino)
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    owned = {read, write, ready_read, ready_write, start_read, start_write}
    child = None
    reaped = False
    profile_path = receipt_path = diagnostic_path = None
    output = bytearray()
    def close(fd):
        if fd in owned:
            os.close(fd)
            owned.remove(fd)
    try:
        child = os.fork()
        if child == 0:
            try:
                os.dup2(write, 1)
                os.dup2(write, 2)
                os.close(ready_read)
                os.close(start_write)
                source_credentials()
                resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
                install_observation_filter()
                os.setsid()
                os.chdir('/source')
                os.write(ready_write, b'R')
                os.close(ready_write)
                if os.read(start_read, 1) != b'1':
                    os._exit(126)
                os.closerange(3, 1 << 20)
                os.execve(PYTHON, argv, environment)
            finally:
                os._exit(126)
        for fd in (write, ready_write, start_read):
            close(fd)
        if os.read(ready_read, 1) != b'R':
            raise RuntimeError('child_relative_control_fence')
        close(ready_read)
        birth = identity(child)
        credentials = process_identity(child)
        if (birth['ppid'] != os.getpid() or credentials['uids'] != [20000] * 4
                or credentials['gids'] != [20000] * 4 or any(credentials['capabilities'].values())
                or credentials['no_new_privs'] != 1):
            raise RuntimeError('child_relative_control_identity')
        profile = {'pid': child, 'parent': os.getpid(), 'start_ticks': birth['start_ticks'],
                   'boot_id': birth['boot_id'], 'orig_argv': argv, 'environment': environment,
                   'cwd': '/source', 'event': 'cpython.run_command', 'flags': [1, 1, 0],
                   'body_sha256': digest((program + '\n').encode()), 'repository': False,
                   'repository_source_sha256': '0' * 64, 'source_role': 'source-bootstrap',
                   'manifest': str(manifest), 'manifest_sha256': manifest_pin,
                   'source_entry_sha256': digest(Path('/guard/primary_source_entry.py').read_bytes()),
                   'source_descriptors': [], 'source_mode': 'TEST-own-prebody-control'}
        profile_path = directory / (str(child) + '.json')
        receipt_path = directory / (str(child) + '.child-relative.json')
        diagnostic_path = Path('/work') / ('primary-native-state-' + str(child) + '.json')
        if diagnostic_path.exists():
            raise RuntimeError('child_relative_control_diagnostic_collision')
        receipt = {'schema': 'unrest.v047.child-relative-prebody.v1', 'token': token,
                   'identity': birth, 'view': None, 'constructor': None,
                   'prebody_required': True, 'allowed': False,
                   'refusal': {'control': 'explicit-own-native-prebody-denial'}}
        for path, value in ((profile_path, profile), (receipt_path, receipt)):
            with path.open('x') as stream:
                stream.write(json.dumps(value, sort_keys=True))
            os.chown(path, 20001, 20001)
            path.chmod(0o444)
        receipt_pin = digest(receipt_path.read_bytes())
        os.set_blocking(read, False)
        def tick(trace):
            while True:
                try:
                    data = os.read(read, 65536)
                except BlockingIOError:
                    return
                if not data:
                    return
                output.extend(data)
                if len(output) > 65536:
                    raise RuntimeError('child_relative_control_output_bound')
        def attached():
            os.write(start_write, b'1')
            close(start_write)
        allowed = [{'pid': child, 'path': PYTHON, 'argv': argv, 'environment': environment,
                    'cwd': '/source', 'sha256': binding['entry']['sha256']}]
        trace = OwnedTrace(child, allowed, 30, on_tick=tick, seize=True,
                           on_attached=attached, selective=True)
        result = trace.run()
        reaped = True
        tick(trace)
        close(read)
        diagnostic = json.loads(diagnostic_path.read_bytes())
        expected = {'token': token, 'receipt_sha256': receipt_pin}
        if (result['root_parent_wait_raw'] != 86 << 8 or result['poison']
                or diagnostic.get('child_relative_prebody_refusal') != expected
                or marker.exists() or output):
            raise RuntimeError('child_relative_control_denial_not_proved')
        with_expected = [row for row in result['records'] if row['kind'] == 'exec_attempt'
                         and row['pid'] == child and row['accepted'] is True
                         and row['path'] == PYTHON and row['argv'] == argv]
        if len(with_expected) != 1:
            raise RuntimeError('child_relative_control_exec_not_proved')
        with_birth = identity(child) if Path('/proc/' + str(child)).exists() else None
        if with_birth is not None:
            raise RuntimeError('child_relative_control_child_residue')
        record = {'kind': 'child_relative_own_native_denial_control', 'token': token,
                  'source_free_control': True, 'constructor_admission_claim': False,
                  'identity': birth, 'source_identity': credentials,
                  'parent_identity': process_identity(os.getpid()),
                  'entry': binding['entry'], 'library': binding['library'],
                  'source_entry_sha256': profile['source_entry_sha256'],
                  'argv_sha256': digest(json.dumps(argv).encode()), 'receipt_sha256': receipt_pin,
                  'native_prebody_refusal': diagnostic['child_relative_prebody_refusal'],
                  'original_parent_wait_raw': result['root_parent_wait_raw'],
                  'before_fds': before, 'body_ran': False, 'poison': result['poison']}
    finally:
        if child is not None and child > 0 and not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        for fd in sorted(owned):
            os.close(fd)
        owned.clear()
        if directory.is_symlink() or (directory.stat().st_dev, directory.stat().st_ino) != directory_key:
            raise RuntimeError('child_relative_control_receipt_namespace_drift')
        expected_files = {p for p in (profile_path, receipt_path) if p is not None}
        if set(directory.iterdir()) != expected_files:
            raise RuntimeError('child_relative_control_unowned_receipt')
        for path in sorted(expected_files):
            value = path.lstat()
            if not stat.S_ISREG(value.st_mode) or value.st_uid != 20001 or value.st_nlink != 1:
                raise RuntimeError('child_relative_control_receipt_cleanup_identity')
            path.unlink()
        directory.rmdir()
        if diagnostic_path is not None and diagnostic_path.exists():
            value = diagnostic_path.lstat()
            if not stat.S_ISREG(value.st_mode) or value.st_uid != 20000 or value.st_nlink != 1:
                raise RuntimeError('child_relative_control_diagnostic_cleanup_identity')
            diagnostic_path.unlink()
        if root.is_symlink() or (root.stat().st_dev, root.stat().st_ino) != root_key:
            raise RuntimeError('child_relative_control_owned_root_drift')
        shutil.rmtree(root)
    after = census()
    if before != after:
        raise RuntimeError('child_relative_control_parent_descriptors')
    record.update(after_fds=after, descriptors_closed=True, verified=True)
    return record
