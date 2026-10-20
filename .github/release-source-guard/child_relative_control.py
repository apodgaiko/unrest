"""Own source-free native denial; no constructor or original-case admission claim."""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import uuid

from finite.linux_identity import identity
from linux_compartment import source_credentials, observer_credentials
from linux_observation import process_identity
from linux_trace import OwnedTrace, install_observation_filter, ptrace
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
                continue  # listdir already closed its enumeration descriptor.
            raise
        rows.append({'fd': fd, 'device': value.st_dev, 'inode': value.st_ino,
                     'mode': value.st_mode, 'uid': value.st_uid, 'gid': value.st_gid,
                     'descriptor_flags': fcntl.fcntl(fd, fcntl.F_GETFD),
                     'status_flags': fcntl.fcntl(fd, fcntl.F_GETFL)})
    return rows


def exercise(binding, environment):
    token = uuid.uuid4().hex
    work_root = Path('/work') / ('child-relative-control-' + token)
    manifest = work_root / 'manifest.json'
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    owned = {read, write, ready_read, ready_write, start_read, start_write}
    child = None
    reaped = False
    directory = Path('/receipts/primary-startup')
    made_directory = False
    profiles = []
    trace = None
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
                work_root.mkdir(mode=0o700)
                (work_root / 'events').mkdir(mode=0o700)
                manifest.write_text(json.dumps({'events': str(work_root / 'events')}, sort_keys=True))
                manifest.chmod(0o444)
                install_observation_filter()
                os.setsid()
                os.chdir('/source')
                os.write(ready_write, b'R')
                os.close(ready_write)
                header = os.read(start_read, 8)
                if len(header) != 8:
                    os._exit(126)
                size = int.from_bytes(header, 'big')
                if not 0 < size <= 4088:
                    os._exit(126)
                data = bytearray()
                while len(data) < size:
                    part = os.read(start_read, size - len(data))
                    if not part:
                        os._exit(126)
                    data.extend(part)
                os.closerange(3, 1 << 20)
                os.execve(PYTHON, [PYTHON, '-I', '-S', '-c', data.decode()], environment)
            finally:
                os._exit(126)
        for fd in (write, ready_write, start_read):
            close(fd)
        if os.read(ready_read, 1) != b'R':
            raise RuntimeError('child_relative_control_fence')
        close(ready_read)
        # This dedicated coordinator uses the existing credential transition.
        # The primary capsule's bootstrap parent keeps its original credentials.
        observer_credentials()
        before = census()
        birth, credentials = identity(child), process_identity(child)
        if (birth['ppid'] != os.getpid() or credentials['uids'] != [20000] * 4
                or credentials['gids'] != [20000] * 4 or any(credentials['capabilities'].values())
                or credentials['no_new_privs'] != 1):
            raise RuntimeError('child_relative_control_identity')
        guard_path = Path('/guard/finite/runtime_guard.py')
        spec = importlib.util.spec_from_file_location('_child_relative_control_bootstrap', guard_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        payload = {'token': token, 'class': 'child-relative-own-denial-control', 'case': None,
                   'mode': 'inline', 'target': 'print("unadmitted own body")', 'isolated': True,
                   'sys_argv': ['-c'], 'orig_argv': [], 'path0': '',
                   'source_binding': {'path': '/guard/child_relative_control.py', 'line': 1,
                                      'sha256': digest(Path('/guard/child_relative_control.py').read_bytes())}}
        manifest_pin = digest(manifest.read_bytes())
        program = module.bootstrap(str(manifest), manifest_pin, str(guard_path),
                                   digest(guard_path.read_bytes()), payload)
        argv = [PYTHON, '-I', '-S', '-c', program]
        frame = len(program.encode()).to_bytes(8, 'big') + program.encode()
        if len(frame) > 4096:
            raise RuntimeError('child_relative_control_atomic_frame')
        if directory.exists() or directory.is_symlink():
            raise RuntimeError('child_relative_control_namespace_exists')
        directory.mkdir(mode=0o755)
        made_directory = True
        directory_key = (directory.stat().st_dev, directory.stat().st_ino)
        profile = {'pid': child, 'parent': os.getpid(), 'start_ticks': birth['start_ticks'],
                   'boot_id': birth['boot_id'], 'orig_argv': argv, 'environment': environment,
                   'cwd': '/source', 'event': 'cpython.run_command', 'flags': [1, 1, 0],
                   'body_sha256': digest((program + '\n').encode()), 'repository': False,
                   'repository_source_sha256': digest(Path('/source/src/unrest_harness/repository_contract.py').read_bytes()),
                   'source_role': 'source-bootstrap', 'manifest': str(manifest),
                   'manifest_sha256': manifest_pin,
                   'source_entry_sha256': digest(Path('/guard/primary_source_entry.py').read_bytes()),
                   'source_descriptors': [], 'source_mode': 'TEST-own-prebody-control'}
        receipt = {'schema': 'unrest.v047.child-relative-prebody.v1', 'token': token,
                   'identity': birth, 'view': None, 'constructor': None, 'prebody_required': True,
                   'allowed': False, 'refusal': {'control': 'explicit-own-native-prebody-denial'}}
        for name, value in ((str(child) + '.json', profile), (str(child) + '.child-relative.json', receipt)):
            path = directory / name
            with path.open('x') as stream:
                stream.write(json.dumps(value, sort_keys=True))
            path.chmod(0o444)
            profiles.append(path)
        receipt_pin = digest(profiles[-1].read_bytes())
        output = bytearray()
        os.set_blocking(read, False)
        def tick(trace):
            while True:
                try:
                    part = os.read(read, 65536)
                except BlockingIOError:
                    return
                if not part:
                    return
                output.extend(part)
                if len(output) > 65536:
                    raise RuntimeError('child_relative_control_output_bound')
        def attached():
            if os.write(start_write, frame) != len(frame):
                raise RuntimeError('child_relative_control_short_frame')
            close(start_write)
        allowed = [{'pid': child, 'path': PYTHON, 'argv': argv, 'environment': environment,
                    'cwd': '/source', 'sha256': binding['entry']['sha256']}]
        trace = OwnedTrace(child, allowed, 30, on_tick=tick, seize=True,
                           on_attached=attached, selective=True)
        result = trace.run()
        reaped = True
        tick(trace)
        close(read)
        diagnostic_path = Path('/work') / ('primary-native-state-' + str(child) + '.json')
        diagnostic = json.loads(diagnostic_path.read_bytes())
        expected = {'token': token, 'receipt_sha256': receipt_pin}
        if (result['root_parent_wait_raw'] != 86 << 8 or result['poison'] or output
                or diagnostic.get('child_relative_prebody_refusal') != expected
                or any((work_root / 'events').iterdir())):
            raise RuntimeError('child_relative_control_denial_not_proved')
        attempts = [row for row in result['records'] if row['kind'] == 'exec_attempt'
                    and row['pid'] == child and row['accepted'] is True
                    and row['path'] == PYTHON and row['argv'] == argv]
        if len(attempts) != 1 or Path('/proc/' + str(child)).exists():
            raise RuntimeError('child_relative_control_exec_or_wait')
        root_info = work_root.lstat()
        record = {'kind': 'child_relative_own_native_denial_control', 'token': token,
                  'source_free_control': True, 'constructor_admission_claim': False,
                  'identity': birth, 'source_identity': credentials,
                  'parent_identity': process_identity(os.getpid()),
                  'entry': binding['entry'], 'library': binding['library'],
                  'source_entry_sha256': profile['source_entry_sha256'],
                  'argv_sha256': digest(json.dumps(argv).encode()), 'receipt_sha256': receipt_pin,
                  'native_prebody_refusal': diagnostic['child_relative_prebody_refusal'],
                  'original_parent_wait_raw': result['root_parent_wait_raw'],
                  'bootstrap_entered': False, 'body_ran': False, 'poison': result['poison'],
                  'work_root': str(work_root), 'work_root_identity': [root_info.st_dev, root_info.st_ino],
                  'manifest_sha256': manifest_pin, 'diagnostic_sha256': digest(diagnostic_path.read_bytes())}
    finally:
        if child is not None and child > 0 and not reaped:
            close(start_write)  # An unstarted source observes EOF and exits126.
            if trace is not None:
                try:
                    ptrace(8, child)
                except OSError:
                    pass  # The trace may already have collected this owned child.
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        for fd in sorted(owned):
            os.close(fd)
        if made_directory:
            if directory.is_symlink() or (directory.stat().st_dev, directory.stat().st_ino) != directory_key:
                raise RuntimeError('child_relative_control_namespace_drift')
            if set(directory.iterdir()) != set(profiles):
                raise RuntimeError('child_relative_control_unowned_receipt')
            for path in sorted(profiles):
                value = path.lstat()
                if not stat.S_ISREG(value.st_mode) or value.st_uid != 20001 or value.st_nlink != 1:
                    raise RuntimeError('child_relative_control_receipt_cleanup_identity')
                path.unlink()
            directory.rmdir()
    # Before included the two remaining owned pipe descriptors. Compare the
    # unchanged inherited coordinator descriptors after subtracting exactly them.
    before = [row for row in before if row['fd'] not in {read, start_write}]
    after = census()
    if before != after:
        raise RuntimeError('child_relative_control_parent_descriptors')
    record.update(before_fds=before, after_fds=after, descriptors_closed=True, verified=True)
    return record


def run(binding, environment):
    if os.getpid() != 1 or os.geteuid() != 0 or binding['entry']['path'] != PYTHON:
        raise RuntimeError('child_relative_control_parent')
    before = census()
    read, write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(read)
        try:
            result = exercise(binding, environment)
            data = json.dumps({'result': result}, sort_keys=True).encode()
            if len(data) > 65536:
                raise RuntimeError('child_relative_control_result_bound')
            while data:
                count = os.write(write, data)
                if count <= 0:
                    raise RuntimeError('child_relative_control_result_write')
                data = data[count:]
            os.close(write)
            os._exit(0)
        except BaseException as error:
            frame = error.__traceback__
            locations = []
            while frame is not None:
                locations.append({'file_sha256': digest(frame.tb_frame.f_code.co_filename.encode()),
                                  'line': frame.tb_lineno})
                frame = frame.tb_next
            data = json.dumps({'error': type(error).__name__, 'errno': getattr(error, 'errno', None),
                               'locations': locations[-8:]}).encode()
            os.write(write, data)
            os._exit(2)
    os.close(write)
    data = bytearray()
    try:
        while True:
            part = os.read(read, 65536)
            if not part:
                break
            data.extend(part)
            if len(data) > 65536:
                raise RuntimeError('child_relative_control_result_bound')
    finally:
        os.close(read)
        waited, raw = os.waitpid(child, 0)
    after = census()
    decoded = json.loads(data)
    if waited != child or raw != 0:
        return {'kind': 'child_relative_own_native_denial_control', 'verified': False,
                'source_free_control': True, 'constructor_admission_claim': False,
                'coordinator_pid': child, 'coordinator_actual_parent_wait_raw': raw,
                'failure': decoded, 'outer_before_fds': before, 'outer_after_fds': after}
    record = decoded['result']
    if (record['parent_identity']['pid'] != child or record['parent_identity']['ppid'] != os.getpid()
            or record['parent_identity']['uids'] != [20001] * 4 or before != after):
        raise RuntimeError('child_relative_control_coordinator_identity_or_descriptors')
    record.update(coordinator_actual_parent_wait_raw=raw, outer_before_fds=before, outer_after_fds=after)
    return record


def source_cleanup(record):
    if os.geteuid() != 20000 or record['constructor_admission_claim'] is not False:
        raise RuntimeError('child_relative_control_cleanup_owner')
    token = record['token']
    if len(token) != 32 or any(value not in '0123456789abcdef' for value in token):
        raise RuntimeError('child_relative_control_cleanup_token')
    root = Path('/work') / ('child-relative-control-' + token)
    info = root.lstat()
    if (str(root) != record['work_root'] or root.is_symlink() or root.resolve() != root
            or [info.st_dev, info.st_ino] != record['work_root_identity'] or info.st_uid != 20000
            or set(p.name for p in root.iterdir()) != {'manifest.json', 'events'}
            or digest((root / 'manifest.json').read_bytes()) != record['manifest_sha256']
            or any((root / 'events').iterdir())):
        raise RuntimeError('child_relative_control_cleanup_identity')
    manifest_info = (root / 'manifest.json').lstat()
    events_info = (root / 'events').lstat()
    if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_nlink != 1
            or manifest_info.st_uid != 20000 or not stat.S_ISDIR(events_info.st_mode)
            or events_info.st_uid != 20000):
        raise RuntimeError('child_relative_control_cleanup_members')
    diagnostic = Path('/work') / ('primary-native-state-' + str(record['identity']['pid']) + '.json')
    info = diagnostic.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20000 or info.st_nlink != 1
            or digest(diagnostic.read_bytes()) != record['diagnostic_sha256']):
        raise RuntimeError('child_relative_control_cleanup_diagnostic')
    diagnostic.unlink()
    shutil.rmtree(root)


def confirm_source_cleanup(record):
    for path in (Path(record['work_root']), Path('/work') / (
            'primary-native-state-' + str(record['identity']['pid']) + '.json')):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise RuntimeError('child_relative_control_cleanup_incomplete')
    record['source_cleanup_verified'] = True
