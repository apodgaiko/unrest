"""Run selected original cases in a private, measured Linux generation.

This is a bounded integration checkpoint, not full source certification. The
root driver only prepares inputs and settles its own children. Admission and
original-parent wait joins run in the separate reduced-credential observer.
"""
from __future__ import annotations

import base64
import ctypes
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import traceback


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def inventory(root):
    """Measure private runtime/dependency copies, including large extension DSOs."""
    rows, total = [], 0
    members = sorted(root.rglob('*'))
    require(len(members) <= 20000, 'input inventory bound')
    for path in members:
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode), 'input member custody')
        require(not stat.S_IMODE(before.st_mode) & 0o6022, 'mutable or privileged input')
        if stat.S_ISDIR(before.st_mode):
            continue
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= 64 * 1024 * 1024, 'input member custody')
        total += before.st_size
        require(total <= 512 * 1024 * 1024, 'input total byte bound')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            pin = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = os.fstat(stream.fileno())
        # Reading can legitimately advance atime on Linux. Bind byte-affecting
        # identity, ownership, mode, size and nanosecond change timestamps.
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(identity(before) == identity(after) == identity(path.lstat()), 'input measurement race')
        rows.append([str(path.relative_to(root)), stat.S_IMODE(before.st_mode), before.st_size, pin])
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def prepare(binding, checkout, root):
    from content_manifest import capture, encode
    require(subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=checkout).decode().strip()
            == binding['head'], 'source revision binding')
    require(not subprocess.check_output(['/usr/bin/git', 'diff', '--name-only', 'HEAD'], cwd=checkout),
            'source tracked drift')
    names = subprocess.check_output(['/usr/bin/git', 'ls-files', '-z'], cwd=checkout).decode().split('\0')[:-1]
    source = root / 'source'
    source.mkdir(mode=0o755)
    manifest = capture(checkout, sorted(names))
    for row in manifest['files']:
        target = source / row['path']
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(checkout / row['path'], target)
        target.chmod(row['mode'])
    require(capture(source, sorted(names)) == manifest, 'private source copy changed')
    dependencies = root / 'dependencies'
    original = checkout / '.venv/lib/python3.13/site-packages'
    # Dereference only contained regular file aliases. Never carry host links
    # or hardlink aliases into the read-only generation.
    for member in sorted(original.rglob('*')):
        target = member.resolve(strict=True)
        require(target.is_relative_to(original) and (target.is_file() or target.is_dir())
                and not (member.is_symlink() and target.is_dir()), 'dependency alias refused')
    shutil.copytree(original, dependencies, symlinks=False, ignore=shutil.ignore_patterns('__pycache__'))
    for member in [dependencies, *sorted(dependencies.rglob('*'))]:
        member.chmod(0o755 if member.is_dir() or member.stat().st_mode & 0o111 else 0o644)
    owned = root / 'owned'
    owned.mkdir(mode=0o700)
    os.chown(owned, 20000, 20000)
    for name in ('home', 'tmp'):
        directory = owned / name
        directory.mkdir(mode=0o700)
        os.chown(directory, 20000, 20000)
    profiles = Path(binding['profiles'])
    require(profiles.is_dir() and profiles.stat().st_uid == 20001, 'protected profiles missing')
    raw = encode(manifest)
    target = profiles / 'source-manifest.json'
    with target.open('xb') as stream:
        stream.write(raw)
    target.chmod(0o444)
    os.chown(target, 20001, 20001)
    runtime = Path(binding['entry']['path']).parent.parent
    support = Path(binding['support'])
    return {'checkout': str(source), 'owned': str(owned), 'dependencies': str(dependencies),
            'runtime_root': str(runtime), 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'support_sha256': inventory(support), 'runtime_sha256': inventory(runtime),
            'dependency_sha256': inventory(dependencies)}


def isolate(metadata, support):
    libc = ctypes.CDLL(None, use_errno=True)
    # Private mount/network/IPC namespaces; no shared-host mount mutation.
    require(libc.unshare(0x00020000 | 0x40000000 | 0x08000000) == 0, 'private namespace refused')
    def mount(source, target, flags):
        if libc.mount(source, target, None, ctypes.c_ulong(flags), None):
            raise OSError(ctypes.get_errno(), 'private input mount refused')
    mount(None, b'/', (1 << 18) | (1 << 14))  # private recursively
    points = (metadata['checkout'], metadata['dependencies'], metadata['runtime_root'], support)
    for point in points:
        encoded = os.fsencode(point)
        mount(encoded, encoded, 4096)
        mount(None, encoded, 4096 | 32 | 1 | 2 | 4)  # bind remount ro,nosuid,nodev
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        request = struct.pack('16sH14x', b'lo', 0)
        current = fcntl.ioctl(stream.fileno(), 0x8913, request)
        flags = struct.unpack_from('H', current, 16)[0]
        fcntl.ioctl(stream.fileno(), 0x8914, struct.pack('16sH14x', b'lo', flags | 1))
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if fields[4] in points:
            info = os.stat(fields[4], follow_symlinks=False)
            require('ro' in fields[5].split(','), 'private input remained writable')
            mounts[fields[4]] = [int(fields[0]), info.st_dev, info.st_ino]
    require(set(mounts) == set(points), 'private mount inventory incomplete')
    return {**metadata, 'mounts': mounts}


def settle(pid, terminate=False, deadline=None):
    try:
        actual, raw = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return None
    if actual:
        return raw
    if terminate:
        os.kill(pid, signal.SIGKILL)
    if deadline is None:
        deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        actual, raw = os.waitpid(pid, os.WNOHANG)
        if actual:
            return raw
        time.sleep(.001)
    raise RuntimeError('owned host cleanup actual wait missing')


def worker(binding, metadata, raw_directory):
    from compartment import credentials
    from linux_trace import OwnedTrace, install_observation_filter
    from source_observer import Observer
    from source_profile import ROOT_COMMAND
    metadata = isolate(metadata, binding['support'])
    timeout = (170 if len(metadata['cases']) > 3 else 60) if metadata['cases'][0].startswith('tests/test_acp_cleanup.py::') else 30 if len(metadata['cases']) in (3, 42) else 60 if len(metadata['cases']) == 2 else 170
    start_read, start_write = os.pipe()
    ready_read, ready_write = os.pipe()
    output_read, output_write = os.pipe()
    environment = {'HOME': str(Path(metadata['owned']) / 'home'), 'TMPDIR': str(Path(metadata['owned']) / 'tmp'),
                   'PATH': '/usr/bin:/bin', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    vector = [binding['entry']['path'], '-I', '-S', '-c', ROOT_COMMAND]
    child = os.fork()
    if child == 0:
        try:
            os.close(start_write)
            os.close(ready_read)
            with open('/dev/null', 'rb') as stream:
                os.dup2(stream.fileno(), 0)
            os.dup2(output_write, 1)
            os.dup2(output_write, 2)
            os.chdir(metadata['checkout'])
            credentials(20000)
            os.setsid()
            install_observation_filter()
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                os._exit(125)
            os.closerange(3, 1 << 20)
            os.execve(vector[0], vector, environment)
        finally:
            os._exit(125)
    observer, trace, result, failure = None, None, None, None
    os.close(start_read)
    os.close(ready_write)
    os.close(output_write)
    try:
        credentials(20001)
        require(bool(select.select([ready_read], [], [], 5)[0]) and os.read(ready_read, 1) == b'R',
                'source held startup handshake')
        os.close(ready_read)
        observer = Observer(binding, metadata, child, output_read)
        allowed = [{'pid': child, 'path': vector[0], 'argv': vector, 'environment': environment,
                    'cwd': metadata['checkout'], 'sha256': binding['entry']['sha256']}]
        trace = OwnedTrace(child, allowed, timeout, start_write=start_write, selective=True, cleanup_seconds=5,
                           on_attached=lambda: observer.consume(trace), on_tick=observer.tick,
                           resolve_exec=lambda *args: observer.resolve(trace, *args))
        result = trace.run()
        observer.tick(trace)
        require(result['root_parent_wait_raw'] == 0 and not result['poison'] and not observer.ledger.poison
                and observer.finished and observer.completed == metadata['cases']
                and not observer.frames and not observer.pair_intents and not observer.endpoints.poison and not observer.eof_drains
                and all(intent['consumed'] for intent in observer.intents.values()), 'original source completion refused')
    except BaseException:
        failure = traceback.format_exc()
        if trace is None:
            os.close(start_write)  # Held subject receives EOF, never a synthetic reap.
            status = settle(child)
            (raw_directory / 'held-source-cleanup.json').write_text(json.dumps({'actual_parent_wait': status}))
        raise
    finally:
        record = {'schema': 'unrest.bootstrap-source-result.v1', 'source_checkpoint_ready': False,
                  'release_certified': False, 'completed': [] if observer is None else observer.completed,
                  'result': result, 'failure': failure, 'metadata': metadata,
                  'kernel': [] if trace is None else trace.records,
                  'controls': [] if observer is None else observer.controls,
                  'endpoint_observations': None if observer is None else {
                      'listeners': {key: asdict(value) for key, value in observer.endpoints.listeners.items()},
                      'routes': {key: asdict(value) for key, value in observer.endpoints.routes.items()},
                      'connections': [asdict(value) for value in observer.endpoints.connections.values()],
                      'negative_probes': {case: {'socket': asdict(value['socket']), 'attempts': value['attempts']}
                          for case, value in observer.probe_ports.items()}},
                  'interrupted_connections': [] if observer is None else observer.interrupted_records,
                  'poison': [] if observer is None else observer.ledger.poison,
                  'output_base64': '' if observer is None else base64.b64encode(observer.output).decode()}
        (raw_directory / 'source-result.json').write_text(json.dumps(record, sort_keys=True))
        if observer is not None:
            observer.close()


def children():
    rows = Path('/proc/self/task/' + str(os.getpid()) + '/children').read_text().split()
    require(len(rows) <= 32 and all(row.isdecimal() for row in rows), 'host child census bound')
    return sorted(int(row) for row in rows)



def drain_owned(rows):
    deadline = time.monotonic() + 5
    while children():
        require(time.monotonic() < deadline and len(rows) < 32, 'bounded adopted cleanup')
        # Reaping this root may reparent its own children to the dedicated
        # driver. Re-census until empty under the same deadline.
        for child in children():
            require(len(rows) < 32, 'adopted population bound')
            rows.append({'pid': child, 'actual_wait': settle(child, terminate=True, deadline=deadline),
                         'original_parent_wait_proven': False})

def main():
    require(sys.platform == 'linux' and os.getuid() == 0 and (len(sys.argv) == 2 or len(sys.argv) == 3 and sys.argv[2] in ('bootstrap27', 'ordinary3', 'ordinary42', 'cleanup3', 'cleanup7', 'cleanup9', 'cleanup5', 'cleanup12', 'cleanup15', 'cleanup27')),
            'source host requires exact root Linux invocation')
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    binding_file = Path(sys.argv[1]).resolve(strict=True)
    binding = json.loads(binding_file.read_bytes())
    root = binding_file.parent
    require(root.name == 'guard-native-control' and binding['profiles'] == str(root / 'profiles'), 'host output binding')
    for name in ('entry', 'bootstrap', 'source', 'library', 'compiler', 'runtime', 'recipient'):
        row = binding[name]
        require(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest() == row['sha256'], 'native host input drift')
    require(not children(), 'source host must begin childless')
    require(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'source host subreaper required')
    def interrupted(signum, frame):
        raise TimeoutError('source host outer deadline')
    signal.signal(signal.SIGTERM, interrupted)
    raw_directory = root / 'source-private'
    raw_directory.mkdir(mode=0o700)
    os.chown(raw_directory, 20001, 20001)
    success = False
    try:
        from bootstrap_cases import BOOTSTRAP
        from controlled_startup import CASES
        from ordinary_acp import ALL_CASES, CASES as ORDINARY_CASES
        from cleanup_launch import ALL_CASES as CLEANUP_CASES, CASES as CLEANUP_SMOKE, RECORDED, FAULTS
        from cleanup_inline import NO_LAUNCH, STARTUP, CLIENT_CASES
        cleanup = {'cleanup3': CLEANUP_SMOKE, 'cleanup7': NO_LAUNCH, 'cleanup9': tuple(STARTUP), 'cleanup5': CLIENT_CASES, 'cleanup12': RECORDED, 'cleanup15': FAULTS, 'cleanup27': CLEANUP_CASES}
        cases = cleanup[sys.argv[2]] if len(sys.argv) == 3 and sys.argv[2] in cleanup else (BOOTSTRAP if sys.argv[2] == 'bootstrap27' else ALL_CASES if sys.argv[2] == 'ordinary42' else ORDINARY_CASES) if len(sys.argv) == 3 else CASES
        metadata = {**prepare(binding, Path.cwd().resolve(strict=True), root), 'cases': list(cases)}
        pid = os.fork()
        if pid == 0:
            try:
                worker(binding, metadata, raw_directory)
            except BaseException:
                (raw_directory / 'worker-failure.txt').write_text(traceback.format_exc())
                os._exit(125)
            os._exit(0)
        raw, deadline = None, time.monotonic() + (190 if cases == CLEANUP_CASES else 80 if cases == CLEANUP_SMOKE else 50 if len(cases) in (3, 42) else 80 if len(cases) == 2 else 190)
        try:
            while raw is None:
                actual, status = os.waitpid(pid, os.WNOHANG)
                if actual:
                    raw = status
                elif time.monotonic() > deadline:
                    raise TimeoutError('source observer finite deadline')
                else:
                    time.sleep(.005)
        finally:
            if raw is None:
                raw = settle(pid, terminate=True)
            (raw_directory / 'observer-parent-wait.json').write_text(json.dumps({'actual_parent_wait': raw}))
        require(raw == 0, 'original source integration failed; encrypted diagnostics retained')
        success = True
    finally:
        adopted: list[dict] = []
        try:
            drain_owned(adopted)
            if adopted:
                success = False
        finally:
            (raw_directory / 'fallback-cleanup.json').write_text(json.dumps(adopted))
            archive = root / 'source-private.tar'
            with tarfile.open(archive, 'w') as stream:
                stream.add(raw_directory, arcname='source-private', recursive=True)
            subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
                            '-in', str(archive), '-out', str(root / 'source-private.cms'), binding['recipient']['path']], check=True)
            archive.unlink()
        require(not children(), 'source host cleanup residue')
    require(success, 'original source integration did not complete')
    print(f'Original bootstrap integration: {len(cases)} original cases, actual parent waits; full source certification: false', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
