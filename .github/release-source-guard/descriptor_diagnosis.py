"""Finite descriptor diagnosis through the current guard, never source tests.

A real child installs the byte-current guard and authenticates READY to the
unchanged supervisor. No fixture, provider or payload process is launched.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import sysconfig
import time

SUPPORT = Path(__file__).resolve().parent
REPOSITORY = SUPPORT.parent.parent
CASES = ('journal', 'positive-loops', 'poisoned-loops', 'caller-owned-selector', 'pair-receipt-refusal')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def census():
    # fstat uses no enumeration descriptor, including at the original limit.
    rows = []
    for fd in range(128):
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        rows.append({'fd': fd, 'device': info.st_dev, 'inode': info.st_ino,
                     'mode': info.st_mode, 'uid': info.st_uid,
                     'inheritable': os.get_inheritable(fd),
                     'target': os.readlink('/proc/self/fd/' + str(fd))})
    return rows


def child(manifest_path, case):
    # The parent has created the actual supervisor before releasing this pipe.
    assert sys.stdin.buffer.read(1) == b'1'
    manifest = json.loads(Path(manifest_path).read_bytes())
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    endpoint = load('endpoint', SUPPORT / 'finite/endpoint.py')
    endpoint.early(manifest['endpoint'])
    guard = load('runtime_guard', SUPPORT / 'finite/runtime_guard.py')
    endpoint.attach(guard)
    guard.install(manifest_path, sha(manifest_path), case='guard-descriptor-control:' + case)
    guard.require_ready('root')
    assert endpoint.STATE['ready'] and endpoint.STATE['identity']['pid'] == os.getpid()
    before = census()
    records = []
    errors = []
    if case == 'journal':
        for index in range(256):
            guard.append({'kind': 'descriptor_control', 'ordinal': index})
            assert census() == before
    elif case == 'positive-loops':
        for index in range(32):
            loop = asyncio.new_event_loop()
            loop.close()
            assert census() == before
    elif case == 'pair-receipt-refusal':
        import socket
        try:
            socket.socketpair(type=socket.SOCK_DGRAM)
        except endpoint.EndpointRefusal as error:
            errors.append(error)
        else:
            raise AssertionError('non-stream pair receipt unexpectedly returned')
        assert census() == before
    elif case in {'poisoned-loops', 'caller-owned-selector'}:
        # Explicit diagnostic poison. No forbidden command or socket payload.
        try:
            endpoint.request('poison', reason='descriptor_lifetime_control')
        except endpoint.EndpointRefusal:
            pass
        assert endpoint.STATE['poison']
        if case == 'caller-owned-selector':
            import selectors
            selector = selectors.DefaultSelector()
            owner_fd = selector.fileno()
            try:
                try:
                    asyncio.SelectorEventLoop(selector)
                except endpoint.EndpointRefusal as error:
                    errors.append(error)
                else:
                    raise AssertionError('poisoned constructor unexpectedly returned')
                assert selector.fileno() == owner_fd
                assert os.fstat(owner_fd)
            finally:
                selector.close()
            assert census() == before
        for index in range(132 if case == 'poisoned-loops' else 0):
            previous = census()
            try:
                loop = asyncio.new_event_loop()
            except BaseException as error:
                # pytest retains exception frames too. Keep their real owners,
                # then identify each generation, rather than assuming GC closes it.
                errors.append(error)
                records.append({'ordinal': index, 'exception': type(error).__name__,
                                'errno': getattr(error, 'errno', None),
                                'before': previous, 'after': census()})
            else:
                loop.close()
                raise AssertionError('poisoned constructor unexpectedly returned')
        # Releasing traceback owners is only diagnostic cleanup, not an inferred
        # original wait or a successful source checkpoint.
    after = census()
    result = {'case': case, 'before': before, 'after': after, 'records': records,
              'journal_failed': guard._STATE.get('journal_failed', False),
              'guard_sha256': manifest['guard_sha256'],
              'endpoint_sha256': manifest['endpoint']['sha256'],
              'ready': endpoint.STATE['ready'], 'poison': endpoint.STATE['poison'],
              'runtime_sha256': manifest['runtime']['sha256']}
    # Stdio remains usable when open() cannot acquire a fresh descriptor.
    sys.stdout.write(json.dumps(result, sort_keys=True) + '\n')
    sys.stdout.flush()
    # The parent retains both status and original stdout, including at EMFILE.
    return 0


def run(root):
    assert sys.platform == 'linux' and sys.version_info[:2] == (3, 13)
    root.mkdir(mode=0o700)
    compiler = Path('/usr/bin/gcc').resolve(strict=True)
    module = root / 'profile_gate.so'
    result = subprocess.run([str(compiler), '-shared', '-fPIC', '-O2',
        '-I' + sysconfig.get_path('include'), str(SUPPORT / 'profile_gate.c'), '-o', str(module)],
        capture_output=True, check=False)
    assert result.returncode == 0
    host = load('descriptor_supervisor', SUPPORT / 'linux_supervisor.py')
    proofs = []
    for case in CASES:
        work = root / case
        work.mkdir(mode=0o700)
        events = work / 'events'
        events.mkdir()
        control = work / 'control'
        control.mkdir()
        finite = SUPPORT / 'finite'
        pins = {str(p): sha(p) for p in sorted(finite.glob('*.py'))}
        template = json.loads((finite / 'source-template.json').read_bytes())
        # No fabricated launch policy: retain every current exact registration;
        # this diagnostic calls none. Source identities come from actual bytes.
        manifest = {**template, 'checkout': str(REPOSITORY), 'owned_root': str(work),
            'events': str(events), 'guard': str(finite / 'runtime_guard.py'),
            'guard_sha256': sha(finite / 'runtime_guard.py'),
            'registry': {'path': str(finite / 'registry.py'), 'sha256': sha(finite / 'registry.py')},
            'direct_support': {'path': str(finite / 'direct_routes.py'), 'files': pins},
            'runtime': {'paths': [sys.executable], 'realpath': str(Path(sys.executable).resolve()),
                        'sha256': sha(sys.executable)},
            'product_pins': {str(p.relative_to(REPOSITORY)): sha(p)
                             for directory in ('src', 'tests', 'tools')
                             for p in sorted((REPOSITORY / directory).rglob('*.py'))},
            'http_source': str(REPOSITORY / 'tests/test_server.py'),
            'native_sysctl_offsets': {'system': 'Linux', 'abi': 'proc-stat-start-ticks'},
            'linux_profile_gate': {'path': str(module), 'sha256': sha(module),
                                   'source_sha256': sha(SUPPORT / 'profile_gate.c')}}
        manifest['endpoint'] = {'responses': str(control), 'nonce': os.urandom(32).hex(),
            'socket': str(control / 'receipt.sock'), 'observer_pid': os.getpid(),
            'observer_uid': os.getuid(), 'sha256': sha(finite / 'endpoint.py')}
        path = work / 'manifest.json'
        path.write_text(json.dumps(manifest, sort_keys=True))
        output_path, error_path = work / 'stdout', work / 'stderr'
        with output_path.open('wb') as output, error_path.open('wb') as errors:
            process = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()),
                '--child', str(path), case], stdin=subprocess.PIPE, stdout=output, stderr=errors,
                close_fds=True, cwd=REPOSITORY)
            spec = {'manifest': str(path), 'pins': {str(path): sha(path)}, 'endpoint': manifest['endpoint']}
            supervisor = host.Supervisor(spec, process)
            info = os.fstat(supervisor.channel.fileno())
            (control / 'HOST-FDS.json').write_text(json.dumps({
                'nonce': manifest['endpoint']['nonce'], 'objects': [
                    {'device': info.st_dev, 'inode': info.st_ino, 'type': __import__('stat').S_IFMT(info.st_mode)}]}))
            process.stdin.write(b'1')
            process.stdin.close()
            deadline = time.monotonic() + 90
            try:
                while True:
                    waited_pid, raw_status = os.waitpid(process.pid, os.WNOHANG)
                    if waited_pid:
                        assert waited_pid == process.pid
                        break
                    supervisor.tick()
                    if time.monotonic() > deadline:
                        process.kill()
                        raise TimeoutError('descriptor control deadline')
                    time.sleep(.001)
                status = os.waitstatus_to_exitcode(raw_status)
                process.returncode = status
                supervisor.tick()
                proofs.append({'case': case, 'status': status, 'child': process.pid,
                    'parent': os.getpid(), 'identity': supervisor.root,
                    'actual_owner_wait': {'pid': waited_pid, 'raw_status': raw_status,
                                          'numeric_status': status},
                    'receipts': supervisor.receipts, 'poison': supervisor.poisoned,
                    'events': supervisor.events(), 'stdout_sha256': sha(output_path),
                    'stderr_sha256': sha(error_path)})
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                supervisor.close()
    (root / 'proof.json').write_text(json.dumps({'schema': 'guard-descriptor-diagnosis-v1',
        'source_cases_executed': False, 'compiler_sha256': sha(compiler),
        'module_sha256': sha(module), 'source_sha256': sha(SUPPORT / 'profile_gate.c'),
        'proofs': proofs}, sort_keys=True))
    assert all(p['status'] == 0 for p in proofs)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--child' and sys.argv[3] in CASES:
        raise SystemExit(child(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 2:
        run(Path(sys.argv[1]))
    else:
        raise SystemExit(2)
