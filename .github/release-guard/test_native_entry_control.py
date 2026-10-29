"""Root-run native entry/kernel/READY composition controls, not a source suite.

The subject runs at UID20000 with no capabilities; the observer at UID20001
retains only DAC_READ_SEARCH and SYS_PTRACE. Raw diagnostics are encrypted with
the existing public recipient before upload; public output contains closed
case/status metadata only. No enforcement module imports this test driver.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time
import traceback

CASES = ('product-order-resolver-positive', 'product-order-resolver-fallback', 'product-order-positive', 'product-order-fallback', 'fastpath-positive', 'compile-bytes', 'compile-current', 'positive', 'caught-process', 'caught-network', 'bad-case', 'bad-argv',
         'bad-flags', 'bad-identity', 'bad-native', 'bad-entry', 'bad-nonce',
         'bad-token', 'bad-observer', 'extra-fd', 'bad-bootstrap', 'bad-environment', 'bad-cwd',
         'source-reject-control', 'source-reject-unknown', 'source-reject-profile')


def worker(case, binding, output):
    from compartment import credentials
    from control_transport import Admission, Frame, REQUEST_LIMIT, reply
    from linux_observation import process_identity
    from linux_trace import OwnedTrace, install_observation_filter
    from test_native_profile import BODIES
    from process_ledger import Birth, Ledger, canonical

    root = Path(binding['profiles'])
    if case.startswith('source-reject-'):
        binding = binding['production']
    native = binding['negative_entry'] if case == 'bad-bootstrap' else binding['entry']
    program = BODIES[case] if case in BODIES else BODIES['positive']
    argv = [native['path'], '-I', '-S', '-c', program]
    if case == 'bad-argv':
        argv[-1] = 'print("UNAPPROVED_BODY", flush=True)'
    nonce, token, seal = os.urandom(32).hex(), os.urandom(16).hex(), os.urandom(32).hex()
    start_read, start_write = os.pipe()
    ready_read, ready_write = os.pipe()
    read, write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(start_write)
            os.close(ready_read)
            os.dup2(write, 1)
            os.dup2(write, 2)
            credentials(20000)
            os.setsid()
            install_observation_filter()
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                os._exit(125)
            if case == 'extra-fd':
                os.set_inheritable(start_read, True)
                for descriptor in range(3, 256):
                    if descriptor != start_read:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
            else:
                os.closerange(3, 1 << 20)
            os.execve(native['path'], argv, {})
        finally:
            os._exit(125)
    try:
        os.write(output, (json.dumps({'owned_source': child}) + '\n').encode())
        os.close(start_read)
        os.close(ready_write)
        os.close(write)
        credentials(20001)
        if not select.select([ready_read], [], [], 5)[0] or os.read(ready_read, 1) != b'R':
            raise RuntimeError('native subject setup refused')
        os.close(ready_read)
        birth = Birth.read(process_identity(child))
        ledger = Ledger(nonce)
        failures=[]
        pins = (('entry', binding['bootstrap']['sha256']), ('native', native['sha256']))
        admission = Admission(ledger, frozenset({'body-ready'}))
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(root / 'control.sock'))
        os.chmod(root / 'control.sock', 0o666)
        server.listen(4)
        server.setblocking(False)
        clients = []
        captured = bytearray()
        next_control = 0
        os.set_blocking(read, False)
        profile = {'schema': 'unrest.native-control.v1', 'case': case if case in BODIES else 'positive',
                   'identity': canonical(process_identity(child)), 'observer': canonical(process_identity(os.getpid())),
                   'argv': [native['path'], '-I', '-S', '-c', program], 'environment': {}, 'cwd': os.getcwd(),
                   'flags': [1, 1, 0], 'native': native['path'], 'native_sha256': native['sha256'],
                   'entry_sha256': binding['bootstrap']['sha256'], 'nonce': nonce, 'token': token,
                   'seal': seal, 'generation': 1, 'mount_namespace': os.readlink('/proc/self/ns/mnt')}
        if case == 'source-reject-unknown':
            profile['schema'] = 'unknown'
        elif case == 'source-reject-profile':
            profile['schema'] = 'unrest.bootstrap-source.v1'
        if case == 'bad-case':
            profile['case'] = 'foreign'
        elif case == 'bad-flags':
            profile['flags'] = [True, 1, 0]
        elif case == 'bad-identity':
            profile['identity']['start_ticks'] += 1
        elif case in ('bad-native', 'bad-entry'):
            profile['native_sha256' if case == 'bad-native' else 'entry_sha256'] = '0' * 64
        elif case in ('bad-nonce', 'bad-token'):
            profile['nonce' if case == 'bad-nonce' else 'token'] = 'f' * (64 if case == 'bad-nonce' else 32)
        elif case == 'bad-environment':
            profile['environment'] = {'LC_CTYPE': 'C.UTF-8'}
        elif case == 'bad-cwd':
            profile['cwd'] = '/tmp'
        elif case == 'bad-observer':
            profile['observer']['uids'] = [0] * 4
        if case in ('fastpath-positive','compile-bytes','compile-current'):
            fixture=root/'compile-filter-fixture.py'
            with fixture.open('xb') as stream:
                stream.write(b'changed\n' if case=='compile-current' else b'pass\n')
            fixture.chmod(0o444)
        target = root / (str(child) + '.json')
        target.write_text(json.dumps(profile, sort_keys=True))
        target.chmod(0o444)

        def consume(trace):
            nonlocal next_control
            while ledger.next_kernel < len(trace.records):
                row = trace.records[ledger.next_kernel]
                ledger.kernel(ledger.next_kernel, row)
                if row['kind'] == 'kernel_root':
                    ledger.register(birth, token, pins, case=case, command_class='native-control', expected_generation=1)
            while len(clients) < 4:
                try:
                    stream, _ = server.accept()
                except BlockingIOError:
                    break
                frame = Frame(stream, REQUEST_LIMIT)
                clients.append(frame)
                frame.capture(ledger, birth, token, 20000)
            for frame in list(clients):
                if frame.received is None:
                    value = frame.read()
                    if value is None:
                        continue
                    try:
                        request = admission.admit(frame)
                        payload = request['payload']
                        ledger.ready(birth, request['kind'], payload)
                        next_control += 1
                        answer = {'ok': True}
                    except (ValueError, KeyError):
                        failures.append('native readiness refused')
                        answer = {'ok': False}
                    frame.answer(reply(frame.received, answer))
                if frame.send():
                    frame.stream.close()
                    clients.remove(frame)
            while True:
                try:
                    chunk = os.read(read, 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                captured.extend(chunk)
                if len(captured) > 1024 * 1024:
                    raise RuntimeError('native control output exceeded')

        allowed = [{'pid': child, 'path': native['path'], 'argv': argv,
                    'sha256': native['sha256'], 'environment': {}, 'cwd': os.getcwd()}]
        trace = OwnedTrace(child, allowed, 20, start_write=start_write, selective=True, cleanup_seconds=5)
    except BaseException:
        # Before SEIZE the subject is held on this pipe. EOF cancels startup;
        # retain an actual numeric parent wait rather than treating absence as reap.
        os.close(start_write)
        deadline = time.monotonic() + 5
        while True:
            pid, raw = os.waitpid(child, os.WNOHANG)
            if pid:
                (root / ('held-cleanup-' + case + '.json')).write_text(json.dumps({
                    'source': child, 'actual_parent_wait_raw': raw, 'source_checkpoint_ready': False}))
                if raw != 125 << 8:
                    raise RuntimeError('held native subject cleanup status')
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('held native subject cleanup wait missing')
            time.sleep(.001)
        raise
    try:
        # Install callbacks before the held source can execute its first byte.
        trace.on_tick = consume
        result = trace.run()
        consume(trace)
        raw = result['root_parent_wait_raw']
        actual_ready = ledger.process(birth).stage
        expected_status = 0 if case in ('positive','fastpath-positive','product-order-positive','product-order-resolver-positive') else 86 << 8
        if raw != expected_status or result['poison']:
            raise RuntimeError('native controlled return or trace refused')
        if case in BODIES:
            if next_control != 1 or failures:
                raise RuntimeError('native readiness order incomplete')
            marker = b'NATIVE_BODY_OK' if case in ('positive','fastpath-positive','product-order-positive','product-order-resolver-positive') else b'REFUSAL_CAUGHT'
            if marker not in captured:
                raise RuntimeError('native controlled body absent')
        elif b'NATIVE_BODY_OK' in captured or b'UNAPPROVED_BODY' in captured:
            raise RuntimeError('native unapproved body executed')
        if len([row for row in result['records'] if row['kind'] == 'exec_attempt']) != 1:
            raise RuntimeError('native caught forbidden launch reached kernel')
        with os.fdopen(output, 'w') as stream:
            stream.write(json.dumps({'case': case, 'raw': raw, 'controls': next_control,
                                     'terminal_stage': actual_ready, 'source_checkpoint_ready': False}) + '\n')
    finally:
        server.close()
        for frame in clients:
            frame.stream.close()
        os.close(read)
        target.unlink(missing_ok=True)
        if case in ('fastpath-positive','compile-bytes','compile-current'):
            (root/'compile-filter-fixture.py').unlink(missing_ok=True)
        (root / 'control.sock').unlink(missing_ok=True)
        # Retain both successful and failed raw diagnostics outside public logs.
        (root / ('raw-' + case + '.json')).write_text(json.dumps({
            'case': case, 'records': trace.records, 'poison': failures,
            'output_base64': base64.b64encode(captured).decode()}, sort_keys=True))


def settle_owned(pid: int, *, terminate: bool) -> int | None:
    """Only an actual direct/adopted child may be signalled or waited here."""
    try:
        actual, raw = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return None  # Already settled by its original parent; no reap claim.
    if actual:
        return raw
    if terminate:
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        actual, raw = os.waitpid(pid, os.WNOHANG)
        if actual:
            return raw
        time.sleep(.001)
    raise RuntimeError('owned native control terminal wait missing')


def direct_children() -> list[int]:
    values = Path('/proc/self/task/' + str(os.getpid()) + '/children').read_text().split()
    if len(values) > 32 or any(not value.isdecimal() for value in values):
        raise RuntimeError('native owned-child census bound')
    return sorted(int(value) for value in values)


def drain_adopted(profiles: Path, label: str = 'unexpected') -> None:
    """Dedicated driver starts childless; only its own forks can be adopted.

    This kernel-child fallback also covers observer death during a partial or
    missing PID notice. Every adopted settlement remains failure evidence.
    """
    from linux_observation import credential_identity
    rows = []
    for child in direct_children():
        identity = credential_identity(child)
        if identity['ppid'] != os.getpid() or identity['uids'][0] not in (0, 20000, 20001):
            raise RuntimeError('native adopted ownership contradiction')
        rows.append({'identity': identity, 'actual_wait': settle_owned(child, terminate=True),
                     'original_parent_wait_proven': False})
    if direct_children():
        raise RuntimeError('native owned cleanup residue')
    if rows:
        (profiles / (label + '-adopted-cleanup.json')).write_text(json.dumps(rows))
        raise RuntimeError('native control required fallback adopted cleanup')


def filesystem_access(binding: dict, profiles: Path) -> None:
    from compartment import credentials
    child = os.fork()
    if child == 0:
        try:
            credentials(20000)
            checks = [(binding[name]['path'], os.R_OK | os.X_OK)
                      for name in ('entry', 'negative_entry', 'runtime')]
            checks += [(binding['library']['path'], os.R_OK)]
            checks += [(str(path), os.R_OK) for path in sorted(Path(binding['support']).glob('*.py'))]
            os._exit(0 if all(os.access(path, mode, effective_ids=True) for path, mode in checks) else 125)
        except BaseException:
            os._exit(124)
    raw = settle_owned(child, terminate=False)
    (profiles / 'filesystem-access.json').write_text(json.dumps({'actual_source_wait': raw}))
    if raw != 0:
        raise RuntimeError('native source UID filesystem access refused')


def ownership_controls(profiles: Path) -> None:
    """Exercise adopted EOF and forced cleanup with real exact child waits."""
    from compartment import credentials
    for mode in ('eof', 'live', 'missing-notice'):
        read, write = os.pipe()
        observer = os.fork()
        if observer == 0:
            os.close(read)
            start_read, start_write = os.pipe()
            ready_read, ready_write = os.pipe()
            source = os.fork()
            if source == 0:
                os.close(write)
                os.close(start_write)
                os.close(ready_read)
                credentials(20000)
                os.write(ready_write, b'R')
                os.close(ready_write)
                if mode == 'eof':
                    os._exit(125 if os.read(start_read, 1) == b'' else 124)
                while True:
                    signal.pause()
            if mode != 'missing-notice':
                os.write(write, str(source).encode())
            os.close(start_read)
            os.close(ready_write)
            if not select.select([ready_read], [], [], 2)[0] or os.read(ready_read, 1) != b'R':
                os._exit(124)
            credentials(20001)
            os._exit(126)  # Deliberate observer loss; no successful wait claim.
        os.close(write)
        notice = b''
        try:
            observer_wait = settle_owned(observer, terminate=False)
            if not select.select([read], [], [], 1)[0]:
                raise RuntimeError('native ownership notice deadline')
            notice = os.read(read, 32)
            if mode == 'missing-notice':
                if observer_wait != 126 << 8 or notice:
                    raise RuntimeError('missing notice control shape')
                try:
                    drain_adopted(profiles, mode)
                except RuntimeError as error:
                    if str(error) != 'native control required fallback adopted cleanup':
                        raise
                else:
                    raise RuntimeError('missing notice was accepted as success')
                rows = json.loads((profiles / (mode + '-adopted-cleanup.json')).read_bytes())
                if (len(rows) != 1 or rows[0]['actual_wait'] != signal.SIGKILL
                        or rows[0]['original_parent_wait_proven'] is not False):
                    raise RuntimeError('missing notice actual cleanup wait')
                print('native ownership control missing-notice: actual fallback cleanup wait', flush=True)
                continue
            if observer_wait != 126 << 8 or not notice.isdigit():
                raise RuntimeError('adoption control owner failed')
            adopted = int(notice)
            adopted_wait = settle_owned(adopted, terminate=mode == 'live')
            expected = 125 << 8 if mode == 'eof' else signal.SIGKILL
            if adopted_wait != expected:
                raise RuntimeError('adoption control numeric wait failed')
            (profiles / ('adoption-control-' + mode + '.json')).write_text(json.dumps({
                'observer_wait': observer_wait, 'adopted_wait': adopted_wait,
                'original_parent_wait_proven': False}))
            print('native ownership control ' + mode + ': actual adopted cleanup wait', flush=True)
        finally:
            settle_owned(observer, terminate=True)
            if not notice and select.select([read], [], [], 1)[0]:
                notice = os.read(read, 32)
            if notice.isdigit():
                settle_owned(int(notice), terminate=True)
            os.close(read)


def diagnostic_binding(production, root):
    import subprocess
    support = root / 'test-support'
    support.mkdir(mode=0o755)
    source = Path(__file__).with_name('test_native_profile.py')
    bootstrap = support / source.name
    bootstrap.write_bytes(source.read_bytes())
    bootstrap.chmod(0o444)
    digest = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    def compile_entry(name, pin):
        target = Path(production['entry']['path']).with_name(name)
        if target.exists() or target.is_symlink():
            raise RuntimeError('test native output already exists')
        argv = [('-DGUARD_BOOTSTRAP=' + json.dumps(repr(str(bootstrap))) if value.startswith('-DGUARD_BOOTSTRAP=')
                 else '-DGUARD_BOOTSTRAP_SHA256=' + json.dumps(pin) if value.startswith('-DGUARD_BOOTSTRAP_SHA256=')
                 else value) for value in production['compiler_argv']]
        argv[-1] = str(target)
        subprocess.run(argv, check=True)
        target.chmod(0o755)
        return {'path':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    binding = {**production,'production':production,
        'bootstrap':{'path':str(bootstrap),'sha256':digest},
        'entry':compile_entry('python-unrest-guard-test',digest),
        'negative_entry':compile_entry('python-unrest-guard-test-badpin','0'*64)}
    record = root/'test-binding.json'
    record.write_text(json.dumps(binding,sort_keys=True)+'\n')
    record.chmod(0o444)
    return binding


def main():
    if sys.platform != 'linux' or os.getuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError('native control requires exact root CI invocation')
    import ctypes
    import subprocess
    # Adopt an exact subject if its observer fails. This is cleanup evidence,
    # never a substitute for the original parent's required successful wait.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        raise RuntimeError('native control subreaper unavailable')
    def interrupted(signum, frame):
        raise TimeoutError('native control outer deadline')
    signal.signal(signal.SIGTERM, interrupted)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    binding_path = Path(sys.argv[1]).resolve(strict=True)
    binding = json.loads(binding_path.read_bytes())
    root = binding_path.parent
    if root.name != 'guard-native-control' or binding['profiles'] != str(root / 'profiles'):
        raise RuntimeError('native controlled output root')
    def verify_inputs(record, names):
        for name in names:
            row = record[name]
            if hashlib.sha256(Path(row['path']).read_bytes()).hexdigest() != row['sha256']:
                raise RuntimeError('native build input changed')
    verify_inputs(binding, ('entry', 'bootstrap', 'source', 'library', 'compiler', 'runtime', 'recipient'))
    binding = diagnostic_binding(binding, root)
    verify_inputs(binding, ('entry', 'negative_entry', 'bootstrap', 'source', 'library', 'compiler', 'runtime', 'recipient'))
    if direct_children():
        raise RuntimeError('native dedicated driver must begin childless')
    profiles = Path(binding['profiles'])
    profiles.mkdir(mode=0o755)
    os.chown(profiles, 20001, 20001)
    success = False
    try:
        from test_namespace_supervisor import actual_namespace_control
        actual_namespace_control(profiles/'namespace-init-failure.txt')
        print('native namespace PID1 adoption and actual numeric waits verified',flush=True)
        filesystem_access(binding, profiles)
        ownership_controls(profiles)
        for case in CASES:
            read, write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read)
                try:
                    worker(case, binding, write)
                except BaseException:
                    (profiles / ('worker-failure-' + case + '.txt')).write_text(traceback.format_exc())
                    os._exit(125)
                os._exit(0)
            os.close(write)
            deadline = time.monotonic() + 35
            raw = None
            data = bytearray()
            os.set_blocking(read, False)
            try:
                while raw is None:
                    try:
                        data.extend(os.read(read, 65537))
                    except BlockingIOError:
                        pass
                    if len(data) > 65536:
                        raise RuntimeError('native control report bound')
                    pid, status = os.waitpid(child, os.WNOHANG)
                    if pid:
                        raw = status
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError('bounded native control worker')
                    time.sleep(.005)
                data.extend(os.read(read, 65537))
                if raw != 0 or len(data) > 65536:
                    raise RuntimeError('native control worker refused: ' + case)
                messages = data.splitlines()
                if len(messages) != 2:
                    raise RuntimeError('native control report framing')
                report = json.loads(messages[1])
                if report['case'] != case or report['source_checkpoint_ready'] is not False:
                    raise RuntimeError('native control report scope')
                print('native entry control ' + case + ': verified actual wait', flush=True)
            finally:
                observer_wait = settle_owned(child, terminate=True) if raw is None else raw
                try:
                    data.extend(os.read(read, 65537))
                except BlockingIOError:
                    pass
                messages = data.splitlines()
                if messages:
                    notice = json.loads(messages[0])
                    if (type(notice) is not dict or set(notice) != {'owned_source'}
                            or type(notice['owned_source']) is not int or notice['owned_source'] <= 0):
                        raise RuntimeError('native controlled ownership notice')
                    adopted_wait = settle_owned(notice['owned_source'], terminate=True)
                    if adopted_wait is not None:
                        (profiles / ('adopted-cleanup-' + case + '.json')).write_text(json.dumps({
                            'observer_wait': observer_wait, 'source_wait': adopted_wait,
                            'original_parent_wait_proven': False}))
                        raise RuntimeError('native subject required adopted cleanup')
                os.close(read)
        success = True
    finally:
        try:
            drain_adopted(profiles)
        finally:
            encrypt_evidence(root, binding, subprocess)
    return 0 if success else 1


def encrypt_evidence(root, binding, subprocess):
    archive = root / 'native-control-private.tar'
    with archive.open('wb') as stream:
        subprocess.run(['/usr/bin/tar', '-C', str(root), '-cf', '-', 'profiles', 'binding.json', 'test-binding.json', 'test-support'],
                       stdout=stream, check=True)
    encrypted = root / 'native-control-private.cms'
    subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc', '-outform', 'DER',
                    '-in', str(archive), '-out', str(encrypted),
                    binding['recipient']['path']], check=True)
    encrypted.chmod(0o644)
    archive.unlink()
    print('native control private evidence encrypted; source certification: false', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
