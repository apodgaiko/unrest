"""Focused original-source entry point, separate from synthetic controls."""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import types
import traceback

ROOT = Path('/guard')

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    if os.getuid() != 0 or os.getpid() != 1:
        raise RuntimeError('finite source bootstrap identity drift')
    credentials = load('linux_compartment', ROOT / 'linux_compartment.py')
    observations = load('linux_observation', ROOT / 'linux_observation.py')
    abi = observations.require_linux_abi()
    closure = load('dependency_closure', ROOT / 'dependency_closure.py')
    closure_bytes = Path('/environment-closure.json').read_bytes()
    abi['dependency_closure'] = closure.verify_source_view(closure_bytes)
    abi['profile_gate'] = load('profile_gate_build', ROOT / 'profile_gate_build.py').verify()
    abi['native_metadata'] = load('native_metadata', ROOT / 'native_metadata.py').verify()


    tracing = load('linux_trace', ROOT / 'linux_trace.py')
    policy = load('linux_supervisor', ROOT / 'linux_supervisor.py')
    manifest_path = Path('/inputs/source.json')
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    pin = hashlib.sha256(manifest_bytes).hexdigest()
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    argv = ['/opt/deps/bin/python', '-I', '-S', '/guard/source_runner.py', str(manifest_path), pin]
    child = os.fork()
    if child == 0:
        try:
            os.dup2(write, 1)
            os.dup2(write, 2)
            os.close(ready_read)
            os.close(start_write)
            credentials.source_credentials()
            tracing.install_observation_filter()
            os.setsid()
            for name in ('home','tmp','events','owned'):
                (Path('/work') / name).mkdir(mode=0o700)
            os.chdir('/source')
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                raise RuntimeError('source attach fence did not settle')
            os.closerange(3, 1 << 20)
            os.execve(argv[0], argv, manifest['root_environment'])
        finally:
            os._exit(126)
    os.close(write)
    os.close(ready_write)
    os.close(start_read)
    credentials.observer_credentials()
    if os.read(ready_read, 1) != b'R':
        actual, raw = os.waitpid(child, 0)
        raise RuntimeError('source bootstrap did not fence: ' + str((actual, raw)))
    os.close(ready_read)
    spec = {'manifest': str(manifest_path), 'pins': {str(manifest_path): pin},
            'endpoint': manifest['endpoint']}
    for name in ('custody_host.py','drain_host.py'):
        path = ROOT / 'finite' / name
        spec['pins'][str(path)] = sha(path)
    supervisor = policy.Supervisor(spec, types.SimpleNamespace(pid=child))
    objects = []
    for descriptor in (read, supervisor.channel.fileno()):
        info = os.fstat(descriptor)
        objects.append({'device': info.st_dev, 'inode': info.st_ino, 'type': stat.S_IFMT(info.st_mode)})
    Path('/receipts/HOST-FDS.json').write_text(json.dumps({'nonce': manifest['endpoint']['nonce'], 'objects': objects}))
    os.set_blocking(read, False)
    log = bytearray()
    consumed = set()
    bound = {}
    native_context = {}
    maintenance = set()
    git_policy = load('linux_git', ROOT / 'linux_git.py')
    trace = None
    def resolve(pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        if parent in native_context:
            if parent in maintenance:
                return False
            accepted = git_policy.admit(native_context[parent], path, vector, environment, cwd,
                                        manifest['git_maintenance_sha256'], manifest['owned_root'])
            if accepted:
                maintenance.add(parent)
            return accepted
        if pid not in bound:
            digest = hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            env_digest = hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
            events = supervisor.events()
            matching = [event for event in events if event['kind'] == 'actual_launch_binding'
                        and event['owner_pid'] == parent and event['token'] not in consumed
                        and event['transformed_argv_sha256'] == digest
                        and event['environment_sha256'] == env_digest and event['cwd'] == cwd]
            if len(matching) != 1:
                return False
            selected = matching[0]
            admitted = [event for event in events if event['kind'] == 'admitted'
                        and event['owner_pid'] == parent and event['token'] == selected['token']]
            if len(admitted) != 1 or parent not in supervisor.registered:
                return False
            registration = admitted[0]
            binding = registration.get('source_binding', {})
            source = binding.get('path', '')
            if source.startswith('/source/'):
                if manifest['product_pins'].get(source.removeprefix('/source/')) != binding.get('sha256'):
                    return False
            elif (registration['class'] != 'restart-custodian'
                  or source != '/guard/finite/restart_custody.py'
                  or manifest['direct_support']['files'].get(source) != binding.get('sha256')):
                return False
            consumed.add(selected['token'])
            bound[pid] = selected
        selected = bound[pid]
        if selected['bootstrap_sha256'] is not None:
            if (len(vector) < 3 or vector[-2] != '-c'
                    or hashlib.sha256(vector[-1].encode()).hexdigest() != selected['bootstrap_sha256']
                    or vector[0] not in manifest['runtime']['paths'] or path != vector[0]
                    or sha(path) != manifest['runtime']['sha256']):
                return False
            return True
        if vector[0] not in {'git', 'ps', 'sleep'}:
            return False
        candidates = [directory + '/' + vector[0] for directory in environment['PATH'].split(':')]
        if path not in candidates:
            return False
        if not Path(path).exists():
            return True
        images = {**manifest['copy_git'], **manifest['cohort_native_pins']}
        if path not in images or sha(path) != images[path]:
            return False
        if vector[0] == 'git':
            native_context[pid] = {'path': path, 'argv': vector, 'cwd': cwd, 'environment': environment}
        return True
    def tick(current):
        supervisor.tick()
        if current.poison and not supervisor.poisoned:
            supervisor.poison('kernel_exec_poison')
        while True:
            try:
                block = os.read(read, 65536)
            except BlockingIOError:
                break
            if not block:
                break
            log.extend(block)
            if len(log) > 16 * 1024 * 1024:
                raise RuntimeError('bounded source output exceeded')
    allowed = [{'pid': child, 'path': argv[0], 'argv': argv, 'environment': manifest['root_environment'],
                'cwd': '/source', 'sha256': manifest['runtime']['sha256']}]
    def attached():
        os.write(start_write, b'1')
        os.close(start_write)
    trace = tracing.OwnedTrace(child, allowed, 180, on_tick=tick, resolve_exec=resolve,
                              seize=True, on_attached=attached, selective=True)
    source_identity = observations.process_identity(child)
    if (source_identity['uids'] != [20000] * 4
            or any(source_identity['capabilities'].values())
            or source_identity['no_new_privs'] != 1 or source_identity['seccomp'] != 2):
        raise RuntimeError('source kernel UID/capability custody drift')
    try:
        result = trace.run()
        tick(trace)
    except Exception as error:
        supervisor.poison('controller_failure:' + type(error).__name__)
        result = {'root_parent_wait_raw': trace.root_parent_wait, 'poison': trace.poison,
                  'records': trace.records, 'failure': traceback.format_exc()}
    finally:
        supervisor.close()
        os.close(read)
    result.update({'event_timings': supervisor.event_timings, 'source_events': supervisor.events(), 'guard_poison': supervisor.poisoned, 'receipts': supervisor.receipts,
                   'receipt_ledger_poison': supervisor.ledger.poison,
                   'abi': abi, 'source_preexec_identity': source_identity,
                   'observer': observations.process_identity(os.getpid())})
    envelope = {'kernel-source.json': base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode(),
                'source-output.log': base64.b64encode(log).decode()}
    for name in ('collection.json','summary.json','source.xml','custodian.stderr'):
        path = Path(manifest['owned_root'] if name == 'custodian.stderr' else '/work') / name
        if path.is_file() and not path.is_symlink():
            envelope[name] = base64.b64encode(path.read_bytes()).decode()
    diagnostics = {}
    for pattern in ('*/workspace/.*-*.log', '*/workspace/.hermetic-acp-trace.jsonl'):
        for path in sorted((Path(manifest['owned_root']) / 'pytest').glob(pattern)):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                raise RuntimeError('finite source diagnostic carrier drift')
            diagnostics[str(path.relative_to(manifest['owned_root']))] = base64.b64encode(path.read_bytes()).decode()
    envelope['source-diagnostics.json'] = base64.b64encode(json.dumps(diagnostics, sort_keys=True).encode()).decode()
    print('PRIVATE-EVIDENCE:' + json.dumps(envelope, sort_keys=True), flush=True)
    return 0 if result['root_parent_wait_raw'] == 0 and not result['poison'] and not supervisor.poisoned else 2

if __name__ == '__main__':
    raise SystemExit(main())
