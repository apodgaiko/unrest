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
    if (hashlib.sha256(closure_bytes).hexdigest() !=
            'adac11fb5bbc8307263d775b8b89c776d1d71ee238ded6a764e480d862c34fac'
            or closure.inventory(Path('/opt/deps')) != json.loads(closure_bytes)):
        raise RuntimeError('source dependency closure drift')
    tracing = load('linux_trace', ROOT / 'linux_trace.py')
    policy = load('linux_supervisor', ROOT / 'linux_supervisor.py')
    manifest_path = Path('/inputs/source.json')
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    pin = hashlib.sha256(manifest_bytes).hexdigest()
    read, write = os.pipe2(os.O_CLOEXEC)
    argv = ['/opt/deps/bin/python', '-I', '-S', '/guard/source_runner.py', str(manifest_path), pin]
    child = os.fork()
    if child == 0:
        try:
            os.dup2(write, 1)
            os.dup2(write, 2)
            credentials.source_credentials()
            os.setsid()
            for name in ('home','tmp','events'):
                (Path('/work') / name).mkdir(mode=0o700)
            os.chdir('/source')
            os.closerange(3, 1 << 20)
            tracing.trace_me()
            os.execve(argv[0], argv, manifest['root_environment'])
        finally:
            os._exit(126)
    os.close(write)
    credentials.observer_credentials()
    stopped = os.waitid(os.P_PID, child, os.WSTOPPED | os.WEXITED | os.WNOWAIT)
    if stopped is None or stopped.si_code not in (os.CLD_STOPPED, os.CLD_TRAPPED):
        actual, raw = os.waitpid(child, 0)
        raise RuntimeError('source bootstrap did not stop: ' + str((actual, raw)))
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
    trace = None
    def resolve(pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
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
            if len(admitted) != 1 or not admitted[0]['class'].startswith('source-git:'):
                return False
            consumed.add(selected['token'])
            bound[pid] = selected
        if vector[0] != 'git':
            return False
        candidates = [directory + '/git' for directory in environment['PATH'].split(':')]
        if path not in candidates:
            return False
        if not Path(path).exists():
            return True
        if path not in manifest['copy_git'] or sha(path) != manifest['copy_git'][path]:
            return False
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
    trace = tracing.OwnedTrace(child, allowed, 180, on_tick=tick, resolve_exec=resolve)
    source_identity = observations.process_identity(child)
    if (source_identity['uids'] != [20000] * 4
            or any(source_identity['capabilities'].values())
            or source_identity['no_new_privs'] != 1 or source_identity['seccomp'] != 2):
        raise RuntimeError('source kernel UID/capability custody drift')
    try:
        result = trace.run()
        tick(trace)
    except Exception:
        result = {'root_parent_wait_raw': None, 'poison': trace.poison,
                  'records': trace.records, 'failure': traceback.format_exc()}
    finally:
        supervisor.close()
        os.close(read)
    result.update({'guard_poison': supervisor.poisoned, 'receipts': supervisor.receipts,
                   'abi': abi, 'source_preexec_identity': source_identity,
                   'observer': observations.process_identity(os.getpid())})
    envelope = {'kernel-source.json': base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode(),
                'source-output.log': base64.b64encode(log).decode()}
    for name in ('collection.json','summary.json','source.xml'):
        path = Path('/work') / name
        if path.is_file() and not path.is_symlink():
            envelope[name] = base64.b64encode(path.read_bytes()).decode()
    print('PRIVATE-EVIDENCE:' + json.dumps(envelope, sort_keys=True), flush=True)
    return 0 if result['root_parent_wait_raw'] == 0 and not result['poison'] and not supervisor.poisoned else 2

if __name__ == '__main__':
    raise SystemExit(main())
