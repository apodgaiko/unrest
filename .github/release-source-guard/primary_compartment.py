"""Execute the actual GitHub script under a separate finite primary authority."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil

from linux_compartment import source_credentials, observer_credentials
from linux_observation import process_identity
from linux_trace import OwnedTrace, install_observation_filter
from primary_policy import environment, plan, sha
from primary_authority import Authority
import dependency_closure
import primary_entry_build


STAGE = 'bootstrap'


def main():
    global STAGE
    if os.getpid() != 1 or os.getuid() != 0:
        raise RuntimeError('primary_bootstrap_identity')
    script = Path('/inputs/github-script.sh').read_bytes()
    workflow = Path('/source/.github/workflows/ci.yml').read_text()
    spec = plan(script, workflow)
    if spec != json.loads(Path('/inputs/plan.json').read_bytes()):
        raise RuntimeError('primary_script_plan_drift')
    STAGE = 'dependencies'
    dependency_closure.verify_source_view(Path('/environment-closure.json').read_bytes())
    STAGE = 'runtime'
    runtime = primary_entry_build.verify()
    env = environment()
    read, write = os.pipe2(os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    start_read, start_write = os.pipe2(os.O_CLOEXEC)
    STAGE = 'source_setup'
    child = os.fork()
    if child == 0:
        try:
            os.dup2(write, 1)
            os.dup2(write, 2)
            os.close(ready_read)
            os.close(start_write)
            source_credentials()
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            for name in ('home', 'tmp'):
                (Path('/work') / name).mkdir(mode=0o700)
            shutil.copytree('/opt/primary-cache', '/work/cache', symlinks=True)
            # Relocate only native-produced internal archive links.
            for path in sorted(Path('/work/cache').rglob('*')):
                if path.is_symlink():
                    target = os.readlink(path)
                    if target.startswith('/opt/primary-cache/'):
                        path.unlink()
                        path.symlink_to('/work/cache/' + target.removeprefix('/opt/primary-cache/'))
            install_observation_filter()
            os.setsid()
            os.chdir('/source')
            os.write(ready_write, b'R')
            os.close(ready_write)
            if os.read(start_read, 1) != b'1':
                os._exit(126)
            os.closerange(3, 1 << 20)
            os.execve(spec['shell_argv'][0], spec['shell_argv'], env)
        finally:
            os._exit(126)
    os.close(write)
    os.close(ready_write)
    os.close(start_read)
    observer_credentials()
    if os.read(ready_read, 1) != b'R':
        os.waitpid(child, 0)
        raise RuntimeError('primary_child_fence')
    os.close(ready_read)
    STAGE = 'authority'
    authority = Authority(spec, child, env)
    os.set_blocking(read, False)
    output = bytearray()
    def tick(trace):
        while True:
            try:
                part = os.read(read, 65536)
            except BlockingIOError:
                break
            if not part:
                break
            output.extend(part)
            if len(output) > 16 * 1024 * 1024:
                raise RuntimeError('primary_output_bound')
    def attached():
        os.write(start_write, b'1')
        os.close(start_write)
    root_identity = process_identity(child)
    if (root_identity['uids'] != [20000] * 4 or any(root_identity['capabilities'].values())
            or root_identity['no_new_privs'] != 1):
        raise RuntimeError('primary_child_credentials')
    allowed = [{'pid': child, 'path': spec['shell_argv'][0], 'argv': spec['shell_argv'],
                'environment': env, 'cwd': '/source',
                'sha256': sha(Path(spec['shell_argv'][0]).read_bytes())}]
    trace = None
    def resolve(pid, path, argv, values, cwd):
        return authority.resolve(trace, pid, path, argv, values, cwd)
    trace = OwnedTrace(child, allowed, spec['timeout_seconds'], on_tick=tick,
                       resolve_exec=resolve, seize=True, on_attached=attached, selective=True)
    failure = None
    STAGE = 'trace'
    try:
        result = trace.run()
        tick(trace)
    except BaseException:
        failure = 'trace_failure'
        result = {'records': trace.records, 'poison': trace.poison,
                  'root_parent_wait_raw': trace.root_parent_wait}
    os.close(read)
    waits = {row['child'] for row in result['records']
             if row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
             and (row['kind'] == 'original_parent_wait4' or row['reaps'])}
    children = {row['child'] for row in result['records'] if row['kind'] == 'kernel_child'
                and row['identity']['tgid'] == row['child']}
    native_failure = any(row['kind'] == 'kernel_exit' and row['raw'] == 86 << 8
                         for row in result['records'])
    diagnostics = []
    for row in authority.records:
        if row['kind'] == 'primary_native_preinit':
            path = Path('/work') / ('primary-native-state-' + str(row['pid']) + '.json')
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192:
                diagnostics.append(json.loads(path.read_bytes()))
    unregistered = children - set(authority.contexts)
    if unregistered:
        result['poison'].append('unregistered_process_birth')
    result.update({'unregistered_processes': sorted(unregistered), 'native_diagnostics': diagnostics, 'primary_plan': spec, 'primary_records': authority.records,
                   'primary_denials': authority.denials, 'failure_code': failure,
                   'native_preinit_refusal': native_failure,
                   'missing_parent_waits': sorted(children - waits),
                   'source_preexec_identity': root_identity,
                   'runtime_binding_sha256': sha(json.dumps(runtime, sort_keys=True).encode()),
                   'actual_script_sha256': hashlib.sha256(script).hexdigest(),
                   'all_commands_dispatched': authority.next_command == len(spec['commands']),
                   'source_checkpoint_ready': False, 'selected_carrier': None})
    envelope = {'kernel-source.json': base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode(),
                'source-output.log': base64.b64encode(output).decode()}
    print('PRIVATE-EVIDENCE:' + json.dumps(envelope, sort_keys=True), flush=True)
    return 0 if (result['root_parent_wait_raw'] == 0 and not result['poison']
                 and not authority.denials and not native_failure and not failure
                 and not children - waits and result['all_commands_dispatched']) else 2


if __name__ == '__main__':
    try:
        status = main()
    except BaseException as error:
        trace = error.__traceback__
        lines = []
        while trace is not None:
            lines.append(trace.tb_lineno)
            trace = trace.tb_next
        record = {'failure_code': 'bootstrap_failure', 'stage': STAGE, 'frame_lines': lines[-8:],
                  'source_checkpoint_ready': False, 'selected_carrier': None}
        envelope = {'kernel-source.json': base64.b64encode(json.dumps(record, sort_keys=True).encode()).decode()}
        print('PRIVATE-EVIDENCE:' + json.dumps(envelope, sort_keys=True), flush=True)
        status = 125
    raise SystemExit(status)
