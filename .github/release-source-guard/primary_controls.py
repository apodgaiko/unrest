"""Source-free controls for the primary native entry and sticky kernel poison."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import resource

from linux_compartment import source_credentials, observer_credentials
from linux_observation import process_identity
from linux_trace import OwnedTrace, install_observation_filter
from finite.linux_identity import identity
from primary_policy import PYTHON, environment
import primary_entry_build

CASES = {
    'isolated_no_site': ('import os,sys;assert os.getuid()==20000;assert sys.flags.isolated;assert sys.flags.no_site', 0),
    'private_path': ('import json;from pathlib import Path;v=json.loads(Path("/inputs/controls.json").read_bytes());assert not Path(v["private_host_path"]).exists()', 0),
    'native_unknown_caught': ('import subprocess\ntry: subprocess.run(["/bin/true"])\nexcept BaseException: pass\n', 86),
    'native_network': ('import socket;socket.create_connection(("127.0.0.1",1))', 86),
    'foreign_fd': ('raise AssertionError("body must not run")', 86),
    'kernel_unknown_caught': (None, 0),
}


def main():
    if os.getpid() != 1 or os.getuid() != 0:
        raise RuntimeError('primary_control_bootstrap')
    primary_entry_build.verify()
    sources = []
    env = environment()
    for name, (body, expected) in CASES.items():
        read, write = os.pipe2(os.O_CLOEXEC)
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        start_read, start_write = os.pipe2(os.O_CLOEXEC)
        foreign_read, foreign_write = os.pipe2(os.O_CLOEXEC)
        argv = [PYTHON, '-I', '-S', '-c', body] if body is not None else [
            '/bin/bash', '--noprofile', '--norc', '-c', '/bin/true || :']
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
                os.chdir('/work')
                os.write(ready_write, b'R')
                os.close(ready_write)
                if os.read(start_read, 1) != b'1':
                    os._exit(126)
                if name == 'foreign_fd':
                    os.dup2(foreign_read, 3, inheritable=True)
                    os.closerange(4, 128)
                else:
                    os.closerange(3, 128)
                os.execve(argv[0], argv, env)
            finally:
                os._exit(126)
        for fd in (write, ready_write, start_read, foreign_read, foreign_write):
            os.close(fd)
        if os.read(ready_read, 1) != b'R':
            raise RuntimeError('primary_control_fence')
        os.close(ready_read)
        sources.append((name, body, expected, child, argv, read, start_write))
    observer_credentials()
    directory = Path('/receipts/primary-startup')
    directory.mkdir(mode=0o755)
    results, outputs = [], bytearray()
    for name, body, expected, child, argv, read, start_write in sources:
        actual = identity(child)
        if body is not None:
            profile = {'pid': child, 'parent': os.getpid(), 'start_ticks': actual['start_ticks'],
                       'boot_id': actual['boot_id'], 'orig_argv': argv, 'environment': env,
                       'cwd': '/work', 'event': 'cpython.run_command', 'flags': [1, 1, 0],
                       'body_sha256': hashlib.sha256((body + '\n').encode()).hexdigest(),
                       'repository': False, 'repository_source_sha256': '0' * 64}
            path = directory / (str(child) + '.json')
            path.write_text(json.dumps(profile, sort_keys=True))
            path.chmod(0o444)
        os.set_blocking(read, False)
        def tick(trace):
            while True:
                try:
                    part = os.read(read, 65536)
                except BlockingIOError:
                    break
                if not part:
                    break
                outputs.extend(part)
                if len(outputs) > 1024 * 1024:
                    raise RuntimeError('primary_control_output')
        def attached():
            os.write(start_write, b'1')
            os.close(start_write)
        allowed = [{'pid': child, 'path': argv[0], 'argv': argv, 'environment': env,
                    'cwd': '/work', 'sha256': hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest()}]
        before = process_identity(child)
        trace = OwnedTrace(child, allowed, 30, on_tick=tick, seize=True,
                           on_attached=attached, selective=True)
        result = trace.run()
        tick(trace)
        os.close(read)
        result.update(control_id=name, expected_status=expected, source_identity=before)
        results.append(result)
    all_valid = True
    for result in results:
        valid = (type(result['root_parent_wait_raw']) is int
                 and os.waitstatus_to_exitcode(result['root_parent_wait_raw']) == result['expected_status']
                 and result['source_identity']['uids'] == [20000] * 4
                 and not any(result['source_identity']['capabilities'].values())
                 and result['source_identity']['no_new_privs'] == 1)
        if result['control_id'] == 'kernel_unknown_caught':
            waits = [row for row in result['records'] if row['kind'] == 'original_parent_wait4']
            valid = valid and result['poison'] == ['unknown_or_drifted_exec'] and len(waits) == 1
        else:
            valid = valid and result['poison'] == []
        result['control_verified'] = valid
        all_valid = all_valid and valid
    record = {'schema': 'unrest.v046.primary-controls.v1', 'controls': results,
              'source_checkpoint_ready': False, 'selected_carrier': None}
    envelope = {'kernel-source.json': base64.b64encode(json.dumps(record, sort_keys=True).encode()).decode(),
                'source-output.log': base64.b64encode(outputs).decode()}
    print('PRIVATE-EVIDENCE:' + json.dumps(envelope, sort_keys=True), flush=True)
    return 0 if all_valid else 2


if __name__ == '__main__':
    raise SystemExit(main())
