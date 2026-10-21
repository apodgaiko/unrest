"""Kernel custody of the closed original LaunchPlan script and alias fixtures."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import time

import linux_trace
from linux_observation import process_identity
from finite.linux_identity import identity
from finite.launch_preflight_routes import (
    ALIAS_CLASS, ALIAS_PATH, NATIVE_CLASS, PIN, SOURCE, fixture, specification,
)


def join(selected, vector, environment, cwd, manifest):
    registration = selected.get('registration', {})
    spec = specification(registration.get('case', ''), cwd)
    if spec is None:
        return None
    expected_class = ALIAS_CLASS if spec['kind'] == 'python-alias' else NATIVE_CLASS
    binding = {'path': '/source/' + SOURCE, 'line': spec['line'], 'sha256': PIN}
    root = Path(cwd)
    if (registration.get('class') != expected_class or registration.get('source_binding') != binding
            or manifest['product_pins'].get(SOURCE) != PIN
            or not root.is_relative_to(Path(manifest['owned_root']) / 'pytest')
            or root.resolve() != root or selected.get('cwd') != cwd
            or environment != spec['environment']
            or selected.get('owner_pid') != registration.get('owner_pid')
            or not selected.get('token') or selected['token'] != registration.get('token')
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()):
        return None
    if spec['kind'] == 'python-alias':
        if (str(spec['launcher']) != ALIAS_PATH or len(vector) != 3 or vector[:2] != ['adapter', '-c']
                or selected.get('bootstrap_sha256') != hashlib.sha256(vector[2].encode()).hexdigest()
                or ALIAS_PATH not in manifest['runtime']['paths']):
            return None
    elif vector != spec['argv'] or selected.get('bootstrap_sha256') is not None:
        return None
    return spec


def successful_exec(authority, trace, pid, spec, path, vector, environment, cwd, parent):
    """Advance only the admitted exec to its stop, before image instructions."""
    before = identity(pid)
    credentials = process_identity(pid)
    if (trace.pending.get(pid, {}).get('syscall') != 59
            or any(before[k] != trace.identities[pid][k] for k in ('pid', 'ppid', 'start_ticks', 'boot_id'))
            or credentials['uids'] != [20000] * 4
            or any(credentials['capabilities'].values()) or credentials['no_new_privs'] != 1):
        raise RuntimeError('launch_preflight_preexec_identity')
    pre = authority.census(pid)
    linux_trace.ptrace(24, pid)
    deadline = time.monotonic() + min(5, trace.timeout)
    while True:
        waited, raw = os.waitpid(pid, os.WNOHANG | 0x40000000)
        if waited:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('launch_preflight_exec_deadline')
        time.sleep(.0001)
    if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
        trace.active.discard(pid)
        trace.records.append({'kind': 'failure_cleanup_tracer_wait', 'pid': pid,
                              'raw': raw, 'normalized': os.waitstatus_to_exitcode(raw),
                              'root_original_parent': pid == trace.child})
    if waited != pid or not os.WIFSTOPPED(raw) or os.WSTOPSIG(raw) != signal.SIGTRAP or raw >> 16 != 4:
        raise RuntimeError('launch_preflight_exec_stop')
    trace.records.append({'kind': 'kernel_exec', 'pid': pid})
    root = Path('/proc/' + str(pid))
    expected_argv = ['/bin/sh', path, *vector[1:]] if spec['kind'] == 'script' else vector
    expected_pin = (authority.manifest['runtime']['sha256'] if spec['kind'] == 'python-alias'
                    else authority.manifest['cohort_native_pins']['/bin/sh' if spec['kind'] == 'script' else '/usr/bin/true'])
    if (identity(pid) != before or identity(parent['pid']) != parent
            or process_identity(pid) != credentials
            or (root / 'cmdline').read_bytes().split(b'\0') != [os.fsencode(v) for v in expected_argv] + [b'']
            or sorted((root / 'environ').read_bytes().split(b'\0')) != sorted([os.fsencode(k + '=' + v) for k, v in environment.items()] + [b''])
            or os.readlink(root / 'cwd') != cwd
            or hashlib.sha256((root / 'exe').read_bytes()).hexdigest() != expected_pin
            or authority.census(pid)
            or not fixture(spec, authority.manifest['runtime'], owner_uid=20000)):
        raise RuntimeError('launch_preflight_postexec_identity')
    authority.pipe_records.append({'kind': 'launch_preflight_exec_custody', 'pid': pid,
                                   'identity': before, 'owner_identity': parent,
                                   'image_sha256': expected_pin, 'closed_fds': [r['fd'] for r in pre],
                                   'first_instruction_not_executed': True})


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if not vector or (vector[0] != '/usr/bin/true' and Path(vector[0]).name not in {'adapter', 'invalid-format'}):
        return False
    selected = authority.bound.get(pid)
    if selected is None or selected.get('registration', {}).get('class') not in {ALIAS_CLASS, NATIVE_CLASS}:
        return False
    spec = join(selected, vector, environment, cwd, authority.manifest)
    if spec is None or path not in spec['paths']:
        return False
    parent = trace.identities[pid]['ppid']
    saved = authority.supervisor.registered.get(parent)
    if (saved is None or selected['owner_pid'] != parent or identity(parent) != saved['identity']
            or Path('/proc/' + str(pid) + '/cwd').resolve() != Path(cwd)
            or not fixture(spec, authority.manifest['runtime'], owner_uid=20000)):
        return False
    if spec['kind'] == 'script' and path != spec['paths'][-1]:
        blocked = Path(path)
        if not blocked.is_dir() or blocked.is_symlink():
            return False
        authority.pipe_records.append({'kind': 'launch_preflight_directory_probe', 'pid': pid,
                                       'token': selected['token'], 'expected_exec_return': -13})
        return True
    if spec['kind'] == 'invalid-format':
        authority.contexts[pid] = {'role': 'source-invalid-format', 'identity': identity(pid)}
        authority.pipe_records.append({'kind': 'launch_preflight_invalid_format', 'pid': pid,
                                       'token': selected['token'], 'expected_exec_return': -8,
                                       'successful_exec_permitted': False})
        return True
    successful_exec(authority, trace, pid, spec, path, vector, environment, cwd, saved['identity'])
    role = 'source-bootstrap' if spec['kind'] == 'python-alias' else 'source-native'
    authority.contexts[pid] = {'role': role, 'identity': identity(pid)}
    return 'source-bootstrap' if spec['kind'] == 'python-alias' else True
