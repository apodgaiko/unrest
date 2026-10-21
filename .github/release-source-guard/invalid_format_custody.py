"""Only the three original malformed launchers may reach the kernel's ENOEXEC."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat

from finite.linux_identity import identity

BODY = b'mode executable, intentionally invalid format\n'
CASES = {
    'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[work]': 'invalid-format-work',
    'tests/test_acp_runner.py::test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[validate]': 'invalid-format-validate',
    'tests/test_acp_runner.py::test_terminal_real_startup_failure_is_safe_and_starts_no_protocol': 'invalid-format-reviewer',
}
PRODUCT = 'src/unrest_harness/acp_runner.py'


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if not vector or vector[0] not in {'./' + name for name in CASES.values()}:
        return False
    selected = authority.bound.get(pid)
    if selected is None:
        return False
    registration = selected.get('registration', {})
    if registration.get('class') != 'source-cohort2:invalid-format':
        return False
    name = CASES.get(registration.get('case'))
    binding = registration.get('source_binding', {})
    parent = trace.identities[pid]['ppid']
    saved = authority.supervisor.registered.get(parent)
    root = Path(cwd)
    launcher = root / (name or 'not-selected')
    if (name is None or saved is None or selected.get('bootstrap_sha256') is not None
            or root.resolve() != root or root.name != 'workspace'
            or not root.is_relative_to(Path(authority.manifest['owned_root']) / 'pytest')
            or path != './' + name or vector != ['./' + name]
            or selected.get('cwd') != cwd or selected.get('owner_pid') != parent
            or registration.get('owner_pid') != parent
            or selected.get('token') != registration.get('token')
            or not selected.get('token') or identity(parent) != saved['identity']
            or binding != {'path': '/source/' + PRODUCT, 'line': 409,
                           'sha256': authority.manifest['product_pins'][PRODUCT], 'function': 'spawn_launch'}
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
            or Path('/proc/' + str(pid) + '/cwd').resolve() != root):
        return False
    before = launcher.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o777 != 0o700
            or before.st_nlink != 1 or before.st_uid != saved['identity']['uid']
            or before.st_size != len(BODY) or launcher.read_bytes() != BODY
            or launcher.lstat() != before):
        return False
    # No interpreter, ELF header, script conversion, or alternate argv is admitted.
    authority.contexts[pid] = {'role': 'source-invalid-format', 'identity': identity(pid)}
    authority.pipe_records.append({'kind': 'invalid_format_kernel_attempt', 'pid': pid,
                                   'identity': identity(pid), 'token': selected['token'],
                                   'body_sha256': hashlib.sha256(BODY).hexdigest(),
                                   'expected_exec_return': -8, 'successful_exec_permitted': False})
    return True
