"""Stopped Git image consumes one exact original finite-orders custody launch."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from finite.orders_git import CLASS, ENVIRONMENT, PRODUCT, repository_profile
from finite.linux_identity import identity


def literals(path):
    tree = ast.parse(path.read_bytes())
    return {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)}


def eligible(selected, vector, environment, cwd, manifest, checkout='/source'):
    registration = selected.get('registration', {})
    if registration.get('class') != CLASS or registration.get('python') is not False:
        return False
    root = Path(checkout)
    data = literals(Path(__file__).parent / 'finite/orders_git_data.py')
    binding = registration.get('source_binding', {})
    caller = registration.get('caller_binding')
    if type(caller) is not dict:
        return False
    case = registration.get('case')
    if (case not in data['CASES']
            or any(manifest['product_pins'].get(n) != pin or hashlib.sha256((root / n).read_bytes()).hexdigest() != pin
                   for n, pin in data['PINS'].items())
            or binding != {'path': str(root / PRODUCT), 'line': 38,
                           'sha256': data['PINS'][PRODUCT], 'function': 'git'}
            or caller.get('path') not in {str(root / n) for n in data['PINS']}
            or data['SITES'].get((str(Path(caller['path']).relative_to(root)), caller.get('line'))) != caller.get('function')
            or caller.get('sha256') != data['PINS'].get(str(Path(caller['path']).relative_to(root)))
            or environment != ENVIRONMENT or selected.get('bootstrap_sha256') is not None
            or selected.get('cwd') != cwd or selected.get('owner_pid') != registration.get('owner_pid')
            or selected.get('token') is None or selected['token'] != registration.get('token')
            or selected.get('transformed_argv_sha256') != hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            or selected.get('environment_sha256') != hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()):
        return False
    return repository_profile(vector, cwd, manifest['owned_root'], caller, data['CASES'][case])



def join_registration(selected, events):
    """Consume the caller explicitly bound to this launch's unique token."""
    admitted = selected.get('registration', {})
    if admitted.get('class') != CLASS:
        return None
    launches = [i for i, row in enumerate(events)
                if row.get('kind') == 'actual_launch_binding'
                and row.get('owner_pid') == selected.get('owner_pid')
                and row.get('token') == selected.get('token')]
    bindings = [(i, row) for i, row in enumerate(events)
                if row.get('kind') == 'orders_custody_launch_binding'
                and row.get('owner_pid') == selected.get('owner_pid')
                and row.get('token') == selected.get('token')]
    if len(launches) != 1 or len(bindings) != 1:
        return None
    index, row = bindings[0]
    launch = events[launches[0]]
    if index >= launches[0] or any(launch.get(name) != selected.get(name) for name in (
            'owner_pid', 'token', 'cwd', 'bootstrap_sha256',
            'transformed_argv_sha256', 'environment_sha256')):
        return None
    if (row.get('class') != CLASS or row.get('python') is not False
            or row.get('case') != admitted.get('case')
            or row.get('source_binding') != admitted.get('source_binding')
            or type(row.get('caller_binding')) is not dict
            or row.get('cwd') != selected.get('cwd')
            or row.get('bootstrap_sha256') is not None
            or row.get('environment_sha256') != selected.get('environment_sha256')
            or row.get('argv_sha256') != selected.get('transformed_argv_sha256')
            or row.get('argv_sha256') != admitted.get('argv_sha256')):
        return None
    # Preserve the original admitted projection. The stopped-image predicate
    # independently rechecks caller source, command, repository and executable.
    return {**selected, 'registration': {**admitted, 'python': False,
                                        'caller_binding': row['caller_binding']}}


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != '/usr/bin/git':
        from orders_git_maintenance import resolve as maintenance
        return maintenance(authority, trace, pid, path, vector, environment, cwd)
    if vector[:2] != [path, '--no-replace-objects']:
        return False
    selected = authority.bound.get(pid)
    if selected is None:
        return False
    selected = join_registration(selected, authority.supervisor.events())
    if selected is None or not eligible(selected, vector, environment, cwd, authority.manifest):
        return False
    parent = trace.identities[pid]['ppid']
    saved = authority.supervisor.registered.get(parent)
    if (saved is None or selected['owner_pid'] != parent or identity(parent) != saved['identity']
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['copy_git'].get(path)
            or Path('/proc/' + str(pid) + '/cwd').resolve() != Path(cwd)):
        return False
    authority.contexts[pid] = {'role': 'source-native', 'identity': identity(pid)}
    authority.native_context[pid] = {'path': path, 'argv': vector, 'cwd': cwd, 'environment': environment,
                                     'orders_registration': selected['registration']}
    authority.pipe_records.append({'kind': 'orders_git_stopped_image', 'pid': pid,
                                   'token': selected['token'], 'identity': identity(pid),
                                   'executable_sha256': authority.manifest['copy_git'][path]})
    return True
