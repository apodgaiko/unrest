"""Consume the already-declared literal native terminal leaf in kernel custody."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

from finite.linux_identity import identity

CLASS = 'source-native-terminal-true'
SOURCE = 'src/unrest_harness/acp_runner.py'
PIN = '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f'
VECTOR = ['/usr/bin/true']
CASES = frozenset('tests/test_acp_runner.py::test_terminal_create_optional_nulls_use_omission_defaults[params' + str(i) + ']' for i in range(2))
BINDING = {'path': '/source/' + SOURCE, 'line': 1034, 'sha256': PIN}


def entry_from(body):
    tree = ast.parse(body)
    if (len(tree.body) != 2 or not isinstance(tree.body[0], ast.Expr)
            or not isinstance(tree.body[0].value, ast.Constant)
            or type(tree.body[0].value.value) is not str
            or not isinstance(tree.body[1], ast.Assign)
            or len(tree.body[1].targets) != 1
            or not isinstance(tree.body[1].targets[0], ast.Name)
            or tree.body[1].targets[0].id != 'COMMANDS'):
        raise RuntimeError('registry_native_carrier')
    rows = ast.literal_eval(tree.body[1].value)
    matches = [row for row in rows if row.get('class') == CLASS]
    if len(matches) != 1:
        raise RuntimeError('registry_native_membership')
    entry = matches[0]
    expected = {'class': CLASS, 'python': False, 'argv': [], 'executable': VECTOR[0],
                'executable_sha256': entry['executable_sha256'], 'checkout_cwd': True,
                'source_binding': BINDING, 'caller_bindings': []}
    if entry != expected or len(entry['executable_sha256']) != 64:
        raise RuntimeError('registry_native_identity')
    return entry


def eligible(selected, vector, environment, cwd, entry):
    registration = selected.get('registration', {})
    return (registration.get('class') == CLASS and registration.get('source_binding') == BINDING
            and registration.get('case') in CASES and selected.get('bootstrap_sha256') is None
            and vector == VECTOR and cwd == selected.get('cwd') == '/source'
            and set(environment) == {'PATH'} and type(environment['PATH']) is str
            and selected.get('owner_pid') == registration.get('owner_pid')
            and selected.get('token') is not None and selected.get('token') == registration.get('token')
            and selected.get('transformed_argv_sha256') == hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            and selected.get('environment_sha256') == hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
            and entry['class'] == CLASS and entry['source_binding'] == BINDING)


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != VECTOR[0] or vector != VECTOR:
        return False
    selected = authority.bound.get(pid)
    if selected is None or selected.get('registration', {}).get('class') != CLASS:
        return False
    registry = authority.manifest['registry']
    body = Path(registry['path']).read_bytes()
    if hashlib.sha256(body).hexdigest() != registry['sha256']:
        raise RuntimeError('registry_native_pin_drift')
    entry = entry_from(body)
    if not eligible(selected, vector, environment, cwd, entry):
        return False
    parent = trace.identities[pid]['ppid']
    saved = authority.supervisor.registered.get(parent)
    if (saved is None or parent != selected['owner_pid'] or identity(parent) != saved['identity']
            or authority.manifest['product_pins'].get(SOURCE) != PIN
            or Path('/proc/' + str(pid) + '/cwd').resolve() != Path('/source')
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != entry['executable_sha256']):
        return False
    authority.contexts[pid] = {'role': 'source-native', 'identity': identity(pid)}
    authority.pipe_records.append({'kind': 'registry_native_leaf', 'identity': identity(pid),
                                   'pid': pid, 'token': selected['token'],
                                   'registry_sha256': registry['sha256'],
                                   'executable_sha256': entry['executable_sha256']})
    return True
