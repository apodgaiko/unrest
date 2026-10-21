"""Stopped native Git image joined to an already consumed exact SOURCE launch."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from finite.candidate_git import CLASS, SOURCE, environment as fixture_environment
from finite.linux_identity import identity

PRODUCT = 'src/unrest_harness/experimental_candidate.py'


def eligible(selected, vector, environment, cwd, checkout, owned_root, pins):
    registration = selected.get('registration', {})
    binding = registration.get('source_binding', {})
    if type(binding) is not dict:
        return False
    kind = registration.get('class')
    if kind == CLASS:
        relative, line, function = SOURCE, 21, 'git'
        valid = (environment == fixture_environment(Path(cwd))
                 and registration.get('case', '').startswith(SOURCE + '::test_')
                 and Path(cwd).name == 'repository')
    elif kind in {'source-candidate-object-git:' + v for v in ('-t', 'commit', 'tree', 'blob')}:
        relative, line, function = PRODUCT, 151, '_Observation.git'
        valid = (len(vector) == 5 and vector[1:3] == ['--no-replace-objects', 'cat-file']
                 and vector[3] == kind.split(':')[-1]
                 and len(vector[4]) == 40 and all(c in '0123456789abcdef' for c in vector[4])
                 and environment == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                     'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                                     'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'})
    else:
        return False
    return (valid and selected.get('bootstrap_sha256') is None
            and vector and vector[0] == '/usr/bin/git'
            and Path(cwd).resolve() == Path(cwd)
            and Path(cwd).is_relative_to(Path(owned_root) / 'pytest')
            and binding.get('path') == str(Path(checkout) / relative)
            and binding.get('sha256') == pins.get(relative) and pins.get(relative) is not None
            and binding.get('line') == line and binding.get('function') == function
            and registration.get('python', False) is False
            and selected.get('cwd') == cwd
            and selected.get('owner_pid') == registration.get('owner_pid')
            and selected.get('token') == registration.get('token')
            and selected.get('token') is not None
            and selected.get('transformed_argv_sha256') == hashlib.sha256(json.dumps(vector).encode()).hexdigest()
            and selected.get('environment_sha256') == hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest())


def resolve(authority, trace, pid, path, vector, environment, cwd):
    if path != '/usr/bin/git':
        from candidate_git_maintenance import resolve as maintenance
        return maintenance(authority, trace, pid, path, vector, environment, cwd)
    selected = authority.bound.get(pid)
    if (selected is None
            or not eligible(selected, vector, environment, cwd, '/source',
                            authority.manifest['owned_root'], authority.manifest['product_pins'])):
        return False
    parent = trace.identities[pid]['ppid']
    saved = authority.supervisor.registered.get(parent)
    if (saved is None or selected['owner_pid'] != parent or identity(parent) != saved['identity']
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != authority.manifest['copy_git'].get(path)
            or Path('/proc/' + str(pid) + '/cwd').resolve() != Path(cwd)):
        return False
    authority.contexts[pid] = {'role': 'source-native', 'identity': identity(pid)}
    authority.native_context[pid] = {'path': path, 'argv': vector, 'cwd': cwd, 'environment': environment,
                                    'candidate_registration': selected['registration']}
    authority.pipe_records.append({'kind': 'candidate_git_stopped_image', 'pid': pid,
                                   'token': selected['token'], 'identity': identity(pid),
                                   'executable_sha256': authority.manifest['copy_git'][path]})
    return True
