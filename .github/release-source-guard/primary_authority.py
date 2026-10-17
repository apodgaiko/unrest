"""Kernel-side finite descendants of the immutable actual GitHub shell script."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from primary_policy import PYTHON, UV, backend_request, command_environment
from producer_inputs import SOURCE_UV_ELF_SHA256
from producer_profile import query_package
from finite.linux_identity import identity


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Authority:
    def __init__(self, plan, root, environment):
        self.plan, self.root, self.environment = plan, root, environment
        self.next_command = 0
        self.contexts = {}
        self.records = []
        self.denials = []
        Path('/receipts/primary-startup').mkdir(mode=0o755)

    def refuse(self, code):
        self.denials.append(code)
        return False

    def resolve(self, trace, pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        previous = self.contexts.get(pid)
        owner = self.contexts.get(parent)
        if cwd != '/source' or not command_environment(environment, self.environment):
            # Build-isolated UV interpreter paths are an exact native cache root.
            return self.refuse('environment_or_cwd')
        if (path == UV and vector and vector[0] == 'uv'
                and (parent == self.root or pid == self.root)
                and previous is None and self.next_command < len(self.plan['commands'])
                and vector == self.plan['commands'][self.next_command]
                and digest(path) == SOURCE_UV_ELF_SHA256):
            self.contexts[pid] = {'role': 'uv', 'command': vector, 'identity': identity(pid),
                                  'python_calls': 0, 'final': False}
            self.next_command += 1
            self.records.append({'kind': 'primary_original_uv', 'pid': pid,
                                 'command_index': self.next_command - 1, 'identity': identity(pid)})
            return True
        context = previous if previous and previous['role'] == 'uv' else owner
        if (context is None or context['role'] != 'uv' or not vector
                or context['python_calls'] >= 16 or path != vector[0]
                or Path(path).resolve() != Path(PYTHON) or digest(path) != digest(PYTHON)):
            return self.refuse('unknown_descendant')
        if owner is context and identity(parent) != context['identity']:
            return self.refuse('uv_parent_identity')
        role = None
        event = 'cpython.run_command'
        body = None
        flags = [0, 0, 1]
        if len(vector) == 5 and vector[1:4] == ['-I', '-B', '-c']:
            try:
                query_package(vector[4], {'cache': '/work/cache'})
            except Exception:
                return self.refuse('query_renderer')
            role, body, flags = 'query', vector[4] + '\n', [1, 0, 1]
        elif len(vector) == 3 and vector[1] == '-c' and backend_request(vector[2]):
            role, body = 'editable_backend', vector[2] + '\n'
        else:
            command = context['command']
            if command[:3] != ['uv', 'run', 'python'] or context['final']:
                return self.refuse('unknown_body')
            if vector[1:] != command[3:]:
                return self.refuse('original_body_argv')
            if len(vector) == 3 and vector[1] == '-c':
                role, body = 'original_command', vector[2] + '\n'
            elif len(vector) == 3 and vector[1] == '-m':
                role, event, body = 'original_module', 'cpython.run_module', vector[2]
            else:
                return self.refuse('original_body_shape')
            context['final'] = True
        context['python_calls'] += 1
        actual = identity(pid)
        profile = {'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
                   'boot_id': actual['boot_id'], 'orig_argv': vector, 'environment': environment,
                   'cwd': cwd, 'event': event, 'flags': flags,
                   'body_sha256': hashlib.sha256(body.encode()).hexdigest()}
        path = Path('/receipts/primary-startup') / (str(pid) + '.json')
        if path.exists():
            return self.refuse('duplicate_profile')
        path.write_text(json.dumps(profile, sort_keys=True))
        path.chmod(0o444)
        self.records.append({'kind': 'primary_native_preinit', 'pid': pid, 'parent': parent,
                             'identity': actual, 'role': role, 'profile_sha256': digest(path)})
        if pid != self.root:
            self.contexts[pid] = {'role': role, 'identity': actual}
        return True
