"""Kernel-side finite descendants of the immutable actual GitHub shell script."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from primary_policy import PYTHON, UV, backend_request, command_environment, console
from producer_inputs import SOURCE_UV_ELF_SHA256
from producer_profile import query_package
from primary_source_inputs import python_flags
from finite.linux_identity import identity


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Authority:
    def __init__(self, plan, root, environment, source=None, output_fd=None):
        self.plan, self.root, self.environment = plan, root, environment
        self.next_command = 0
        self.contexts = {}
        self.records = []
        self.denials = []
        self.source, self.output_fd = source, output_fd
        Path('/receipts/primary-startup').mkdir(mode=0o755)

    def refuse(self, code):
        self.denials.append(code)
        return False

    def resolve(self, trace, pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        if self.source is not None:
            accepted = self.source.resolve(trace, pid, path, vector, environment, cwd)
            if accepted is not None:
                if accepted == 'source-bootstrap':
                    self.profile(pid, parent, vector, environment, cwd, 'cpython.run_command',
                                 vector[-1] + '\n', python_flags(vector, environment),
                                 'source-bootstrap')
                    return True
                return accepted or self.refuse('source_descendant')
        previous = self.contexts.get(pid)
        owner = self.contexts.get(parent)
        if cwd != '/source' or not command_environment(environment, self.environment, source=self.source is not None):
            # Build-isolated UV interpreter paths are an exact native cache root.
            return self.refuse('environment_or_cwd')
        if (self.source is not None and path in ['/usr/bin/env', '/bin/env']
                and vector == self.plan['commands'][0] and vector[:3] == ['env', '-u', 'CODEX_PATH']
                and (parent == self.root or pid == self.root) and previous is None
                and self.next_command == 0 and digest(path) == digest('/usr/bin/env')):
            self.contexts[pid] = {'role': 'env', 'identity': identity(pid)}
            self.records.append({'kind': 'primary_original_env', 'pid': pid, 'identity': identity(pid)})
            return True
        if (self.source is not None and previous and previous['role'] == 'env'
                and vector == self.plan['commands'][0][3:] and vector[0] == 'uv'):
            candidates = [directory + '/uv' for directory in environment['PATH'].split(':')]
            if path not in candidates:
                return self.refuse('source_env_path')
            if not Path(path).exists():
                return True
            if path != UV or digest(path) != SOURCE_UV_ELF_SHA256:
                return self.refuse('source_env_uv_identity')
            self.contexts[pid] = {'role': 'uv', 'command': vector, 'identity': identity(pid),
                                  'python_calls': 0, 'final': False}
            self.next_command = 1
            self.records.append({'kind': 'primary_original_uv', 'pid': pid,
                                 'command_index': 0, 'identity': identity(pid)})
            return True
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
        if (owner and owner['role'] == 'original_console' and owner.get('repository')
                and vector == ['git', '-C', '/source', 'rev-parse', '--show-toplevel']
                and path in [directory + '/git' for directory in environment['PATH'].split(':')]
                and identity(parent) == owner['identity']):
            if not Path(path).exists():
                return True
            if path != '/usr/bin/git' or digest(path) != digest('/usr/lib/git-core/git'):
                return self.refuse('unknown_descendant')
            if owner.get('git_dispatched'):
                return self.refuse('unknown_descendant')
            owner['git_dispatched'] = True
            self.contexts[pid] = {'role': 'git', 'identity': identity(pid)}
            self.records.append({'kind': 'primary_repository_git', 'pid': pid, 'identity': identity(pid)})
            return True
        context = previous if previous and previous['role'] == 'uv' else owner
        command = context['command'] if context else []
        if (context and command == ['uv', 'run', 'ruff', 'check', '.']
                and path == '/source/.venv/bin/ruff' and vector == ['ruff', 'check', '.']
                and digest(path) == digest('/opt/deps/bin/ruff') and not context['final']):
            context['final'] = True
            self.contexts[pid] = {'role': 'ruff', 'identity': identity(pid)}
            return True
        console_name = command[2] if command[:2] == ['uv', 'run'] and len(command) > 2 else None
        console_interpreter = None
        if (console_name in {'unrest', 'unrest-server', 'mypy', 'pytest'}
                and path == '/source/.venv/bin/' + console_name and vector == command[2:]):
            for candidate in ('/source/.venv/bin/python', '/source/.venv/bin/python3',
                              '/source/.venv/bin/python3.13'):
                if (Path(candidate).resolve() == Path(PYTHON)
                        and digest(candidate) == digest(PYTHON)
                        and Path(path).read_bytes() == console(console_name, candidate)):
                    console_interpreter = candidate
                    break
        is_console = console_interpreter is not None
        if (context is None or context['role'] != 'uv' or not vector
                or context['python_calls'] >= 16 or (path != vector[0] and not is_console)
                or not (is_console or (Path(path).resolve() == Path(PYTHON) and digest(path) == digest(PYTHON)))):
            return self.refuse('unknown_descendant')
        if owner is context and identity(parent) != context['identity']:
            return self.refuse('uv_parent_identity')
        role = None
        event = 'cpython.run_command'
        body = None
        flags = [0, 0, 1]
        if is_console and not context['final']:
            role, event, body = 'original_console', 'cpython.run_file', path
            vector = [console_interpreter, path, *vector[1:]]
            context['final'] = True
            if console_name == 'pytest':
                if self.source is None:
                    return self.refuse('source_authority_missing')
                role = 'source-root'
                self.source.start(pid, self.output_fd)
        elif len(vector) == 5 and vector[1:4] == ['-I', '-B', '-c']:
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
            elif len(vector) >= 3 and vector[1] == '-m':
                role, event, body = 'original_module', 'cpython.run_module', vector[2]
            else:
                return self.refuse('original_body_shape')
            context['final'] = True
        context['python_calls'] += 1
        return self.profile(pid, parent, vector, environment, cwd, event, body, flags, role,
                            repository=context['command'] == ['uv', 'run', 'unrest', 'check-repository'])

    def profile(self, pid, parent, vector, environment, cwd, event, body, flags, role, repository=False):
        actual = identity(pid)
        profile = {'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
                   'boot_id': actual['boot_id'], 'orig_argv': vector, 'environment': environment,
                   'cwd': cwd, 'event': event, 'flags': flags,
                   'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                   'repository': repository,
                   'repository_source_sha256': digest('/source/src/unrest_harness/repository_contract.py'),
                   'console_source_sha256': digest(body) if role in {'original_console', 'source-root'} else None}
        if role in {'source-root', 'source-bootstrap'}:
            profile.update(source_role=role, manifest=self.source.path,
                           manifest_sha256=self.source.pin,
                           source_entry_sha256=digest('/guard/primary_source_entry.py'),
                           source_mode=self.plan['source_mode'], source_budget=self.plan['source_budget'])
        path = Path('/receipts/primary-startup') / (str(pid) + '.json')
        if path.exists():
            return self.refuse('duplicate_profile')
        path.write_text(json.dumps(profile, sort_keys=True))
        path.chmod(0o444)
        self.records.append({'kind': 'primary_native_preinit', 'pid': pid, 'parent': parent,
                             'identity': actual, 'role': role, 'profile_sha256': digest(path)})
        self.contexts[pid] = {'role': role, 'identity': actual, 'repository': profile['repository']}
        return True
