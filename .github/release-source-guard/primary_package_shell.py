"""Finite native operations of the two original package shell consumers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from primary_authority import Authority, digest
from primary_custody import INSTALLED, CHECKSUM, WHEEL, SDIST
from primary_policy import PYTHON, UV, console
from producer_inputs import SOURCE_UV_ELF_SHA256
from finite.linux_identity import identity

PREFIX = '/source/.wheel-venv'
UNSET = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CODEX_API_KEY',
         'GLM_API_KEY', 'OPENAI_API_KEY', 'ZAI_API_KEY')
LIFECYCLE = ['env', *[item for key in UNSET for item in ('-u', key)],
             PREFIX + '/bin/python', '-m', 'unrest_harness.installed_wheel_check']


def operations(duty):
    if duty == CHECKSUM:
        return [['sha256sum', WHEEL, SDIST], ['sha256sum', '--check', '--strict', 'SHA256SUMS']]
    if duty != INSTALLED:
        raise RuntimeError('package_shell_duty')
    return [['uv', 'venv', '--clear', '.wheel-venv'],
            ['uv', 'pip', 'install', '--python', '.wheel-venv/bin/python', 'dist/' + WHEEL],
            ['mktemp', '-d'], [PREFIX + '/bin/unrest', '--help'],
            [PREFIX + '/bin/unrest', 'measure-baseline', '--help'],
            [PREFIX + '/bin/unrest-server', '--help'],
            [PREFIX + '/bin/python', '-m', 'unrest_harness', '--help'],
            [PREFIX + '/bin/python', '-c', 'from unrest_harness.config import HarnessConfig; assert HarnessConfig.discover().capability_policy.schema_version == 1'],
            LIFECYCLE, [PREFIX + '/bin/unrest-server', '--mode', 'orchestrator']]


def environment_matches(actual, initial, cwd, executable, *, unsupported=False):
    value = dict(actual)
    for key, choices in {'PWD': {cwd}, 'OLDPWD': {'/source'}, 'SHLVL': {'0', '1'},
                         '_': {executable}}.items():
        if key in value and value.pop(key) not in choices:
            return False
    if unsupported and value.pop('UNREST_CAPABILITY_PROFILE', None) != 'unsupported':
        return False
    return value == initial


class PackageShellAuthority(Authority):
    def __init__(self, plan, root, environment):
        super().__init__(plan, root, environment)
        if (plan.get('package_mode') not in {'TEST', 'FULL'} or plan['duty'] not in {INSTALLED, CHECKSUM}
                or digest('/inputs/github-script.sh') != plan['script_sha256']):
            raise RuntimeError('package_shell_script_binding')
        self.operations = operations(plan['duty'])
        self.operation_index = 0
        self.unrelated = None
        self.pending_env = None

    def resolve(self, trace, pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        previous = self.contexts.get(pid)
        if self.pending_env == pid and previous and previous['role'] == 'package-env':
            expected = LIFECYCLE[-3:]
            if (vector != expected or path != expected[0] or cwd != self.unrelated
                    or not environment_matches(environment, self.environment, cwd, '/usr/bin/env')):
                return self.refuse('package_shell_lifecycle_env_exec')
            self.pending_env = None
            return self.python(pid, parent, path, vector, environment, cwd, lifecycle=True, trace=trace)
        if self.operation_index < len(self.operations):
            expected = self.operations[self.operation_index]
            if vector == expected and (parent == self.root or pid == self.root):
                native = expected[0]
                if native in {'uv', 'mktemp', 'sha256sum', 'env'}:
                    selected = UV if native == 'uv' else '/usr/bin/' + native
                    candidates = [directory + '/' + native for directory in self.environment['PATH'].split(':')]
                    if path not in candidates:
                        return self.refuse('package_shell_native_path')
                    if not Path(path).exists():
                        return True
                    if path != selected or (native == 'uv' and digest(path) != SOURCE_UV_ELF_SHA256):
                        return self.refuse('package_shell_native_image')
                else:
                    selected = native
                    if path != selected:
                        return self.refuse('package_shell_installed_path')
                if self.plan['duty'] == CHECKSUM:
                    required_cwd = '/source/dist'
                elif self.operation_index <= 2:
                    required_cwd = '/source'
                else:
                    required_cwd = self.unrelated or cwd
                    if self.unrelated is None:
                        root = Path(cwd)
                        if (root.parent != Path('/work/owned/tmp') or not root.name.startswith('tmp.')
                                or root.resolve() != root or not root.is_dir()):
                            return self.refuse('package_shell_unrelated_cwd')
                        self.unrelated = cwd
                unsupported = self.plan['duty'] == INSTALLED and self.operation_index == len(self.operations) - 1
                if (cwd != required_cwd or not environment_matches(
                        environment, self.environment, cwd, selected, unsupported=unsupported)):
                    return self.refuse('package_shell_environment_or_cwd')
                self.operation_index += 1
                actual = identity(pid)
                if actual['uid'] != 20000 or actual['ppid'] != parent:
                    return self.refuse('package_shell_birth')
                if native == 'uv':
                    self.contexts[pid] = {'role': 'uv', 'command': vector, 'identity': actual,
                                          'python_calls': 0, 'final': False}
                elif native == 'env':
                    self.contexts[pid] = {'role': 'package-env', 'identity': actual}
                    self.pending_env = pid
                elif native in {'mktemp', 'sha256sum'}:
                    self.contexts[pid] = {'role': 'package-native', 'identity': actual}
                else:
                    if not self.python(pid, parent, path, vector, environment, cwd, trace=trace):
                        return False
                self.records.append({'kind': 'primary_package_shell_operation', 'pid': pid,
                                     'identity': actual, 'operation_index': self.operation_index - 1,
                                     'argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                                     'image_sha256': digest(selected), 'cwd': cwd})
                self.next_command = len(self.plan['commands']) if self.operation_index == len(self.operations) else 0
                return True
        # Original query renderer, flags, image and profile predicates remain in
        # the original authority. A finite package UV context is required first.
        owner = self.contexts.get(parent)
        context = previous if previous and previous['role'] == 'uv' else owner
        if (context is None or context['role'] != 'uv' or len(vector) != 5
                or vector[1:4] != ['-I', '-B', '-c']):
            return self.refuse('package_shell_unknown_exec')
        return super().resolve(trace, pid, path, vector, environment, cwd)

    def python(self, pid, parent, path, vector, environment, cwd, *, lifecycle=False, trace=None):
        if Path(path).resolve() != Path(PYTHON) and not path.startswith(PREFIX + '/bin/unrest'):
            return self.refuse('package_shell_python_image')
        from primary_package_installed import verify_installation
        verification = verify_installation()
        if path.startswith(PREFIX + '/bin/unrest'):
            name = Path(path).name
            if Path(path).read_bytes() != console(name, PREFIX + '/bin/python'):
                return self.refuse('package_shell_console_renderer')
            original = [PREFIX + '/bin/python', path, *vector[1:]]
            event, body = 'cpython.run_file', path
        elif vector[1:2] == ['-m']:
            original, event, body = vector, 'cpython.run_module', vector[2]
        elif vector[1:2] == ['-c']:
            original, event, body = vector, 'cpython.run_command', vector[2] + '\n'
        else:
            return self.refuse('package_shell_python_body')
        actual = identity(pid)
        profile = {'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
                   'boot_id': actual['boot_id'], 'orig_argv': original, 'environment': environment,
                   'cwd': cwd, 'event': event, 'flags': [0, 0, 1],
                   'body_sha256': hashlib.sha256(body.encode()).hexdigest(), 'repository': False,
                   'repository_source_sha256': digest('/source/src/unrest_harness/repository_contract.py'),
                   'console_source_sha256': digest(path) if event == 'cpython.run_file' else None,
                   'installed_package_sha256': verification}
        if lifecycle:
            self.source.start(pid, self.output_fd, trace=trace, primary=self)
            profile.update(source_role='package-installed-root', manifest=self.source.path,
                           manifest_sha256=self.source.pin,
                           source_entry_sha256=digest('/guard/primary_package_installed_entry.py'))
        destination = Path('/receipts/primary-startup') / (str(pid) + '.json')
        with destination.open('x') as stream:
            stream.write(json.dumps(profile, sort_keys=True))
        destination.chmod(0o444)
        self.contexts[pid] = {'role': 'package-installed-root' if lifecycle else 'package-installed-console',
                              'identity': actual, 'repository': False}
        self.records.append({'kind': 'primary_native_preinit', 'pid': pid, 'parent': parent,
                             'identity': actual, 'role': self.contexts[pid]['role'],
                             'profile_sha256': digest(destination), 'installed_sha256': verification})
        return True

    def require_complete(self, trace):
        if (self.operation_index != len(self.operations) or self.pending_env is not None
                or trace.poison or self.denials):
            raise RuntimeError('package_shell_original_script_incomplete')
