"""Original archive entry without changing the SOURCE authority's AST."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from primary_authority import Authority, digest
from primary_policy import PYTHON, command_environment
from primary_source_inputs import python_environment
from finite.linux_identity import identity

COMMAND = ['uv', 'run', 'python', 'tools/check_distribution.py', 'dist']
SOURCE = Path('/source/tools/check_distribution.py')


class PackageArchivePrimaryAuthority(Authority):
    def profile(self, pid, parent, vector, environment, cwd, event, body, flags, role,
                repository=False, trace=None):
        if role != 'source-bootstrap':
            return super().profile(pid, parent, vector, environment, cwd, event, body, flags,
                                   role, repository=repository, trace=trace)
        # The original extracted oracle uses the existing endpoint/bootstrap
        # composition, but does not run the SOURCE collection observer.
        selected = self.source.bound[pid]
        registration = selected['registration']
        binding = registration['source_binding']
        actual = identity(pid)
        if (self.plan.get('package_mode') not in {'TEST', 'FULL'}
                or self.plan['duty'] != 'Check distribution archives'
                or self.plan['commands'] != [COMMAND] or repository
                or registration['class'] != 'source-extracted-oracle'
                or binding['path'] != str(SOURCE)
                or binding['function'] != '_run_extracted_restart_oracle'
                or binding['sha256'] != self.source.manifest['product_pins']['tools/check_distribution.py']
                or actual['ppid'] != parent or registration['owner_pid'] != parent
                or event != 'cpython.run_command' or body != vector[-1] + '\n'
                or selected['bootstrap_sha256'] != hashlib.sha256(vector[-1].encode()).hexdigest()):
            raise RuntimeError('primary_package_extracted_profile_binding')
        profile = {'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
                   'boot_id': actual['boot_id'], 'orig_argv': vector, 'environment': environment,
                   'cwd': cwd, 'event': event, 'flags': flags,
                   'body_sha256': hashlib.sha256(body.encode()).hexdigest(), 'repository': False,
                   'repository_source_sha256': digest('/source/src/unrest_harness/repository_contract.py'),
                   'console_source_sha256': None, 'source_role': role,
                   'manifest': self.source.path, 'manifest_sha256': self.source.pin,
                   'source_entry_sha256': digest('/guard/primary_source_entry.py'),
                   'source_descriptors': self.source.exec_descriptors(trace, pid, vector, environment, cwd),
                   'python_environment': python_environment(environment, registration, flags)}
        path = Path('/receipts/primary-startup') / (str(pid) + '.json')
        with path.open('x') as stream:
            stream.write(json.dumps(profile, sort_keys=True))
        path.chmod(0o444)
        self.records.append({'kind': 'primary_native_preinit', 'pid': pid, 'parent': parent,
                             'identity': actual, 'role': role, 'profile_sha256': digest(path)})
        self.contexts[pid] = {'role': role, 'identity': actual, 'repository': False}
        return True

    def resolve(self, trace, pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        previous = self.contexts.get(pid)
        owner = self.contexts.get(parent)
        context = previous if previous and previous['role'] == 'uv' else owner
        if (self.plan.get('package_mode') in {'TEST', 'FULL'}
                and self.plan['duty'] == 'Check distribution archives'
                and self.plan['commands'] == [COMMAND]
                and context is not None and context['role'] == 'uv'
                and context['command'] == COMMAND and not context['final']
                and vector[1:] == COMMAND[3:] and path == vector[0]
                and Path(path).resolve() == Path(PYTHON) and digest(path) == digest(PYTHON)
                and cwd == '/source' and command_environment(environment, self.environment, source=True)):
            if (self.source is None or owner is context and identity(parent) != context['identity']
                    or digest(SOURCE) != self.source.manifest['product_pins']['tools/check_distribution.py']):
                return self.refuse('primary_package_archive_original_entry')
            self.source.start(pid, self.output_fd, trace=trace, primary=self)
            actual = identity(pid)
            body = str(SOURCE)
            profile = {'pid': pid, 'parent': parent, 'start_ticks': actual['start_ticks'],
                       'boot_id': actual['boot_id'], 'orig_argv': vector, 'environment': environment,
                       'cwd': cwd, 'event': 'cpython.run_file', 'flags': [0, 0, 1],
                       'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                       'repository': False,
                       'repository_source_sha256': digest('/source/src/unrest_harness/repository_contract.py'),
                       'console_source_sha256': digest(SOURCE), 'source_role': 'package-root',
                       'manifest': self.source.path, 'manifest_sha256': self.source.pin,
                       'source_entry_sha256': digest('/guard/primary_package_entry.py')}
            profile_path = Path('/receipts/primary-startup') / (str(pid) + '.json')
            if profile_path.exists():
                return self.refuse('primary_package_archive_duplicate_profile')
            with profile_path.open('x') as stream:
                stream.write(json.dumps(profile, sort_keys=True))
            profile_path.chmod(0o444)
            self.records.append({'kind': 'primary_native_preinit', 'pid': pid, 'parent': parent,
                                 'identity': actual, 'role': 'package-root',
                                 'profile_sha256': digest(profile_path)})
            context['python_calls'] += 1
            context['final'] = True
            self.contexts[pid] = {'role': 'package-root', 'identity': actual, 'repository': False}
            return True
        return super().resolve(trace, pid, path, vector, environment, cwd)
