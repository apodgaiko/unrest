"""PRIMARY build admission from the original script and live kernel owner.

This origin is distinct from pytest fixture admission. It never fabricates a
fixture frame, Popen retention, READY response, function return, or wait.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import secrets
from types import SimpleNamespace

from primary_source_authority import SourceAuthority, sha
from primary_custody import BUILD
from primary_policy import UV, command_environment
from finite.linux_identity import identity
from producer_setup import write
from linux_supervisor import Supervisor
from linux_producers import NativeProducers



class PackageBuildAuthority(SourceAuthority):
    def initialize(self, primary, child, output_fd):
        import producer_profile
        self.primary = primary
        if primary.plan['duty'] != BUILD or primary.plan.get('package_mode') not in {'TEST', 'FULL'}:
            raise RuntimeError('primary_package_build_plan')
        current, _ = producer_profile.cache_view(self.common, set())
        seed = self.common['primary_producer']['cache_seed_inventory']
        from dependency_closure import inventory
        if inventory(Path('/opt/primary-cache')) != seed:
            raise RuntimeError('primary_package_seed_changed')
        bootstrap = {'schema': 'unrest.v046.primary-cache-bootstrap.v1',
                     'entries': current, 'external_links': [],
                     'source_pid': child, 'parent': identity(child)['ppid'],
                     'producers': [], 'origin': 'immutable-primary-seed',
                     'source_checkpoint_ready': False, 'selected_carrier': None}
        path = Path('/receipts/producers/package-seed-cache.json')
        pin = write(path, bootstrap)
        self.common = {**self.common, 'primary_producer': {
            **self.common['primary_producer'], 'bootstrap_cache': {'path': str(path), 'sha256': pin}}}
        self.supervisor = Supervisor({'manifest': self.path, 'pins': {self.path: self.pin},
                                      'endpoint': self.manifest['endpoint']}, SimpleNamespace(pid=child))
        self.producers = PackageProducers(self.manifest, self.supervisor, self.common)
        self.supervisor.source_response_output = self.producers.stage_response
        from primary_package_ready import install
        install(self.supervisor, self.producers)
        objects = []
        for descriptor in (output_fd, self.supervisor.channel.fileno()):
            info = os.fstat(descriptor)
            objects.append({'device': info.st_dev, 'inode': info.st_ino,
                            'type': stat.S_IFMT(info.st_mode)})
        with Path('/receipts/HOST-FDS.json').open('x') as stream:
            stream.write(json.dumps({'nonce': self.manifest['endpoint']['nonce'],
                                     'objects': objects}, sort_keys=True))
        self.output_fd = output_fd

    def resolve(self, trace, pid, path, vector, environment, cwd):
        parent = trace.identities[pid]['ppid']
        if (path == UV and vector == ['uv', 'build'] and (parent == self.primary.root or pid == self.primary.root)
                and self.primary.next_command == 0 and pid not in self.contexts
                and cwd == '/source' and command_environment(environment, self.primary.environment)):
            if not self.producers.admit_primary(trace, pid, parent, environment, self.primary.plan):
                return False
            self.contexts[pid] = {'role': 'package-build-uv', 'identity': identity(pid)}
            self.primary.next_command = 1
            self.primary.records.append({'kind': 'primary_original_uv', 'pid': pid,
                                         'command_index': 0, 'identity': identity(pid)})
            return True
        return super().resolve(trace, pid, path, vector, environment, cwd)

    def producer_profile(self, pid, parent, vector, environment, cwd):
        super().producer_profile(pid, parent, vector, environment, cwd)
        path = Path('/receipts/primary-startup') / (str(pid) + '.json')
        self.primary.records.append({'kind': 'primary_native_preinit', 'pid': pid,
                                     'parent': parent, 'identity': identity(pid),
                                     'role': 'source-producer-child',
                                     'profile_sha256': sha(path)})

    def require_complete(self, trace):
        births = [row for row in self.producers.records if row['kind'] == 'native_source_child']
        helpers = [row['helper'] for row in births if row['role'] == 'isolated-uv-helper']
        if (set(helpers) != {'get_requires_for_build_sdist', 'build_sdist',
                            'get_requires_for_build_wheel', 'build_wheel'}
                or len(helpers) != 4 or len(births) != 5
                or sum(row['role'] == 'isolated-uv-query' for row in births) != 1
                or len(self.producers.uv) != 1
                or set(self.producers.uv) != self.producers.cache_completed
                or self.supervisor.poisoned or trace.poison):
            raise RuntimeError('primary_package_original_build_incomplete')


class PackageProducers(NativeProducers):
    def admit_primary(self, trace, pid, parent, environment, plan):
        from producer_inputs import SOURCE_UV_ELF_SHA256
        if (sha(UV) != SOURCE_UV_ELF_SHA256 or identity(pid)['ppid'] != parent
                or identity(pid)['uid'] != 20000 or trace.poison or self.supervisor.poisoned
                or self.uv or plan['duty'] != BUILD or plan['commands'] != [['uv', 'build']]):
            return False
        current, _ = self.interface.cache_view(self.common, self.cache_external)
        if current != self.cache_current:
            raise RuntimeError('primary_package_unregistered_cache_writer')
        token = secrets.token_hex(16)
        binding = {'path': '/inputs/github-script.sh', 'sha256': plan['script_sha256'],
                   'function': 'PRIMARY-original-script'}
        origin = {'schema': 'unrest.v046.primary-package-build-origin.v1', 'plan': plan,
                  'identity': identity(pid), 'parent_identity': identity(parent),
                  'argv': ['uv', 'build'], 'environment': environment, 'cwd': '/source', 'token': token}
        path = Path('/receipts/producers') / ('package-origin-' + str(pid) + '.json')
        pin = write(path, origin)
        profile = {'argv': origin['argv'], 'environment': environment, 'cwd': '/source',
                   'output': '/source/dist', 'source_binding': binding}
        context = {'pid': pid, 'identity': identity(pid), 'owner_pid': parent,
                   'launch_token': token, 'token': token, 'operation': 'source-build',
                   'record_sha256': pin, 'profile': profile, 'binding': binding,
                   'seen_requests': set(), 'children': [],
                   'package_origin': {'path': str(path), 'sha256': pin}}
        self.uv[pid] = context
        # This is an actual observed admission, not an emulated fixture event.
        # The native origin consumer uses only the separate private receipt.
        self.package_admissions = [{'kind': 'admitted', 'owner_pid': parent, 'token': token,
                                    'case': 'PRIMARY-package-TEST' if plan['package_mode'] == 'TEST'
                                    else 'PRIMARY-package-FULL'}]
        original_events = self.supervisor.events
        self.supervisor.events = lambda: [*original_events(), *self.package_admissions]
        self.records.append({'kind': 'primary_package_build_admission', 'pid': pid,
                             'identity': identity(pid), 'origin_sha256': pin})
        return True

    def stage_response(self, request):
        result = super().stage_response(request)
        from primary_package_directory_diagnostic import capture
        capture(self, self.children[request['pid']], 'original-module-return')
        return result

    def completed_cache(self, event, trace):
        try:
            return super().completed_cache(event, trace)
        except RuntimeError as error:
            if str(error) == 'primary_cache_unbound_original_output' and event.get('pid') in self.uv:
                from primary_package_cache_diagnostic import observe
                try:
                    self.package_cache_refusal = observe(self, self.uv[event['pid']])
                except BaseException as diagnostic_error:
                    self.package_cache_refusal = {
                        'schema': 'unrest.v046.primary-package-cache-refusal.v1',
                        'status': 'diagnostic-refused',
                        'exception_class': type(diagnostic_error).__name__,
                        'authority_granted': False, 'eligible_certificate': False,
                        'source_checkpoint_ready': False, 'selected_carrier': None}
            if str(error) == 'primary_cache_output_extra_directory' and event.get('pid') in self.uv:
                from primary_package_directory_diagnostic import refusal
                try:
                    self.package_cache_refusal = refusal(self, self.uv[event['pid']], error, trace)
                except BaseException as diagnostic_error:
                    self.package_cache_refusal = {
                        'schema': 'unrest.v046.primary-package-directory-diagnostic.v1',
                        'status': 'diagnostic-refused',
                        'exception_class': type(diagnostic_error).__name__,
                        'authority_granted': False, 'eligible_certificate': False,
                        'source_checkpoint_ready': False, 'selected_carrier': None}
            # Preserve the exact original cache refusal and the failed epoch.
            raise

    def resolve_child(self, pid, parent, path, vector, environment, cwd):
        context = self.uv.get(parent)
        if context is None:
            return None
        # NativeProducers derives and pins the exact child spec before exec.
        # Add only this observer-owned origin to that derivation.
        from primary_package_directory_diagnostic import capture
        capture(self, {'pid': pid, 'parent': parent, 'helper': None, 'cwd': cwd}, 'before-original-child')
        original = self.common
        self.common = {**original, 'primary_package_origin': context['package_origin']}
        try:
            return super().resolve_child(pid, parent, path, vector, environment, cwd)
        finally:
            self.common = original
