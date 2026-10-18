"""Finite kernel admission of descendants of actual original UV source calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys

ROOT = Path('/receipts/producers')


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write(path, value):
    body = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)
    return hashlib.sha256(body).hexdigest()


class NativeProducers:
    def __init__(self, manifest, supervisor, common):
        self.manifest, self.supervisor, self.common = manifest, supervisor, common
        self.public = load('producer_inputs', '/guard/producer_inputs.py')
        self.activation = load('operation_activation', '/guard/finite/operation_activation.py')
        self.inputs = load('isolated_inputs', '/guard/finite/isolated_inputs.py')
        self.renderer = load('isolated_activation', '/guard/finite/isolated_activation.py')
        self.interface = load('producer_profile', '/guard/producer_profile.py')
        self.kernel = load('linux_identity', '/guard/finite/linux_identity.py')
        self.uv = {}
        self.children = {}
        self.records = []
        self.producer_diagnostic_keys = set()
        self.poisoned_exits = set()

    def admit_uv(self, pid, path, vector, environment, cwd, parent, registration, selected):
        if (registration['class'] not in {'source-build', 'source-install'}
                or path != '/opt/source-bootstrap/bin/uv'
                or digest(path) != self.public.SOURCE_UV_ELF_SHA256):
            return False
        rows = self.supervisor.events()
        operations = [event for event in rows if event['kind'] == 'operation_admission'
                      and event['owner_pid'] == parent and event['operation'] == registration['class']
                      and event['argv_sha256'] == registration['argv_sha256']]
        if len(operations) != 1:
            return False
        operation = operations[0]
        profile = operation.get('native_profile')
        if (profile is None or profile['argv'] != vector or profile['environment'] != environment
                or profile['cwd'] != cwd or operation['environment_sha256'] != hashed(environment)
                or operation['cwd'] != cwd or profile['source_binding'] != registration['source_binding']
                or not Path(profile['output']).resolve().is_relative_to(self.manifest['owned_root'])):
            return False
        binding = registration['source_binding']
        allowed = {'/source/tests/contracts/conftest.py', '/source/tests/test_distribution_check.py'}
        if (binding['path'] not in allowed or binding.get('function') != 'built_distribution'
                or digest(binding['path']) != binding['sha256']):
            return False
        identity = self.kernel.identity(pid)
        if identity['ppid'] != parent or identity['uid'] != 20000:
            return False
        context = {'pid': pid, 'identity': identity, 'owner_pid': parent,
                   'launch_token': selected['token'], 'token': operation['token'],
                   'operation': operation['operation'], 'record_sha256': hashed(operation),
                   'profile': profile, 'binding': binding, 'seen_requests': set(), 'children': []}
        self.uv[pid] = context
        self.records.append({'kind': 'native_original_UV_admission',
                             **{key: context[key] for key in ('pid', 'identity', 'owner_pid',
                                                             'launch_token', 'token', 'operation',
                                                             'record_sha256', 'binding')},
                             'argv_sha256': registration['argv_sha256'],
                             'environment_sha256': operation['environment_sha256'],
                             'cwd': cwd, 'image_sha256': self.public.SOURCE_UV_ELF_SHA256})
        return True

    def producer_check(self, pid, stage, value):
        key = (pid, stage)
        if key not in self.producer_diagnostic_keys and len(self.producer_diagnostic_keys) < 128:
            self.producer_diagnostic_keys.add(key)
            self.records.append({'kind': 'native_producer_predicate', 'pid': pid,
                                 'stage': stage, 'value': value})
        return value

    def resolve_child(self, pid, parent, path, vector, environment, cwd):
        context = self.uv.get(parent)
        if context is None:
            return None
        if self.producer_check(pid, 'duplicate_child', pid in self.children):
            return False
        if (self.producer_check(pid, 'parent_identity', self.kernel.identity(parent) != context['identity']) or self.producer_check(pid, 'child_limit', len(context['children']) >= 8)
                or self.producer_check(pid, 'argv_path', path != vector[0]) or self.producer_check(pid, 'realpath', Path(path).resolve() != Path(self.common['base']))
                or self.producer_check(pid, 'image_bytes', digest(path) != self.common['base_identity']['sha256'])):
            return False
        spec = dict(self.common)
        profile = context['profile']
        spec.update({'profile': {'argv': profile['argv'], 'environment': profile['environment'],
                                 'cwd': profile['cwd']}, 'output': profile['output'],
                     'source_binding': profile['source_binding'],
                     'parent_operation': {key: context[key] for key in (
                         'pid', 'identity', 'owner_pid', 'launch_token', 'token', 'operation',
                         'record_sha256')}})
        base_environment = {**profile['environment'], 'UV': '/opt/source-bootstrap/bin/uv'}
        if vector[1:4] == ['-I', '-B', '-c'] and len(vector) == 5:
            if (self.producer_check(pid, 'query_path', path != self.common['query_python']) or self.producer_check(pid, 'query_cwd', cwd != profile['cwd'])
                    or self.producer_check(pid, 'query_environment', environment != base_environment)):
                return False
            self.producer_check(pid, 'query_renderer_enter', True)
            package = self.interface.query_package(vector[-1], spec)
            self.producer_check(pid, 'query_renderer_return', True)
            key = ('query', package['path'])
            if self.producer_check(pid, 'duplicate_query', any(item['role'] == 'isolated-uv-query' for item in context['children'])):
                return False
            role, helper, flags = 'isolated-uv-query', 'main', [1, 0, 1]
        elif len(vector) == 3 and vector[1] == '-c' and context['operation'] == 'source-build':
            self.producer_check(pid, 'helper_renderer_enter', True)
            helper = self.renderer.helper_class(vector[-1], spec)
            self.producer_check(pid, 'helper_renderer_return', True)
            self.producer_check(pid, 'selected_runtime_enter', True)
            selected = self.inputs.runtime(spec, vector[0])
            self.producer_check(pid, 'selected_runtime_return', True)
            expected_environment = {
                **base_environment, 'PATH': selected['prefix'] + '/bin:' + profile['environment']['PATH'],
                'VIRTUAL_ENV': selected['prefix'], 'PYTHONIOENCODING': 'utf-8:backslashreplace'}
            if self.producer_check(pid, 'backend_environment', environment != expected_environment):
                return False
            if cwd != spec['project']:
                self.producer_check(pid, 'extracted_source_enter', True)
                self.inputs.extracted_source(spec, Path(cwd), self.supervisor.events(), parent)
                self.producer_check(pid, 'extracted_source_return', True)
            key = ('backend', selected['prefix'], helper)
            role = 'isolated-uv-helper'
            flags = [0, 0, int(bool(environment.get('PYTHONDONTWRITEBYTECODE')))]
        else:
            return False
        if self.producer_check(pid, 'duplicate_request', key in context['seen_requests']):
            return False
        context['seen_requests'].add(key)
        identity = self.kernel.identity(pid)
        if self.producer_check(pid, 'child_parent', identity['ppid'] != parent) or self.producer_check(pid, 'child_uid', identity['uid'] != 20000):
            return False
        token = secrets.token_hex(16)
        if role == 'isolated-uv-helper' and 'primary_producer' in spec:
            spec['primary_runtime_output'] = self.interface.runtime_members(spec, selected, self.records.append)
        spec_path = ROOT / ('spec-' + str(pid) + '.json')
        spec_pin = write(spec_path, spec)
        manifest = dict(self.manifest)
        for field in ('operation_support', 'activation_support', 'isolated_support',
                      'source_activation_support', 'native_producer_support'):
            manifest.pop(field, None)
        manifest['runtime'] = {'paths': [str(path), self.common['base']],
                               'realpath': self.common['base'],
                               'sha256': self.common['base_identity']['sha256']}
        child_manifest = ROOT / ('manifest-' + str(pid) + '.json')
        child_pin = write(child_manifest, manifest)
        source_profile = {
            'pid': pid, 'ppid': parent, 'start_ticks': identity['start_ticks'],
            'boot_id': identity['boot_id'], 'token': token, 'role': role,
            'case': next(event['case'] for event in reversed(self.supervisor.events())
                         if event['kind'] == 'admitted' and event['token'] == context['launch_token']),
            'event': 'cpython.run_command', 'orig_argv': vector, 'flags': flags,
            'environment': environment, 'cwd': cwd,
            'command_sha256': hashlib.sha256((vector[-1] + '\n').encode()).hexdigest(),
            'spec': str(spec_path), 'spec_sha256': spec_pin,
            'manifest': str(child_manifest), 'manifest_sha256': child_pin,
            'activation_sha256': digest('/guard/finite/native_producer.py'),
            'profile_support_sha256': digest('/guard/producer_profile.py'),
        }
        if self.manifest['source_selection'] == 'producer-controls' and role == 'isolated-uv-query':
            source_profile['caught_control'] = True
        header_pin = write(Path('/receipts/native-startup') / (str(pid) + '.json'), source_profile)
        pins = {'manifest_sha256': child_pin, 'guard_sha256': manifest['guard_sha256'],
                'registry_sha256': manifest['registry']['sha256'],
                'runtime_sha256': manifest['runtime']['sha256']}
        self.supervisor.registered[pid] = {'identity': identity, 'token': token, 'ready_pins': pins}
        item = {'kind': 'native_source_child', 'pid': pid, 'parent': parent, 'identity': identity,
                'role': role, 'helper': helper, 'token': token, 'profile_sha256': header_pin,
                'original_argv_sha256': hashlib.sha256(json.dumps(vector).encode()).hexdigest(),
                'environment_sha256': hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest(),
                'flags': flags, 'cwd': cwd, 'source_operation_token': context['token']}
        context['children'].append(item)
        self.children[pid] = item
        self.records.append(item)
        return True

    def tick(self, trace):
        for event in trace.records:
            if (event['kind'] == 'kernel_exit' and event['pid'] in self.children
                    and event['raw'] == 86 << 8 and event['pid'] not in self.poisoned_exits):
                self.poisoned_exits.add(event['pid'])
                self.supervisor.poison('native_preinitialization_refusal')
