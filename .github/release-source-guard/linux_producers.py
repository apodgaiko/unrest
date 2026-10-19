"""Finite kernel admission of descendants of actual original UV source calls."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from primary_package_cache import admit as admit_package_interpreter_output
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
        self.response_receipts = {}
        self.response_staged = {}
        self.cache_current = None
        self.cache_names = {}
        self.cache_external = set()
        self.cache_completed = set()
        if common.get('primary_producer') is not None:
            prior = common['primary_producer']['bootstrap_cache']
            bootstrap = self.interface.protected_json(prior['path'], prior['sha256'])
            self.cache_current = bootstrap['entries']
            self.cache_external = set(bootstrap['external_links'])
            current, self.cache_names = self.interface.cache_view(common, self.cache_external)
            if current != self.cache_current:
                raise RuntimeError('primary_cache_bootstrap_changed_before_source')

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
        if self.cache_current is not None:
            current, _ = self.interface.cache_view(self.common, self.cache_external)
            if current != self.cache_current:
                raise RuntimeError('primary_cache_unregistered_writer_before_uv')
            if any(old_pid not in self.cache_completed for old_pid in self.uv):
                raise RuntimeError('primary_cache_overlapping_uv_writer')
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
            spec['primary_runtime_output'] = self.interface.runtime_members(spec, selected, self.records.append, self.response_receipts)
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

    def stage_response(self, request):
        if set(request) != {'id', 'kind', 'nonce', 'pid', 'token', 'identity'}:
            raise RuntimeError('primary_response_request_fields')
        pid = request['pid']
        child = self.children.get(pid)
        if (not self.common.get('primary_producer') or child is None
                or child['role'] != 'isolated-uv-helper' or pid in self.response_staged
                or request['token'] != child['token'] or self.kernel.identity(pid) != child['identity']):
            raise RuntimeError('primary_response_live_peer_refused')
        path = Path('/receipts/native-startup') / (str(pid) + '.json')
        if digest(path) != child['profile_sha256']:
            raise RuntimeError('primary_response_live_profile_drift')
        header = json.loads(path.read_bytes())
        spec = self.interface.protected_json(header['spec'], header['spec_sha256'])
        if self.kernel.identity(child['parent']) != spec['parent_operation']['identity']:
            raise RuntimeError('primary_response_live_parent_drift')
        output = self.interface.original_response_output(spec, header, child['helper'], producer_pid=pid)
        if output['profile_sha256'] != child['profile_sha256']:
            raise RuntimeError('primary_response_live_header_drift')
        self.response_staged[pid] = output
        self.records.append({'kind': 'original_UV_live_response', 'pid': pid,
                             'helper': child['helper'], 'member_sha256': output['member_sha256'],
                             'sha256': output['sha256'], 'live_kernel_peer': True})
        return {'source_response_observed': True, 'member_sha256': output['member_sha256']}

    def completed_cache(self, event, trace):
        if self.cache_current is None or event['kind'] != 'kernel_exit' or event['pid'] not in self.uv:
            return
        pid = event['pid']
        if pid in self.cache_completed or event['raw'] != 0:
            return
        context = self.uv[pid]
        if trace.poison or self.supervisor.poisoned:
            raise RuntimeError('primary_cache_poisoned_producer')
        rows = self.supervisor.events()
        external = set(self.cache_external)
        runtime_names, extracted_files, query_roots = set(), {}, []
        for child in context['children']:
            path = Path('/receipts/native-startup') / (str(child['pid']) + '.json')
            if digest(path) != child['profile_sha256']:
                raise RuntimeError('primary_cache_output_profile_drift')
            header = json.loads(path.read_bytes())
            spec = self.interface.protected_json(header['spec'], header['spec_sha256'])
            waits = [row for row in trace.records if row['kind'] == 'original_parent_wait4'
                     and row['child'] == child['pid'] and row['parent_tgid'] == pid and row['raw'] == 0]
            if len(waits) != 1:
                raise RuntimeError('primary_cache_output_child_wait_missing')
            if child['role'] == 'isolated-uv-helper':
                if child['pid'] not in self.response_receipts:
                    raise RuntimeError('primary_cache_output_response_missing')
                output = spec['primary_runtime_output']
                root = Path(output['root'])
                for name in [*output['members'], self.response_receipts[child['pid']]['member']]:
                    relative = str((root / name).relative_to(self.common['cache']))
                    runtime_names.add(hashlib.sha256(relative.encode()).hexdigest())
                runtime_names.add(hashlib.sha256(str(root.relative_to(self.common['cache'])).encode()).hexdigest())
                for name in ('python', 'python3', 'python3.13'):
                    relative = str((root / 'bin' / name).relative_to(self.common['cache']))
                    external.add(hashlib.sha256(relative.encode()).hexdigest())
                if header['cwd'] != spec['project']:
                    lineages = [row for row in rows if row['kind'] == 'isolated_actual_extraction_consumption'
                                and row['owner_pid'] == child['pid'] and row['parent_pid'] == pid]
                    if len(lineages) != 1 or lineages[0]['lineage']['extracted_root'] != header['cwd']:
                        raise RuntimeError('primary_cache_extracted_output_lineage')
                    for member in lineages[0]['lineage']['members']:
                        relative = str(Path(member['path']).relative_to(self.common['cache']))
                        extracted_files[hashlib.sha256(relative.encode()).hexdigest()] = member
                    # Pure-Python build/lib copies are exactly the actual wheel's
                    # members, never arbitrary descendants of the extracted root.
                    wheels = [row for row in rows if row['kind'] == 'isolated_backend_output'
                              and row['parent_pid'] == pid and row['helper'] == 'build_wheel']
                    if wheels:
                        if len(wheels) != 1:
                            raise RuntimeError('primary_cache_generated_wheel_count')
                        import zipfile
                        with zipfile.ZipFile(wheels[0]['artifact']['path']) as archive:
                            for name in archive.namelist():
                                if name.endswith('/') or '.dist-info/' in name:
                                    continue
                                destination = Path(header['cwd']) / 'build/lib' / name
                                relative = str(destination.relative_to(self.common['cache']))
                                extracted_files[hashlib.sha256(relative.encode()).hexdigest()] = {
                                    'sha256': hashlib.sha256(archive.read(name)).hexdigest()}
            elif child['role'] == 'isolated-uv-query':
                returns = [row for row in rows if row['kind'] == 'query_actual_main_return'
                           and row['owner_pid'] == child['pid'] and row['parent_pid'] == pid]
                if len(returns) != 1:
                    raise RuntimeError('primary_cache_query_return_missing')
                # Exact original query package was validated before dispatch.
                import ast
                nodes = ast.parse(header['orig_argv'][-1]).body
                query_roots.append(Path(nodes[1].value.left.elts[0].value))
            else:
                raise RuntimeError('primary_cache_output_unknown_child')
        helpers = {child['helper'] for child in context['children'] if child['role'] == 'isolated-uv-helper'}
        if context['operation'] == 'source-build' and helpers != {
                'get_requires_for_build_sdist', 'build_sdist', 'get_requires_for_build_wheel', 'build_wheel'}:
            raise RuntimeError('primary_cache_output_original_helpers')
        if context['operation'] == 'source-install' and len(query_roots) != 1:
            raise RuntimeError('primary_cache_output_original_query')
        current, names = self.interface.cache_view(self.common, external)
        query_files = {}
        for root in query_roots:
            for name, binding in self.public.UV_EMBEDDED.items():
                if name.startswith('python/'):
                    relative = str((root / name).relative_to(self.common['cache']))
                    query_files[hashlib.sha256(relative.encode()).hexdigest()] = binding['sha256']
        installed_cache = set()
        if context['operation'] == 'source-install':
            import zipfile
            wheel = Path(context['profile']['argv'][-1])
            admissions = [row for row in rows if row['kind'] == 'operation_admission'
                          and row['token'] == context['token'] and row['owner_pid'] == context['owner_pid']]
            if len(admissions) != 1 or digest(wheel) != admissions[0]['wheel']['sha256']:
                raise RuntimeError('primary_cache_install_input_wheel')
            with zipfile.ZipFile(wheel) as archive:
                payload = {name: hashlib.sha256(archive.read(name)).hexdigest()
                           for name in archive.namelist() if not name.endswith('/')}
            for key, entry in current.items():
                if key in self.cache_current or entry['type'] != 'symlink':
                    continue
                link = Path(self.common['cache']) / names[key]
                target = link.resolve(strict=True)
                if target.parent != Path(self.common['cache']) / 'archive-v0' or not target.is_dir():
                    raise RuntimeError('primary_cache_install_archive_target')
                members = {path.relative_to(target).as_posix(): digest(path)
                           for path in target.rglob('*') if path.is_file()}
                if members != payload or any(path.is_symlink() for path in target.rglob('*')):
                    raise RuntimeError('primary_cache_install_archive_bytes')
                installed_cache.add(key)
                for path in [target, *target.rglob('*')]:
                    relative = str(path.relative_to(self.common['cache']))
                    installed_cache.add(hashlib.sha256(relative.encode()).hexdigest())
                revision = str(link.relative_to(self.common['cache'])) + '.rev'
                installed_cache.add(hashlib.sha256(revision.encode()).hexdigest())
        fixed = {'.gitignore': b'*', '.lock': b'', 'sdists-v9/.git': b'', 'sdists-v9/.gitignore': b'',
                 'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55'}
        permitted = set(self.cache_current) | runtime_names
        for key, entry in current.items():
            path = Path(self.common['cache']) / names[key]
            if key in self.cache_current:
                old = self.cache_current[key]
                if self.interface.cache_core(entry) != self.interface.cache_core(old):
                    parts = Path(names[key]).parts
                    if not (context['operation'] == 'source-install' and len(query_roots) == 1
                            and len(parts) == 3 and parts[0] == 'interpreter-v4'
                            and path.suffix == '.msgpack' and entry['type'] == old['type'] == 'file'):
                        raise RuntimeError('primary_cache_original_input_mutation')
            elif key in runtime_names:
                pass
            elif key in extracted_files:
                if entry['type'] != 'file' or entry['sha256'] != extracted_files[key]['sha256']:
                    raise RuntimeError('primary_cache_extracted_member_bytes')
            elif key in query_files:
                if entry['type'] != 'file' or entry['sha256'] != query_files[key]:
                    raise RuntimeError('primary_cache_query_package_bytes')
            elif key in installed_cache:
                pass
            elif (context['operation'] == 'source-install' and len(Path(names[key]).parts) == 3
                  and Path(names[key]).parts[0] == 'interpreter-v4' and path.suffix == '.msgpack'
                  and entry['type'] == 'file'):
                pass
            elif (context.get('package_origin') is not None
                  and admit_package_interpreter_output(self, context, key, entry, current, names, trace)):
                pass
            elif names[key] in fixed and path.read_bytes() == fixed[names[key]]:
                pass
            elif entry['type'] == 'directory':
                continue
            else:
                self.records.append({'kind': 'primary_cache_output_unbound', 'pid': pid,
                                     'member_sha256': key, 'member_type': entry['type']})
                raise RuntimeError('primary_cache_unbound_original_output')
            permitted.add(key)
        allowed_dirs = {str(parent) for key in permitted for parent in Path(names.get(key, self.cache_names.get(key, ''))).parents}
        for key, entry in current.items():
            if entry['type'] == 'directory' and key not in permitted and names[key] not in allowed_dirs:
                raise RuntimeError('primary_cache_output_extra_directory')
        if not set(self.cache_current) <= set(current):
            raise RuntimeError('primary_cache_original_input_removed')
        value = {'schema': 'unrest.v046.original-uv-cache-output.v1', 'pid': pid,
                 'owner_pid': context['owner_pid'], 'operation': context['operation'],
                 'operation_sha256': hashlib.sha256(context['token'].encode()).hexdigest(),
                 'bootstrap_sha256': self.common['primary_producer']['bootstrap_cache']['sha256'],
                 'kernel_exit_raw': 0, 'before_sha256': hashed(self.cache_current),
                 'entries': current, 'external_links': sorted(external)}
        pin = write(ROOT / ('cache-output-' + str(pid) + '.json'), value)
        self.cache_current, self.cache_names, self.cache_external = current, names, external
        self.cache_completed.add(pid)
        self.records.append({'kind': 'original_UV_cache_output', 'pid': pid,
                             'operation': context['operation'], 'manifest_sha256': pin,
                             'member_count': len(current), 'kernel_exit_raw': 0})

    def completed_response(self, event, trace):
        if not getattr(self, 'common', {}).get('primary_producer'):
            return
        if event['kind'] != 'original_parent_wait4' or event['child'] not in self.children:
            return
        pid = event['child']
        child = self.children[pid]
        if pid in self.response_receipts or child['role'] != 'isolated-uv-helper' or event['raw'] != 0:
            return
        context = self.uv[child['parent']]
        if event['parent_tgid'] != context['pid']:
            raise RuntimeError('primary_response_foreign_parent_wait')
        for native in (child['identity'], context['identity']):
            birth = trace.identities[native['pid']]
            if (any(birth[key] != native[key] for key in ('pid', 'ppid', 'start_ticks', 'boot_id', 'pgid', 'sid', 'clock_ticks_per_second'))
                    or native['uid'] != 20000 or birth['uids'] != [20000] * 4):
                raise RuntimeError('primary_response_birth_drift')
        path = Path('/receipts/native-startup') / (str(pid) + '.json')
        info = path.lstat()
        import stat
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 20001
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1):
            raise RuntimeError('primary_response_profile_custody')
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() != child['profile_sha256']:
            raise RuntimeError('primary_response_profile_drift')
        header = json.loads(body)
        spec = self.interface.protected_json(header['spec'], header['spec_sha256'])
        if 'primary_producer' not in spec:
            return
        receipt = self.interface.response_receipt(spec, header, child, event, self.response_staged.get(pid))
        pin = write(ROOT / ('response-' + str(pid) + '.json'), receipt)
        self.response_receipts[pid] = receipt
        self.records.append({'kind': 'original_UV_response_receipt', 'pid': pid,
                             'parent': child['parent'], 'helper': child['helper'],
                             'receipt_sha256': pin, 'response_sha256': receipt['sha256'],
                             'parent_wait_raw': event['raw'], 'member_sha256': receipt['member_sha256']})

    def tick(self, trace):
        for event in trace.records:
            self.completed_response(event, trace)
            self.completed_cache(event, trace)
            if (event['kind'] == 'kernel_exit' and event['pid'] in self.children
                    and event['raw'] == 86 << 8 and event['pid'] not in self.poisoned_exits):
                self.poisoned_exits.add(event['pid'])
                self.supervisor.poison('native_preinitialization_refusal')
