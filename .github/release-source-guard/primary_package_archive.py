"""Actual archive function returns and exact authenticated input lineage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import types

from primary_dependency_authority import DependencySourceAuthority
from primary_custody import ARCHIVE, canonical, decode_outputs
from primary_source_authority import sha
from producer_setup import write
from finite.linux_identity import identity


def install_return_observer(authority, primary):
    from linux_supervisor import Supervisor
    supervisor = authority.supervisor
    if type(supervisor) is not Supervisor or supervisor.handle.__func__ is not Supervisor.handle:
        raise RuntimeError('primary_package_return_owner')
    original = supervisor.handle

    def handle(owner, request, events):
        if owner is not supervisor or original.__self__ is not owner:
            raise RuntimeError('primary_package_return_binding')
        if request.get('kind') != 'primary_package_function_return':
            return original(request, events)
        if owner.poisoned or authority.package_proof is not None:
            raise RuntimeError('primary_package_return_poison_or_duplicate')
        saved = owner.authenticate(request, events)
        expected_fields = {'id', 'kind', 'nonce', 'pid', 'token', 'identity',
                           'function', 'source_sha256', 'result'}
        context = primary.contexts.get(request['pid'])
        source = Path('/source/tools/check_distribution.py')
        if (set(request) != expected_fields or request['function'] != 'check_distribution'
                or request['source_sha256'] != sha(source)
                or request['source_sha256'] != authority.manifest['product_pins']['tools/check_distribution.py']
                or request['pid'] != owner.child.pid or request['token'] != 'root'
                or context is None or context['role'] != 'package-root'
                or context['identity'] != saved['identity'] or identity(request['pid']) != saved['identity']):
            raise RuntimeError('primary_package_original_return_refused')
        result = request['result']
        if (type(result) is not dict or set(result) != {'package_files', 'restart_oracle', 'sdist', 'wheel'}
                or type(result['package_files']) is not int or result['package_files'] <= 0
                or result['wheel'] != 'unrest_harness-0.4.6-py3-none-any.whl'
                or result['sdist'] != 'unrest_harness-0.4.6.tar.gz'
                or type(result['restart_oracle']) is not dict or result['restart_oracle'].get('cases') != 15):
            raise RuntimeError('primary_package_original_return_shape')
        from primary_outputs import export
        from checkpoint_issuer import member_hashes
        outputs = decode_outputs(export(ARCHIVE), ARCHIVE)
        descriptor = json.loads(Path('/inputs/package-input.json').read_bytes())
        if any(hashlib.sha256(body).hexdigest() != descriptor['members'][name]['sha256']
               for name, body in outputs.items()):
            raise RuntimeError('primary_package_observed_archive_drift')
        proof = {'schema': 'unrest.v046.primary-archive-observation.v1',
                 'source_sha256': request['source_sha256'], 'function': request['function'],
                 'result': result, 'member_bytes_sha256': member_hashes(outputs)}
        authority.package_proof = proof
        primary.records.append({'kind': 'primary_function_return', 'pid': request['pid'],
                                'identity': saved['identity'], 'source_sha256': request['source_sha256'],
                                'function': request['function'],
                                'proof_sha256': hashlib.sha256(canonical(proof)).hexdigest()})
        return {'original_function_return_observed': True}

    supervisor.handle = types.MethodType(handle, supervisor)


class PackageArchiveAuthority(DependencySourceAuthority):
    def prepare_bootstrap_cache(self, pid, trace, primary):
        from primary_package_bootstrap import bootstrap_cache
        declaration = bootstrap_cache(self.common, trace, pid, primary)
        path = Path('/receipts/producers/package-bootstrap-cache.json')
        pin = write(path, declaration)
        self.common = {**self.common, 'primary_producer': {
            **self.common['primary_producer'], 'bootstrap_cache': {'path': str(path), 'sha256': pin}}}
        common_path = Path('/receipts/producers/package-common.json')
        common_pin = write(common_path, self.common)
        self.manifest['isolated_support'].update(spec_path=str(common_path), spec_sha256=common_pin)
        self.manifest['native_producer_support'].update(path=str(common_path), sha256=common_pin)
        self.prepare_primary_dependency()

    def start(self, pid, output_fd, *, trace=None, primary=None):
        super().start(pid, output_fd, trace=trace, primary=primary)
        self.package_proof = None
        support = self.manifest['operation_support']
        operations = json.loads(Path(support['spec_path']).read_bytes())
        operations['primary_package_input'] = json.loads(Path('/inputs/package-input.json').read_bytes())
        spec = Path('/receipts/producers/package-operations.json')
        pin = write(spec, operations)
        support.update(path='/guard/primary_package_operations.py',
                       sha256=sha('/guard/primary_package_operations.py'),
                       spec_path=str(spec), spec_sha256=pin)
        self.manifest['source_case'] = 'PRIMARY-package-' + primary.plan['package_mode']
        self.manifest['scope'] = 'primary package archive entry'
        self.path = '/receipts/primary-package-source.json'
        self.pin = write(Path(self.path), self.manifest)
        self.supervisor.spec['manifest'] = self.path
        self.supervisor.spec['pins'][self.path] = self.pin
        self.supervisor.manifest = self.manifest
        self.supervisor.manifest_pin = self.pin
        install_return_observer(self, primary)

    def require_complete(self, trace):
        if (self.package_proof is None or self.supervisor.poisoned or trace.poison
                or not any(event['kind'] == 'source_producer_python_startup_consumption'
                           and event['class'] == 'source-extracted-oracle'
                           for event in self.supervisor.events())):
            raise RuntimeError('primary_package_original_archive_incomplete')
