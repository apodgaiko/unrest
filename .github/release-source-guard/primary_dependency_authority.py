"""PRIMARY dependency specialization; the legacy authority stays byte-identical."""
from __future__ import annotations

from pathlib import Path

from primary_source_authority import SourceAuthority, sha
from producer_setup import write


class DependencySourceAuthority(SourceAuthority):
    def start(self, pid, output_fd, *, trace=None, primary=None):
        super().start(pid, output_fd, trace=trace, primary=primary)
        import primary_dependency
        descriptor = self.primary_dependency_declaration
        body, receipt = primary_dependency.read(descriptor['path'], 20001)
        if (receipt['sha256'] != descriptor['sha256'] or receipt['identity'][5] != 1
                or receipt['identity'][2] & 0o777 != 0o444):
            raise RuntimeError('primary_dependency_evidence_custody')
        self.producers.records.append({'kind': 'primary_dependency_produced',
                                       'declaration_sha256': descriptor['sha256'],
                                       'declaration': primary_dependency.decode(body)})

    def prepare_bootstrap_cache(self, pid, trace, primary):
        super().prepare_bootstrap_cache(pid, trace, primary)
        self.prepare_primary_dependency()

    def tick(self, trace):
        if self.supervisor is None:
            import primary_dependency
            primary_dependency.capture(self, trace)
            return
        super().tick(trace)

    def prepare_primary_dependency(self):
        import producer_profile
        import primary_dependency
        support = self.common['primary_producer']['dependency_support']
        if (support['path'] != '/guard/primary_dependency.py'
                or sha(support['path']) != support['sha256']
                or sha('/guard/producer_outputs.py') != support['outputs_sha256']):
            raise RuntimeError('primary_dependency_support_drift')
        bootstrap = self.common['primary_producer']['bootstrap_cache']
        declaration = primary_dependency.seal(
            self, producer_profile.protected_json(bootstrap['path'], bootstrap['sha256']))
        self.primary_dependency_declaration = declaration
        original = self.manifest['operation_support']
        operations = producer_profile.protected_json(original['spec_path'], original['spec_sha256'])
        operations['primary_dependency'] = {
            **declaration, 'activation_sha256': sha('/guard/finite/operation_activation.py')}
        operations['primary_dependency_support'] = support
        path = Path('/receipts/producers/primary-operations.json')
        pin = write(path, operations)
        original.update(path='/guard/primary_operations.py', sha256=sha('/guard/primary_operations.py'),
                    spec_path=str(path), spec_sha256=pin)
