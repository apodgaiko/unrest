"""PRIMARY-only operation domain; execute the exact unchanged legacy base."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

_BASE = Path('/guard/finite/source_operations.py')
_BODY = _BASE.read_bytes()
if hashlib.sha256(_BODY).hexdigest() != '12108d981607212eac8b3f37413664229bee77fa1510a2adefaad2a397cbf89e':
    raise RuntimeError('primary_dependency_operations_base_drift')
exec(compile(_BODY, str(_BASE), 'exec', dont_inherit=True), globals())


_LegacyOperations: Any = globals()['Operations']


class Operations(_LegacyOperations):
    def inputs(self):
        if hashlib.sha256(_BASE.read_bytes()).hexdigest() != '12108d981607212eac8b3f37413664229bee77fa1510a2adefaad2a397cbf89e':
            self.refuse('primary_dependency_operations_base_drift')
        observed = super().inputs()
        self.dependency('/source/.venv/lib/python3.13/site-packages')
        return observed

    def dependency(self, site):
        support = self.spec.get('primary_dependency_support')
        if (type(support) is not dict or set(support) != {'path', 'sha256', 'outputs_sha256'}
                or support['path'] != '/guard/primary_dependency.py'):
            self.refuse('primary_dependency_support_missing')
        body = Path(support['path']).read_bytes()
        if hashlib.sha256(body).hexdigest() != support['sha256']:
            self.refuse('primary_dependency_support_drift')
        if hashlib.sha256(Path('/guard/producer_outputs.py').read_bytes()).hexdigest() != support['outputs_sha256']:
            self.refuse('primary_dependency_outputs_support_drift')
        namespace = {'__file__': support['path'], '__name__': 'primary_dependency_consumer'}
        exec(compile(body, support['path'], 'exec', dont_inherit=True), namespace)
        try:
            observed = namespace['verify'](site, self.spec['primary_dependency'])
        except Exception as error:
            self.emit({'kind': 'primary_dependency_refusal',
                       'code_sha256': hashlib.sha256(str(error).encode()).hexdigest()})
            self.refuse('primary_dependency_consumption_refused')
        self.emit(observed)
