"""PRIMARY journal framing and diagnostic specialization; legacy gates stay exact."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

_PRIMARY = Path('/guard/primary_operations.py')
_PRIMARY_BODY = _PRIMARY.read_bytes()
if hashlib.sha256(_PRIMARY_BODY).hexdigest() != '07b9f4bd15176816fe8cdf06493141a7022bdd6a086f856d3d90af630a874905':
    raise RuntimeError('primary_journal_operation_base_drift')
exec(compile(_PRIMARY_BODY, str(_PRIMARY), 'exec', dont_inherit=True), globals())
_PrimaryOperations: Any = globals()['Operations']
sha: Any = globals()['sha']


class Operations(_PrimaryOperations):
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
            if not hasattr(self, '_dependency_comparisons'):
                self._dependency_comparisons = {}
            observed = namespace['verify'](site, self.spec['primary_dependency'],
                                           comparisons=self._dependency_comparisons)
        except Exception as error:
            self.emit({'kind': 'primary_dependency_refusal',
                       'code_sha256': hashlib.sha256(str(error).encode()).hexdigest()})
            self.refuse('primary_dependency_consumption_refused')
        self.emit(observed)


    def rows(self):
        rows = []
        for path in sorted(Path(self.state['events']).glob('*.jsonl')):
            data = path.read_bytes()
            committed = data[:data.rfind(b'\n') + 1]
            # A live owner's unfinished write cannot supply settlement evidence.
            rows.extend(json.loads(line) for line in committed.decode('utf-8').split('\n')[:-1])
        return rows

    def admit(self, argv, cwd, env):
        try:
            return super().admit(argv, cwd, env)
        except (OSError, RuntimeError, KeyError, ValueError, TypeError) as error:
            refusal = getattr(sys.modules.get("runtime_guard"), "GuardRefusal", ())
            if isinstance(error, refusal):
                raise
            frames = []
            trace = error.__traceback__
            allowed = {"source_operations.py", "source_activation.py", "operation_activation.py",
                       "primary_operation_journal.py",
                       "producer_profile.py"}
            while trace is not None and len(frames) < 8:
                code = trace.tb_frame.f_code
                name = Path(code.co_filename).name
                frames.append({"support": name if name in allowed else "other",
                               "line": trace.tb_lineno, "code_sha256": sha(code.co_code)})
                trace = trace.tb_next
            try:
                name = type(error).__name__
                error_class = name if name in {"OSError", "RuntimeError", "KeyError", "ValueError",
                                              "TypeError", "UnicodeDecodeError", "JSONDecodeError",
                                              "FileNotFoundError", "PermissionError"} else "other"
                self.emit({"kind": "operation_binding_failure", "error_class": error_class,
                           "errno": getattr(error, "errno", None), "frames": frames})
            except OSError:
                # Diagnostic durability cannot replace the original refusal.
                pass
            raise
