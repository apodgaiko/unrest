"""Host-only physical FULL input controls, never SOURCE execution evidence."""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import shutil
import tempfile

from full_bootstrap import consume, produce, SCRIPT
from primary_custody import read_regular
from structured_evidence import canonical, loads, require


def main():
    original = os.environ['RUNNER_TEMP']
    cases = ('valid', 'stale-copy', 'replace', 'mode', 'hardlink', 'symlink', 'partial',
             'cross-run', 'cross-attempt', 'workflow', 'operation', 'script',
             'clock', 'deadline', 'mac', 'key', 'missing', 'root-mode', 'root-replaced')
    passed = []
    for case in cases:
        root = Path(tempfile.mkdtemp(prefix='full-input-control-', dir=original))
        environment = dict(os.environ)
        os.environ['RUNNER_TEMP'] = str(root)
        try:
            produce('PREPAREONLY')
            target = root / 'primary-source-input.json'
            custody = root / 'primary-input-custody'
            operation, script = 'PREPAREONLY', SCRIPT
            if case in {'stale-copy', 'replace'}:
                body = target.read_bytes()
                replacement = root / 'replacement'
                replacement.write_bytes(body)
                replacement.chmod(0o600)
                replacement.replace(target)
            elif case == 'mode':
                target.chmod(0o644)
            elif case == 'hardlink':
                os.link(target, root / 'alias')
            elif case == 'symlink':
                target.rename(root / 'original')
                target.symlink_to(root / 'original')
            elif case == 'partial':
                target.write_bytes(b'{}')
            elif case in {'cross-run', 'cross-attempt'}:
                name = 'GITHUB_RUN_ID' if case == 'cross-run' else 'GITHUB_RUN_ATTEMPT'
                os.environ[name] = str(int(os.environ[name]) + 1)
            elif case == 'workflow':
                os.environ['GITHUB_WORKFLOW'] = 'CI'
            elif case == 'operation':
                operation = 'FULL'
            elif case == 'script':
                script += b' -x'
            elif case in {'clock', 'deadline'}:
                # Re-sign only this owned negative fixture. The real consumer
                # must enforce clock bounds independently of MAC validity.
                receipt = custody / 'receipt.json'
                signed = loads(read_regular(receipt, 16384, 0o600))
                shift = -1 if case == 'clock' else 7201
                for key in ('wall_ns', 'monotonic_ns'):
                    signed['receipt']['clock'][key] -= shift * 10**9
                key = read_regular(custody / 'key', 32, 0o600)
                signed['mac'] = hmac.digest(key, canonical(signed['receipt']), 'sha256').hex()
                receipt.write_bytes(canonical(signed))
            elif case == 'mac':
                receipt = custody / 'receipt.json'
                signed = loads(receipt.read_bytes())
                signed['mac'] = '0' * 64
                receipt.write_bytes(canonical(signed))
            elif case == 'key':
                (custody / 'key').write_bytes(b'x' * 32)
            elif case == 'missing':
                target.unlink()
            elif case == 'root-mode':
                custody.chmod(0o755)
            elif case == 'root-replaced':
                custody.rename(root / 'old')
                shutil.copytree(root / 'old', custody)
            refused = False
            try:
                consume(operation, script)
            except (RuntimeError, OSError, ValueError, KeyError):
                refused = True
            require(refused == (case != 'valid'), 'full_host_control_failed')
            passed.append(case)
        finally:
            os.environ.clear()
            os.environ.update(environment)
            shutil.rmtree(root)
    print(canonical({'schema': 'unrest.v046.full-host-controls.v1', 'controls': passed,
                     'source_testcase_executed': False, 'eligible_certificate': False}).decode())


if __name__ == '__main__':
    main()
