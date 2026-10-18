"""Export the first original full certificate from this run's custody journal.

No source result is taken from metadata, CLI switches, or a pass boolean. The
original direct records must close before encryption or artifact materialization.
The job identity was fetched by the existing read-only decision control plane;
the source capsules never receive that API credential or the custody MAC key.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

from checkpoint_decision import REPOSITORY, SUPPORT, expected_identity
from checkpoint_issuer import issue
from checkpoint_packages import LIMIT
from primary_custody import (Binding, CHECKSUM, Custody, OUTPUTS, canonical, exclusive,
                             read_regular, sha)
from structured_evidence import loads, require


def frozen_pins(repository):
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=repository).decode().split('\0')
    pins = {}
    for name in sorted(filter(None, names)):
        body = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=repository)
        path = repository / name
        require(not path.is_symlink() and path.is_file() and path.read_bytes() == body,
                'issuer_current_checkout_drift')
        pins[name] = sha(body)
    return pins


def export(custody, workflow, source_pins, job, root, recipient):
    # Reduction happens first. A missing phase cannot leave a certificate,
    # package output, or even a newly created full-evidence directory.
    issue(custody, workflow, source_pins, job, b'')
    root.mkdir(mode=0o700)
    archive = root / 'private-current-phases.tar.gz'
    from ci_commands import REGISTRY
    with tarfile.open(archive, 'x:gz') as stream:
        for duty in sorted(loads(REGISTRY.read_bytes())):
            body = canonical(custody.phase(duty))
            row = tarfile.TarInfo('phases/' + sha(duty.encode()) + '.json')
            row.size, row.mode = len(body), 0o600
            stream.addfile(row, io.BytesIO(body))
        body = canonical(source_pins)
        row = tarfile.TarInfo('source-pins.json')
        row.size, row.mode = len(body), 0o600
        stream.addfile(row, io.BytesIO(body))
    cipher = root / 'evidence.cms'
    with (root / 'encryption.stderr').open('xb') as errors:
        result = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc',
                                 '-outform', 'DER', '-in', str(archive), '-out', str(cipher),
                                 str(recipient)], stdout=subprocess.DEVNULL, stderr=errors, check=False)
    require(result.returncode == 0, 'issuer_evidence_encryption')
    receipt = issue(custody, workflow, source_pins, job, cipher.read_bytes())
    exclusive(root / 'safe-provenance.json', canonical(receipt))
    archive.unlink()
    return receipt


def materialize(custody, destination):
    phase = custody.phase(CHECKSUM)
    require(set(phase['outputs']) == set(OUTPUTS), 'issuer_package_output_set')
    bodies = {name: read_regular(custody.root / sha(CHECKSUM.encode()) / name, LIMIT, 0o600)
              for name in OUTPUTS}
    require(all(sha(body) == phase['outputs'][name] for name, body in bodies.items()),
            'issuer_current_package_bytes')
    destination.mkdir(mode=0o700)
    for name, body in sorted(bodies.items()):
        exclusive(destination / name, body)


def main():
    require(os.environ['GITHUB_WORKFLOW'] == 'CI' and os.environ['GITHUB_EVENT_NAME'] == 'push'
            and re.fullmatch(r'refs/heads/(?:main|codex/release-v046-[a-z0-9-]+)',
                             os.environ['GITHUB_REF']), 'issuer_primary_execution_context')
    temporary = Path(os.environ['RUNNER_TEMP'])
    expected = expected_identity()
    decision = loads(read_regular(temporary / 'primary-decision.json', 65536, 0o600))
    require(decision['expected'] == expected, 'issuer_frozen_decision')
    if decision['decision'] == 'reuse-authentic-full':
        require(decision['receipt']['head_sha'] == expected['head_sha'], 'issuer_reuse_head')
        return 0
    require(decision['decision'] == 'execute-first-full' and decision['receipt'] is None,
            'issuer_original_execution_decision')
    run, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    job = loads(read_regular(temporary / 'primary-job.json', 8192, 0o600))
    require(job['expected'] == expected and job['run_attempt'] == attempt, 'issuer_current_job')
    custody = Custody(temporary / 'primary-custody', Binding(expected, run, attempt))
    export(custody, (REPOSITORY / '.github/workflows/ci.yml').read_text(), frozen_pins(REPOSITORY),
           job, temporary / 'primary-full', SUPPORT / 'evidence-recipient.pem')
    materialize(custody, REPOSITORY / 'dist')
    return 0


if __name__ == '__main__':
    try:
        status = main()
    except Exception:
        status = 125
    print(json.dumps({'schema': 'unrest.v046.checkpoint-issuer-status.v1',
                      'status': 'exported-or-authentic-reuse' if status == 0 else 'refused'}))
    raise SystemExit(status)
