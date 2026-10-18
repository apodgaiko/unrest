"""Closed package identity and certificate-ineligibility controls."""
from __future__ import annotations

import base64
import hmac
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from structured_evidence import identity_check, EvidenceRefused
from primary_custody import BUILD, canonical, loads, sha
from checkpoint_issuer import issue
from test_checkpoint_issuer import setup


def execution(ref='01'):
    return {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40,
            'run_id': '12', 'run_attempt': '1', 'workflow_sha': 'a' * 40,
            'workflow_ref': 'apodgaiko/unrest/.github/workflows/v046-source-readiness.yml@'
            'refs/heads/codex/source-guard-structured-20261018-package-entry-' + ref,
            'artifact_name': 'v046-source-primary-package-build-12-1', 'support_sha256': 'b' * 64}


@pytest.mark.parametrize('ref', ['01', '02', '03', '04'])
def test_exact_finite_test_package_identity(ref):
    identity_check(execution(ref))


@pytest.mark.parametrize('ref', ['00', '05', '1', '001', '01-extra', '../01', '', '01/main'])
def test_no_prefix_or_unbounded_package_epoch_authority(ref):
    with pytest.raises(EvidenceRefused):
        identity_check(execution(ref))


def test_test_package_kernel_cannot_enter_original_release_issuer(tmp_path):
    custody, workflow, pins, job = setup(tmp_path)
    path = custody.root / (sha(BUILD.encode()) + '.json')
    value = loads(path.read_bytes())['payload']
    kernel = loads(base64.b64decode(value['records']['kernel-source.json']))
    kernel['primary_plan']['package_mode'] = 'TEST'
    value['records']['kernel-source.json'] = base64.b64encode(canonical(kernel)).decode()
    body = canonical(value)
    path.write_bytes(canonical({'payload': value, 'mac': hmac.digest(custody.key, body, 'sha256').hex()}))
    with pytest.raises(RuntimeError, match='issuer_package_test_ineligible'):
        issue(custody, workflow, pins, job, b'synthetic ciphertext')
