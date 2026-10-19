"""Composition controls; Linux ownership/transport proof remains separate."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import phase_catalog
import release_source_inputs

ROOT = Path(__file__).resolve().parents[2]


def test_catalog_covers_every_command_and_every_encrypted_phase():
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    phase_catalog.require_retention(workflow)
    phases = phase_catalog.catalog()
    assert {name: phase.command for name, phase in phases.items()} == json.loads(
        phase_catalog.REGISTRY.read_bytes())
    members = phase_catalog.retained_members()
    assert len(members) == len(set(members))
    for phase in phases.values():
        assert set(phase.encrypted_members) <= set(members)
    assert set(phase_catalog.ORDER) <= phases.keys()


@pytest.mark.parametrize('mutation', ['source', 'package', 'preparation', 'condition'])
def test_upload_drift_fails_before_execution(mutation):
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    if mutation == 'condition':
        workflow = workflow.replace('        if: always()\n', '        if: success()\n')
    else:
        path = {'source': 'primary-source', 'package': 'primary-package-build',
                'preparation': 'primary-preparation'}[mutation]
        workflow = workflow.replace('            ${{ runner.temp }}/' + path + '/evidence.cms\n', '')
    with pytest.raises(RuntimeError):
        phase_catalog.require_retention(workflow)


def test_exact_version_transition_keeps_historical_template_and_core():
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    original = copy.deepcopy(template)
    release_source_inputs.admit(template, ROOT, lambda root, name: (root / name).read_bytes())
    assert template['anchor_inventory'] == original['anchor_inventory']
    assert set(name for name, pin in template['product_pins'].items()
               if pin != original['product_pins'][name]) == set(release_source_inputs.POST)
    assert template['product_pins'] | release_source_inputs.PRE == original['product_pins']
    for name, pin in {
        'finite/runtime_guard.py': '475f460e197fa896a7a8ef59ca48f986445e7749ba7efd09137d9cc480f5686e',
        'primary_source_authority.py': 'ac7de9fabf159b37517a8acfba9eea9b3d903750c05f8509e8b80627b8371abc',
    }.items():
        assert hashlib.sha256((ROOT / '.github/release-source-guard' / name).read_bytes()).hexdigest() == pin


@pytest.mark.parametrize('mutation', ['preimage', 'postimage'])
def test_version_transition_never_adopts_observed_drift(mutation):
    template = json.loads((ROOT / '.github/release-source-guard/finite/source-template.json').read_bytes())
    if mutation == 'preimage':
        template['product_pins']['pyproject.toml'] = '0' * 64
    def read(root, name):
        body = (root / name).read_bytes()
        return body + b'foreign' if mutation == 'postimage' and name == 'pyproject.toml' else body
    with pytest.raises(RuntimeError):
        release_source_inputs.admit(template, ROOT, read)


@pytest.mark.parametrize('suffix', ['01', '06', '00', '07', '1', '01-extra', ''])
@pytest.mark.parametrize('workflow', ['CI', 'v0.4.6 source guard readiness', 'foreign'])
def test_preflight_context_is_finite_and_does_not_admit_historical_methods(monkeypatch, suffix, workflow):
    import preflight_policy
    from structured_evidence import EvidenceRefused
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')
    monkeypatch.setenv('GITHUB_WORKFLOW', workflow)
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/codex/release-v047-preflight-20261019-' + suffix)
    if workflow == 'CI' and suffix in {'01', '06'}:
        preflight_policy.context()
    else:
        with pytest.raises(EvidenceRefused):
            preflight_policy.context()


def test_acquired_preparation_failure_is_encrypted_without_adopting_stale_root(tmp_path, monkeypatch):
    import ci_shell
    from structured_evidence import canonical
    from preparation_retention import acquire
    root = acquire(tmp_path, 'primary-import')
    raw = root / 'raw'
    monkeypatch.setattr('preparation_retention.execution_identity', lambda *args: {'head_sha': 'a' * 40})
    marker = b'private preparation diagnostic'
    (raw / 'coordinator.log').write_bytes(marker)
    monkeypatch.setattr(ci_shell, 'ACTIVE_ROOT', root)
    monkeypatch.setattr(ci_shell, 'STAGE', 'image')
    def fail():
        raise RuntimeError('controlled preparation failure')
    monkeypatch.setattr(ci_shell, 'main', fail)
    assert ci_shell.retained_main() == 125
    metadata = json.loads((root / 'safe-provenance.json').read_bytes())
    assert metadata['stage'] == 'image' and metadata['exit_code'] == 125
    assert metadata['ciphertext_sha256'] == hashlib.sha256((root / 'evidence.cms').read_bytes()).hexdigest()
    assert marker not in canonical(metadata) and marker not in (root / 'evidence.cms').read_bytes()
    assert not raw.exists() and not (root / 'raw.tar.gz').exists()
    original = (root / 'evidence.cms').read_bytes()
    with pytest.raises(RuntimeError):
        ci_shell.retained_main()
    assert (root / 'evidence.cms').read_bytes() == original
    monkeypatch.setattr(ci_shell, 'ACTIVE_ROOT', None)
    with pytest.raises(RuntimeError):
        ci_shell.retained_main()
    assert sorted(path.name for path in tmp_path.iterdir()) == ['primary-import']
