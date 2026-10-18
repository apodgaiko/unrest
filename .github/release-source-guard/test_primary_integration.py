"""Repository integration checks; the source-free synthetic capsule omits these."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('primary_ci_commands', Path(__file__).with_name('ci_commands.py'))
assert spec is not None and spec.loader is not None
commands = importlib.util.module_from_spec(spec)
spec.loader.exec_module(commands)

def test_current_primary_original_run_blocks_bind_and_literal_mutation_anchors_survive():
    actual = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
    assert actual.count('  primary:\n    name: primary source and package gate (py3.13)') == 1
    assert actual.count('      - name: Type-check (mypy)\n        run: uv run mypy src') == 1
    registry = json.loads(commands.REGISTRY.read_bytes())
    for name, script in registry.items():
        assert commands.bind(script.encode(), actual)['name'] == name


def test_actual_primary_uses_custom_shell_for_every_original_duty_and_release_ref_activation():
    actual = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
    assert "branches: [main, 'codex/release-v046-*']" in actual
    assert 'cancel-in-progress: false' in actual
    for name in json.loads(commands.REGISTRY.read_bytes()):
        block = actual.split('      - name: ' + name + '\n', 1)[1].split('      - ', 1)[0]
        assert 'shell: python3 .github/release-source-guard/ci_shell.py {0}\n' in block
    assert 'GH_TOKEN: ${{ github.token }}' in actual
    assert 'run: python3 .github/release-source-guard/checkpoint_decision.py' in actual
    assert 'Upload encrypted primary evidence' in actual


def test_primary_and_readiness_private_records_never_form_a_full_certificate():
    from structured_evidence import identity_check, EvidenceRefused
    import pytest
    identity = {'repository': 'apodgaiko/unrest', 'head_sha': 'a' * 40, 'workflow_sha': 'a' * 40,
                'run_id': '1', 'run_attempt': '1', 'support_sha256': 'b' * 64,
                'artifact_name': 'v046-source-primary-import-1-1',
                'workflow_ref': 'apodgaiko/unrest/.github/workflows/ci.yml@refs/heads/codex/release-v046-unit'}
    identity_check(identity)
    identity['artifact_name'] = 'unrest-v046-primary-1-1'
    with pytest.raises(EvidenceRefused):
        identity_check(identity)
    identity['artifact_name'] = 'v046-source-producer-contract-1-1'
    with pytest.raises(EvidenceRefused):
        identity_check(identity)
