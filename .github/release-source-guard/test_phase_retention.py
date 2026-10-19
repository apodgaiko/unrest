"""Actual SOURCE output and always-upload path controls; no source cases run."""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import ci_shell
import full_bootstrap
import source_raw_transport
from ci_commands import bind_generated

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/ci.yml').read_text()
SCRIPT = b'env -u CODEX_PATH uv run pytest -q'


def always_upload(workflow):
    block = workflow.split('      - name: Preserve encrypted primary phase evidence\n')[1]
    block = block.split('      - ', 1)[0]
    assert '\n        if: always()\n' in '\n' + block
    assert 'uses: actions/upload-artifact@v4.6.2' in block
    paths = block.split('          path: |\n')[1].split('          if-no-files-found:')[0]
    return [line.strip().removeprefix('${{ runner.temp }}/') for line in paths.splitlines()]


def test_every_original_nonpackage_phase_has_both_always_retained_outputs():
    paths = always_upload(WORKFLOW)
    for duty, kind in ci_shell.KINDS.items():
        if duty.startswith('TEST-') or duty in ci_shell.ORDER:
            continue
        assert kind + '/evidence.cms' in paths
        assert kind + '/safe-provenance.json' in paths
    assert 'primary-host-stage.json' in paths
    assert 'primary-image-stage.json' in paths
    assert 'primary-decision-status.json' in paths
    assert all(name.endswith(('/evidence.cms', '/safe-provenance.json')) or name in {
        'primary-host-stage.json', 'primary-image-stage.json', 'primary-decision-status.json'}
        for name in paths)
    assert bind_generated(SCRIPT, WORKFLOW)['full_source'] is True


def test_original_missing_source_paths_are_detected():
    broken = WORKFLOW.replace('            ${{ runner.temp }}/primary-source/evidence.cms\n', '')
    broken = broken.replace('            ${{ runner.temp }}/primary-source/safe-provenance.json\n', '')
    assert 'primary-source/evidence.cms' not in always_upload(broken)
    assert 'primary-source/safe-provenance.json' not in always_upload(broken)
    # The success-only issuer output never substitutes for the original capture.
    assert 'primary-full/evidence.cms' in always_upload(broken)


@pytest.mark.parametrize('outcome', ['success', 'source_failure', 'create_failure', 'capture_failure',
                                    'custody_failure'])
def test_real_shell_encrypts_original_source_paths_even_before_issuer(tmp_path, monkeypatch, outcome):
    expected = {'source_tree': 'a' * 40}
    monkeypatch.setenv('RUNNER_TEMP', str(tmp_path))
    monkeypatch.setenv('GITHUB_WORKFLOW', 'CI')
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/codex/release-v046-retention-test')
    monkeypatch.setenv('GITHUB_SHA', 'b' * 40)
    (tmp_path / 'primary-decision.json').write_text(json.dumps({
        'schema': 'unrest.v046.primary-decision.v1', 'expected': expected,
        'decision': 'execute-first-full', 'receipt': None}))
    script_path = tmp_path / 'github-script.sh'
    script_path.write_bytes(SCRIPT)
    monkeypatch.setattr(sys, 'argv', ['ci_shell.py', str(script_path)])
    monkeypatch.setattr(ci_shell, 'expected_identity', lambda: expected)
    monkeypatch.setattr(full_bootstrap, 'consume', lambda *args: {'definition': expected})
    spec = {'duty': bind_generated(SCRIPT, WORKFLOW)['name'],
            'script_sha256': ci_shell.digest(script_path)}
    monkeypatch.setattr(ci_shell, 'plan', lambda *args: spec)
    monkeypatch.setattr(ci_shell, 'public_plan', lambda value: value)
    marker = b'controlled private SOURCE output; never public plaintext'
    cleanup = []

    def prepare(spec, *args):
        root = tmp_path / ci_shell.KINDS[spec['duty']]
        root.mkdir(mode=0o700)
        raw = root / 'raw'
        raw.mkdir(mode=0o700)
        (raw / 'source-output.txt').write_bytes(marker)
        return dict(root=root, raw=raw, log=raw / 'coordinator.log', control={'support': {}},
                    custody=None, image='controlled-image', source_pins={}, container='controlled',
                    identity={}, source_invocation='c' * 64)

    def create(prepared):
        if outcome == 'create_failure':
            raise RuntimeError('private controlled creation failure')

    def capture(argv, raw, *args, **kwargs):
        assert argv == ['docker', 'start', '--attach', 'controlled']
        if outcome == 'capture_failure':
            raise RuntimeError('private controlled capture failure')
        (raw / 'structured-envelope.json').write_bytes(b'controlled envelope')
        return None, {'kernel-source.json': b'controlled named record'}

    original_run = ci_shell.run

    def run(argv, log):
        if argv[0] == 'docker':
            assert argv == ['docker', 'rm', '--force', 'controlled']
            cleanup.append(argv)
            return SimpleNamespace(returncode=0)
        assert argv[:3] == ['openssl', 'cms', '-encrypt']
        return original_run(argv, log)

    state = json.dumps({'Running': False, 'OOMKilled': False,
                        'ExitCode': 2 if outcome == 'source_failure' else 0}).encode()
    monkeypatch.setattr(ci_shell, 'prepare_capsule', prepare)
    monkeypatch.setattr(ci_shell, 'create_capsule', create)
    monkeypatch.setattr(source_raw_transport, 'capture', capture)
    monkeypatch.setattr(ci_shell, 'run', run)
    monkeypatch.setattr(ci_shell.subprocess, 'check_output', lambda *args, **kwargs: state)
    real_subprocess_run = subprocess.run

    def inspect(argv, **kwargs):
        if argv[0] == 'docker':
            return SimpleNamespace(returncode=0, stdout=state)
        return real_subprocess_run(argv, **kwargs)

    monkeypatch.setattr(ci_shell.subprocess, 'run', inspect)
    custody_calls = []

    def retain(*args):
        custody_calls.append(True)
        return (125, None) if outcome == 'custody_failure' else (0, 'd' * 64)

    monkeypatch.setattr(ci_shell, 'retain_phase', retain)
    status = ci_shell.main()
    assert status == {'success': 0, 'source_failure': 2}.get(outcome, 125)
    assert len(cleanup) == 1
    assert bool(custody_calls) == (outcome in {'success', 'custody_failure'})
    root = tmp_path / 'primary-source'
    paths = always_upload(WORKFLOW)
    retained = {name: (tmp_path / name).read_bytes() for name in paths if (tmp_path / name).is_file()}
    assert set(retained) == {'primary-source/evidence.cms', 'primary-source/safe-provenance.json'}
    ciphertext = retained['primary-source/evidence.cms']
    metadata = json.loads(retained['primary-source/safe-provenance.json'])
    assert metadata['source_exit_code'] == status
    assert metadata['ciphertext_sha256'] == ci_shell.digest(root / 'evidence.cms')
    assert metadata['custody_phase_sha256'] == ('d' * 64 if outcome == 'success' else None)
    assert marker not in ciphertext
    assert str(tmp_path).encode() not in retained['primary-source/safe-provenance.json']
    assert b'private controlled' not in retained['primary-source/safe-provenance.json']
    assert not (root / 'raw').exists() and not (root / 'raw.tar.gz').exists()
    assert not (tmp_path / 'primary-full').exists()
    assert not (tmp_path / 'dist').exists()


def test_readiness_capsule_failure_outputs_are_always_retained_before_source():
    paths = always_upload(WORKFLOW)
    required = {'source-readiness/evidence.cms', 'source-readiness/safe-provenance.json'}
    assert required <= set(paths)
    for name in required:
        broken = WORKFLOW.replace('            ${{ runner.temp }}/' + name + '\n', '')
        assert name not in always_upload(broken)
    assert bind_generated(SCRIPT, WORKFLOW)['full_source'] is True
    assert SCRIPT == b'env -u CODEX_PATH uv run pytest -q' and len(SCRIPT) == 34
