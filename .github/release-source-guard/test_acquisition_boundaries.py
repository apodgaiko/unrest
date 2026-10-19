"""Direct real-resource acquisition regressions; Linux CI supplies guard proof."""
from __future__ import annotations

import errno
import inspect
import json
import multiprocessing
import os
import sys
import subprocess

import pytest

import ci_shell
import full_bootstrap as full
from preflight_policy import SCRIPT
from structured_evidence import execution_identity
from tests.multiprocess_lifetime import SpawnResources


@pytest.mark.parametrize('operation', ['dup', 'fstat', 'get_inheritable', 'set_inheritable'])
def test_acquisition_failure_rolls_back_real_tracker_and_preserves_error(operation, monkeypatch):
    owner = SpawnResources()
    original = getattr(os, operation)
    error = OSError(errno.EMFILE, 'owned acquisition failure')
    injected = False
    directory = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
    before = len(os.listdir(directory))

    def fail_once(*args, **kwargs):
        nonlocal injected
        frame = inspect.currentframe().f_back
        wanted = owner.custody if operation == 'set_inheritable' else owner.tracker._fd
        if (not injected and wanted is not None and args[0] == wanted
                and frame.f_code.co_filename == SpawnResources.context.__code__.co_filename
                and frame.f_code.co_name in {'context', '_acquired_pipe'}):
            injected = True
            raise error
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, operation, fail_once)
        with pytest.raises(OSError) as caught:
            with owner:
                owner.context(multiprocessing.get_context('spawn'))
    assert injected and caught.value is error
    assert owner.closed and owner.tracker._pid is None and owner.tracker._fd is None
    assert owner.tracker._exitcode == 0
    assert owner.identity is not None and owner.pid is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(owner.pid, os.WNOHANG)
    assert len(os.listdir(directory)) == before


def host(tmp_path, monkeypatch):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=full.REPOSITORY).decode().strip()
    environment = {
        'RUNNER_TEMP': str(tmp_path), 'GITHUB_REPOSITORY': 'apodgaiko/unrest',
        'GITHUB_SHA': head, 'GITHUB_WORKFLOW_SHA': head,
        'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKFLOW': 'CI',
        'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/codex/release-v047-preflight-20261019-06',
        'GITHUB_WORKFLOW_REF': 'apodgaiko/unrest/.github/workflows/ci.yml@refs/heads/codex/release-v047-preflight-20261019-06'}
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    # Direct diagnostic: stable definition and Linux host context are supplied. Neither
    # this test nor its direct subprocesses claim current Linux envelope proof.
    monkeypatch.setattr(full, 'context', lambda operation: execution_identity(full.SUPPORT, 'primary-source'))
    monkeypatch.setattr(ci_shell, 'expected_identity', lambda: {'head_sha': head})
    monkeypatch.setattr(ci_shell, 'ACTIVE_ROOT', None)


def test_actual_custom_shell_retains_initial_physical_input_failure(tmp_path, monkeypatch):
    host(tmp_path, monkeypatch)
    (tmp_path / 'primary-input-custody').mkdir(mode=0o755)
    script = tmp_path / 'script.sh'
    script.write_bytes(SCRIPT)
    monkeypatch.setattr(sys, 'argv', ['ci_shell.py', '--preflight', 'TEST-positive', str(script)])
    assert ci_shell.retained_main() == 125
    root = tmp_path / 'primary-source-positive'
    metadata = json.loads((root / 'safe-provenance.json').read_bytes())
    assert metadata['stage'] == 'binding' and metadata['exit_code'] == 125
    assert (root / 'evidence.cms').stat().st_size > 0
    assert not (root / 'raw').exists()
    assert not list(root.rglob('kernel-source.json'))


def test_unadmitted_script_never_acquires_retention(tmp_path, monkeypatch):
    host(tmp_path, monkeypatch)
    script = tmp_path / 'script.sh'
    script.write_bytes(SCRIPT + b' --foreign')
    monkeypatch.setattr(sys, 'argv', ['ci_shell.py', '--preflight', 'TEST-positive', str(script)])
    with pytest.raises(RuntimeError, match='primary_source_test_script'):
        ci_shell.retained_main()
    assert ci_shell.ACTIVE_ROOT is None
    assert sorted(path.name for path in tmp_path.iterdir()) == ['script.sh']


@pytest.mark.parametrize('kind', ['stale', 'symlink', 'runner-mode'])
def test_retention_never_adopts_foreign_output(tmp_path, kind):
    from preparation_retention import acquire
    from structured_evidence import EvidenceRefused
    root = tmp_path / 'primary-import'
    if kind == 'stale':
        root.mkdir(mode=0o700)
    elif kind == 'symlink':
        root.symlink_to(tmp_path / 'private-target')
    else:
        tmp_path.chmod(0o777)
    with pytest.raises((OSError, EvidenceRefused)):
        acquire(tmp_path, root.name)
    assert not (tmp_path / 'private-target').exists()
    assert not (root / 'evidence.cms').exists()


def test_actual_producer_retains_initial_custody_creation_failure(tmp_path, monkeypatch):
    host(tmp_path, monkeypatch)
    from types import SimpleNamespace
    actual_run = subprocess.run

    def clean_checkout(argv, **kwargs):
        if argv[:3] == ['git', 'diff', '--quiet']:
            return SimpleNamespace(returncode=0)
        return actual_run(argv, **kwargs)

    monkeypatch.setattr(subprocess, 'run', clean_checkout)
    monkeypatch.setattr(full, 'expected_identity', lambda: {})
    monkeypatch.setattr(full, 'carrier', lambda: ({'source_carrier_sha256': 'b' * 64,
                                                'package_closure_sha256': 'c' * 64,
                                                'input_scope_sha256': 'd' * 64}, 'e' * 64))
    (tmp_path / 'primary-input-custody').mkdir(mode=0o755)
    with pytest.raises(FileExistsError):
        full.produce('PREFLIGHT')
    root = tmp_path / 'primary-preparation'
    metadata = json.loads((root / 'safe-provenance.json').read_bytes())
    assert metadata['exit_code'] == 125 and metadata['stage'] == 'binding'
    assert (root / 'evidence.cms').stat().st_size > 0
    assert not (tmp_path / 'primary-source-input.json').exists()
    assert not (root / 'raw').exists()


@pytest.mark.parametrize('mutation', ['none', 'preimage', 'postimage'])
def test_tracker_acquisition_rebinds_only_exact_helper(mutation, monkeypatch):
    import copy
    import hashlib
    import prepare_source
    support = full.SUPPORT
    manifest = json.loads((support / 'finite/source-template.json').read_bytes())
    before = copy.deepcopy(manifest)
    name = 'tests/multiprocess_lifetime.py'
    if mutation == 'preimage':
        manifest['product_pins'][name] = '0' * 64
    monkeypatch.setattr(prepare_source, 'ROOT', full.REPOSITORY)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER',
                        lambda root, path: (root / path).read_bytes()
                        + (b'foreign' if mutation == 'postimage' and path == name else b''), raising=False)
    if mutation != 'none':
        with pytest.raises(RuntimeError, match='tracker_acquisition_'):
            prepare_source.admit_tracker_acquisition(manifest)
    else:
        prepare_source.admit_tracker_acquisition(manifest)
        before['product_pins'][name] = hashlib.sha256((full.REPOSITORY / name).read_bytes()).hexdigest()
        assert manifest == before


def test_replaced_retention_root_never_receives_failure_or_ciphertext(tmp_path, monkeypatch):
    from preparation_retention import acquire, retain, release
    from structured_evidence import EvidenceRefused
    root = acquire(tmp_path, 'primary-import')
    root.rename(tmp_path / 'original')
    root.mkdir(mode=0o700)
    (root / 'raw').mkdir(mode=0o700)
    monkeypatch.setattr('preparation_retention.execution_identity', lambda *args: {})
    try:
        with pytest.raises(EvidenceRefused, match='primary_retention_identity'):
            retain(root, {}, RuntimeError('private body'))
        assert sorted(path.name for path in root.iterdir()) == ['raw']
        assert list((root / 'raw').iterdir()) == []
    finally:
        release(root)
