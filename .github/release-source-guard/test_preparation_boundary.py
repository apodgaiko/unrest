"""Preparation composition and private closed-error preservation controls."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import preparation_diagnostics
import prepare_source

SUPPORT = Path(__file__).parent
ROOT = SUPPORT.parent.parent


def test_exact_ownership_document_composes_with_original_engine_pins(monkeypatch):
    manifest = json.loads((SUPPORT / 'finite/source-template.json').read_bytes())
    before = copy.deepcopy(manifest)
    monkeypatch.setattr(prepare_source, 'ROOT', ROOT)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER', lambda root, name: (root / name).read_bytes(), raising=False)
    name = 'docs/architecture/experimental-lease.md'
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != before['product_pins'][name]
    prepare_source.admit_ownership_document(manifest)
    before['product_pins'][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert manifest == before


@pytest.mark.parametrize('mutation', ['baseline', 'document', 'lease', 'session', 'engine-pin'])
def test_ownership_document_never_admits_other_inputs(monkeypatch, mutation):
    manifest = json.loads((SUPPORT / 'finite/source-template.json').read_bytes())
    if mutation == 'baseline':
        manifest['product_pins']['docs/architecture/experimental-lease.md'] = '0' * 64
    if mutation == 'engine-pin':
        manifest['product_pins']['src/unrest_harness/experimental_lease.py'] = '0' * 64
    changed = {'document': 'docs/architecture/experimental-lease.md',
               'lease': 'src/unrest_harness/experimental_lease.py',
               'session': 'src/unrest_harness/experimental_session.py'}.get(mutation)
    monkeypatch.setattr(prepare_source, 'ROOT', ROOT)
    monkeypatch.setattr(prepare_source, 'CLOCK_READER',
                        lambda root, name: (root / name).read_bytes() + (b'changed' if name == changed else b''),
                        raising=False)
    before = copy.deepcopy(manifest)
    with pytest.raises(RuntimeError, match='ownership_document_'):
        prepare_source.admit_ownership_document(manifest)
    assert manifest == before


@pytest.mark.parametrize('error,code', [
    (RuntimeError('primary_source_prepare'), 'primary_source_prepare'),
    (RuntimeError('original source baseline drift: private/source'), 'source_baseline_drift'),
    (RuntimeError('private/source body key'), 'unknown'),
    (PermissionError(13, 'private/path'), 'unknown'),
])
def test_closed_diagnostic_never_serializes_exception_body(error, code):
    try:
        raise error
    except BaseException as caught:
        value = preparation_diagnostics.failure(caught)
    assert value['code'] == code
    assert len(value['location_sha256']) == 64
    assert b'private/' not in json.dumps(value).encode()
    assert value['errno'] == (13 if isinstance(error, PermissionError) else None)


@pytest.mark.parametrize('prevent_bytecode', [False, True])
def test_host_control_import_cannot_poison_readonly_source_support(tmp_path, prevent_bytecode):
    import os
    import shutil
    import subprocess
    import sys

    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    assert '\nenv:\n  PYTHONDONTWRITEBYTECODE: "1"\n' in workflow
    support = tmp_path / 'support'
    shutil.copytree(SUPPORT, support, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}}
    if prevent_bytecode:
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
    result = subprocess.run(
        [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); '
         'import primary_dependency_authority', str(support)],
        env=environment, capture_output=True, check=False, timeout=30)
    assert result.returncode == 0, result.stderr
    caches = list((support / 'finite/__pycache__').glob('linux_identity.*.pyc'))
    assert bool(caches) is not prevent_bytecode
