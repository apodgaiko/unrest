"""Finite native metadata and archive-only output; no generic export relaxation."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

import primary_package_exports as package
from primary_custody import BUILD, WHEEL, SDIST, decode_outputs
from structured_evidence import source_header, EvidenceRefused
from test_primary_package_entry import execution
from test_source_transport import vector, INVOCATION


@pytest.mark.parametrize('kind', ['build', 'archive', 'installed', 'checksum', 'source'])
@pytest.mark.parametrize('status', [0, 2, 125])
def test_package_output_failure_is_a_closed_failed_status_only(kind, status):
    identity = execution('cache-lineage-05')
    identity['artifact_name'] = 'v046-source-' + ('primary-source' if kind == 'source' else 'primary-package-' + kind) + '-12-1'
    kernel, records = vector()
    kernel['failure_code'] = 'package_output_refused'
    records['kernel-source.json'] = json.dumps(kernel).encode()
    if kind != 'source' and status in {2, 125}:
        header = source_header(records, kernel, identity, INVOCATION, status)
        assert b'package_output_refused' in header
    else:
        with pytest.raises(EvidenceRefused, match='header_status'):
            source_header(records, kernel, identity, INVOCATION, status)


def fixture(tmp_path, monkeypatch):
    root = tmp_path / 'dist'
    root.mkdir()
    for name, body in {WHEEL: b'wheel', SDIST: b'sdist', '.gitignore': b'*'}.items():
        (root / name).write_bytes(body)
    monkeypatch.setattr(package, 'ROOT', root)
    monkeypatch.setattr(package, 'kernel_success', lambda *args: None)
    def read(path, limit):
        return path.read_bytes(), ('current-identity',)
    monkeypatch.setattr(package, 'read', read)
    context = {'pid': 8, 'owner_pid': 7, 'identity': {'pid': 8, 'uid': 20000}, 'package_output_before': 'empty-artifact-mount',
               'package_output_identity': package.source_root.key(root)}
    producers = SimpleNamespace(uv={8: context}, cache_completed={8}, records=[],
                                kernel=SimpleNamespace(identity=lambda pid: {'uid': 20000}))
    source = SimpleNamespace(producers=producers, require_complete=lambda trace: None)
    kernel = {'primary_plan': {'duty': BUILD, 'package_mode': 'TEST'}, 'actual_script_sha256': 'a' * 64}
    return source, kernel, root, context


def test_exact_current_metadata_stays_local_and_only_archives_are_exported(tmp_path, monkeypatch):
    source, kernel, root, _ = fixture(tmp_path, monkeypatch)
    body = package.export(source, object(), kernel)
    assert decode_outputs(body, BUILD) == {WHEEL: b'wheel', SDIST: b'sdist'}
    assert (root / '.gitignore').read_bytes() == b'*'
    assert source.producers.records[0]['metadata_sha256'] == hashlib.sha256(b'*').hexdigest()


@pytest.mark.parametrize('mutation', ['extra', 'metadata', 'missing', 'preexisting', 'unsettled', 'duty', 'mode'])
def test_unknown_or_unproven_output_is_refused(tmp_path, monkeypatch, mutation):
    source, kernel, root, context = fixture(tmp_path, monkeypatch)
    if mutation == 'extra':
        (root / 'unknown').write_bytes(b'foreign')
    elif mutation == 'metadata':
        (root / '.gitignore').write_bytes(b'foreign')
    elif mutation == 'missing':
        (root / '.gitignore').unlink()
    elif mutation == 'preexisting':
        context['package_output_before'] = 'preexisting'
    elif mutation == 'unsettled':
        source.producers.cache_completed.clear()
    elif mutation == 'duty':
        kernel['primary_plan']['duty'] = 'foreign'
    elif mutation == 'mode':
        kernel['primary_plan']['package_mode'] = 'foreign'
    with pytest.raises(RuntimeError, match='package_build_export_'):
        package.export(source, object(), kernel)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'foreign-owner'])
def test_actual_reader_rejects_untrusted_carriers(tmp_path, kind):
    path = tmp_path / 'metadata'
    path.write_bytes(b'*')
    if kind == 'symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(path)
        path = alias
    elif kind == 'hardlink':
        os.link(path, tmp_path / 'alias')
    # Test fixtures never impersonate the execute UID; real hosted package proof
    # exercises its positive exact-owner path.
    if kind == 'foreign-owner' and os.getuid() == 20000:
        path.chmod(0o600)
    with pytest.raises((OSError, RuntimeError)):
        package.read(path, 1)
