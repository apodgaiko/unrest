"""Immutable namespace controls, separate from all original product tests."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import ci_shell
import source_controller
import source_root


def config():
    mounts = {'/source': '/sealed/source', '/guard': '/guard-support'}
    return {'HostConfig': {
        'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'none',
        'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
        'PidsLimit': 128, 'Memory': 1073741824, 'Tmpfs': dict(ci_shell.TMPFS),
        'SecurityOpt': ['no-new-privileges'], 'CapDrop': ['ALL'],
        'CapAdd': ['SETUID', 'SETGID', 'SETPCAP', 'SYS_PTRACE', 'DAC_READ_SEARCH']},
        'Mounts': [{'Type': 'bind', 'RW': False, 'Propagation': 'rprivate',
                    'Source': origin, 'Destination': target} for target, origin in mounts.items()],
        'Image': 'sha256:owned', 'Config': {'OpenStdin': False,
            'Entrypoint': ['/usr/local/bin/python'], 'Cmd': ['-B', '/guard/primary_compartment.py']}}, mounts


def test_complete_source_bind_and_finite_artifacts(tmp_path):
    assert source_controller.source_bindings(tmp_path, 'producer-primary') == {'/source': str(tmp_path)}
    assert '/source' not in ci_shell.TMPFS
    assert '/source' not in source_controller.tmpfs_for('producer-contract')
    assert {p for p in ci_shell.TMPFS if p.startswith('/source/')} == set(source_root.OVERLAYS)
    (tmp_path / 'src').mkdir()
    source_root.layout(tmp_path)
    assert all((tmp_path / Path(p).relative_to('/source')).is_dir() for p in source_root.OVERLAYS)
    current, mounts = config()
    ci_shell.validate(current, 'sha256:owned', mounts)


@pytest.mark.parametrize('mutation', ['writable-root', 'wrong-mount', 'extra-overlay',
                                      'root-tmpfs', 'extra-bind', 'capability', 'overlay-mode'])
def test_inspected_container_drift_refuses(mutation):
    current, mounts = config()
    if mutation == 'writable-root':
        current['Mounts'][0]['RW'] = True
    elif mutation == 'wrong-mount':
        current['Mounts'][0]['Source'] = '/substituted/source'
    elif mutation == 'extra-overlay':
        current['HostConfig']['Tmpfs']['/source/src'] = 'rw'
    elif mutation == 'root-tmpfs':
        current['HostConfig']['Tmpfs']['/source'] = 'rw'
    elif mutation == 'extra-bind':
        current['Mounts'].append(copy.deepcopy(current['Mounts'][0]))
    elif mutation == 'capability':
        current['HostConfig']['CapAdd'].append('SYS_ADMIN')
    else:
        current['HostConfig']['Tmpfs']['/source/.venv'] = 'rw,mode=0777'
    with pytest.raises(RuntimeError):
        ci_shell.validate(current, 'sha256:owned', mounts)


@pytest.mark.parametrize('mutation', ['bytes', 'mode', 'substitution', 'alias'])
def test_host_snapshot_drift_refuses(tmp_path, mutation):
    source = tmp_path / 'source'
    source.mkdir()
    member = source / 'module.py'
    member.write_bytes(b'original')
    expected = source_root.inventory(source)
    source_root.verify_identity(source, expected)
    if mutation == 'bytes':
        member.write_bytes(b'mutated!')
    elif mutation == 'mode':
        member.chmod(0o700)
    elif mutation == 'substitution':
        member.rename(source / 'old')
        member.write_bytes(b'original')
    else:
        source.rename(tmp_path / 'original')
        source.symlink_to(tmp_path / 'original', target_is_directory=True)
    with pytest.raises(RuntimeError):
        source_root.verify_identity(source, expected)


def test_mountpoint_must_be_empty_and_real(tmp_path):
    (tmp_path / 'src').mkdir()
    source_root.layout(tmp_path)
    (tmp_path / '.venv/unexpected').write_bytes(b'x')
    with pytest.raises(RuntimeError, match='source_artifact_mountpoint'):
        source_root.layout(tmp_path)


def test_probe_requires_actual_linux_source_identity(monkeypatch):
    monkeypatch.setattr(os, 'getuid', lambda: 1234)
    with pytest.raises(RuntimeError, match='source_probe_identity'):
        source_root.probe()


def test_producer_canary_no_longer_claims_writable_root():
    source = Path(__file__).with_name('producer_setup.py').read_text()
    assert 'artifact_directory_create_remove' not in source
    assert 'source_root.probe()' in source
    assert "source_root.retain_proof(result, root_identity, runtime)" in Path(__file__).with_name('primary_compartment.py').read_text()
    assert json.loads(json.dumps(source_root.OVERLAYS)) == source_root.OVERLAYS


def test_own_proof_uses_unchanged_closed_transport(tmp_path, monkeypatch):
    import source_raw_transport as raw
    import structured_evidence as evidence
    from test_structured_evidence import identity, archive
    proof = {'pid': 17, 'source_uid': 20000, 'source_gid': 20000}
    carrier = tmp_path / 'setup-controls.json'
    carrier.write_text(json.dumps(proof))
    monkeypatch.setattr(source_root, 'Path', lambda name: carrier)
    kernel = {'primary_records': []}
    source_root.retain_proof(kernel, {'pid': 17}, {'primary': {'entry': 'own-test'}})
    assert kernel['primary_records'][0]['kind'] == 'immutable_source_root'
    assert kernel['primary_records'][0]['proof'] == proof
    records = {'kernel-source.json': evidence.canonical(kernel)}
    nonce = '1' * 64
    header = evidence.source_header(records, kernel, identity(), nonce, 0)
    envelope = evidence.loads(header[len(evidence.HEADER_PREFIX):-1])
    evidence.validate_header(envelope, identity(), nonce)
    assert raw.decode(raw.encode(records, identity(), nonce), identity(), nonce,
                      envelope['records']) == records
    retained = tmp_path / 'retained'
    retained.mkdir()
    body = records['kernel-source.json']
    member = 'structured-kernel-source.json'
    (retained / member).write_bytes(body)
    direct = {'schema': evidence.SCHEMA, 'scope': 'primary-executor', 'identity': identity(),
              'records': {'kernel-source.json': {'member': member, 'sha256': evidence.digest(body),
                                                'size': len(body)}},
              'source_checkpoint_ready': False, 'selected_carrier': None}
    encoded = evidence.canonical(direct)
    (retained / evidence.MEMBER).write_bytes(encoded)
    (retained / 'source-pins.json').write_text('{}')
    (retained / 'container-inspect.json').write_text('[]')
    assert evidence.consume(archive(retained), identity(), evidence.digest(encoded)) == (
        'primary-executor', records)
    (retained / 'source-custody.json').write_text('{}')
    with pytest.raises(evidence.EvidenceRefused, match='unknown_archive_member'):
        evidence.consume(archive(retained), identity(), evidence.digest(encoded))
    with pytest.raises(evidence.EvidenceRefused, match='header_kernel_fields'):
        evidence.source_header(records, {**kernel, 'immutable_source_root': proof}, identity(), nonce, 0)
    with pytest.raises(RuntimeError, match='source_setup_owner_drift'):
        source_root.retain_proof(kernel, {'pid': 18}, {})


def test_output_export_rejects_mount_generation_substitution(tmp_path, monkeypatch):
    import primary_package_exports as package
    from test_primary_package_exports import fixture
    source, kernel, root, context = fixture(tmp_path, monkeypatch)
    context['package_output_identity'][1] += 1
    with pytest.raises(RuntimeError, match='package_build_export_output_generation'):
        package.export(source, object(), kernel)


def test_empty_dist_refuses_foreign_mount_or_owner(tmp_path, monkeypatch):
    path = tmp_path / 'dist'
    path.mkdir(mode=0o700)
    monkeypatch.setattr(source_root, 'Path', lambda name: path)
    monkeypatch.setattr(source_root, 'mount_inventory', lambda: {})
    with pytest.raises(RuntimeError, match='primary_package_preexisting_output'):
        source_root.require_empty_dist(source_root.key(path))
