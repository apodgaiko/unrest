"""Materialize only byte-authenticated package artifacts from original full CI."""
from __future__ import annotations

import io
import os
from pathlib import Path
import zipfile

from checkpoint_receipt import require, sha256

PACKAGE_ARTIFACT = 'unrest-v0.4.7-python313'
WHEEL = 'unrest_harness-0.4.7-py3-none-any.whl'
SDIST = 'unrest_harness-0.4.7.tar.gz'
LIMIT = 128 * 1024 * 1024


def verified_members(archive, artifact, reuse):
    require(type(artifact['size_in_bytes']) is int and len(archive) == artifact['size_in_bytes']
            and len(archive) <= LIMIT and artifact['digest'] == 'sha256:' + sha256(archive),
            'package_artifact_archive_digest')
    require(artifact['expired'] is False and artifact['name'] == PACKAGE_ARTIFACT
            and artifact['workflow_run']['id'] == reuse['original_run_id']
            and artifact['workflow_run']['head_sha'] == reuse['head_sha'], 'package_artifact_identity')
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = source.infolist()
        require(len(entries) == 3 and {row.filename for row in entries} == {WHEEL, SDIST, 'SHA256SUMS'},
                'package_artifact_members')
        require(sum(row.file_size for row in entries) <= LIMIT
                and all(not row.is_dir() and row.external_attr >> 16 & 0o170000 in (0, 0o100000)
                        for row in entries), 'package_artifact_types_or_bound')
        members = {row.filename: source.read(row) for row in entries}
    expected = reuse['package_archives']
    require(set(expected) == {WHEEL, SDIST} and all(sha256(members[name]) == expected[name]
            for name in (WHEEL, SDIST)), 'package_member_bytes')
    sums = ''.join(expected[name] + '  ' + name + '\n' for name in (WHEEL, SDIST)).encode()
    require(members['SHA256SUMS'] == sums, 'package_checksum_bytes')
    return members


def materialize(reader, reuse, destination):
    require(reuse['execution_kind'] == 'verified-same-commit-reuse', 'package_reuse_kind')
    run = reuse['original_run_id']
    result = reader.api(f'actions/runs/{run}/artifacts?per_page=100')
    require(result['total_count'] <= 100, 'package_artifact_count')
    candidates = [row for row in result['artifacts'] if row['name'] == PACKAGE_ARTIFACT]
    require(len(candidates) == 1, 'package_artifact_ambiguous')
    artifact = candidates[0]
    members = verified_members(reader.archive(artifact), artifact, reuse)
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink()
            and destination.parent.resolve() == destination.parent, 'package_output_carrier')
    destination.mkdir(mode=0o700)
    for name, body in sorted(members.items()):
        descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb', closefd=False) as output:
                output.write(body)
                output.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {'package_artifact_id': artifact['id'], 'package_artifact_digest': artifact['digest']}
