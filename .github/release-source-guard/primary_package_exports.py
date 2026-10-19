"""Build-only archive export after actual native closure, preserving UV metadata.

Pinned UV0.11.0 prepare_output_directory creates dist/.gitignore with b'*'.
That local metadata is not a package export. The original strict generic exporter
is unchanged; this route needs a new empty output origin and the actual current
build/query/four-backend/wait proof before reading the exact two archives.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat

import source_root

from primary_custody import BUILD, WHEEL, SDIST, canonical, kernel_success, file_identity, sha
from checkpoint_packages import LIMIT

ROOT = Path('/source/dist')


def read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 20000 or before.st_gid != 20000
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o644
                or not 0 < before.st_size <= limit):
            raise RuntimeError('package_build_export_carrier')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(limit + 1)
        if (len(body) != before.st_size or file_identity(before) != file_identity(os.fstat(descriptor))
                or file_identity(before) != file_identity(path.lstat())):
            raise RuntimeError('package_build_export_race')
        return body, file_identity(before)
    finally:
        os.close(descriptor)


def export(source, trace, kernel):
    if (kernel['primary_plan']['duty'] != BUILD
            or kernel['primary_plan'].get('package_mode') not in {'TEST', 'FULL'}):
        raise RuntimeError('package_build_export_plan')
    kernel_success({'kernel-source.json': canonical(kernel)}, kernel['actual_script_sha256'])
    source.require_complete(trace)
    contexts = list(source.producers.uv.values())
    if (len(contexts) != 1 or contexts[0].get('package_output_before') != 'empty-artifact-mount'
            or contexts[0]['pid'] not in source.producers.cache_completed
            or contexts[0]['identity']['uid'] != 20000):
        raise RuntimeError('package_build_export_current_origin')
    if ROOT.resolve() != ROOT or ROOT.is_symlink() or not ROOT.is_dir():
        raise RuntimeError('package_build_export_root')
    if source_root.key(ROOT) != contexts[0].get('package_output_identity'):
        raise RuntimeError('package_build_export_output_generation')
    root_before = ROOT.lstat()
    wanted = {WHEEL, SDIST, '.gitignore'}
    if {path.name for path in ROOT.iterdir()} != wanted:
        raise RuntimeError('package_build_export_inventory')
    metadata, metadata_identity = read(ROOT / '.gitignore', 1)
    if metadata != b'*':
        raise RuntimeError('package_build_export_native_metadata')
    members = {}
    for name in sorted((WHEEL, SDIST)):
        body, identity = read(ROOT / name, LIMIT)
        members[name] = {'size': len(body), 'sha256': sha(body),
                         'bytes': base64.b64encode(body).decode()}
    if (sum(row['size'] for row in members.values()) > LIMIT
            or {p.name for p in ROOT.iterdir()} != wanted
            or file_identity(ROOT.lstat()) != file_identity(root_before)):
        raise RuntimeError('package_build_export_membership_drift')
    source.producers.records.append({'kind': 'primary_package_native_output_metadata',
                                     'pid': contexts[0]['pid'], 'identity': contexts[0]['identity'],
                                     'metadata_sha256': sha(metadata),
                                     'metadata_identity': metadata_identity,
                                     'complete_archive_hashes': {name: row['sha256'] for name, row in members.items()},
                                     'exported_members': sorted(members), 'release_certificate': False})
    return json.dumps({'schema': 'unrest.v046.primary-package-output.v1', 'members': members},
                      sort_keys=True).encode()
