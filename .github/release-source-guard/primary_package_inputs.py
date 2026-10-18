"""Exact host-authenticated archive transfer between PRIMARY capsules.

Only wheel/sdist bytes cross the boundary. The custody key, earlier capsule
records and cache never enter a consumer capsule.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

from primary_custody import (BUILD, ORDER, WHEEL, SDIST, canonical, loads, sha,
                             exclusive, file_identity, read_regular)
from checkpoint_packages import LIMIT
from structured_evidence import require

SCHEMA = 'unrest.v046.primary-package-input.v1'
MOUNT = '/package-input'


def prepare(custody, duty, destination):
    require(duty in ORDER[1:], 'package_input_duty')
    origin = custody.package_inputs(duty)
    prior = custody.phase(ORDER[ORDER.index(duty) - 1])
    # Recheck all bytes after the custody call; create a closed immutable mount
    # rather than exporting the custody directory or trusting a caller path.
    members = {name: read_regular(origin / name, LIMIT, 0o600) for name in (WHEEL, SDIST)}
    require(all(sha(body) == prior['outputs'][name] for name, body in members.items()),
            'package_input_changed')
    root = Path(destination)
    require(not root.exists() and not root.is_symlink() and root.parent.resolve() == root.parent,
            'package_input_destination')
    root.mkdir(mode=0o700)
    descriptor = {'schema': SCHEMA, 'binding': custody.binding, 'duty': duty,
                  'previous_sha256': sha(canonical(prior)),
                  'members': {name: {'size': len(body), 'sha256': sha(body)}
                              for name, body in sorted(members.items())}}
    for name, body in sorted(members.items()):
        exclusive(root / name, body, 0o444)
    exclusive(root / 'input.json', canonical(descriptor), 0o444)
    # Docker's read-only bind enforces immutability; execute credentials need
    # only directory traversal and read access, never the host custody key.
    root.chmod(0o555)
    return descriptor


def consume(expected, destination=Path('/source/dist'), root=Path(MOUNT)):
    """Revalidate the host-pinned descriptor and every complete member byte."""
    require(type(expected) is dict and set(expected) == {
        'schema', 'binding', 'duty', 'previous_sha256', 'members'}
        and expected['schema'] == SCHEMA and expected['duty'] in ORDER[1:]
        and set(expected['members']) == {WHEEL, SDIST}, 'package_input_descriptor')
    require(not root.is_symlink() and root.resolve() == root and root.is_dir()
            and {p.name for p in root.iterdir()} == {WHEEL, SDIST, 'input.json'},
            'package_input_inventory')
    descriptor = _read(root / 'input.json', 65536)
    require(descriptor == canonical(expected) and loads(descriptor) == expected,
            'package_input_identity')
    members = {name: _read(root / name, LIMIT) for name in (WHEEL, SDIST)}
    require(sum(map(len, members.values())) <= LIMIT, 'package_input_bound')
    require(all(type(expected['members'][name]) is dict
                and set(expected['members'][name]) == {'size', 'sha256'}
                and type(expected['members'][name]['size']) is int
                and expected['members'][name]['size'] == len(body)
                and expected['members'][name]['sha256'] == sha(body)
                for name, body in members.items()), 'package_input_bytes')
    require(destination.parent.resolve() == destination.parent and not destination.exists()
            and not destination.is_symlink(), 'package_input_output')
    destination.mkdir(mode=0o700)
    for name, body in sorted(members.items()):
        exclusive(destination / name, body, 0o600)
    return {'schema': 'unrest.v046.primary-package-input-consumption.v1',
            'descriptor_sha256': sha(descriptor), 'members': expected['members']}


def _read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
                and info.st_nlink == 1 and 0 < info.st_size <= limit, 'package_input_carrier')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            body = stream.read(limit + 1)
        require(len(body) == info.st_size
                and file_identity(info) == file_identity(os.fstat(descriptor))
                == file_identity(path.lstat()), 'package_input_race')
        return body
    finally:
        os.close(descriptor)


def require_full(value, workflow):
    # Full package producers consume the SAME final-readiness object as SOURCE;
    # no package TEST plan, source-only seal, or synthetic proof activates it.
    from primary_source_inputs import require_full_input
    require_full_input(value, b'env -u CODEX_PATH uv run pytest -q', workflow)


def plan(script, workflow, source_input, *, test=False):
    from ci_commands import bind_generated
    from primary_policy import SHELL, SHELL_FLAGS
    import shlex
    duty = bind_generated(script, workflow)
    require(duty['name'] in ORDER, 'primary_package_duty')
    if not test:
        require_full(source_input, workflow)
    return {'schema': 'unrest.v046.primary-script-plan.v1', 'duty': duty['name'],
            'script_sha256': duty['script_sha256'], 'workflow_sha256': sha(workflow.encode()),
            'shell_argv': [SHELL, *SHELL_FLAGS, '/inputs/github-script.sh'],
            'commands': [shlex.split(line) for line in script.decode().replace('\\\n', '').splitlines() if line.strip()],
            'source_checkpoint_ready': False, 'selected_carrier': None,
            'timeout_seconds': 180, 'package_mode': 'TEST' if test else 'FULL',
            'source_input_sha256': sha(canonical(source_input)) if not test else None,
            'package_input_required': duty['name'] != BUILD}
