"""Bind the production native profile before any source body."""
from __future__ import annotations

from collections.abc import Callable

import json
import os
from pathlib import Path
import stat
import sys

POLICY: Callable[[str, tuple], bool]
BODY_READY = False
SCRIPT_TARGET: str | None


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('native duplicate field')
        value[key] = item
    return value


def key(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def acquire(directory: str) -> tuple[Path, dict]:
    root = Path(directory)
    parent = root.lstat()
    if (root.resolve() != root or parent.st_uid != 20001
            or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o755):
        raise ValueError('native profile directory')
    file = root / (str(os.getpid()) + '.json')
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 20001
                or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1 or before.st_size > 65536):
            raise ValueError('native profile file')
        body = os.read(descriptor, 65537)
        if key(before) != key(os.fstat(descriptor)) or key(before) != key(file.lstat()) or len(body) != before.st_size:
            raise ValueError('native profile acquisition')
    finally:
        os.close(descriptor)
    profile = json.loads(body, object_pairs_hook=unique)
    if type(profile) is not dict:
        raise ValueError('native profile object')
    return root, profile


def consume(directory: str, event: str, arguments: tuple) -> None:
    global BODY_READY, POLICY, SCRIPT_TARGET
    root, profile = acquire(directory)
    if profile.get('schema') != 'unrest.bootstrap-source.v1':
        raise ValueError('native source profile schema')
    sys.path.insert(0, str(Path(__file__).parent))
    from source_entry import activate
    POLICY = activate(root, profile, event, arguments)
    SCRIPT_TARGET = profile['script']
    BODY_READY = True


if __name__ == '_release_native_entry':
    consume(globals()['PROFILE_DIRECTORY'], globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
