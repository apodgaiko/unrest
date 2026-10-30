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


def acquire(directory: str) -> tuple[Path, dict]:
    root = Path(directory)
    parent = root.lstat()
    if (root.resolve() != root or parent.st_uid != 20001
            or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o755):
        raise ValueError('native profile directory')
    file = root / (str(os.getpid()) + '.json')
    from content_manifest import read_regular
    from control_transport import unique
    body,_,_=read_regular(file,65536,uid=20001,mode=0o444)
    profile = json.loads(body, object_pairs_hook=unique)
    if type(profile) is not dict:
        raise ValueError('native profile object')
    return root, profile


def consume(directory: str, event: str, arguments: tuple) -> None:
    global BODY_READY, POLICY, SCRIPT_TARGET, PRIVATE_COMPARTMENT
    sys.path.insert(0, str(Path(__file__).parent))
    root, profile = acquire(directory)
    if profile.get('schema') != 'unrest.bootstrap-source.v1':
        raise ValueError('native source profile schema')
    from source_entry import activate
    POLICY = activate(root, profile, event, arguments)
    SCRIPT_TARGET = profile['script']
    PRIVATE_COMPARTMENT = True
    BODY_READY = True


if __name__ == '_release_native_entry':
    consume(globals()['PROFILE_DIRECTORY'], globals()['ENTRY_EVENT'], globals()['ENTRY_ARGUMENTS'])
