"""Observer export of the two current-candidate archives and checksum file."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat

from checkpoint_packages import WHEEL, SDIST, LIMIT
from primary_custody import CHECKSUM, ORDER, file_identity


def export(duty, root=Path('/source/dist')):
    if duty not in ORDER or root.is_symlink() or not root.is_dir():
        raise RuntimeError('primary_package_output_root')
    wanted = {WHEEL, SDIST, 'SHA256SUMS'} if duty == CHECKSUM else {WHEEL, SDIST}
    if {path.name for path in root.iterdir()} != wanted:
        raise RuntimeError('primary_package_output_inventory')
    members = {}
    total = 0
    for name in sorted(wanted):
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != 20000 or not 0 < info.st_size <= LIMIT):
                raise RuntimeError('primary_package_output_identity')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                body = stream.read(LIMIT + 1)
            if (len(body) != info.st_size or file_identity(os.fstat(descriptor))
                    != file_identity(info) or file_identity(path.lstat()) != file_identity(info)):
                raise RuntimeError('primary_package_output_race')
        finally:
            os.close(descriptor)
        total += len(body)
        if total > LIMIT:
            raise RuntimeError('primary_package_output_bound')
        members[name] = {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body),
                         'bytes': base64.b64encode(body).decode()}
    return json.dumps({'schema': 'unrest.v046.primary-package-output.v1', 'members': members},
                      sort_keys=True).encode()
