"""Read-only source cwd facts, shared by constructor and stopped-child custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat


def view(cwd='.', *, process=None):
    """No launch authority: compare actual cwd with the sealed source member."""
    expected = json.loads(Path('/inputs/source-custody.json').read_bytes())
    actual = Path(cwd) if process is None else Path('/proc') / str(process) / 'cwd'
    directory = str(actual.resolve(strict=True))
    relative = Path(directory).relative_to('/source').as_posix()
    row = expected['members'][relative]
    info = actual.stat()
    key = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]
    if (key != row['identity'] or not stat.S_ISDIR(info.st_mode)
            or not os.statvfs(actual).f_flag & os.ST_RDONLY
            or not os.access(actual, os.X_OK)):
        raise RuntimeError('child_relative_source_cwd')
    mounts = []
    mountinfo = Path('/proc/self/mountinfo' if process is None else
                     '/proc/' + str(process) + '/mountinfo')
    for line in mountinfo.read_text().splitlines():
        fields = line.split()
        if fields[4] == '/source':
            mounts.append({'id': fields[0], 'device': fields[2], 'root': fields[3],
                           'point': fields[4], 'options': fields[5].split(',')})
    if (len(mounts) != 1 or 'ro' not in mounts[0]['options']
            or mounts[0]['root'] != expected['physical_path']):
        raise RuntimeError('child_relative_source_mount')
    return {'cwd': directory, 'identity': key, 'mount': mounts[0],
            'searchable': True, 'readonly': True}
