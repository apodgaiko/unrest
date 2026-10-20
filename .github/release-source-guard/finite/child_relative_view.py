"""Read-only source cwd facts, shared by constructor and stopped-child custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat


class ViewRefusal(RuntimeError):
    def __init__(self, reason, facts):
        super().__init__(reason)
        self.facts = facts



def same_object(first, second):
    keys = {'cwd', 'identity', 'mount', 'searchable', 'readonly'}
    return (type(first) is dict and type(second) is dict and set(first) == set(second) == keys
            and first['readonly'] is True and second['readonly'] is True
            and all(first[key] == second[key] for key in keys - {'searchable'}))


def child_matches(actual, stopped):
    return same_object(actual, stopped) and actual['searchable'] is True

def view(cwd='.', *, process=None):
    """No launch authority: compare actual cwd with the sealed source member."""
    expected = json.loads(Path('/inputs/source-custody.json').read_bytes())
    actual = Path(cwd) if process is None else Path('/proc') / str(process) / 'cwd'
    directory = str(actual.resolve(strict=True))
    relative = Path(directory).relative_to('/source').as_posix()
    row = expected['members'][relative]
    info = actual.stat()
    key = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]
    flags = os.statvfs(actual).f_flag
    # access(/proc/other/cwd) evaluates the observer's real credentials.
    # Only the child itself can attest search permission before its body/READY.
    searchable = os.access(actual, os.X_OK) if process is None else None
    if (key != row['identity'] or not stat.S_ISDIR(info.st_mode)
            or not flags & os.ST_RDONLY or searchable is False):
        raise ViewRefusal('child_relative_source_cwd', {
            'cwd': directory, 'identity': key, 'expected_identity': row['identity'],
            'statvfs_flags': flags, 'searchable': searchable, 'observer_uid': os.geteuid(),
            'process': process})
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
            'searchable': searchable, 'readonly': True}
