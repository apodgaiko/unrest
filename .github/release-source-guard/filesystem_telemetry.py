"""Bounded read-only observations of the capsule's existing writable mounts."""
from __future__ import annotations

import os
import stat
import time

# No traversal, content reads, allocation, cleanup or capacity changes.
PATHS = ('/work', '/tmp', '/receipts', '/source/.mypy_cache')
PHASES = frozenset({'before_dispatch', 'first_poison', 'trace_failure', 'after_trace'})


def identity(info):
    return {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode')}


class Telemetry:
    def __init__(self):
        self.records = []
        self.seen = set()

    def observe(self, phase, initiating_error=None):
        if phase not in PHASES:
            raise ValueError('filesystem_telemetry_phase')
        if phase in self.seen:
            return
        self.seen.add(phase)
        record = {'phase': phase, 'monotonic_ns': time.monotonic_ns(),
                  'pid': os.getpid(), 'uid': os.geteuid(),
                  'initiating_error': None if initiating_error is None else {
                      'class': type(initiating_error).__name__,
                      'errno': getattr(initiating_error, 'errno', None)}, 'filesystems': []}
        for path in PATHS:
            row = {'path': path}
            try:
                before = os.lstat(path)
                if (not stat.S_ISDIR(before.st_mode) or before.st_uid not in (0, 20000, 20001)):
                    raise RuntimeError('filesystem_telemetry_identity')
                usage = os.statvfs(path)
                after = os.lstat(path)
                if identity(before) != identity(after):
                    raise RuntimeError('filesystem_telemetry_changed')
                row.update(identity=identity(after), fragment_size=usage.f_frsize,
                           blocks=usage.f_blocks, blocks_free=usage.f_bfree,
                           blocks_available=usage.f_bavail, inodes=usage.f_files,
                           inodes_free=usage.f_ffree, inodes_available=usage.f_favail,
                           bytes_available=usage.f_bavail * usage.f_frsize)
            except (OSError, RuntimeError) as error:
                row['diagnostic_error'] = {'class': type(error).__name__,
                                           'errno': getattr(error, 'errno', None)}
            record['filesystems'].append(row)
        self.records.append(record)

    def failed(self):
        return any('diagnostic_error' in row for record in self.records for row in record['filesystems'])


def observe_trace_failure(source, error):
    """Best-effort diagnostics must never replace an already-failed trace."""
    try:
        telemetry = getattr(source, 'filesystem_telemetry', None)
        if telemetry is None:
            return False
        telemetry.observe('trace_failure', error)
        return True
    except BaseException:
        # Resource exhaustion can also prevent its own observation. The caller
        # retains the initiating failure and its original fail-closed outcome.
        return False
