"""Telemetry never changes storage or loses initiating/diagnostic errors."""
import errno
import importlib.util
from pathlib import Path
import stat
import types

import pytest

SPEC = importlib.util.spec_from_file_location('filesystem_telemetry_control', Path(__file__).with_name('filesystem_telemetry.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize('failure', [None, 'stat', 'vfs', 'identity', 'drift'])
def test_bounded_phase_and_error_observations(monkeypatch, failure):
    info = types.SimpleNamespace(st_dev=2, st_ino=3, st_uid=20000, st_gid=20000,
                                 st_mode=stat.S_IFDIR | 0o700)
    calls = []
    def lstat(path):
        calls.append(path)
        if failure == 'stat':
            raise OSError(errno.ENOSPC, 'private content must not be retained')
        if failure == 'identity':
            return types.SimpleNamespace(**{**vars(info), 'st_mode': stat.S_IFLNK | 0o777})
        if failure == 'drift' and len(calls) % 2 == 0:
            return types.SimpleNamespace(**{**vars(info), 'st_ino': 4})
        return info
    def vfs(path):
        if failure == 'vfs':
            raise OSError(errno.EIO, 'private diagnostic')
        return types.SimpleNamespace(f_frsize=4096, f_blocks=128, f_bfree=16,
            f_bavail=8, f_files=64, f_ffree=4, f_favail=3)
    monkeypatch.setattr(MODULE.os, 'lstat', lstat)
    monkeypatch.setattr(MODULE.os, 'statvfs', vfs)
    telemetry = MODULE.Telemetry()
    initiating = OSError(errno.ENOSPC, 'private initiating failure')
    for _ in range(3):
        for phase in sorted(MODULE.PHASES):
            telemetry.observe(phase, initiating)
    assert len(telemetry.records) == 4
    assert len(calls) <= 2 * 4 * len(MODULE.PATHS)
    assert telemetry.failed() is (failure is not None)
    for record in telemetry.records:
        assert record['initiating_error'] == {'class': 'OSError', 'errno': errno.ENOSPC}
        assert len(record['filesystems']) == len(MODULE.PATHS)
        for row in record['filesystems']:
            assert ('diagnostic_error' in row) is (failure is not None)
            if failure is None:
                assert row['bytes_available'] == 8 * 4096 and row['inodes_available'] == 3
    assert 'private' not in repr(telemetry.records)
    with pytest.raises(ValueError):
        telemetry.observe('arbitrary')


def test_real_owned_directory_is_read_only(tmp_path, monkeypatch):
    # Host control only; production paths remain literal and mount-bound.
    monkeypatch.setattr(MODULE, 'PATHS', (str(tmp_path),))
    marker = tmp_path / 'kept'
    marker.write_bytes(b'unchanged')
    before = (tmp_path.stat().st_ino, marker.stat().st_ino, marker.read_bytes())
    telemetry = MODULE.Telemetry()
    telemetry.observe('before_dispatch')
    assert len(telemetry.records) == 1
    assert before == (tmp_path.stat().st_ino, marker.stat().st_ino, marker.read_bytes())
