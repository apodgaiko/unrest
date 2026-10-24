"""Bounded acquisition discards raced censuses without changing authority methods."""
import os
import socket
import sys

import pytest

import linux_sockets as observation

RACES = ('owned descriptor observation raced',
         'owned descriptor binding changed during socket observation')


@pytest.mark.parametrize('race', RACES)
@pytest.mark.parametrize('failures', [1, 2, 3])
def test_every_attempt_rechecks_birth_and_reacquires_all_rows(monkeypatch, race, failures):
    calls = []
    birth = {'pid': 123, 'start_ticks': 456}
    fresh = [{'fd': 7, 'inode': 9, 'socket_cookie': 10}]
    attempts = 0
    def identity(pid):
        calls.append(('birth', pid))
        return dict(birth)
    def snapshot(pid):
        nonlocal attempts
        attempts += 1
        calls.append(('whole-census', pid))
        if attempts <= failures:
            raise RuntimeError(race)
        return fresh
    monkeypatch.setattr(observation, 'identity', identity)
    monkeypatch.setattr(observation, '_socket_snapshot', snapshot)
    if failures == 3:
        with pytest.raises(RuntimeError, match=race):
            observation.sockets(123)
    else:
        assert observation.sockets(123) is fresh
    expected = [('birth', 123)] + [('birth', 123), ('whole-census', 123)] * min(failures + 1, 3)
    if failures < 3:
        expected.append(('birth', 123))
    assert calls == expected


@pytest.mark.parametrize('reason', ['stale_or_reused_ownership', 'foreign_or_unregistered_endpoint',
                                  'listener_kernel_binding_refused', 'socket diagnostic envelope drift'])
def test_unrelated_errors_are_never_retried(monkeypatch, reason):
    calls = []
    monkeypatch.setattr(observation, 'identity', lambda pid: {'pid': pid, 'start_ticks': 1})
    def snapshot(pid):
        calls.append(pid)
        raise RuntimeError(reason)
    monkeypatch.setattr(observation, '_socket_snapshot', snapshot)
    with pytest.raises(RuntimeError, match=reason):
        observation.sockets(123)
    assert calls == [123]


@pytest.mark.parametrize('replace_at', [3, 4])
def test_process_replacement_during_or_after_retry_refuses(monkeypatch, replace_at):
    births, scans = [], []
    def identity(pid):
        births.append(pid)
        return {'start_ticks': 456 if len(births) < replace_at else 457}
    def snapshot(pid):
        scans.append(pid)
        if len(scans) == 1:
            raise RuntimeError(RACES[0])
        return [{'fd': 7, 'inode': 9}]
    monkeypatch.setattr(observation, 'identity', identity)
    monkeypatch.setattr(observation, '_socket_snapshot', snapshot)
    with pytest.raises(RuntimeError, match='stale_or_reused_ownership'):
        observation.sockets(123)
    assert len(births) == replace_at and len(scans) == replace_at - 2


def test_changed_first_inventory_never_supplies_rows_to_second_snapshot(monkeypatch):
    maps = iter([{7: 10}, {7: 11}, {8: 12}, {8: 12}])
    tables = iter([{10: {'inode': 10, 'socket_cookie': 20}},
                   {12: {'inode': 12, 'socket_cookie': 22}}])
    monkeypatch.setattr(observation, 'identity', lambda pid: {'pid': pid})
    monkeypatch.setattr(observation, 'socket_fds', lambda pid: next(maps))
    monkeypatch.setattr(observation, 'tcp_table', lambda: next(tables))
    assert observation.sockets(123) == [{'pid': 123, 'fd': 8, 'inode': 12, 'socket_cookie': 22}]


@pytest.mark.skipif(sys.platform != 'linux', reason='actual /proc and SOCK_DIAG require Linux')
def test_reacquisition_returns_actual_live_kernel_descriptor_and_rejects_closed_one(monkeypatch):
    pid = os.getpid()
    original = observation._socket_snapshot
    calls = []
    def snapshot(current):
        calls.append(current)
        if len(calls) == 1:
            raise RuntimeError(RACES[0])
        return original(current)
    monkeypatch.setattr(observation, '_socket_snapshot', snapshot)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        descriptor = listener.fileno()
        inode = os.fstat(descriptor).st_ino
        row = next(r for r in observation.sockets(pid) if r['fd'] == descriptor)
        assert row['inode'] == inode and row['local_port'] == listener.getsockname()[1]
        assert row['state'] == 10 and row['socket_cookie'] > 0
    assert not any(r['fd'] == descriptor and r['inode'] == inode for r in observation.sockets(pid))
    assert len(calls) == 3


def test_exact_listener_does_not_acquire_unrelated_descriptor_inventory(monkeypatch):
    """Reproduce the fatal full-run scan race without any child/provider launch."""
    calls = []
    monkeypatch.setattr(observation, 'identity', lambda pid: {'pid': pid, 'start_ticks': 11})
    def census(pid):
        raise RuntimeError(RACES[0])
    monkeypatch.setattr(observation, 'socket_fds', census)
    def readlink(path):
        calls.append(str(path))
        assert str(path) == '/proc/123/fd/16'
        return 'socket:[279801]'
    monkeypatch.setattr(observation.os, 'readlink', readlink)
    row = {'inode': 279801, 'socket_cookie': 7369, 'socket_uid': 20000,
           'state': 10, 'local_host': '127.0.0.1', 'local_port': 45415}
    monkeypatch.setattr(observation, 'tcp_table', lambda: {279801: dict(row)})
    with pytest.raises(RuntimeError, match=RACES[0]):
        observation.sockets(123)
    assert observation.socket_descriptor(123, 16) == {'pid': 123, 'fd': 16, **row}
    assert calls == ['/proc/123/fd/16'] * 2


@pytest.mark.parametrize('target', ['missing', 'pipe', 'changed', 'absent-table', 'permission', 'malformed'])
def test_exact_descriptor_never_substitutes_another_or_old_row(monkeypatch, target):
    monkeypatch.setattr(observation, 'identity', lambda pid: {'pid': pid})
    def readlink(path):
        if target == 'missing':
            raise FileNotFoundError()
        if target == 'permission':
            raise PermissionError()
        return 'pipe:[9]' if target == 'pipe' else 'socket:[9]'
    monkeypatch.setattr(observation.os, 'readlink', readlink)
    def table():
        if target == 'malformed':
            raise RuntimeError('socket diagnostic envelope drift')
        if target == 'changed':
            monkeypatch.setattr(observation.os, 'readlink', lambda path: 'socket:[10]')
        return {10: {'inode': 10}} if target == 'absent-table' else {9: {'inode': 9}}
    monkeypatch.setattr(observation, 'tcp_table', table)
    if target == 'permission':
        with pytest.raises(PermissionError):
            observation.socket_descriptor(123, 16)
    elif target == 'malformed':
        with pytest.raises(RuntimeError, match='socket diagnostic envelope drift'):
            observation.socket_descriptor(123, 16)
    else:
        assert observation.socket_descriptor(123, 16) is None


@pytest.mark.parametrize('failures', [1, 2, 3])
def test_exact_descriptor_reacquires_whole_target_snapshot_with_original_bound(monkeypatch, failures):
    scans, births = [], []
    def birth(pid):
        births.append(pid)
        return {'pid': pid, 'start_ticks': 11}
    def snapshot(pid, fd):
        scans.append((pid, fd))
        if len(scans) <= failures:
            raise RuntimeError(RACES[1])
        return {'pid': pid, 'fd': fd, 'inode': 21}
    monkeypatch.setattr(observation, 'identity', birth)
    monkeypatch.setattr(observation, '_descriptor_snapshot', snapshot)
    if failures == 3:
        with pytest.raises(RuntimeError, match=RACES[1]):
            observation.socket_descriptor(123, 16)
    else:
        assert observation.socket_descriptor(123, 16) == {'pid': 123, 'fd': 16, 'inode': 21}
    assert len(scans) == min(failures + 1, 3)
    assert len(births) == 1 + len(scans) + (failures < 3)


@pytest.mark.parametrize('replace_at', [2, 3, 4])
def test_exact_descriptor_birth_drift_cannot_supply_authority(monkeypatch, replace_at):
    calls = []
    def birth(pid):
        calls.append(pid)
        return {'pid': pid, 'start_ticks': 11 if len(calls) < replace_at else 12}
    monkeypatch.setattr(observation, 'identity', birth)
    snapshots = []
    def snapshot(pid, fd):
        snapshots.append(fd)
        if replace_at == 4 and len(snapshots) == 1:
            raise RuntimeError(RACES[1])
        return {'pid': pid, 'fd': fd, 'inode': 21}
    monkeypatch.setattr(observation, '_descriptor_snapshot', snapshot)
    with pytest.raises(RuntimeError, match='stale_or_reused_ownership'):
        observation.socket_descriptor(123, 16)


@pytest.mark.skipif(sys.platform != 'linux', reason='actual /proc and SOCK_DIAG require Linux')
def test_exact_listener_has_live_cookie_and_refuses_closed_or_reused_target():
    pid = os.getpid()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        fd = listener.fileno()
        original = observation.socket_descriptor(pid, fd)
        assert original['inode'] == os.fstat(fd).st_ino
        assert original['state'] == 10 and original['local_port'] == listener.getsockname()[1]
        assert original['socket_cookie'] > 0 and original['socket_uid'] == os.getuid()
        listener.close()
        assert observation.socket_descriptor(pid, fd) is None
        with socket.socket() as replacement:
            replacement.bind(('127.0.0.1', 0))
            replacement.listen(1)
            if replacement.fileno() != fd:
                os.dup2(replacement.fileno(), fd)
            try:
                current = observation.socket_descriptor(pid, fd)
                assert current['socket_cookie'] != original['socket_cookie']
                assert current != original
            finally:
                if replacement.fileno() != fd:
                    os.close(fd)
