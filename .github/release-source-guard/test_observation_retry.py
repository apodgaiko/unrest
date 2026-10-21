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
