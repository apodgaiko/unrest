"""Differential census checks against the complete unchanged original supervisor."""
from copy import deepcopy
import json
import os
from pathlib import Path
import random
import socket
import struct
import sys

import pytest

import event_journal
from journal_supervisor import JournalSupervisor
import linux_supervisor as original


def owner(directory, composed):
    value = original.Supervisor.__new__(original.Supervisor)
    value.manifest = {'events': str(directory)}
    value.root = {'uid': 20000}
    value.registered = {1: {'identity': {'pid': 1, 'pgid': 1}, 'token': 'root'}}
    value.timed_events, value.event_timings = set(), []
    value.diagnostic_schedule = {'refresh_wall_ns': 0, 'refresh_cpu_ns': 0}
    value.effects = []
    value.poison = value.effects.append
    return JournalSupervisor.adopt(value) if composed else value


def state(value):
    return {'registered': deepcopy(value.registered), 'timed': set(value.timed_events),
            'timings': [(r['event_sha256'], deepcopy(r['event'])) for r in value.event_timings],
            'poisons': list(value.effects)}


def execute(value, calls, monkeypatch):
    def identity(pid):
        calls.append(pid)
        return {'pid': pid, 'ppid': pid - 1, 'uid': 20000, 'pgid': 1}
    monkeypatch.setattr(original.kernel, 'identity', identity)
    try:
        rows = value.refresh()
        return list(rows), None
    except Exception as error:
        return None, (type(error), error.args)


def assert_equivalent(left, right, monkeypatch):
    a, b = [], []
    result_a = execute(left, a, monkeypatch)
    result_b = execute(right, b, monkeypatch)
    assert result_a == result_b
    assert a == b
    assert state(left) == state(right)


def records():
    return [
        {'kind': 'ready', 'owner_pid': 1, 'token': 'root', 'value': [1]},
        {'kind': 'admitted', 'owner_pid': 1, 'token': 't2'},
        {'kind': 'registered', 'owner_pid': 1, 'pid': 2, 'token': 't2'},
        {'kind': 'launch_lifecycle_binding', 'token': 't2', 'start_new_session': False},
        {'kind': 'registered', 'owner_pid': 2, 'pid': 3, 'token': 't3'},
        {'kind': 'launch_lifecycle_binding', 'token': 't3', 'start_new_session': False},
        {'kind': 'forbidden', 'reason': 'must repeat'},
        {'kind': 'finished', 'token': 't2'},
        {'kind': 'registered', 'python': False},
    ]


def write(directory, rows):
    (directory / '1.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))


@pytest.mark.parametrize('seed', range(12))
def test_original_state_kernel_calls_and_poison_effects_match_across_current_rewrites(tmp_path, monkeypatch, seed):
    left, right = owner(tmp_path, False), owner(tmp_path, True)
    rows = records()
    random.Random(seed).shuffle(rows)
    for current in (rows, rows, rows + [{'kind': 'custodian_stage', 'phase': 'new'}],
                    [r for r in rows if r['kind'] != 'registered'], [], records()):
        write(tmp_path, current)
        assert_equivalent(left, right, monkeypatch)


@pytest.mark.parametrize('bad', [None, {}, {'kind': []}, {'kind': 'ready', 'phase': []},
                               {'kind': 'registered', 'pid': []},
                               {'kind': 'registered', 'pid': 2, 'owner_pid': 1, 'token': 'missing'},
                               {'kind': 'launch_lifecycle_binding'}])
def test_malformed_or_unresolved_rows_keep_original_error_and_effect_order(tmp_path, monkeypatch, bad):
    left, right = owner(tmp_path, False), owner(tmp_path, True)
    rows = [records()[0], bad, records()[2]]
    write(tmp_path, rows)
    assert_equivalent(left, right, monkeypatch)


@pytest.mark.parametrize('fault', ['uid', 'ppid', 'pgid', 'unavailable'])
def test_original_kernel_ownership_refusals_remain_effectful(tmp_path, monkeypatch, fault):
    left, right = owner(tmp_path, False), owner(tmp_path, True)
    write(tmp_path, records()[:4])
    calls = []
    def identity(pid):
        calls.append(pid)
        if fault == 'unavailable':
            raise RuntimeError('unavailable')
        result = {'pid': pid, 'ppid': 1, 'uid': 20000, 'pgid': 1}
        result[fault] = -1
        return result
    monkeypatch.setattr(original.kernel, 'identity', identity)
    assert list(left.refresh()) == list(right.refresh())
    assert calls == [2, 2]
    assert state(left) == state(right)
    assert left.effects == ['registered_child_identity_unavailable']
    assert 2 not in right.registered


def test_current_dedupe_state_is_rechecked_without_a_cached_registration_verdict(tmp_path, monkeypatch):
    left, right = owner(tmp_path, False), owner(tmp_path, True)
    write(tmp_path, records())
    assert_equivalent(left, right, monkeypatch)
    for value in (left, right):
        value.timed_events.clear()
        value.registered.pop(2)
        value.registered.pop(3)
    assert_equivalent(left, right, monkeypatch)


def test_idle_census_uses_current_bytes_without_decoding_old_rows_or_caching_decisions(tmp_path, monkeypatch):
    value = owner(tmp_path, True)
    write(tmp_path, [records()[0]])
    first = value.refresh()
    assert len(first) == 1
    reads, decodes = [], []
    read, decode = Path.read_bytes, event_journal.json.loads
    def read_bytes(path):
        reads.append(path)
        return read(path)
    def loads(body):
        decodes.append(body)
        return decode(body)
    monkeypatch.setattr(Path, 'read_bytes', read_bytes)
    monkeypatch.setattr(event_journal.json, 'loads', loads)
    current = value.refresh()
    assert len(current) == 1 and current.full is None
    assert reads == [tmp_path / '1.jsonl'] and decodes == []
    assert current.materialize() == first.materialize()
    assert current[0] is not first[0]
    write(tmp_path, [{'kind': 'forbidden', 'reason': 'current'}])
    value.refresh()
    value.refresh()
    assert value.effects == ['finite_guard:current', 'finite_guard:current']


def test_lazy_snapshot_retains_its_exact_acquisition_and_policy_gets_complete_plain_list(tmp_path, monkeypatch):
    value = owner(tmp_path, True)
    write(tmp_path, records())
    snapshot = value.journal().snapshot(tmp_path)
    write(tmp_path, [])
    seen = []
    def handle(self, request, events):
        assert self is value and type(events) is list
        seen.append(events)
        return request
    monkeypatch.setattr(original.Supervisor, 'handle', handle)
    request = {'kind': 'custody_peer'}
    assert value.handle(request, snapshot) is request
    assert seen == [records()]
    assert value.events() == []


@pytest.mark.skipif(sys.platform != 'linux', reason='actual Linux peer credentials and process birth required')
def test_real_socket_receipt_consumes_full_snapshot_through_original_authentication(tmp_path):
    manifest = tmp_path / 'manifest.json'
    manifest.write_text('{}')
    config = {'manifest': str(manifest), 'pins': {str(manifest): original.sha(manifest)},
              'endpoint': {'responses': str(tmp_path), 'nonce': 'a' * 64,
                           'socket': str(tmp_path / 'receipt.sock')}}
    value = original.Supervisor(config, type('Child', (), {'pid': os.getpid()})())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pins = dict(manifest_sha256='a' * 64, guard_sha256='b' * 64,
                    registry_sha256='c' * 64, runtime_sha256='d' * 64)
        directory = tmp_path / 'events'
        directory.mkdir()
        value.manifest.update(events=str(directory), guard_sha256=pins['guard_sha256'],
                              registry={'sha256': pins['registry_sha256']},
                              runtime={'sha256': pins['runtime_sha256']})
        value.registered[os.getpid()]['ready_pins'] = pins
        write(directory, [{'kind': 'ready', 'owner_pid': os.getpid(), 'token': 'root', **pins}])
        JournalSupervisor.adopt(value)
        client.connect(config['endpoint']['socket'])
        client.settimeout(1)
        request = {'kind': 'ready', 'id': 'b' * 32, 'pid': os.getpid(), 'token': 'root',
                   'nonce': 'a' * 64, 'identity': value.root}
        body = json.dumps(request).encode()
        client.sendall(struct.pack('!I', len(body)) + body)
        value.tick()
        assert client.recv(16388)
        assert not value.poisoned and value.receipts[-1]['ok'] is True
        assert value.receipts[-1]['kernel_peer']['birth'] == value.root
    finally:
        client.close()
        value.close()
