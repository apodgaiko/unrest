"""Port reuse expires old authority only with the actual parent/kernel wait join."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

import linux_trace
from journal_supervisor import JournalSupervisor
from listener_lifecycle import reaped


def fixture(code=-15):
    parent = {'pid': 10, 'ppid': 1, 'start_ticks': 100, 'boot_id': 'boot', 'uid': 20000}
    child = {'pid': 20, 'ppid': 10, 'start_ticks': 200, 'boot_id': 'boot', 'uid': 20000}
    entry = {'pid': 20, 'fd': 6, 'state': 10, 'local_host': '127.0.0.1', 'local_port': 12345,
             'socket_uid': 20000, 'socket_cookie': 99, 'inode': 88}
    registered = {10: {'identity': parent, 'token': 'parent'},
                  20: {'identity': child, 'token': 'old-child'}}
    raw = -code if code < 0 else code << 8
    events = [{'kind': 'raw_actual_parent_waitpid', 'pid': 20, 'child_token': 'old-child',
               'owner_pid': 10, 'owner_identity': dict(parent), 'owner_token': 'parent',
               'nonce': 'nonce', 'requested_pid': 20, 'options': 0,
               'raw_status': raw, 'numeric_returncode': code, 'wait_event': 'actual_os_waitpid_return'}]
    native = {key: value for key, value in child.items() if key != 'uid'}
    native['uids'] = [20000] * 4
    records = [{'kind': 'kernel_child', 'child': 20, 'parent': 11, 'identity': deepcopy(native)},
               {'kind': 'kernel_exit', 'pid': 20, 'raw': raw},
               {'kind': 'tracer_terminal_wait', 'pid': 20, 'raw': raw, 'normalized': code,
                'identity': deepcopy(native)},
               {'kind': 'original_parent_wait4', 'child': 20, 'parent': 11, 'parent_tgid': 10,
                'raw': raw, 'normalized': code, 'options': 0}]
    return entry, registered, events, records


@pytest.mark.parametrize('code', [0, 17, -15])
def test_raw_numeric_exit_or_signal_is_preserved_without_mutating_evidence(code):
    values = fixture(code)
    before = deepcopy(values)
    assert reaped(*values, 'nonce') is True
    assert values == before


@pytest.mark.parametrize('change', ['no-source-wait', 'no-kernel-wait', 'no-tracer-wait', 'no-exit',
                                   'no-birth', 'order', 'duplicate', 'nonce', 'child-token',
                                   'parent-token', 'owner-birth', 'child-birth', 'parent-pid',
                                   'raw', 'numeric', 'options', 'requested', 'not-actual', 'bool', 'foreign', 'uid'])
def test_absence_or_partial_forged_waits_never_expire_a_listener(change):
    entry, registered, events, records = fixture()
    if change.startswith('no-'):
        if change == 'no-source-wait':
            events.clear()
        else:
            index = {'no-kernel-wait': 3, 'no-tracer-wait': 2, 'no-exit': 1, 'no-birth': 0}[change]
            records.pop(index)
    elif change == 'order':
        records.reverse()
    elif change == 'duplicate':
        events *= 2
    elif change == 'nonce':
        events[0]['nonce'] = 'foreign'
    elif change == 'child-token':
        events[0]['child_token'] = 'foreign'
    elif change == 'parent-token':
        events[0]['owner_token'] = 'foreign'
    elif change == 'owner-birth':
        events[0]['owner_identity']['start_ticks'] += 1
    elif change == 'child-birth':
        records[0]['identity']['start_ticks'] += 1
    elif change == 'parent-pid':
        records[3]['parent_tgid'] += 1
    elif change == 'raw':
        records[3]['raw'] = 0
    elif change == 'numeric':
        events[0]['numeric_returncode'] = 0
    elif change == 'options':
        records[3]['options'] = 1
    elif change == 'requested':
        events[0]['requested_pid'] = -1
    elif change == 'not-actual':
        events[0]['wait_event'] = 'absence'
    elif change == 'bool':
        events[0]['raw_status'] = True
    elif change == 'uid':
        records[2]['identity']['uids'][1] = 0
    else:
        entry['local_host'] = '192.0.2.1'
    assert reaped(entry, registered, events, records, 'nonce') is False


def model(monkeypatch):
    entry, registered, events, records = fixture()
    value = JournalSupervisor.__new__(JournalSupervisor)
    value.poisoned = False
    value.authenticate = lambda *args: None
    value.spec = {'endpoint': {'nonce': 'nonce'}}
    value.listeners, value.plans = {12345: entry}, {}
    value.registered = registered
    value.connections = {(10, 55, 44, 22222, 12345)}
    value.connect_admissions = {(10, 9): entry}
    value.owned_trace = linux_trace.OwnedTrace.__new__(linux_trace.OwnedTrace)
    value.owned_trace.records = records
    request = {'kind': 'plan', 'pid': 10, 'host': '127.0.0.1', 'port': 12345,
               'child_token': 'replacement', 'argv_sha256': 'a' * 64}
    return value, entry, events, request


def test_expiry_preserves_history_connections_and_requires_fresh_replacement_listener(monkeypatch):
    value, entry, events, request = model(monkeypatch)
    before = deepcopy((events, value.connections, value.connect_admissions))
    result = value.handle(request, events)
    assert result == {'plan_recorded': True, 'network_admitted': False}
    assert value.listeners == {} and value.plans[12345] is request
    assert (events, value.connections, value.connect_admissions) == before
    with pytest.raises(RuntimeError, match='foreign_or_unregistered_endpoint'):
        value.handle({'kind': 'connect', 'pid': 10, 'fd': 11, 'host': '127.0.0.1', 'port': 12345}, events)
    assert (10, 11) not in value.connect_admissions and value.connections == before[1]


@pytest.mark.parametrize('change', ['live-old-child', 'unknown-trace', 'same-token', 'bad-auth'])
def test_no_wait_or_unsupported_authority_leaves_old_cache_unchanged(monkeypatch, change):
    value, entry, events, request = model(monkeypatch)
    if change == 'live-old-child':
        events.clear()
    elif change == 'unknown-trace':
        value.owned_trace = SimpleNamespace(records=value.owned_trace.records)
    elif change == 'same-token':
        request['child_token'] = 'old-child'
    else:
        def reject(*args):
            raise RuntimeError('nonce_refused')
        value.authenticate = reject
    if change == 'bad-auth':
        with pytest.raises(RuntimeError, match='nonce_refused'):
            value.handle(request, events)
        assert value.plans == {}
    else:
        assert value.handle(request, events)['network_admitted'] is False
    assert value.listeners == {12345: entry}
