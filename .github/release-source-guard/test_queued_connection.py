"""Connected/payload policy composition retains fresh kernel-owned queue checks."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

import linux_supervisor as base
from journal_supervisor import JournalSupervisor


@pytest.fixture
def model(monkeypatch):
    value = JournalSupervisor.__new__(JournalSupervisor)
    value.poisoned, value.connections, value.pairs = False, set(), {}
    value.authenticate = lambda *args: None
    listener = {'pid': 200, 'fd': 4, 'local_host': '127.0.0.1', 'local_port': 12345,
                'state': 10, 'socket_cookie': 88, 'inode': 99}
    own = {'pid': 100, 'fd': 5, 'local_host': '127.0.0.1', 'remote_host': '127.0.0.1',
           'local_port': 40000, 'remote_port': 12345, 'state': 1, 'socket_cookie': 77, 'inode': 66}
    value.connect_admissions = {(100, 5): listener}
    value.listeners = {12345: listener}
    value.registered = {100: {}, 200: {}}
    value.root = {'uid': 20000}
    observations = []
    def observe(pid):
        observations.append(pid)
        return [dict(listener)] if pid == 200 else [dict(own)]
    value.observe = observe
    value.observe_connection = lambda pid: value.observe(pid)
    monkeypatch.setattr(base, 'sockets', SimpleNamespace(
        reciprocal_peer=lambda *args: None, retained_tcp_descriptor=lambda *args: None,
        live_binding=lambda *args: None, closed_binding=lambda *args: None))
    request = {'kind': 'connected', 'pid': 100, 'fd': 5}
    return value, listener, own, request, observations


def test_unaccepted_owned_queue_uses_original_payload_policy_and_fresh_reads(model):
    value, listener, own, request, observations = model
    before = deepcopy(request)
    result = value.handle(request, [])
    assert request == before and result == {'socket': own, 'listener': listener, 'accepted_queue_allowed': True}
    assert observations.count(100) >= 3 and observations.count(200) >= 2
    assert value.connections == {(100, 77, 66, 40000, 12345)} and value.poisoned is False


@pytest.mark.parametrize('state', [2, 3])
def test_syn_keeps_original_pending_without_provisional_payload_authority(model, state):
    value, listener, own, request, observations = model
    own['state'] = state
    with pytest.raises(base.AwaitOwnedPeer, match='accepted_peer_not_yet_observable'):
        value.handle(request, [])
    assert value.connections == set()


@pytest.mark.parametrize('change', ['foreign-address', 'missing-admission', 'changed-listener',
                                   'late-listener-loss', 'late-descriptor-loss', 'late-cookie'])
def test_foreign_changed_or_late_binding_never_gains_queue_authority(model, change):
    value, listener, own, request, observations = model
    if change == 'foreign-address':
        own['remote_host'] = '192.0.2.1'
    elif change == 'missing-admission':
        value.connect_admissions.clear()
    elif change == 'changed-listener':
        value.observe = lambda pid: [] if pid == 200 else [dict(own)]
    else:
        original = value.observe
        parent_reads = 0
        def changed(pid):
            nonlocal parent_reads
            if pid == 100:
                parent_reads += 1
                if parent_reads >= 2 and change == 'late-descriptor-loss':
                    return []
                if parent_reads >= 2 and change == 'late-cookie':
                    return [{**own, 'socket_cookie': 123}]
            if pid == 200 and parent_reads >= 2 and change == 'late-listener-loss':
                return []
            return original(pid)
        value.observe = changed
    with pytest.raises(RuntimeError):
        value.handle(request, [])
    assert value.connections == set()
    # A discarded/changed descriptor cannot match the old cookie-bound key.
    assert (100, 123, 66, 40000, 12345) not in value.connections


def test_refused_current_descriptor_preserves_unrelated_authenticated_connections(model):
    value, listener, own, request, observations = model
    prior = (90, 91, 92, 40001, 12346)
    value.connections.add(prior)
    original = value.observe
    reads = 0
    def changed(pid):
        nonlocal reads
        if pid == 100:
            reads += 1
            if reads >= 2:
                return []
        return original(pid)
    value.observe = changed
    with pytest.raises(RuntimeError, match='descriptor_changed'):
        value.handle(request, [])
    assert value.connections == {prior}
