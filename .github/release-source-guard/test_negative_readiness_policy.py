"""Existing supervisor plan policy does not admit any socket connection."""
from types import SimpleNamespace

import pytest

import linux_supervisor as host


@pytest.mark.parametrize('change', [None, 'token', 'vector', 'birth', 'missing-child'])
def test_exact_owned_plan_returns_pending_only_and_never_admits_connect(monkeypatch, change):
    value = host.Supervisor.__new__(host.Supervisor)
    value.poisoned = []
    value.authenticate = lambda *args: None
    value.plans, value.listeners, value.connect_admissions = {}, {}, {}
    identity = {'pid': 101, 'start_ticks': 4}
    value.registered = {101: {'token': 'child', 'identity': identity}}
    monkeypatch.setattr(host, 'kernel', SimpleNamespace(identity=lambda pid: identity
                         if change != 'birth' else {**identity, 'start_ticks': 5}))
    plan = {'kind': 'plan', 'pid': 20, 'host': '127.0.0.1', 'port': 1,
            'child_token': 'child', 'argv_sha256': 'vector'}
    assert value.handle(plan, []) == {'plan_recorded': True, 'network_admitted': False}
    events = [{'kind': 'admitted', 'owner_pid': 20, 'token': 'child', 'argv_sha256': 'vector'}]
    if change in {'token', 'vector'}:
        events[0]['token' if change == 'token' else 'argv_sha256'] = 'foreign'
    elif change == 'missing-child':
        value.registered.clear()
    error = host.PendingOwnedListener if change is None else RuntimeError
    with pytest.raises(error):
        value.handle({'kind': 'connect', 'pid': 20, 'host': '127.0.0.1', 'port': 1, 'fd': 5}, events)
    assert value.listeners == value.connect_admissions == {} and not value.poisoned
