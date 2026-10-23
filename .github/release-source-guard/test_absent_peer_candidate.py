"""A missing historical candidate supplies no live peer or cleanup authority."""
from copy import deepcopy

import pytest

import linux_supervisor as original
from test_ready_projection import make_owner, ready


def setup(monkeypatch, historical_error=None, peer_change=None, actor_error=None):
    owner = make_owner(False)
    owner.pairs = {}
    actor = deepcopy(owner.registered[20])
    owner.registered = {21: {'identity': {'pid': 21}, 'token': 'old'},
                        20: actor, 22: {'identity': {'pid': 22}, 'token': 'peer'}}
    own = dict(pid=20, fd=6, state=1, local_host='127.0.0.1', remote_host='127.0.0.1',
               local_port=1001, remote_port=1002, socket_cookie=123, inode=456)
    peer = dict(pid=22, fd=8, state=1, local_host='127.0.0.1', remote_host='127.0.0.1',
                local_port=1002, remote_port=1001, socket_cookie=789, inode=987)
    peer.update(peer_change or {})
    calls = []

    def identity(pid):
        calls.append(('identity', pid))
        if pid == 20 and actor_error:
            raise actor_error
        if pid == 21 and historical_error:
            raise historical_error
        return owner.registered[pid]['identity']

    def sockets(pid):
        calls.append(('sockets', pid))
        return [own] if pid == 20 else [peer] if pid == 22 else []

    monkeypatch.setattr(original.kernel, 'identity', identity)
    monkeypatch.setattr(original.kernel, 'sockets', sockets)
    monkeypatch.setattr(original.sockets, 'retained_tcp_descriptor', lambda *args: None)
    request = dict(kind='payload', pid=20, fd=6, token='owned', nonce='n')
    return owner, request, calls, own, peer


def missing():
    return FileNotFoundError(2, 'No such file or directory', '/proc/21/stat')


@pytest.mark.parametrize('error', [missing(), RuntimeError('stale_or_reused_ownership')])
def test_historical_candidate_cannot_mask_fresh_reciprocal_peer(monkeypatch, error):
    owner, request, calls, own, peer = setup(monkeypatch, historical_error=error)
    before = deepcopy(owner.registered)
    assert owner.handle(request, [ready()]) == {'socket': own, 'peer': peer}
    assert calls == [('identity', 20), ('identity', 20), ('sockets', 20),
                     ('identity', 21), ('identity', 20), ('sockets', 20),
                     ('identity', 22), ('sockets', 22)]
    assert owner.connections == {(20, 123, 456, 1001, 1002)}
    assert owner.registered == before and not owner.poisoned


@pytest.mark.parametrize('change', [dict(state=10), dict(local_host='127.0.0.2'),
    dict(remote_host='127.0.0.2'), dict(local_port=1003), dict(remote_port=1003)])
def test_missing_candidate_does_not_admit_nonreciprocal_live_peer(monkeypatch, change):
    owner, request, calls, _, _ = setup(monkeypatch, missing(), change)
    with pytest.raises(RuntimeError, match='^foreign_or_unregistered_payload_peer$'):
        owner.handle(request, [ready()])
    assert ('sockets', 22) in calls and not owner.connections
    assert 21 in owner.registered


def test_missing_candidate_without_any_live_peer_refuses(monkeypatch):
    owner, request, _, _, _ = setup(monkeypatch, missing())
    del owner.registered[22]
    with pytest.raises(RuntimeError, match='^foreign_or_unregistered_payload_peer$'):
        owner.handle(request, [ready()])
    assert not owner.connections and 21 in owner.registered


@pytest.mark.parametrize('error', [PermissionError(13, 'Permission denied'), OSError(5, 'Input/output error')])
def test_other_candidate_acquisition_errors_remain_fatal(monkeypatch, error):
    owner, request, calls, _, _ = setup(monkeypatch, error)
    with pytest.raises(type(error)) as caught:
        owner.handle(request, [ready()])
    assert caught.value is error
    assert ('identity', 22) not in calls and not owner.connections


def test_requester_disappearance_still_fails_authentication(monkeypatch):
    error = missing()
    owner, request, calls, _, _ = setup(monkeypatch, actor_error=error)
    with pytest.raises(FileNotFoundError) as caught:
        owner.handle(request, [ready()])
    assert caught.value is error and calls == [('identity', 20)]
    assert not owner.connections


def test_requester_socket_observation_disappearance_still_fails(monkeypatch):
    owner, request, calls, _, _ = setup(monkeypatch, missing())
    error = missing()
    monkeypatch.setattr(original.kernel, 'sockets', lambda pid: (_ for _ in ()).throw(error))
    with pytest.raises(FileNotFoundError) as caught:
        owner.handle(request, [ready()])
    assert caught.value is error and ('identity', 21) not in calls
    assert not owner.connections
