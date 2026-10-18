"""Adapter unit controls; actual Linux execution remains separately required."""
from types import SimpleNamespace
import sys

import pytest

from primary_package_ready import install


@pytest.fixture
def pair(monkeypatch):
    class Supervisor:
        def authenticate(self, request, events):
            self.original_calls.append((request, events))
            if events != [self.expected]:
                raise RuntimeError('original_authentication_refused')
            return self.registered[17]

        def events(self):
            self.reads += 1
            return list(self.journal)

    class PackageProducers:
        pass

    monkeypatch.setitem(sys.modules, 'linux_supervisor', SimpleNamespace(Supervisor=Supervisor))
    monkeypatch.setitem(sys.modules, 'primary_package_build', SimpleNamespace(PackageProducers=PackageProducers))
    owner = Supervisor()
    owner.original_calls, owner.reads = [], 0
    owner.expected = {'kind': 'ready', 'owner_pid': 17, 'token': 'p'}
    owner.journal = [owner.expected]
    owner.registered = {17: {'token': 'p', 'identity': {'birth': 1}, 'ready_pins': {'pin': 'a'}}}
    producers = PackageProducers()
    producers.supervisor = owner
    producers.children = {17: {'token': 'p', 'identity': {'birth': 1}}}
    request = {'kind': 'ready', 'pid': 17, 'token': 'p'}
    return owner, producers, request


def test_exact_package_pair_rereads_current_ready_and_delegates(pair):
    owner, producers, request = pair
    install(owner, producers)
    assert owner.authenticate(request, []) is owner.registered[17]
    assert owner.reads == 1 and len(owner.original_calls) == 1
    # A later disappearance must be observed on the next request.
    owner.journal = []
    with pytest.raises(RuntimeError, match='original_authentication_refused'):
        owner.authenticate(request, [])
    assert owner.reads == 2


@pytest.mark.parametrize('mutation', ['unknown_child', 'wrong_token', 'wrong_birth',
                                    'missing_pins', 'other_request', 'current_wrong_ready'])
def test_adapter_never_broadens_original_authentication(pair, mutation):
    owner, producers, request = pair
    events = []
    if mutation == 'unknown_child':
        producers.children.clear()
    elif mutation == 'wrong_token':
        producers.children[17]['token'] = 'foreign'
    elif mutation == 'wrong_birth':
        producers.children[17]['identity'] = {'birth': 2}
    elif mutation == 'missing_pins':
        owner.registered[17].pop('ready_pins')
    elif mutation == 'other_request':
        request['kind'] = 'connect'
    else:
        events = [{**owner.expected, 'wrong': True}]
    install(owner, producers)
    with pytest.raises(RuntimeError, match='original_authentication_refused'):
        owner.authenticate(request, events)
    assert owner.reads == 0 and len(owner.original_calls) == 1


@pytest.mark.parametrize('mutation', ['owner', 'producer', 'pair', 'duplicate'])
def test_only_exact_package_pair_can_install(pair, mutation):
    owner, producers, _ = pair
    if mutation == 'owner':
        owner = object()
    elif mutation == 'producer':
        producers = object()
    elif mutation == 'pair':
        producers.supervisor = object()
    else:
        install(owner, producers)
    with pytest.raises(RuntimeError, match='primary_package_ready_owner'):
        install(owner, producers)
