"""Same-case listener containment retains finite lifetime and kernel identity."""
from dataclasses import replace

import pytest

from content_manifest import Refused
from controlled_cases import CASES
from controlled_pairs import limits
from source_observer import Observer
from test_endpoint_policy import prepared


def test_listener_quota_cannot_be_reset_by_reusing_a_descriptor(monkeypatch):
    import source_observer

    endpoints,route,listener=prepared(same_owner=True)
    case=next(case for case in CASES if limits(case)[0]==1)
    host=object.__new__(Observer)
    host.case,host.root_birth,host.finished=case,route.server.birth,False
    host.bindings,host.listeners,host.listener_counts,host.descriptors={},{},{},{}
    actor={'role':'root','birth':host.root_birth,'token':route.server.token}
    number=[0]
    def fresh(owner,fd):
        number[0]+=1
        return replace(listener,owner=owner,fd=fd,cookie=1000+number[0],state=7,local=('0.0.0.0',0))
    monkeypatch.setattr(source_observer,'acquire_tcp',fresh)
    request={'kind':'bind','payload':{'fd':3,'tag':'owned','nonce':None}}
    for _ in range(3):
        host.dispatch(actor,request)
    assert len(host.bindings)==1 and host.listener_counts=={case:3}
    with pytest.raises(Refused,match='finite case bound'):
        host.dispatch(actor,request)


def test_listener_tags_and_application_nonce_cannot_create_authority(monkeypatch):
    host=object.__new__(Observer)
    _,route,_=prepared(same_owner=True)
    host.case,host.root_birth,host.finished=next(iter(CASES)),route.server.birth,False
    actor={'role':'root','birth':host.root_birth,'token':route.server.token}
    for payload in ({'fd':3,'tag':'bridge','nonce':None},{'fd':3,'tag':'owned','nonce':'a'*64}):
        with pytest.raises(Refused):
            host.dispatch(actor,{'kind':'bind','payload':payload})


@pytest.mark.parametrize('maximum',[2,3,4,8])
def test_multiple_listeners_cannot_multiply_one_clients_connection_budget(maximum):
    from types import SimpleNamespace
    from endpoint_policy import Route
    from owned_listeners import budget

    endpoints,route,_=prepared(same_owner=True)
    endpoints.routes={str(index):Route(str(index),route.case,route.server,route.client,12000+index)
                      for index in range(maximum)}
    host=SimpleNamespace(case=route.case,endpoints=endpoints,
        connected_routes={name:1 for name in endpoints.routes},owner=lambda actor:route.client)
    with pytest.raises(Refused,match='client connection total'):
        budget(host,{},maximum)
    host.connected_routes.pop('0')
    budget(host,{},maximum)
    host.case='next-case'
    budget(host,{},maximum)
