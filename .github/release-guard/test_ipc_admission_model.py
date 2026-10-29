"""Admission containment retains ownership; payload certification is retired."""
from dataclasses import replace
from types import SimpleNamespace
import os
import socket
import threading

import pytest

from content_manifest import Refused
from source_sockets import Hooks
from source_profile import METHODS
from test_endpoint_policy import prepared,idle_client


def test_installed_hooks_leave_kernel_stream_and_file_io_operations_ordinary(monkeypatch):
    from multiprocessing.connection import Connection
    payload={name:getattr(socket.socket,name) for name in ('send','sendall','recv','recv_into','accept')}
    files=os.read,os.write
    connection=getattr(Connection,'_send'),getattr(Connection,'_recv')
    for name in ('bind','listen','connect','connect_ex','__init__'):
        monkeypatch.setattr(socket.socket,name,getattr(socket.socket,name))
    for name in ('socketpair','getaddrinfo'):
        monkeypatch.setattr(socket,name,getattr(socket,name))
    hooks=Hooks(SimpleNamespace(local=threading.local()))
    hooks.install()
    assert payload=={name:getattr(socket.socket,name) for name in payload}
    assert (os.read,os.write)==files
    assert (getattr(Connection,'_send'),getattr(Connection,'_recv'))==connection
    assert not {'payload','connected','accepted'} & METHODS


def test_admission_does_not_claim_application_accept_or_defer_reaping():
    endpoints,route,listener=prepared()
    admitted=endpoints.connect(route.name,listener,idle_client(route))
    assert admitted.route is route and admitted.listener is listener
    assert endpoints.connection_counts=={route.name:1}
    assert not any(hasattr(endpoints,name) for name in ('accepted','queued_send','retained','tickets','connections'))
    assert not endpoints.ledger.reaped(route.server.birth,route.server.token)
    with pytest.raises(Refused,match='actual parent join'):
        endpoints.retire_owner(route.server,route.case)


@pytest.mark.parametrize('mutation',['owner','connected','bound','duplicate','retired','port'])
def test_each_new_connection_still_requires_fresh_owned_listener_admission(mutation):
    endpoints,route,listener=prepared()
    client=idle_client(route)
    if mutation=='owner':
        client=replace(client,owner=route.server.birth)
    elif mutation=='connected':
        client=replace(client,state=1,local=('127.0.0.1',23456),remote=listener.local)
    elif mutation=='bound':
        client=replace(client,local=('127.0.0.1',23456))
    elif mutation=='duplicate':
        endpoints.connect(route.name,listener,client)
    elif mutation=='retired':
        endpoints.retire_case(route.case)
    else:
        listener=replace(listener,local=('127.0.0.1',12346))
    with pytest.raises(Refused):
        endpoints.connect(route.name,listener,client)
    assert endpoints.poison


@pytest.mark.parametrize('mutation',[None,'case','port','owner','tag','generation','duplicate'])
def test_root_http_needs_this_cases_actual_owned_broker_listener(monkeypatch,mutation):
    from controlled_cases import ROOT_HTTP
    from endpoint_policy import Endpoints,root_http_route
    import socket_observation
    endpoints,route,listener=prepared(same_owner=True)
    case=next(iter(ROOT_HTTP))
    birth=route.server.birth
    token=route.server.token
    endpoints.ledger.process(birth).case=case
    endpoints=Endpoints(endpoints.ledger)
    listener=replace(listener,owner=birth)
    host=SimpleNamespace(case=case,listeners={1:{'case':case,'tag':'broker','socket':listener}},
        endpoints=endpoints,root_only=lambda actor:None,owner=lambda actor:route.server)
    monkeypatch.setattr(socket_observation,'acquire_tcp',lambda *args:replace(listener,cookie=3000) if mutation=='generation' else listener)
    if mutation=='case':
        host.case='undeclared'
    elif mutation=='port':
        listener=replace(listener,local=('127.0.0.1',12346))
    elif mutation=='owner':
        host.listeners[1]['socket']=replace(listener,owner=replace(birth,ticks=birth.ticks+1))
    elif mutation=='tag':
        host.listeners[1]['tag']='bridge'
    elif mutation=='duplicate':
        host.listeners[2]=dict(host.listeners[1])
    actor={'birth':birth,'token':token}
    if mutation is None:
        name,maximum=root_http_route(host,actor,12345)
        assert endpoints.routes[name].server==endpoints.routes[name].client==host.owner(actor)
        assert maximum in (3,4)
    else:
        with pytest.raises(Refused):
            root_http_route(host,actor,12345)
