"""Synthetic scoped-context/endpoint controls, never kernel or provider proof."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from controlled_cases import ROOT_HTTP, INITIALIZED_HTTP
from endpoint_policy import Endpoints, Socket
from root_http import Contexts, SCOPE
import root_http_observer as observer_calls
from test_endpoint_policy import ready, connected
from test_process_ledger import setup


def policy(case,request,**extra):
    value=SimpleNamespace(case=case,poison=False,client=SimpleNamespace(request=request),**extra)
    def refuse(reason):
        value.poison=True
        raise Refused(reason)
    value.refuse=refuse
    return value


@pytest.fixture
def model(tmp_path,monkeypatch):
    case = next(case for case in ROOT_HTTP if case != INITIALIZED_HTTP)
    ledger,root,_ = setup()
    ledger.process(root).case = case
    owner = ready(ledger,root)
    endpoints = Endpoints(ledger)
    scope = tmp_path/'pytest/case/campaign/owner'
    listener = Socket(root,7,1000,2000,10,20000,('127.0.0.1',12345),None)
    actor = {'birth':root,'role':'root','token':'root-token'}
    def root_only(value):
        if value is not actor:
            raise Refused('synthetic root identity')
    observer = SimpleNamespace(case=case,meta={'owned':str(tmp_path)},http_contexts={},
        root_only=root_only,owner=lambda value:owner,endpoints=endpoints,
        listener_key=lambda case,tag,scope:(case,tag,scope),
        listeners={(case,'broker',str(scope)):{'socket':listener}})
    monkeypatch.setattr(observer_calls,'acquire_tcp',lambda birth,fd,retained:listener)
    return observer,actor,{'ordinal':1,'listener':7,'scope':str(scope)},listener


def test_original_root_context_is_serial_and_retired(model):
    observer,actor,payload,_ = model
    assert observer_calls.context(observer,actor,'root-http-open',payload)=={'ok':True,'port':12345}
    route,maximum = observer_calls.connection(observer,actor,{'context':1},12345)
    assert maximum==3 and observer.endpoints.routes[route].client==observer.endpoints.routes[route].server
    observer_calls.context(observer,actor,'root-http-close',{'ordinal':1})
    with pytest.raises(Refused):
        observer_calls.connection(observer,actor,{'context':1},12345)
    with pytest.raises(Refused):
        observer_calls.context(observer,actor,'root-http-close',{'ordinal':1})


@pytest.mark.parametrize('mutation',['scope','fd','ordinal','boolean','case','root','generation'])
def test_unknown_context_cannot_select_a_listener(model,monkeypatch,mutation):
    observer,actor,payload,listener = model
    if mutation=='scope':
        payload['scope']='/foreign/campaign/owner'
    elif mutation=='fd':
        payload['listener']=8
    elif mutation=='ordinal':
        payload['ordinal']=2
    elif mutation=='boolean':
        payload['ordinal']=True
    elif mutation=='case':
        observer.case='foreign'
    elif mutation=='root':
        actor=dict(actor)
    else:
        monkeypatch.setattr(observer_calls,'acquire_tcp',lambda *args,**kwargs:replace(listener,cookie=2001))
    with pytest.raises(Refused):
        observer_calls.context(observer,actor,'root-http-open',payload)
    assert not observer.http_contexts


def test_retirement_requires_real_reciprocal_join_not_just_connect(model):
    observer,actor,payload,listener = model
    observer_calls.context(observer,actor,'root-http-open',payload)
    route,_ = observer_calls.connection(observer,actor,{'context':1},12345)
    client = Socket(actor['birth'],8,1001,2001,7,20000,('0.0.0.0',0),None)
    observer.endpoints.connect(route,listener,client)
    with pytest.raises(Refused):
        observer_calls.context(observer,actor,'root-http-close',{'ordinal':1})


def test_copied_task_context_loses_authority_after_registry_retirement():
    manager = object.__new__(Contexts)
    case = next(iter(ROOT_HTTP))
    manager.calls=SimpleNamespace(policy=policy(case,lambda *args:{'ok':True}))
    record={'client':object(),'owner':object(),'case':case,'ordinal':1,'port':12345,'active':True}
    manager.records=[record]
    async def run():
        started,retired = asyncio.Event(),asyncio.Event()
        async def inherited():
            assert manager.connection(12345)==1
            started.set()
            await retired.wait()
            with pytest.raises(Refused):
                manager.connection(12345)
        token=SCOPE.set((manager,1))
        try:
            task=asyncio.create_task(inherited())
        finally:
            SCOPE.reset(token)
        await started.wait()
        manager.retire(record)
        retired.set()
        await task
    asyncio.run(run())


@pytest.mark.parametrize('scope',[None,(object(),1),(object(),True)])
def test_foreign_task_scope_never_authorizes_connection(scope):
    manager=object.__new__(Contexts)
    manager.calls=SimpleNamespace(policy=policy('foreign',lambda *args:None))
    token=SCOPE.set(scope)
    try:
        with pytest.raises(Refused):
            manager.connection(12345)
    finally:
        SCOPE.reset(token)


@pytest.mark.parametrize('mutation',[None,'auth','url','headers','factory','owner','grant'])
def test_capture_checks_actual_locked_client_transport_without_network(tmp_path,mutation):
    import hashlib
    import sys
    from pathlib import Path
    from fastmcp import Client
    from unrest_harness import experimental_session as session
    from source_calls import Sources
    from source_owner import prepare
    from tests import test_experimental_notifications as tests
    case=next(case for case in ROOT_HTTP if case!=INITIALIZED_HTTP and case.startswith('tests/test_experimental_notifications.py'))
    when,status=case.rsplit('[',1)[1][:-1].rsplit('-',1)
    root=tmp_path/'pytest/case/campaign/owner'
    owner=object.__new__(session._SessionOwner)
    broker=object.__new__(session.TurnBroker)
    broker._active=object() if mutation=='grant' else None
    vars(owner).update(root=root,broker=broker,url='http://127.0.0.1:12345/mcp',_connection='synthetic-token',_listener=object())
    def current(*args,**kwargs):
        frame=sys._getframe(1)
        while frame.f_code is not test_capture_checks_actual_locked_client_transport_without_network.__code__:
            frame=frame.f_back
        return frame
    source=SimpleNamespace(current=current)
    file=Path(session.__file__)
    unit=prepare(file.read_bytes(),str(file),session.__name__,Sources.mode(session),hashlib.sha256(file.read_bytes()).hexdigest())
    requests=[]
    def request(kind,payload):
        requests.append((kind,payload))
        return {'ok':True,'port':12345}
    calls=SimpleNamespace(session=session,session_unit=unit,owner=Sources.owner,mode=Sources.mode,
        profile={'dependencies':str(Path(__import__('fastmcp').__file__).parents[1]),'owned':str(tmp_path)},
        startup=SimpleNamespace(base=session._SessionOwner,case=case,owners={str(root):object() if mutation=='owner' else owner},root_key=lambda:1,root_identity=1),
        notification=(tests,None,source,None,None,None,None),test_owner=source,tests=tests,
        policy=policy(case,request,sockets=SimpleNamespace(descriptor=lambda stream:7)))
    manager=Contexts(calls)
    try:
        manager.enter_owner.verify_binding()
        manager.exit_owner.verify_binding()
        client=Client('http://127.0.0.1:9999/mcp' if mutation=='url' else owner.url,
                      auth='wrong' if mutation=='auth' else owner._connection)
        if mutation=='headers':
            client.transport.headers={'foreign':'value'}
        elif mutation=='factory':
            client.transport.httpx_client_factory=lambda **kwargs:None
        if mutation is None:
            record=manager.capture(client)
            assert record['client'] is client and record['owner'] is owner and record['ordinal']==1
            manager.retire(record)
            manager.finish()
        else:
            with pytest.raises(Refused):
                manager.capture(client)
            assert not requests
    finally:
        Client.__aenter__,Client.__aexit__=manager.anchors['enter'],manager.anchors['exit']


def test_retired_context_revokes_retained_client_payload_but_preserves_server_drain():
    endpoints,ticket,client,server=connected(same_owner=True)
    observer=SimpleNamespace(http_contexts={('case[one]',1):{'route':ticket.route.name,'active':True}})
    connection=endpoints.accepted(ticket,client,server)
    observer_calls.retained(observer,connection,client)
    observer.http_contexts['case[one]',1]['active']=False
    with pytest.raises(Refused):
        observer_calls.retained(observer,connection,client)
    observer_calls.retained(observer,connection,server)


def test_caught_extra_context_attempt_is_sticky_before_original_enter():
    manager=object.__new__(Contexts)
    manager.client_type=object
    manager.calls=SimpleNamespace(policy=policy(next(iter(ROOT_HTTP)),lambda *args:None))
    manager.records=[{'client':object(),'active':False} for _ in range(2)]
    with pytest.raises(Refused):
        manager.capture(object())
    assert manager.calls.policy.poison
    with pytest.raises(Refused):
        manager.finish()
