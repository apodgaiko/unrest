"""Original refused broker clients, scoped across their transport tasks."""
from __future__ import annotations

from contextvars import ContextVar
import hashlib
import importlib
from pathlib import Path

from content_manifest import Refused
from controlled_cases import ROOT_HTTP, INITIALIZED_HTTP
from controlled_startup import dictionary, path
from notification_calls import closure
from source_owner import Link, active_frames, frame_fields, instance_fields, _namespace, prepare

SCOPE: ContextVar[tuple[object, int] | None] = ContextVar('release-root-http',default=None)


def guarded(function):
    def checked(self,*args,**kwargs):
        try:
            return function(self,*args,**kwargs)
        except Refused:
            self.calls.policy.refuse('root HTTP scoped refusal')
    return checked


class Contexts:
    def __init__(self,calls):
        from fastmcp import Client
        from fastmcp.client.transports.http import StreamableHttpTransport
        from fastmcp.client.auth.bearer import BearerAuth
        from pydantic import SecretStr
        self.calls,self.client_type = calls,Client
        self.transport_type,self.auth_type,self.secret_type = StreamableHttpTransport,BearerAuth,SecretStr
        self.records: list[dict] = []
        self.anchors = {'enter':vars(Client)['__aenter__'],'exit':vars(Client)['__aexit__'],
                        'initialize':vars(calls.startup.base)['initialize_only']}
        module = importlib.import_module('fastmcp.client.client')
        file = Path(module.__file__)
        if not file.is_relative_to(Path(calls.profile['dependencies'])):
            raise Refused('root HTTP locked dependency origin')
        body = file.read_bytes()
        unit = prepare(body,str(file),module.__name__,calls.mode(module),hashlib.sha256(body).hexdigest())
        self.enter_owner = unit.owner(module,self.anchors['enter'],'Client.__aenter__',
            (Link(module,'Client',Client),Link(self.anchors,'enter',self.anchors['enter'])))
        self.exit_owner = unit.owner(module,self.anchors['exit'],'Client.__aexit__',
            (Link(module,'Client',Client),Link(self.anchors,'exit',self.anchors['exit'])))
        self.initialize_owner = calls.owner(calls.session_unit,calls.session,self.anchors['initialize'],
            '_SessionOwner.initialize_only',(Link(self.anchors,'initialize',self.anchors['initialize']),))
        async def enter(client):
            record = self.capture(client)
            token = SCOPE.set((self,record['ordinal']))
            try:
                try:
                    self.enter_owner.verify_binding()
                except Refused:
                    calls.policy.refuse('root HTTP original enter binding')
                return await self.anchors['enter'](client)
            except BaseException:
                try:
                    self.retire(record)
                except BaseException:
                    calls.policy.poison = True
                raise
            finally:
                SCOPE.reset(token)
        async def exit(client,*args):
            record = self.record(client)
            token = SCOPE.set((self,record['ordinal']))
            try:
                try:
                    self.exit_owner.verify_binding()
                except Refused:
                    calls.policy.refuse('root HTTP original exit binding')
                return await self.anchors['exit'](client,*args)
            finally:
                try:
                    self.retire(record)
                finally:
                    SCOPE.reset(token)
        self.enter,self.exit = enter,exit
        Client.__aenter__,Client.__aexit__ = enter,exit

    @guarded
    def capture(self,client):
        calls = self.calls
        case = calls.policy.case
        ordinal = len(self.records)+1
        if (type(case) is not str or case not in ROOT_HTTP or type(client) is not self.client_type
                or ordinal > (2 if case == INITIALIZED_HTTP else 1)
                or any(record['active'] for record in self.records)
                or any(record['client'] is client for record in self.records)):
            raise Refused('root HTTP exact client context frontier')
        frames = active_frames()
        try:
            if case == INITIALIZED_HTTP:
                live = vars(calls.startup.base)['initialize_only']
                values = closure(live)
                if (set(values) != {'Client','TurnIdentity','asdict','initialize'}
                        or values['Client'] is not self.client_type
                        or values['initialize'] is not self.anchors['initialize']):
                    raise Refused('root HTTP original initialization closure')
                self.initialize_owner.verify_binding()
                owner = calls.test_unit.owner(calls.tests,live,
                    'test_initialized_owner_has_no_http_mutation_authority.<locals>.check',
                    (Link(calls.startup.base,'initialize_only',live),),
                    closure=tuple(values[name] for name in live.__code__.co_freevars))
                frame = owner.current(frames,line=209 if ordinal == 1 else 217)
                instance = frame_fields(frame).get('self')
            else:
                module,_,owner,*_ = calls.notification
                frame = owner.current(frames,line=286)
                local = frame_fields(frame)
                instance = local.get('owner')
                when,status = case.rsplit('[',1)[1][:-1].rsplit('-',1)
                if (type(local.get('when')) is not str or local['when'] != when
                        or type(local.get('status')) is not str or local['status'] != status or status != 'disabled'):
                    raise Refused('root HTTP original notification parameters')
                calls.test_owner.current(frames,line=286 if calls.tests is module else 41)
            if type(instance) is not calls.startup.base:
                raise Refused('root HTTP original owner type')
            values = dictionary(instance,calls.startup.base)
            root = path(values.get('root'))
            broker_type = vars(calls.session)['TurnBroker']
            broker = values.get('broker')
            if (calls.startup.owners.get(str(root)) is not instance or calls.startup.case != case
                    or calls.startup.root_key() != calls.startup.root_identity
                    or type(broker) is not broker_type or dictionary(broker,broker_type).get('_active') is not None):
                raise Refused('root HTTP original owner generation or no active grant')
            expected_auth = 'invalid-connection-token' if ordinal == 2 else values.get('_connection')
            transport = instance_fields(client).get('transport')
            if type(transport) is not self.transport_type:
                raise Refused('root HTTP original transport type')
            settings = instance_fields(transport)
            auth = settings.get('auth')
            secret = instance_fields(auth).get('token') if type(auth) is self.auth_type else None
            token = instance_fields(secret).get('_secret_value') if type(secret) is self.secret_type else None
            if (type(token) is not str or type(expected_auth) is not str or token != expected_auth
                    or type(settings.get('url')) is not str or type(values.get('url')) is not str
                    or settings['url'] != values['url'] or type(settings.get('headers')) is not dict
                    or _namespace(settings['headers']) or settings.get('httpx_client_factory') is not None):
                raise Refused('root HTTP original URL/auth/default transport')
            listener = calls.policy.sockets.descriptor(values.get('_listener'))
            answer = calls.policy.client.request('root-http-open',{'ordinal':ordinal,'listener':listener,'scope':str(root)})
            if settings['url'] != 'http://127.0.0.1:'+str(answer['port'])+'/mcp':
                raise Refused('root HTTP original broker URL binding')
            record = {'client':client,'owner':instance,'case':case,'ordinal':ordinal,
                      'port':answer['port'],'active':True}
            self.records.append(record)
            return record
        finally:
            del frames

    @guarded
    def record(self,client):
        selected = [record for record in self.records if record['client'] is client and record['active']]
        if len(selected) != 1:
            raise Refused('root HTTP active client context')
        return selected[0]

    @guarded
    def retire(self,record):
        if not record['active']:
            raise Refused('root HTTP context retirement replay')
        record['active'] = False
        self.calls.policy.client.request('root-http-close',{'ordinal':record['ordinal']})

    @guarded
    def connection(self,port):
        scope = SCOPE.get()
        if type(scope) is not tuple or len(scope) != 2 or scope[0] is not self or type(scope[1]) is not int:
            raise Refused('root HTTP inherited context absent')
        records = [record for record in self.records if record['ordinal'] == scope[1]]
        if (len(records) != 1 or not records[0]['active'] or records[0]['case'] != self.calls.policy.case
                or type(port) is not int or records[0]['port'] != port):
            raise Refused('root HTTP retired or foreign transport context')
        return scope[1]

    @guarded
    def finish(self):
        if (self.calls.policy.poison or any(record['active'] for record in self.records)
                or len(self.records) != (2 if self.calls.policy.case == INITIALIZED_HTTP else 1)
                or vars(self.client_type)['__aenter__'] is not self.enter
                or vars(self.client_type)['__aexit__'] is not self.exit):
            raise Refused('root HTTP unfinished context or wrapper binding')
        self.client_type.__aenter__,self.client_type.__aexit__ = self.anchors['enter'],self.anchors['exit']
