"""Serial broker contexts retain endpoint operands and revoke inherited grants."""
from contextvars import ContextVar

from content_manifest import Refused
from controlled_cases import ROOT_HTTP,INITIALIZED_HTTP
from operands import instance_fields

SCOPE=ContextVar('release-root-http',default=None)


def guarded(function):
    def operation(self,*args,**kwargs):
        try:
            return function(self,*args,**kwargs)
        except Refused:
            self.context.policy.refuse('root HTTP scoped refusal')
    return operation


class Contexts:
    def __init__(self,context):
        from fastmcp import Client
        self.context,self.records=context,[]
        original_enter,original_exit=Client.__aenter__,Client.__aexit__
        state=self
        async def enter(client,*args,**kwargs):
            if state.context.policy.case not in ROOT_HTTP:
                return await original_enter(client,*args,**kwargs)
            record=state.capture(client)
            token=SCOPE.set((state,record['ordinal']))
            try:
                return await original_enter(client,*args,**kwargs)
            except BaseException:
                state.retire(record)
                raise
            finally:
                SCOPE.reset(token)
        async def exit(client,*args,**kwargs):
            records=[value for value in state.records if value['client'] is client and value['active']]
            if not records:
                return await original_exit(client,*args,**kwargs)
            record=records[0]
            token=SCOPE.set((state,record['ordinal']))
            try:
                return await original_exit(client,*args,**kwargs)
            finally:
                state.retire(record)
                SCOPE.reset(token)
        Client.__aenter__,Client.__aexit__=enter,exit

    @guarded
    def capture(self,client):
        from fastmcp.client.auth import BearerAuth
        from pydantic import SecretStr
        policy=self.context.policy
        case=policy.case
        records=[value for value in self.records if value['case']==case]
        ordinal=len(records)+1
        settings=instance_fields(instance_fields(client)['transport'])
        url=settings.get('url')
        if type(url) is not str:
            policy.refuse('root HTTP primitive URL')
        owners=[owner for current,owner in self.context.owners if current==case and type(instance_fields(owner).get('url')) is str and instance_fields(owner)['url']==url]
        if (case not in ROOT_HTTP or len(owners)!=1 or ordinal>(2 if case==INITIALIZED_HTTP else 1)
                or any(value['active'] for value in records)):
            policy.refuse('root HTTP finite context or owner')
        owner=instance_fields(owners[0])
        auth=settings.get('auth')
        secret=instance_fields(auth).get('token') if type(auth) is BearerAuth else None
        token=instance_fields(secret).get('_secret_value') if type(secret) is SecretStr else None
        expected='invalid-connection-token' if ordinal==2 else owner.get('_connection')
        if (type(expected) is not str or type(token) is not str or token!=expected or type(settings.get('headers')) is not dict
                or settings['headers'] or settings.get('httpx_client_factory') is not None
                or instance_fields(owner['broker']).get('_active') is not None):
            policy.refuse('root HTTP exact authentication and transport')
        answer=policy.client.request('root-http-open',{'ordinal':ordinal,'listener':policy.sockets.descriptor(owner['_listener']),'scope':str(owner['root'])})
        if settings['url']!='http://127.0.0.1:'+str(answer['port'])+'/mcp':
            policy.refuse('root HTTP exact URL')
        record={'client':client,'case':case,'ordinal':ordinal,'port':answer['port'],'active':True}
        self.records.append(record)
        return record

    @guarded
    def retire(self,record):
        if not record['active']:
            self.context.policy.refuse('root HTTP context replay')
        record['active']=False
        self.context.policy.client.request('root-http-close',{'ordinal':record['ordinal']})

    @guarded
    def connection(self,port):
        scope=SCOPE.get()
        if type(scope) is not tuple or len(scope)!=2 or scope[0] is not self:
            self.context.policy.refuse('root HTTP inherited context absent')
        records=[value for value in self.records if value['case']==self.context.policy.case and value['ordinal']==scope[1] and value['active']]
        if len(records)!=1 or records[0]['port']!=port:
            self.context.policy.refuse('root HTTP context retired or foreign')
        return records[0]['ordinal']

    @guarded
    def finish(self):
        if self.context.policy.poison or any(value['active'] for value in self.records if value['case']==self.context.policy.case):
            self.context.policy.refuse('root HTTP unfinished context')
