"""Effect metadata for finite observer checks; no Python caller authentication."""
from contextvars import ContextVar
import types

from operands import instance_fields
from controlled_cases import CASES as CONTROLLED
from bootstrap_cases import BOOTSTRAP
from cleanup_inline import STARTUP

LISTENER = ContextVar('release-listener',default=None)
OWNED = ContextVar('release-owned-scope',default=None)


class Context:
    def __init__(self,policy):
        self.policy=policy

    def listener(self):
        value=LISTENER.get()
        if type(value) is not dict:
            self.policy.refuse('finite listener has no metadata')
        return {**value,**({'scope':OWNED.get()} if self.policy.case in CONTROLLED else {})}

    def install(self):
        import asyncio
        from cleanup_launch import EXECUTION_CASES
        cases=self.policy.profile['cases']
        from multiprocess_entry import ALL_CASES as MP_CASES
        if any(case in MP_CASES for case in cases):
            from multiprocess_hooks import install
            install(self.policy)
        from http_cases import CASES as HTTP_CASES
        if any(case in HTTP_CASES for case in cases):
            from tests import test_server
            free = test_server._free_loopback_port
            def port():
                token=LISTENER.set({'tag':'mcp-probe','nonce':None})
                try:
                    return free()
                finally:
                    LISTENER.reset(token)
            test_server._free_loopback_port=port
        if any(case in (*BOOTSTRAP,*CONTROLLED) for case in cases):
            import unrest_harness.experimental_session as session
            from unrest_harness.experimental_relay import Bridge
            start,opened=session._SessionOwner.start,session._SessionOwner._open_role_owned
            async def broker(owner,*args,**kwargs):
                fields=instance_fields(owner)
                owned=OWNED.set(str(fields['root']))
                listener=LISTENER.set({'tag':'broker','nonce':None})
                try:
                    return await start(owner,*args,**kwargs)
                finally:
                    LISTENER.reset(listener)
                    OWNED.reset(owned)
            async def role(owner,name,*args,**kwargs):
                token=OWNED.set(str(instance_fields(owner)['root']/name))
                try:
                    return await opened(owner,name,*args,**kwargs)
                finally:
                    OWNED.reset(token)
            original_server=asyncio.start_server
            async def server(callback,*args,**kwargs):
                instance=callback.__self__ if type(callback) is types.MethodType else None
                tag='bridge' if type(instance) is Bridge else 'lifetime' if type(instance) is session._FixtureLifetime else None
                if tag is None:
                    return await original_server(callback,*args,**kwargs)
                token=LISTENER.set({'tag':tag,'nonce':instance_fields(instance)['nonce']})
                try:
                    return await original_server(callback,*args,**kwargs)
                finally:
                    LISTENER.reset(token)
            session._SessionOwner.start,session._SessionOwner._open_role_owned=broker,role
            asyncio.start_server=server
        if any(case in (*EXECUTION_CASES,*STARTUP) for case in cases):
            from unrest_harness.acp_runner import ACPNodeRunner
            original=ACPNodeRunner._find_free_port
            def probe(*args,**kwargs):
                token=LISTENER.set({'tag':'mcp-probe','nonce':None})
                try:
                    return original(*args,**kwargs)
                finally:
                    LISTENER.reset(token)
            ACPNodeRunner._find_free_port=staticmethod(probe)
