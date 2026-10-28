"""Spawn transport metadata; the observer owns all execution authority."""
import os
import types

from content_manifest import Refused
from multiprocess_entry import CASES


def install(policy):
    from multiprocessing import util
    from multiprocessing.process import BaseProcess
    original,start=util.spawnv_passfds,BaseProcess.start
    def start_with_label(process,*args,**kwargs):
        target=vars(process).get('_target')
        if type(target) is not types.FunctionType or type(target.__module__) is not str or type(target.__name__) is not str:
            policy.refuse('spawn target metadata primitive')
        previous=getattr(policy.local,'mp_target',None)
        policy.local.mp_target=[target.__module__,target.__name__]
        try:
            return start(process,*args,**kwargs)
        finally:
            policy.local.mp_target=previous
    def spawn(executable,arguments,passfds):
        if policy.profile['role']!='root' or policy.case not in CASES:
            policy.refuse('spawn outside finite root cases')
        if (type(executable) not in (str,bytes) or type(arguments) not in (list,tuple)
                or any(type(arg) not in (str,bytes) for arg in arguments)
                or type(passfds) not in (list,tuple) or any(type(fd) is not int for fd in passfds)):
            policy.refuse('spawn primitive transport')
        raw={'case':policy.case,'executable':os.fsdecode(executable),'argv':[os.fsdecode(arg) for arg in arguments],
             'passfds':list(passfds),'target':getattr(policy.local,'mp_target',None),
             'cwd':os.getcwd(),'environment':dict(os.environ)}
        try:
            answer=policy.client.request('multiprocess-proposal',raw)
            if (type(answer) is not dict or type(answer.get('ticket')) is not int or type(answer.get('token')) is not str
                    or type(answer.get('translated')) is not list or any(type(arg) is not str for arg in answer['translated'])):
                raise Refused('spawn response schema')
            pid=original(executable,answer['translated'],passfds)
            policy.children[pid]={'token':answer['token'],'case':policy.case,'process':None}
            policy.client.request('launch-return',{'pid':pid,'ticket':answer['ticket'],'token':answer['token']})
            return pid
        except Refused:
            policy.refuse('finite spawn refused')
    util.spawnv_passfds=spawn
    setattr(BaseProcess,'start',start_with_label)
