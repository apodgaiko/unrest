"""Spawn transport metadata; the observer owns all execution authority."""
import os

from content_manifest import Refused
from multiprocess_entry import eligible


def install(policy):
    if not any(eligible(case) for case in policy.profile['cases']):
        return
    from multiprocessing import util
    original=util.spawnv_passfds
    def spawn(executable,arguments,passfds):
        if policy.profile['role']!='root' or not eligible(policy.case):
            policy.refuse('spawn outside finite root cases')
        if (type(executable) not in (str,bytes) or type(arguments) not in (list,tuple)
                or any(type(arg) not in (str,bytes) for arg in arguments)
                or type(passfds) not in (list,tuple) or any(type(fd) is not int for fd in passfds)):
            policy.refuse('spawn primitive transport')
        raw={'case':policy.case,'executable':os.fsdecode(executable),'argv':[os.fsdecode(arg) for arg in arguments],
             'passfds':list(passfds),
             'cwd':os.getcwd(),'environment':dict(os.environ)}
        try:
            answer=policy.client.request('multiprocess-proposal',raw)
            if (type(answer) is not dict or type(answer.get('ticket')) is not int or type(answer.get('token')) is not str
                    or type(answer.get('translated')) is not list or any(type(arg) is not str for arg in answer['translated'])):
                raise Refused('spawn response schema')
            pid=original(executable,answer['translated'],passfds)
            policy.children[pid]={'token':answer['token'],'case':policy.case,'process':None}
            return pid
        except Refused:
            policy.refuse('finite spawn refused')
    util.spawnv_passfds=spawn
