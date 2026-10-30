"""Exact failed-PATH progression and native script/binary identity joins."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import time

from content_manifest import Refused, native_digest
from launch_policy import admit_expected
from plan_launch import CASES, INVALID, expected
from process_ledger import Birth
from linux_observation import process_identity


def key(file):
    info=file.lstat()
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]


def launch(host,actor,raw,result):
    host.root_only(actor)
    answer=admit_expected(host,actor,raw,result.expected,result.role,list(result.vector),result.expected.payload_sha256)
    if answer is not None:
        value=host.intents[answer['ticket']]
        value['plan']=result
        value['plan_stage']=0
        value['plan_pending']=None
        value['plan_pid']=None
        value['plan_script_key']=key(Path(result.expected.executable))
        value['plan_parent_key']=key(Path(result.expected.executable).parent)
    return answer


def resolve(host,trace,pid,path,vector,environment,cwd):
    host.consume(trace)
    birth=host.ledger.current.get(pid)
    parent=host.ledger.process(birth).parent if birth is not None else None
    choices=[value for value in host.intents.values() if value['case']==host.case and value['case'] in CASES and not value['consumed']
             and value.get('parent',host.root_birth)==parent and value['translated']==vector
             and value['environment']==environment and value['cwd']==cwd]
    if len(choices)!=1:
        return False
    value=choices[0]
    model=value['plan']
    if value['plan_pid'] not in (None,pid) or value['plan_pending'] is not None:
        raise Refused('preflight attempted-path replay or foreign child')
    stage=value['plan_stage']
    if stage>=len(model.attempts) or path!=model.attempts[stage]:
        return False
    current=expected(value['case'],cwd,Path(host.meta['owned']),host.binding['entry']['path'],host.binding['entry']['sha256'])
    if (current!=model or key(Path(model.expected.executable))!=value['plan_script_key']
            or key(Path(model.expected.executable).parent)!=value['plan_parent_key']):
        raise Refused('preflight script or native generation changed')
    if process_identity(pid)['namespaces']['mnt']!=os.readlink('/proc/self/ns/mnt'):
        raise Refused('preflight private native namespace')
    value['plan_pid']=pid
    value['plan_path']=path
    value['plan_pending']='blocked' if stage<len(model.attempts)-1 else 'invalid' if value['case']==INVALID else 'run'
    if value['plan_pending']=='blocked':
        value['plan_blocked_key']=key(Path(path))
        return True
    value['consumed'],value['pid'],value['birth']=True,pid,birth
    if value['role']=='plan-python':
        host.profile(pid,value['role'],value['case'],vector,environment,cwd,value['token'])
    else:
        actual=process_identity(pid)
        birth=Birth.read(actual)
        host.ledger.register(birth,value['token'],(('native-plan',model.image[1]),),
            case=value['case'],command_class='native-'+value['role'],expected_generation=0 if value['case']==INVALID else 1)
        host.actors[pid]={'birth':birth,'role':value['role'],'case':value['case'],'token':value['token'],
                         'body_ready':False,'signals':set(),'kernel_admitted':True,'intent':value}
    return True


def consume(host,row):
    if row['kind'] not in ('kernel_exec','exec_syscall_return'):
        return
    values=[value for value in host.intents.values() if value['case'] in CASES and value.get('plan_pid')==row['pid']]
    if not values:
        return
    if len(values)!=1:
        raise Refused('preflight exec child ambiguity')
    value=values[0]
    model=value['plan']
    pending=value['plan_pending']
    if row['kind']=='exec_syscall_return':
        if pending=='blocked':
            if row.get('return')!=-errno.EACCES or row.get('denied') or key(Path(model.attempts[0]))!=value['plan_blocked_key']:
                raise Refused('preflight exact blocked directory errno or generation')
            value['plan_stage']+=1
            value['plan_pending']=None
        elif pending=='invalid':
            if row.get('return')!=-errno.ENOEXEC or row.get('denied'):
                raise Refused('preflight original invalid-format errno')
            value['plan_failed']=True
            value['plan_pending']=None
        elif pending=='run':
            if row.get('return')!=0 or row.get('denied'):
                raise Refused('preflight expected successful exec return')
        return
    if pending!='run':
        raise Refused('preflight unexpected successful candidate')
    executable=Path('/proc')/str(row['pid'])/'exe'
    actual=executable.resolve(strict=True)
    target=Path(model.image[0])
    if (actual!=target or executable.stat().st_dev!=target.stat().st_dev or executable.stat().st_ino!=target.stat().st_ino
            or native_digest(target)!=model.image[1] or key(Path(model.expected.executable))!=value['plan_script_key']
            or key(Path(model.expected.executable).parent)!=value['plan_parent_key']):
        raise Refused('preflight post-binfmt executable or script generation')
    raw=(Path('/proc')/str(row['pid'])/'cmdline').read_bytes()
    if not raw or len(raw)>65536 or not raw.endswith(b'\0'):
        raise Refused('preflight post-binfmt argument vector')
    vector=[os.fsdecode(part) for part in raw[:-1].split(b'\0')]
    expected_vector=(['/bin/sh',value['plan_path'],*model.vector[1:]]
                     if model.image[0]=='/usr/bin/dash' else list(model.vector))
    if vector!=expected_vector:
        raise Refused('preflight post-binfmt script arguments')
    value['plan_exec_verified']=True
    host.plan_records.append({'case':value['case'],'pid':row['pid'],'image':str(actual),'image_sha256':model.image[1],
        'script_key':value['plan_script_key'],'argv_sha256':hashlib.sha256(json.dumps(vector,separators=(',',':')).encode()).hexdigest(),'observed_monotonic_ns':time.monotonic_ns(),
        'python_alias_resolution_verified':False if value['role']=='plan-python' else None})
