"""Separate namespace adoption and init waits; original parent facts stay intact."""
import json
import hashlib
import os
from pathlib import Path
import re
import time

from composed_cases import ADOPT
from content_manifest import Refused,read_regular
from control_transport import unique
from cohort_controller import publish
from linux_observation import process_identity,credential_identity
from process_ledger import Birth,canonical
from approval_launch import CRASH as APPROVAL_CRASH

CLOSEOUT=(*ADOPT,*APPROVAL_CRASH)


def refresh(host):
    if host.case in APPROVAL_CRASH:
        from approval_adoption import refresh as approval_refresh
        return approval_refresh(host)
    if host.case not in ADOPT:
        return
    for actor in host.actors.values():
        row=actor.get('intent')
        if row is None or row['case']!=host.case or not row.get('adoptable') or not host.executed(row):
            continue
        process=host.ledger.process(actor['birth'])
        if process.adopted_identity is not None:
            if process.terminal is not None:
                wait_request(host,actor,process)
            continue
        if process.exit is not None or process.terminal is not None:
            continue
        if process.parent is None or host.ledger.process(process.parent).exit is None:
            continue
        if host.case not in ADOPT or row['composed_worker']!=ADOPT[host.case] or not actor['body_ready']:
            raise Refused('composed adoption exact authored worker')
        try:
            observed=process_identity(actor['birth'].pid)
        except (FileNotFoundError,ProcessLookupError):
            # The tracer may already hold its exit row in the unconsumed batch.
            # No adoption authority follows from disappearance.
            continue
        if canonical(observed)==process.registered_identity:
            continue
        if observed['namespaces']['pid']!=host.meta['pid_namespace']:
            raise Refused('composed adoption namespace')
        host.ledger.adopt(actor['birth'],observed)


def wait_request(host,actor,process):
    path=host.directory/('composed-closeout-'+actor['token']+'.json')
    if not path.exists():
        publish(path,{'case':host.case,'started':time.monotonic(),'identity':process.adopted_identity,'token':actor['token']})
    return path


def closeout(host,children):
    if host.case not in CLOSEOUT:
        return True
    adopted=[actor for actor in children if host.ledger.process(actor['birth']).adopted_identity is not None]
    if not adopted:
        return host.case not in APPROVAL_CRASH
    if len(adopted)!=(2 if host.case in APPROVAL_CRASH else 1):
        raise Refused('composed adoption closeout population')
    if host.case in APPROVAL_CRASH:
        from approval_adoption import certified_owner
        if adopted!=certified_owner(host):
            raise Refused('approval follower closeout exact population')
    return all(receipt(host,actor) for actor in adopted)


def receipt(host,actor):
    process=host.ledger.process(actor['birth'])
    if process.terminal is None:
        return False
    path=wait_request(host,actor,process)
    body,_,_=read_regular(path,4096,uid=20001,mode=0o444)
    request=json.loads(body,object_pairs_hook=unique)
    receipt=path.with_suffix('.receipt')
    if not receipt.exists():
        if not 0<=time.monotonic()-request['started']<=20:
            raise Refused('composed init closeout deadline')
        return False
    body,_,_=read_regular(receipt,4096,uid=0,mode=0o444)
    value=json.loads(body,object_pairs_hook=unique)
    if (value!={**request,'raw':value.get('raw'),'init_pid':1,'namespace':host.meta['pid_namespace'],'waited':value.get('waited')}
            or type(value['waited']) is not float or not 0<=value['waited']-request['started']<=20
            or value['waited']>time.monotonic()):
        raise Refused('composed init receipt scope')
    if process.init_wait is None:
        host.ledger.retire_adopted(actor['birth'],value['raw'])
        host.adoptions.append({**value,'birth':canonical(process.identity),
            'session_identity':process.registered_identity,
            'original_parent_wait_proven':False,'namespace_init_wait_proven':True})
    return True


def host_tick(directory):
    if os.getpid()!=1:
        raise Refused('composed actual namespace init')
    for path in sorted(Path(directory).glob('composed-closeout-*.json')):
        if not re.fullmatch(r'composed-closeout-[a-f0-9]{32}\.json',path.name):
            raise Refused('composed init request name')
        receipt=path.with_suffix('.receipt')
        if receipt.exists():
            continue
        body,_,_=read_regular(path,4096,uid=20001,mode=0o444)
        value=json.loads(body,object_pairs_hook=unique)
        if (set(value)!={'case','started','identity','token'} or value['case'] not in CLOSEOUT
                or type(value['started']) is not float or not 0<=time.monotonic()-value['started']<=20
                or path.name!='composed-closeout-'+value['token']+'.json'):
            raise Refused('composed init exact request')
        birth=Birth.read(value['identity'])
        if birth.parent!=1 or birth.uid!=20000 or canonical(credential_identity(birth.pid))!=value['identity']:
            raise Refused('composed init actual child identity')
        pid,raw=os.waitpid(birth.pid,os.WNOHANG)
        if pid:
            if pid!=birth.pid:
                raise Refused('composed init waited wrong child')
            publish(receipt,{**value,'raw':raw,'init_pid':os.getpid(),'namespace':os.readlink('/proc/self/ns/pid'),'waited':time.monotonic()})


def signal(host,actor,payload):
    from completion_roles import actor_slot
    from composed_runtime import root,record
    server=actor_slot(host,actor)
    rows=[row for row in host.intents.values() if row['case']==host.case and row.get('adoptable')
        and row.get('pid')==payload['pid'] and host.executed(row)]
    if host.case not in ADOPT or server['server_slot']<1 or len(rows)!=1:
        raise Refused('composed resumed signal owner')
    row=rows[0]
    child=host.actors[payload['pid']]
    process=host.ledger.process(child['birth'])
    if process.adopted_identity is None or not row['run_control'] or not row['run_project']:
        raise Refused('composed resumed signal admission')
    if not (payload['signal']==0 and payload['group'] is False or
            payload['signal']==15 and payload['group'] is True and 15 not in child['signals']):
        raise Refused('composed resumed finite signal')
    if process.exit is not None or process.terminal is not None:
        return {'ok':True,'live':False}
    home=root(host)/'.unrest'
    cursor=record(home/'.unrest-runtime/runs'/(hashlib.sha256(row['run_id'].encode()).hexdigest()+'.worker.json'))
    expected={'run_id':row['run_id'],'generation':1,'control_identity_digest':row['run_control'],
        'pid':child['birth'].pid,'pgid':child['birth'].pid}
    if any(cursor.get(key)!=value for key,value in expected.items()):
        raise Refused('composed resumed signal cursor corroboration')
    observed=process_identity(child['birth'].pid)
    if canonical(observed)!=process.adopted_identity or observed['namespaces']['pid']!=host.meta['pid_namespace']:
        raise Refused('composed resumed process changed')
    if payload['signal']==15:
        record_group(host,child,15)
    return {'ok':True,'live':True}


def record_group(host,leader,signum):
    members=[]
    for member in host.actors.values():
        if member['case']!=host.case:
            continue
        current=host.ledger.process(member['birth'])
        ancestor=current
        while ancestor.parent is not None and ancestor.birth!=leader['birth']:
            ancestor=host.ledger.process(ancestor.parent)
        if ancestor.birth!=leader['birth'] or current.exit is not None or current.terminal is not None:
            continue
        actual=process_identity(member['birth'].pid)
        if (Birth.read(actual)!=host.ledger.peer_birth(member['birth'])
                or actual['namespaces']['pid']!=host.meta['pid_namespace']):
            raise Refused('source signal group birth changed')
        if (actual['pgid'],actual['sid'])==(leader['birth'].pid,leader['birth'].pid):
            members.append(member)
    for member in members:
        member['signals'].add(signum)
