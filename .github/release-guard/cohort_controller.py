"""Exact intentional controller crashes and separately labelled adoptive waits."""
import json
import os
from pathlib import Path
import re
import time

from cohort_cases import TEST
from content_manifest import Refused, read_regular
from control_transport import unique
from launch_policy import source_unit, literal, build_expected, admit_expected
from linux_observation import credential_identity
from owned_fixture import retain
from process_ledger import Birth, canonical

NAME='test_actual_controller_crash_has_no_resume_authority'
CASES=tuple(TEST+'::'+NAME+'['+value+']' for value in ('reservation','prompt_sent','backend_received','provider_completed'))
WAIVED=CASES[1:]
PIN='3a5011af0c03a10da383cdfa1b105b59a8c87b6626606309c8052d519eb34d99'


def publish(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    with temporary.open('x') as stream:
        json.dump(value,stream,sort_keys=True)
    temporary.chmod(0o444)
    if path.exists():
        raise Refused('cohort duplicate closeout publication')
    temporary.rename(path)


def owner(host,actor):
    rows=[row for row in host.intents.values() if row.get('cohort_controller') and row['case']==host.case
          and row.get('birth')==actor['birth'] and row['token']==actor['token']]
    if host.case not in CASES or actor['case']!=host.case or actor['role']!='fixed-inline' or not actor['body_ready'] or len(rows)!=1 or not host.executed(rows[0]):
        raise Refused('cohort original controller owner')
    return rows[0]


def parent(host,actor):
    return host.root_only(actor) if host.case not in CASES else owner(host,actor)


def proposal(host,actor,raw):
    host.root_only(actor)
    checkout=Path(host.meta['checkout'])
    unit=source_unit(checkout,TEST,PIN,(NAME,))
    root=retain(host,Path(raw['argv'][-1].split('ROOT=Path(',1)[1].split(')\n',1)[0].strip("'\"")).parent,NAME[:30],20000)
    adapter=Path('/native/bin/codex-acp').resolve() if '/native' in host.meta['mounts'] else Path('/missing')
    boundary=host.case.rsplit('[',1)[1][:-1]
    body=('BOUNDARY='+repr(boundary)+'\nfrom pathlib import Path\nROOT=Path('+repr(str(root/'crashed'))+')\n'
        +'ADAPTER=Path('+repr(str(adapter))+')\nFIXTURE=Path('+repr(str(checkout/'tests/fixtures/experimental_session_app_server.py'))+')\n'+literal(unit,'source'))
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':host.case+' (call)'}
    expected=build_expected('cohort:controller',host.case,native,pin,(native,'-c',body),tuple(sorted(env.items())),str(checkout),'python-command')
    if raw['executable']!=native or raw['stdin'] is not None:
        raise Refused('cohort exact controller image or input')
    return admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S','-c',body],fields={'cohort_controller':True})


def closeout(host,children):
    controllers=[actor for actor in children if actor['role']=='fixed-inline']
    git=[actor for actor in children if actor['role']=='git-custody']
    pair=[actor for actor in children if actor['role'] in ('backend','acp')]
    if len(controllers)!=1 or len(git)!=4 or len(children)!=5+len(pair):
        raise Refused('cohort exact crash population')
    controller=controllers[0]
    row=owner(host,controller)
    process=host.ledger.process(controller['birth'])
    if (process.terminal is None or process.terminal[2]!=73 or not host.ledger.reaped(controller['birth'],controller['token'])
            or any(host.ledger.process(actor['birth']).parent!=controller['birth'] or not host.git.reaped(actor) or not host.completed_child(actor) for actor in git)):
        raise Refused('cohort controller actual wait73 and Git cleanup')
    if host.case==CASES[0]:
        if pair:
            raise Refused('cohort reservation crash cannot own transport')
        return set()
    if (host.case not in WAIVED or {actor['role'] for actor in pair}!={'backend','acp'} or len(pair)!=2
            or any(host.ledger.process(actor['birth']).parent!=controller['birth'] or not actor['body_ready'] for actor in pair)):
        raise Refused('cohort exact approved crash pair')
    request=host.directory/('cohort-closeout-'+controller['token']+'.json')
    if type(row.get('closeout_started')) is not float:
        raise Refused('cohort controller observed wait deadline absent')
    if not request.exists():
        value={'case':host.case,'started':row['closeout_started'],
            'children':[{'identity':canonical(host.ledger.process(actor['birth']).identity),'token':actor['token']} for actor in pair]}
        publish(request,value)
    if time.monotonic()-row['closeout_started']>20:
        raise Refused('cohort approved provenance closeout deadline')
    receipt=request.with_suffix('.receipt')
    if not receipt.exists():
        return None
    body,_,_=read_regular(receipt,4096,uid=0,mode=0o444)
    value=json.loads(body,object_pairs_hook=unique)
    if value.get('case')!=host.case or len(value.get('waits',[]))!=2:
        raise Refused('cohort adoptive receipt scope')
    for actor,wait in zip(pair,value['waits'],strict=True):
        process=host.ledger.process(actor['birth'])
        if (wait.get('identity')!=canonical(process.identity) or wait.get('token')!=actor['token']
                or type(wait.get('raw')) is not int or process.terminal is None or process.terminal[1]!=wait['raw']):
            raise Refused('cohort adoptive actual terminal join')
    host.cohort_observations.append({**value,'original_parent_wait_proven':False,'child_numeric_status_and_final_timing':'UNVERIFIED'})
    return {actor['birth'] for actor in pair}


def host_tick(directory,pending):
    for request in sorted(Path(directory).glob('cohort-closeout-*.json')):
        if not re.fullmatch('cohort-closeout-[a-f0-9]{32}\\.json',request.name):
            raise Refused('cohort closeout request name')
        receipt=request.with_suffix('.receipt')
        if receipt.exists():
            continue
        body,_,_=read_regular(request,4096,uid=20001,mode=0o444)
        value=json.loads(body,object_pairs_hook=unique)
        if (value.get('case') not in WAIVED or type(value.get('started')) is not float
                or not 0<=time.monotonic()-value['started']<=20 or len(value.get('children',[]))!=2):
            raise Refused('cohort closeout request scope or deadline')
        waits=pending.setdefault(request.name,[])
        for child in value['children'][len(waits):]:
            birth=Birth.read(child['identity'])
            actual=Birth.read(credential_identity(birth.pid))
            if (actual.parent!=os.getpid() or (actual.pid,actual.tgid,actual.ticks,actual.boot,actual.uid)!=(birth.pid,birth.tgid,birth.ticks,birth.boot,20000)):
                raise Refused('cohort exact adopted process identity')
            pid,raw=os.waitpid(birth.pid,os.WNOHANG)
            if not pid:
                break
            waits.append({**child,'raw':raw})
        if len(waits)==2:
            publish(receipt,{'case':value['case'],'waits':waits})
