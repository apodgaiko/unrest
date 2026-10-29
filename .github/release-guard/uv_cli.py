"""Stock uv and one exact installed-console child for original refusal routes."""
from pathlib import Path
import json
import os

from content_manifest import Refused,read_regular,native_digest,_capture
from control_transport import unique
from console_entries import normalized,script
from launch_policy import build_expected,source_unit
from owned_fixture import acquire

TEST='tests/test_v04_activation.py'
INVALID=TEST+'::test_subprocess_commands_reject_private_invalid_requests_without_effect'
TASK=TEST+'::test_task_click_and_subprocess_stop_without_provider_approval'
CASES=(INVALID,TASK)
COMMANDS={INVALID:('run-task','run-project','run-improvement'),TASK:('run-task',)}
PIN='4741feb6a71d9c06be777a08a34e064be0610c1f8b755ebfffef21489621c435'


def uv_digest(path):
    return _capture(path.parent,[path.name],None,64*1024*1024)['files'][0]['sha256']


def child_environment(metadata,parent):
    depth=parent.get('UV_RUN_RECURSION_DEPTH','0')
    if type(depth) is not str or depth not in ('0','1'):
        raise Refused('stock uv exact bounded recursion')
    runtime=Path(metadata['runtime_root'])
    return {**parent,'PATH':str(runtime/'bin')+':'+parent['PATH'],
        'UV':str(runtime/'bin/uv'),'UV_RUN_RECURSION_DEPTH':str(int(depth)+1)}


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    rows=[row for row in host.intents.values() if row['case']==case]
    launches=[row for row in rows if row['role']=='uv-cli']
    if (case not in CASES or len(launches)>=len(COMMANDS[case]) or raw['stdin'] is not None
            or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in rows)):
        raise Refused('stock uv original sequential refusal frontier')
    source_unit(Path(host.meta['checkout']),TEST,PIN)
    command=COMMANDS[case][len(launches)]
    args=raw['argv']
    if len(args)!=6 or args[:5]!=['uv','run','unrest',command,'--request']:
        raise Refused('stock uv exact original command')
    path=Path(args[5])
    parent,info=acquire(str(path.parent),Path(host.meta['owned']),case.split('::')[-1][:30],20000)
    if host.fixture_roots.setdefault(case,(str(parent),info.st_dev,info.st_ino))!=(str(parent),info.st_dev,info.st_ino):
        raise Refused('stock uv changed original fixture')
    if case==INVALID:
        home=parent/(command+'-invalid-home')
        file=parent/(command+'-invalid.json')
        private='private-subprocess-invalid-token'
        document={'run-task':{'brief':private},'run-project':{'max_steps':1,'mission_id':'mission-001',
            'nodes':[{'body':private,'id':'node','needs':['missing']}],'project_id':'project:invalid'},
            'run-improvement':{'repository':str(parent/'invalid-improvement-repository'),'request':{'private':private}}}[command]
    else:
        home=parent/'task-subprocess-home'
        file=parent/'task-subprocess.json'
        document={'bounds':{'max_branches':1,'max_steps':1,'timeout_seconds':30},'brief':'private cli task brief',
            'idempotency_key':'private-cli-idempotency','pause_reason':'private-pause-secret'}
    body,_,_=read_regular(file,65536,uid=20000)
    if path!=file or path.resolve()!=path or json.loads(body,object_pairs_hook=unique)!=document or home.exists():
        raise Refused('stock uv original request bytes and unused home')
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)',
        'UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
    if raw['executable']!='uv' or raw['cwd']!=host.meta['checkout'] or raw['environment']!=env:
        raise Refused('stock uv original environment and cwd')
    runtime=Path(host.meta['runtime_root'])
    executable=runtime/'bin/uv'
    pin=uv_digest(executable)
    if {'path':str(executable),'sha256':pin}!=host.binding['uv']:
        raise Refused('stock uv current native bytes')
    file,file_pin=script(host,'unrest')
    value=build_expected('console:uv',case,str(executable),pin,tuple(args),tuple(sorted(env.items())),raw['cwd'],'native')
    answer=host.admit_launch(actor,value,'uv-cli',args,None,maximum=len(COMMANDS[case]))
    if answer is not None:
        host.intents[answer['ticket']].update(uv_console={'argv':['unrest',*args[3:]],'pin':file_pin,'script':str(file)})
    return None if answer is None else {**answer,'translated':args,'rule':value.rule}


def reserve_child(host,intent,birth):
    if intent['case'] not in CASES or intent['role']!='uv-cli' or not intent['consumed'] or intent['birth']!=birth:
        raise Refused('stock uv actual admitted parent')
    if any(row.get('parent')==birth for row in host.intents.values()):
        raise Refused('stock uv single console child')
    declaration=intent['uv_console']
    runtime=Path(host.meta['runtime_root'])
    executable=runtime/'bin/unrest'
    if native_digest(executable)!=host.binding['entry']['sha256']:
        raise Refused('stock uv exact native console guard')
    file,pin=script(host,'unrest')
    if str(file)!=declaration['script'] or pin!=declaration['pin']:
        raise Refused('stock uv retained console script')
    host.serial+=1
    host.intents[host.serial]={'case':intent['case'],'role':'fixed-inline','parent':birth,
        'environment':child_environment(host.meta,intent['environment']),'cwd':intent['cwd'],
        'translated':declaration['argv'],'python_vector':normalized(runtime,Path(host.meta['dependencies']),'unrest',declaration['argv'][1:]),
        'token':os.urandom(16).hex(),'consumed':False,'pid':None,'executable':str(executable),
        'executable_sha256':host.binding['entry']['sha256'],'script_sha256':pin,'inherited':[],'port':None}
