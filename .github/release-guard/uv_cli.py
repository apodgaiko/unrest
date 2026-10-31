"""Stock uv and one exact installed-console child for original refusal routes."""
from pathlib import Path
import json
import os

from content_manifest import Refused as Refused, read_regular, native_digest, _capture, refuse_if
from control_transport import unique
from console_entries import normalized,script
from launch_policy import admit_expected,build_expected,source_unit
from owned_fixture import retain

TEST='tests/test_v04_activation.py'
INVALID=TEST+'::test_subprocess_commands_reject_private_invalid_requests_without_effect'
TASK=TEST+'::test_task_click_and_subprocess_stop_without_provider_approval'
PROJECT=TEST+'::test_project_click_and_subprocess_stop_without_exact_request'
IMPROVEMENT=TEST+'::test_improvement_click_and_subprocess_stop_without_exact_request'
CASES=(INVALID,TASK,PROJECT,IMPROVEMENT)
COMMANDS={INVALID:('run-task','run-project','run-improvement'),TASK:('run-task',),PROJECT:('run-project',),IMPROVEMENT:('run-improvement',)}
PIN='91af3f3447d89b2c4415e19eb4f0da427224f0cb0c9d642266dc31ebbbd6f52e'


def uv_digest(path):
    return _capture(path.parent,[path.name],None,64*1024*1024)['files'][0]['sha256']


def child_environment(metadata,parent):
    depth=parent.get('UV_RUN_RECURSION_DEPTH','0')
    refuse_if(type(depth) is not str or depth not in ('0','1'), 'stock uv exact bounded recursion')
    runtime=Path(metadata['runtime_root'])
    return {**parent,'PATH':str(runtime/'bin')+':'+parent['PATH'],
        'UV':str(runtime/'bin/uv'),'UV_RUN_RECURSION_DEPTH':str(int(depth)+1)}


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    rows=[row for row in host.intents.values() if row['case']==case]
    launches=[row for row in rows if row['role']=='uv-cli']
    refuse_if(case not in CASES or len(launches)>=len(COMMANDS[case]) or raw['stdin'] is not None
            or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in rows), 'stock uv original sequential refusal frontier')
    source_unit(Path(host.meta['checkout']),TEST,PIN)
    command=COMMANDS[case][len(launches)]
    args=raw['argv']
    refuse_if(len(args)!=6 or args[:5]!=['uv','run','unrest',command,'--request'], 'stock uv exact original command')
    path=Path(args[5])
    parent=retain(host,path.parent, 20000)
    if case==INVALID:
        home=parent/(command+'-invalid-home')
        file=parent/(command+'-invalid.json')
        private='private-subprocess-invalid-token'
        document={'run-task':{'brief':private},'run-project':{'max_steps':1,'mission_id':'mission-001',
            'nodes':[{'body':private,'id':'node','needs':['missing']}],'project_id':'project:invalid'},
            'run-improvement':{'repository':str(parent/'invalid-improvement-repository'),'request':{'private':private}}}[command]
    elif case==TASK:
        home=parent/'task-subprocess-home'
        file=parent/'task-subprocess.json'
        document={'bounds':{'max_branches':1,'max_steps':1,'timeout_seconds':30},'brief':'private cli task brief',
            'idempotency_key':'private-cli-idempotency','pause_reason':'private-pause-secret'}
    else:
        file=parent/('project-subprocess.json' if case==PROJECT else 'improvement-subprocess.json')
        home=parent/('home-subprocess' if case==PROJECT else 'unused-improvement-home')
        document=None
    refuse_if(path!=file or path.resolve()!=path, 'stock uv exact original request path')
    body,_,_=read_regular(file,65536,uid=20000)
    refuse_if((document is not None and json.loads(body,object_pairs_hook=unique)!=document) or (case!=PROJECT and home.exists()), 'stock uv original request bytes and unused home')
    if case in (PROJECT,IMPROVEMENT):
        # Requests remain application inputs: the original product test owns their
        # semantic assertions. Admit only the exact owned path and bounded JSON.
        refuse_if(type(json.loads(body,object_pairs_hook=unique)) is not dict, 'stock uv bounded original request object')
        refuse_if(case==PROJECT and (not home.is_dir() or home.resolve()!=home), 'stock uv original project home')
    env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)',
        'UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
    refuse_if(raw['executable']!='uv', 'stock uv original command')
    runtime=Path(host.meta['runtime_root'])
    executable=runtime/'bin/uv'
    pin=uv_digest(executable)
    refuse_if({'path':str(executable),'sha256':pin}!=host.binding['uv'], 'stock uv current native bytes')
    file,file_pin=script(host,'unrest')
    value=build_expected(case,str(executable),pin,tuple(args),tuple(sorted(env.items())),host.meta['checkout'],'native')
    return admit_expected(host,actor,raw,value,'uv-cli',args,maximum=len(COMMANDS[case]),
        fields={'uv_console':{'argv':['unrest',*args[3:]],'pin':file_pin,'script':str(file)}})


def reserve_child(host,intent,birth):
    refuse_if(intent['case'] not in CASES or intent['role']!='uv-cli' or not intent['consumed'] or intent['birth']!=birth, 'stock uv actual admitted parent')
    refuse_if(any(row.get('parent')==birth for row in host.intents.values()), 'stock uv single console child')
    declaration=intent['uv_console']
    runtime=Path(host.meta['runtime_root'])
    executable=runtime/'bin/unrest'
    refuse_if(native_digest(executable)!=host.binding['entry']['sha256'], 'stock uv exact native console guard')
    file,pin=script(host,'unrest')
    refuse_if(str(file)!=declaration['script'] or pin!=declaration['pin'], 'stock uv retained console script')
    host.serial+=1
    host.intents[host.serial]={'ticket':host.serial,'case':intent['case'],'role':'fixed-inline','parent':birth,
        'environment':child_environment(host.meta,intent['environment']),'cwd':intent['cwd'],
        'translated':declaration['argv'],'python_vector':normalized(runtime,Path(host.meta['dependencies']),'unrest',declaration['argv'][1:]),
        'token':os.urandom(16).hex(),'consumed':False,'pid':None,'executable':str(executable),
        'executable_sha256':host.binding['entry']['sha256'],'script_sha256':pin,'inherited':[],'port':None}
