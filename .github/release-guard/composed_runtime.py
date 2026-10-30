"""Owned composed fixtures and exact parent-bound original node sequences."""
import os
from pathlib import Path

from composed_cases import CASES,STEPS,DIRECT,DIRECT_ROLES,HTTP,ADOPT,UNDELIVERABLE,roles,query_count
from content_manifest import Refused,read_regular,_key
from measurement_runtime import record

ADAPTER_PIN='245f9fc0eabd9d4ea5c8f701e77380cbadcc137f476d4cf87933d8c9202f06cb'
DIRECT_PINS=dict(zip(DIRECT,('4db1a5ec24bb138fef3cc6d663efa65986f52b37e51e069048e89bc544e40375',
    '0a16fea38bc51c2b0befc3affc9a8a5bb07456e4561185cdb6b6dd92c7d659bf'),strict=True))
SHIM_PIN='50c2fac90e35c49d1ee817c4c86367292cb2efaed44e922800ae80aab46a908a'


def root(host):
    value=host.fixture_roots.get(('completion-role',host.case))
    if host.case not in CASES or value is None:
        raise Refused('composed fixture before acquired Git root')
    return Path(value[0])


def adapter(host,parent):
    if host.case not in CASES:
        raise Refused('composed declared adapter case')
    expected=DIRECT_PINS.get(host.case,ADAPTER_PIN)
    file=parent/'workspace/.hermetic-acp-adapter.py'
    _,info,pin=read_regular(file,32768,uid=20000,mode=0o700)
    if pin!=expected or host.fixture_roots.setdefault(('composed-script',host.case),(str(file),_key(info),pin))!=(str(file),_key(info),pin):
        raise Refused('composed original adapter bytes or generation')
    return file,pin



def bootstrap(host,parent):
    if host.case!=UNDELIVERABLE:
        return None
    checkout=Path(host.meta['checkout'])
    file=parent/'workspace/sitecustomize.py'
    _,info,pin=read_regular(file,4096,uid=20000,mode=0o644)
    if pin!=SHIM_PIN:
        raise Refused('composed exact delivery-blocked bootstrap bytes')
    from content_manifest import native_digest
    return {'kind':'undeliverable','path':str(file),'sha256':pin,'identity':list(_key(info)),
        'module_sha256':native_digest(checkout/'src/unrest_harness/api.py')}


def worker(host,actor,raw):
    from completion_roles import actor_slot
    from run_worker_launch import admit_worker
    server=actor_slot(host,actor)
    parent=root(host)
    workers=[row for row in host.intents.values() if row['case']==host.case and row.get('run_worker')]
    index=len(workers)
    if index>=len(STEPS[host.case]) or any(not host.executed(row) for row in workers):
        raise Refused('composed original worker sequence')
    slot,operation,project_slot,sequence=STEPS[host.case][index]
    if server['server_slot']!=slot or raw['cwd']!=str(parent/'.unrest'):
        raise Refused('composed original worker parent or home')
    keys=('UNREST_HOME','UNREST_PROJECTS_DIR',*(f'UNREST_{name}_{field}' for name in ('WORKER','VALIDATOR','TERMINAL_REVIEWER') for field in ('PROVIDER','ACP_COMMAND')))
    env={key:actor['profile']['environment'][key] for key in keys}
    env.update(LANG='C.UTF-8',PATH=os.defpath,PYTHONPATH=str(Path(host.meta['checkout'])/'src'),UNREST_APPROVAL_RECOVERY='0')
    answer=admit_worker(host,actor,raw,parent/'.unrest',operation,env,len(STEPS[host.case]))
    if answer is None:
        return None
    row=host.intents[answer['ticket']]
    project=row['run_project']
    path=project_root(host,parent,project)
    key=('composed-project',host.case,project_slot)
    if host.fixture_roots.setdefault(key,project)!=project or any(value==project for current,value in host.fixture_roots.items()
            if type(current) is tuple and len(current)==3 and current[:2]==key[:2] and current!=key):
        raise Refused('composed distinct retained project slots')
    row.update(composed_roles=sequence,composed_project=str(path),composed_worker=index,
        adoptable=index==ADOPT.get(host.case,-1))
    return answer


def project_root(host,parent,identity):
    if type(identity) is not str or not identity or Path(identity).name!=identity or identity in ('.','..'):
        raise Refused('composed original project identifier')
    path=parent/'.unrest/projects'/identity
    document=record(path/'.unrest-runtime/project.json')
    if document.get('id')!=identity or document.get('workspace_dir')!=str(parent/'workspace'):
        raise Refused('composed acquired project and workspace')
    return path


def owner(host,actor):
    rows=[row for row in host.intents.values() if row['case']==host.case and row.get('birth')==actor['birth']
        and row['token']==actor['token'] and row['consumed']]
    if len(rows)!=1 or not actor['body_ready'] or not host.executed(rows[0]):
        raise Refused('composed actual parent identity')
    row=rows[0]
    if 'composed_roles' in row and row['role']=='fixed-inline':
        return row,row['composed_roles'],Path(row['composed_project'])
    if host.case in DIRECT and row.get('server_slot')==0 and row['role']=='mcp':
        parent=root(host)
        projects=sorted((parent/'.unrest/projects').iterdir())
        if len(projects)!=1:
            raise Refused('composed sole direct project')
        return row,DIRECT_ROLES[host.case],project_root(host,parent,projects[0].name)
    raise Refused('composed parent has no node authority')


def nested(host,actor,raw):
    from collections import Counter
    _,sequence,project=owner(host,actor)
    parent=root(host)
    file,pin=adapter(host,parent)
    from node_launch import proposal
    return proposal(host,actor,raw,parent/'workspace',actor['profile']['environment'],
        parent/'.unrest',project.name,Counter(sequence),file,pin,
        (str(parent/'workspace/.hermetic-acp-trace.jsonl'),),HTTP[host.case]+len(roles(host.case)),
        {'composed_project':str(project),'execution_fixture':bootstrap(host,parent)},'cleanup-acp')



def query_quota(host,actor):
    rows=[row for row in host.intents.values() if row['case']==host.case and row['role']=='mcp' and 'node_role' in row
        and row.get('birth')==actor['birth'] and row['token']==actor['token'] and row['consumed']]
    if len(rows)!=1 or actor['role']!='mcp' or not actor['body_ready']:
        raise Refused('composed exact node-owned Git query')
    return query_count(host.case,rows[0]['node_role'])
