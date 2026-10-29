"""Owned composed fixtures and exact parent-bound original node sequences."""
import os
import re
from pathlib import Path

from composed_cases import CASES,STEPS,DIRECT,DIRECT_NODES,HTTP,ADOPT,UNDELIVERABLE,nodes,query_count,targets
from content_manifest import Refused,read_regular,_key
from measurement_runtime import record,running

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
    row.update(composed_nodes=sequence,composed_project=str(path),composed_worker=index,
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
    if 'composed_nodes' in row and row['role']=='fixed-inline':
        return row,row['composed_nodes'],Path(row['composed_project'])
    if host.case in DIRECT and row.get('server_slot')==0 and row['role']=='mcp':
        parent=root(host)
        projects=sorted((parent/'.unrest/projects').iterdir())
        if len(projects)!=1:
            raise Refused('composed sole direct project')
        return row,DIRECT_NODES[host.case],project_root(host,parent,projects[0].name)
    raise Refused('composed parent has no node authority')


def nested(host,actor,raw):
    _,sequence,project=owner(host,actor)
    records=[row for row in host.intents.values() if row['case']==host.case and row.get('parent')==actor['birth']]
    servers=[row for row in records if 'composed_node' in row and row['role']=='mcp']
    module=raw['argv'][1:3]==['-m','unrest_harness']
    if module:
        if len(servers)>=len(sequence) or any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records):
            raise Refused('composed node sequence before actual waits')
        node,role=sequence[len(servers)]
    else:
        if not servers or not host.executed(servers[-1]) or any(row.get('composed_node')==servers[-1]['composed_node'] and row['role']=='cleanup-acp' for row in records):
            raise Refused('composed original ACP server pair')
        node,role=servers[-1]['composed_node'],servers[-1]['composed_role']
    runtime=project/'.unrest-runtime/missions/mission-001'
    if role=='terminal_reviewer':
        snapshots=[record(path) for path in sorted((runtime/'supervision').glob('*.json')) if not path.name.endswith(('.policy.json','.inbox.json'))]
        active=[row for row in snapshots if row.get('role')=='terminal_reviewer' and row.get('phase')=='active' and row.get('supervision_status')=='running']
        if len(active)!=1 or active[0].get('project_id')!=project.name or active[0].get('terminal_review_id')!=active[0].get('attempt_id'):
            raise Refused('composed original terminal review attempt')
        attempt=active[0]['attempt_id']
        if (active[0].get('node_id') is not None or active[0].get('mission_id')!='mission-001'
                or type(attempt) is not str or not re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d-\d\d-\d\dZ(?:-\d{4}){0,2}',attempt)):
            raise Refused('composed terminal review identity')
    else:
        runtime,attempt=running(project,node)
    parent=root(host)
    from node_environment import environment
    ambient=actor['profile']['environment']
    env=environment(ambient,parent/'.unrest',project.name,node,role,attempt)
    file,pin=adapter(host,parent)
    from node_launch import proposal
    return proposal(host,actor,raw,parent/'workspace',env,role,targets(host.case,node),file,pin,
        (str(parent/'workspace/.hermetic-acp-trace.jsonl'),),HTTP[host.case]+len(nodes(host.case)),
        {'composed_node':node,'composed_role':role,'execution_fixture':bootstrap(host,parent)},'cleanup-acp')



def query_quota(host,actor):
    rows=[row for row in host.intents.values() if row['case']==host.case and row['role']=='mcp' and 'composed_node' in row
        and row.get('birth')==actor['birth'] and row['token']==actor['token'] and row['consumed']]
    if len(rows)!=1 or actor['role']!='mcp' or not actor['body_ready']:
        raise Refused('composed exact node-owned Git query')
    return query_count(host.case,rows[0]['composed_role'])
