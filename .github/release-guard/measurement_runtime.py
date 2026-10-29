"""Six original local ACP nodes beneath the exact measurement RunControl workers."""
import json
import os
import re
from pathlib import Path

from content_manifest import Refused,read_regular
from control_transport import unique
from launch_policy import source_unit,build_expected,admit_expected
from run_worker_launch import MEASUREMENT_PROJECT as PROJECT

PROJECT_STEPS=((1,'start_project',()),(1,'submit_plan',()),(1,'advance_project',('p1-work','p1-validate')),
    (6,'start_project',()),(6,'submit_plan',()),(6,'advance_project',('p2-initial-work','p2-initial-validate')),
    (6,'decide_attention',()),(6,'advance_project',('p2-corrected-work','p2-corrected-validate')))
MOCK='tests/mock_measurement_acp.py'
SERVER='src/unrest_harness/__main__.py'
PINS={'tests/mock_measurement_acp.py': '47d099bd120a96d86d1e052567744be63b3c103a11a043ad40976776d1f400dd', 'src/unrest_harness/__main__.py': 'b1fd5ade6e15ae7d24d6e14a68cef15cd5b626c2650716172719de100ca43e48'}


def owner(host,actor):
    rows=[row for row in host.intents.values() if row['case']==PROJECT and row['role']=='fixed-inline'
        and row.get('measurement_nodes') and row.get('birth')==actor['birth'] and row['token']==actor['token']]
    if (host.case!=PROJECT or actor['role']!='fixed-inline' or not actor['body_ready']
            or len(rows)!=1 or not host.executed(rows[0])):
        raise Refused('measurement nested original worker identity')
    return rows[0]


def record(path):
    body,_,_=read_regular(path,65536,uid=20000,forbidden=0o6022)
    return json.loads(body,object_pairs_hook=unique)


def nested(host,actor,raw):
    parent=owner(host,actor)
    checkout=Path(host.meta['checkout'])
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    home=Path(parent['cwd'])
    entries=sorted((home/'projects').iterdir())
    if len(entries)!=1 or not entries[0].is_dir() or entries[0].resolve()!=entries[0]:
        raise Refused('measurement one original project')
    project=entries[0]
    document=record(project/'.unrest-runtime/project.json')
    if document.get('id')!=project.name or document.get('workspace_dir')!=str(home.parent/'workspace'):
        raise Refused('measurement original project record')
    records=[row for row in host.intents.values() if row['case']==PROJECT and row.get('parent')==actor['birth']]
    servers=[row for row in records if row['role']=='mcp']
    module=raw['argv'][1:3]==['-m','unrest_harness']
    if module:
        if len(servers)>=len(parent['measurement_nodes']):
            raise Refused('measurement finite original node quota')
        if any(not row['consumed'] or not host.ledger.reaped(row['birth'],row['token']) for row in records):
            raise Refused('measurement next node before actual waits')
        node=parent['measurement_nodes'][len(servers)]
    else:
        if not servers or not host.executed(servers[-1]) or any(row.get('measurement_node')==servers[-1]['measurement_node'] and row['role']=='mock-acp' for row in records):
            raise Refused('measurement ACP original server pair')
        node=servers[-1]['measurement_node']
    role='validate' if node.endswith('validate') else 'work'
    runtime=project/'.unrest-runtime/missions/mission-001'
    state=record(runtime/'task-state.json')['tasks'].get(node,{})
    attempt=state.get('last_attempt')
    if state.get('status')!='running' or type(attempt) is not str or not re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d-\d\d-\d\dZ(?:-\d{4}){0,2}',attempt):
        raise Refused('measurement actual running node attempt')
    environment={'LANG':'C.UTF-8','PATH':os.defpath,'UNREST_CAPABILITY_PROFILE':'safe','UNREST_CAPABILITY_POLICY_VERSION':'1',
        'UNREST_HOME':str(home),'UNREST_PROJECT_ID':project.name,'UNREST_MISSION_ID':'mission-001',
        'UNREST_NODE_ID':node,'UNREST_NODE_TYPE':role,'UNREST_HANDOFF_PATH':str(runtime/'attempts'/(attempt+'__'+node+'.json'))}
    inherited=[]
    port=None
    if module:
        argv=raw['argv']
        if len(argv)!=13 or not argv[-3].isdigit() or not 0<int(argv[-3])<=65535 or not argv[-1].isdigit():
            raise Refused('measurement original MCP port or descriptor')
        port,fd=int(argv[-3]),int(argv[-1])
        from cleanup_launch import read_pipe
        inherited=[read_pipe(actor['birth'].pid,fd)]
        environment['UNREST_NODE_ASSIGNMENT']=json.dumps({'targets':['VAL-MEASURE-REJECT' if '-initial-' in node else 'VAL-MEASURE'],'task_type':role},sort_keys=True,separators=(',',':'))
        vector=(native,'-m','unrest_harness','--mode','validator' if role=='validate' else 'worker','--transport','streamable-http','--host','127.0.0.1','--port',str(port),'--sensitive-inventory-fd',str(fd))
        domain,kind,path='mcp','python-module',SERVER
    else:
        vector=(native,str(checkout/MOCK))
        domain,kind,path='mock-acp','python-script',MOCK
    source_unit(checkout,path,PINS[path])
    if raw['executable']!=native or raw['stdin'] is not None:
        raise Refused('measurement exact Python image or input')
    expected=build_expected(PROJECT,native,pin,vector,tuple(sorted(environment.items())),str(home.parent/'workspace'),kind,PINS[path])
    return admit_expected(host,actor,raw,expected,domain,[native,'-I','-S',*vector[1:]],PINS[path],maximum=6,
        inherited=inherited,port=port,fields={'measurement_node':node})
