"""Closed original role-server schedules, environments and literal templates."""
import ast
import re
import stat
from pathlib import Path

from content_manifest import Refused
from owned_fixture import acquire
from launch_policy import source_unit,assignment

OWNERSHIP_TEST='tests/test_completion_ownership.py'
SETUP_TEST='tests/test_completion_setup.py'
OWNERSHIP=OWNERSHIP_TEST+'::test_role_process_ownership'
CRASH=OWNERSHIP_TEST+'::test_role_interrupted_publication'
SETUP=SETUP_TEST+'::test_real_roles_first_use'
ROLES=(('work',0),('work',1),('validate',2))
CASES={**{OWNERSHIP+f'[{scenario}-{role}-targets{target}]':('ownership',role,scenario)
          for scenario in ('valid','invalid','exhausted','both-invalid') for role,target in ROLES},
    **{CRASH+f'[{role}-{phase}]':('crash',role,phase) for role in ('work','validate') for phase in ('before','after')},
    **{SETUP+f'[{scenario}-{role}-targets{target}]':('setup',role,scenario)
       for scenario in ('invalid-invalid','valid-invalid','valid-valid','distinct') for role,target in ROLES}}
HTTP=tuple(case for case,row in CASES.items() if row[0]!='setup')
GROUPS={'roles28':tuple(CASES), **{family+suffix:tuple(case for case,row in CASES.items() if row[0]==family)
    for family,suffix in (('ownership','12'),('crash','4'),('setup','12'))},
    'roles2':tuple(case for case,row in CASES.items() if row[0]=='ownership' and row[2]=='valid' and not case.endswith('targets1]')),
    'setup2':tuple(case for case,row in CASES.items() if row[0]=='setup' and row[2]=='valid-valid' and not case.endswith('targets1]')),
    'crash2':tuple(case for case,row in CASES.items() if row[0]=='crash' and row[2]=='before')}

GROUPS['roles26']=tuple(case for case in CASES if case not in GROUPS['roles2'])
GROUPS['roles5']=tuple(case for case,row in CASES.items() if row[0]=='setup' and (row[2]=='distinct' or row[2]=='valid-valid' and not case.endswith('targets0]')))
GROUPS['roles14']=tuple(case for case,row in CASES.items() if row[0]=='setup' or row[0]=='crash' and row[1]=='validate')
PINS={'tests/test_completion_ownership.py': '2b67510bdd8f40d584baab65837174b2f5a3935aff343b7d9eaccedf09b5df8b', 'tests/test_completion_setup.py': 'fe1a1c98792d1b30d81d975cb23ad9122ae74678295ef4ed8c5e532a7aa00b6a', 'tests/test_server.py': '4524714474b49852af00d4533f30456b87839ed0d5bbd2d10ba5502717ddef4e'}
OWNER=20000


def schedule(case):
    if type(case) is not str or case not in CASES:
        raise Refused('completion closed role case')
    family,role,scenario=CASES[case]
    work=role=='work'
    if family=='ownership':
        return (('http','attempt',2 if work and scenario=='exhausted' else int(work)),
            ('http','attempt',int(work)),('http','attempt',0),('http','other',int(work)))
    if family=='crash':
        return (('stdio','attempt',int(work)),('http','attempt',int(work and scenario=='before')))
    return (('stdio','attempt',int(work)),('stdio','other' if scenario=='distinct' else 'attempt',int(work)))


def root(host,cwd):
    case=host.case
    if case not in CASES:
        raise Refused('completion undeclared role')
    workspace=Path(cwd)
    if workspace.name!='workspace' or workspace.resolve()!=workspace:
        raise Refused('completion original workspace')
    parent,info=acquire(str(workspace.parent),Path(host.meta['owned']),re.sub(r'[\W]','_',case.split('::')[1])[:30],OWNER)
    item=workspace.stat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid!=OWNER or item.st_mode&0o6022:
        raise Refused('completion workspace custody')
    generation=(str(parent),info.st_dev,info.st_ino,item.st_dev,item.st_ino)
    if host.fixture_roots.setdefault(('completion-role',case),generation)!=generation:
        raise Refused('completion changed role fixture generation')
    return parent



def attempt(parent,case,ordinal):
    family,_,_=CASES[case]
    return parent/'.unrest/projects'/family/'.unrest-runtime/missions/mission-001/attempts'/(schedule(case)[ordinal][1]+'__node.json')


def program(checkout,parent,case,ordinal):
    family,_,scenario=CASES[case]
    if schedule(case)[ordinal][0]=='http':
        source_unit(checkout,case.split('::')[0],PINS[case.split('::')[0]])
        source_unit(checkout,'tests/test_server.py',PINS['tests/test_server.py'])
        return 'from unrest_harness.server import main; main()'
    path,name=case.split('::')
    name=name.split('[')[0]
    owner=source_unit(checkout,path,PINS[path],(name,))
    template=assignment(owner,'script')
    if not isinstance(template,ast.JoinedStr):
        raise Refused('completion sole original role template')
    path=attempt(parent,case,ordinal)
    substitutions=(('str(path)',str(path)),('phase',scenario)) if family=='crash' else (
        ('str(path.parent)',str(path.parent)),('str(barrier)',str(parent/'workspace/barrier')),
        ('str(barrier)',str(parent/'workspace/barrier')))
    index=0
    result=[]
    for part in template.values:
        if isinstance(part,ast.Constant) and type(part.value) is str:
            result.append(part.value)
        elif (isinstance(part,ast.FormattedValue) and part.conversion==114 and part.format_spec is None
              and index<len(substitutions) and ast.unparse(part.value)==substitutions[index][0]):
            result.append(repr(substitutions[index][1]))
            index+=1
        else:
            raise Refused('completion closed role template substitution')
    if index!=len(substitutions):
        raise Refused('completion incomplete original role template')
    return ''.join(result)


def environment(checkout,parent,case,ordinal,ambient):
    family,role,_=CASES[case]
    http=schedule(case)[ordinal][0]=='http'
    result=dict(ambient) if http else {key:value for key,value in ambient.items() if not key.startswith('UNREST_')}
    result.update(UNREST_HOME=str(parent/'.unrest'),UNREST_PROJECTS_DIR=str(parent/'.unrest/projects'),
        UNREST_PROJECT_ID=family,UNREST_MISSION_ID='mission-001',UNREST_NODE_ID='node',
        UNREST_NODE_TYPE=role,UNREST_HANDOFF_PATH=str(attempt(parent,case,ordinal)))
    if http:
        result['PYTHONPATH']=str(checkout/'src')
        for name in ('WORKER','VALIDATOR','TERMINAL_REVIEWER'):
            result['UNREST_'+name+'_PROVIDER']='claude'
            result['UNREST_'+name+'_ACP_COMMAND']='/bin/true'
    return result



def actor_slot(host,actor):
    if (host.case not in CASES or actor['case']!=host.case or not actor['body_ready']
            or not host.ledger.body_ready(actor['birth'],actor['token'])):
        raise Refused('completion actual ready server')
    rows=[row for row in host.intents.values() if row['case']==host.case and 'server_slot' in row
          and row['consumed'] and row.get('birth')==actor['birth'] and row['token']==actor['token']]
    if len(rows)!=1:
        raise Refused('completion unique server generation')
    row=rows[0]
    slot=row['server_slot']
    if type(slot) is not int or not 0<=slot<len(schedule(host.case)):
        raise Refused('completion finite server slot')
    kind=schedule(host.case)[slot][0]
    if row['role']!=actor['role'] or actor['role']!=('mcp' if kind=='http' else 'fixed-inline'):
        raise Refused('completion server role generation')
    return row
