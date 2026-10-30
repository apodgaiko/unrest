"""Closed original role-server schedules, environments and literal templates."""
import re
import stat
from pathlib import Path

from content_manifest import Refused
from owned_fixture import acquire
from launch_policy import source_unit,assignment,render_string
from composed_cases import CASES as COMPOSED,HTTP as COMPOSED_HTTP,DIRECT,UNDELIVERABLE

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
SERVER_TEST='tests/test_server.py'
SOURCE={
    **{SERVER_TEST+'::test_canonical_task_truth_ignores_runtime_assignment_envelope['+value+']':1
       for value in ('malformed','mismatched','generic')},
    SERVER_TEST+'::test_missing_task_truth_derives_exact_work_completion_from_closed_envelope':2,
    **{SERVER_TEST+f'::test_completion_carrier_exhaustive_structural_matrix[{value}-expected_fields{index}-{role}]':2 if role=='work' else 0
       for index,value in enumerate(('missing','unknown','null','wrong_type','order','duplicate','coverage','status','attempt',
           'return','return_uppercase','evidence','evidence_locator','evidence_multiple','scope','blocker','items','passed','done'))
       for role in ('work','validate')},
    **{SERVER_TEST+f'::test_completion_refusal_survives_server_restart[{repair}-{role}]':2 if role=='work' else 0
       for repair in ('valid-repair','second-invalid') for role in ('work','validate')},
    SERVER_TEST+'::test_completion_preflight_is_invariant_to_prose_and_evidence_body':4,
}
CASES.update(dict.fromkeys(SOURCE,('source','work','')))
RESTART={SERVER_TEST+f'::test_real_orchestrator_restart_preserves_completion_refusal_attempt[{repair}-{role}]':
    ('restart',role,repair) for repair in ('repair','second-invalid') for role in ('work','validate')}
TARGETLESS={SERVER_TEST+f'::test_real_targetless_work_completion[{done}-{attention}]':('targetless','work','')
    for done,attention in ((True,False),(False,False),(True,True),(False,True))}
BINDING={SERVER_TEST+f'::test_real_completion_target_binding[{value}]':('binding','validate' if value=='validator' else 'work',value)
    for value in ('missing','extra','attempt','type','validator','scope','evidence')}
DEFECT=SERVER_TEST+'::test_structurally_valid_defect_requires_independent_validator_and_gate'
CASES.update({**RESTART,**TARGETLESS,**BINDING,DEFECT:('defect','work','')})
CASES.update(dict.fromkeys(COMPOSED,('composed','orchestrator','')))
ROOT_QUERIES={**SOURCE,**{case:int(role=='work') for case,(_,role,_) in RESTART.items()},**dict.fromkeys(BINDING,1)}
HTTP=tuple(case for case,row in CASES.items() if row[0] not in ('setup','source','defect'))

PINS={'tests/test_completion_ownership.py': '2b67510bdd8f40d584baab65837174b2f5a3935aff343b7d9eaccedf09b5df8b', 'tests/test_completion_setup.py': 'fe1a1c98792d1b30d81d975cb23ad9122ae74678295ef4ed8c5e532a7aa00b6a', 'tests/test_server.py': '0550689ff20fb183ea62b47606bd3e66c5fc1222b5d4166e57e74d546afbb286'}
OWNER=20000


def schedule(case):
    if type(case) is not str or case not in CASES:
        raise Refused('completion closed role case')
    family,role,scenario=CASES[case]
    if family=='composed':
        return (('http','',0),)*COMPOSED_HTTP[case]
    if family=='source':
        return ()
    if family=='defect':
        return (('inline','',1),('inline','',0))
    if family=='restart':
        return (('http','same-process-attempt',2 if role=='work' else 0),('http','',0),('http','',0))
    if family=='targetless':
        return (('http','attempt',1),('http','attempt',0))
    if family=='binding':
        return (('http','attempt',int(role=='work')),)
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
    if case.split('::')[0]==SERVER_TEST:
        source_unit(Path(host.meta['checkout']),SERVER_TEST,PINS[SERVER_TEST])
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
    if family=='defect':
        owner=source_unit(checkout,SERVER_TEST,PINS[SERVER_TEST],(case.split('::')[1],'ProcessDispatcher','dispatch'))
        call=assignment(owner,'child')
        return call.args[0].elts[2].value
    if schedule(case)[ordinal][0]=='http':
        source_unit(checkout,case.split('::')[0],PINS[case.split('::')[0]])
        source_unit(checkout,'tests/test_server.py',PINS['tests/test_server.py'])
        return 'from unrest_harness.server import main; main()'
    path,name=case.split('::')
    name=name.split('[')[0]
    owner=source_unit(checkout,path,PINS[path],(name,))
    template=assignment(owner,'script')
    path=attempt(parent,case,ordinal)
    substitutions=(('str(path)',str(path)),('phase',scenario)) if family=='crash' else (
        ('str(path.parent)',str(path.parent)),('str(barrier)',str(parent/'workspace/barrier')),
        ('str(barrier)',str(parent/'workspace/barrier')))
    return render_string(template,tuple((name,114,repr(value)) for name,value in substitutions))


def mode(case,ordinal):
    family,role,_=CASES[case]
    if family=='composed':
        return 'orchestrator'
    if family=='defect':
        return 'worker' if ordinal==0 else 'validator'
    return 'orchestrator' if family=='restart' and ordinal>0 else 'validator' if role=='validate' else 'worker'


def environment(checkout,parent,case,ordinal,ambient,*,native=None,observed=None):
    family,role,scenario=CASES[case]
    http=schedule(case)[ordinal][0]=='http'
    result=dict(ambient) if http else {key:value for key,value in ambient.items() if not key.startswith('UNREST_')}
    result.update(UNREST_HOME=str(parent/'.unrest'),UNREST_PROJECTS_DIR=str(parent/'.unrest/projects'))
    if family=='defect':
        from measurement_runtime import record
        projects=sorted((parent/'.unrest/projects').iterdir())
        if len(projects)!=1:
            raise Refused('completion independent validator project count')
        document=record(projects[0]/'.unrest-runtime/project.json')
        if document.get('id')!=projects[0].name or document.get('workspace_dir')!=str(parent/'workspace'):
            raise Refused('completion independent validator project scope')
        role='work' if ordinal==0 else 'validate'
        from node_environment import scoped
        result.update(PYTHONPATH=str(checkout/'src'),UNREST_WORKSPACE=str(parent/'workspace'))
        return scoped(observed,result,parent/'.unrest',projects[0].name,role,module=False)
    if http:
        result['PYTHONPATH']=str(checkout/'src')
        for name in ('WORKER','VALIDATOR','TERMINAL_REVIEWER'):
            result['UNREST_'+name+'_PROVIDER']='claude'
            result['UNREST_'+name+'_ACP_COMMAND']=str(parent/'workspace/.forbidden-child-trap') if family=='restart' and ordinal==0 else '/bin/true'
    if family=='composed':
        if native is None:
            raise Refused('composed original native command binding')
        command=native+' '+str(parent/'workspace/.hermetic-acp-adapter.py')+' '+str(parent/'workspace/.hermetic-acp-trace.jsonl')
        for name in (('WORKER',) if case in DIRECT else ('WORKER','VALIDATOR','TERMINAL_REVIEWER')):
            result['UNREST_'+name+'_ACP_COMMAND']=command
        if case==UNDELIVERABLE:
            result['PYTHONPATH']=str(parent/'workspace')
    if mode(case,ordinal)=='orchestrator':
        return result
    project=f'real-restart-{role}-{scenario=="repair"}' if family=='restart' else family
    node=role+'-node' if family=='restart' else 'work' if family=='targetless' else 'node'
    path=(parent/'.unrest/projects'/project/'.unrest-runtime/missions/mission-001/attempts'/
          (schedule(case)[ordinal][1]+'__'+node+'.json') if family in ('restart','targetless','binding') else attempt(parent,case,ordinal))
    result.update(UNREST_PROJECT_ID=project,UNREST_MISSION_ID='mission-001',UNREST_NODE_ID=node,
        UNREST_NODE_TYPE=role,UNREST_HANDOFF_PATH=str(path))
    return result



def actor_slot(host,actor):
    from source_observer import bound_intent
    row=bound_intent(host,actor)
    if (host.case not in CASES or actor['case']!=host.case or not actor['body_ready']
            or row is None or not host.ledger.body_ready(actor['birth'],actor['token'])):
        raise Refused('completion actual ready server')
    slot=row.get('server_slot')
    if type(slot) is not int or not 0<=slot<len(schedule(host.case)):
        raise Refused('completion finite server slot')
    kind=schedule(host.case)[slot][0]
    if row['role']!=actor['role'] or actor['role']!=('mcp' if kind=='http' else 'fixed-inline'):
        raise Refused('completion server role generation')
    return row
