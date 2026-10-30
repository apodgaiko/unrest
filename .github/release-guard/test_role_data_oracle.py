"""Original fixture values for matcher tests; never imported by enforcement."""
from ordinary_acp import EXECUTION_CASES, STARTUP_CASES, TEMPLATE_CASES, BATCH_CASES, MOCK_CASE
from content_manifest import Refused
from completion_roles import CASES, schedule, mode
from composed_cases import DIRECT,UNDELIVERABLE


def ordinary_environment(case, base, root_environment, ordinal=0):
    from node_environment import environment as role_environment
    if case not in EXECUTION_CASES:
        raise Refused('ordinary finite case')
    if case in STARTUP_CASES:
        role='work' if case==STARTUP_CASES[0] else 'validate' if case==STARTUP_CASES[1] else 'terminal_reviewer'
        spawn='2026-08-30T05-00-00Z' if role=='terminal_reviewer' else '2026-08-30T04-00-00Z-'+role
        return role_environment(root_environment,base/'.unrest','p1','startup-'+role,role,spawn)
    if case in (*TEMPLATE_CASES,*BATCH_CASES):
        if ordinal not in range(2 if case in BATCH_CASES else 1):
            raise Refused('ordinary mock ordinal')
        if case in BATCH_CASES:
            provider=case.rsplit('[',1)[1][:-1]
            node,role,spawn=f'v{ordinal}','validate',f'2026-08-10T07-00-00Z-{ordinal:04d}'
        else:
            selected,provider=case.rsplit('[',1)[1][:-1].split('-')
            role='work' if selected=='worker' else 'validate'
            credential=case in TEMPLATE_CASES[4:]
            node=provider+'-'+role+('-format-credential' if credential else '')
            spawn=f"2026-07-29T{'08' if credential else '05'}-00-00Z-{provider}-{role}"
        result=role_environment(root_environment,base/'.unrest','p1',node,role,spawn)
        if provider=='codex':
            result.update(INITIAL_AGENT_MODE='agent',CODEX_CONFIG='{"approval_policy":"on-request","model_reasoning_effort":"medium","sandbox_mode":"workspace-write"}')
        return result
    role = 'work' if case==MOCK_CASE else case.rsplit('[', 1)[1][:-1]
    node, spawn = ('v-good', '2026-08-10T07-05-00Z-0000') if role == 'claude' else (
        'plan-' + role, '2026-08-30T00-00-00Z-' + role)
    if case==MOCK_CASE:
        node,spawn='w1','2026-05-17T00-00-00Z'
    result=role_environment(root_environment,base/'.unrest','p1',node,'validate' if role=='claude' else role,spawn)
    if role == 'claude':
        result['ANTHROPIC_API_KEY'] = 'batch-crash-known-value'  # Original public redaction canary.
    return result


# Original completion fixture vectors are test data, not launch authority.

def completion_attempt(parent,case,ordinal):
    family,_,_=CASES[case]
    return parent/'.unrest/projects'/family/'.unrest-runtime/missions/mission-001/attempts'/(schedule(case)[ordinal][1]+'__node.json')

def completion_environment(checkout,parent,case,ordinal,ambient,*,native=None,observed=None):
    family,role,scenario=CASES[case]
    http=schedule(case)[ordinal][0]=='http'
    result=dict(ambient) if http else {key:value for key,value in ambient.items() if not key.startswith('UNREST_')}
    result.update(UNREST_HOME=str(parent/'.unrest'),UNREST_PROJECTS_DIR=str(parent/'.unrest/projects'))
    if family=='defect':
        role='work' if ordinal==0 else 'validate'
        from node_environment import scoped,project_path
        project=project_path(parent/'.unrest',observed.get('UNREST_PROJECT_ID'))
        result.update(PYTHONPATH=str(checkout/'src'),UNREST_WORKSPACE=str(parent/'workspace'))
        return scoped(observed,result,parent/'.unrest',project.name,role,module=False)
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
          (schedule(case)[ordinal][1]+'__'+node+'.json') if family in ('restart','targetless','binding') else completion_attempt(parent,case,ordinal))
    result.update(UNREST_PROJECT_ID=project,UNREST_MISSION_ID='mission-001',UNREST_NODE_ID=node,
        UNREST_NODE_TYPE=role,UNREST_HANDOFF_PATH=str(path))
    return result
