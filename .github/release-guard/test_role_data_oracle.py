"""Original fixture values for matcher tests; never imported by enforcement."""
from ordinary_acp import EXECUTION_CASES, STARTUP_CASES, TEMPLATE_CASES, BATCH_CASES, MOCK_CASE
from content_manifest import Refused


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
