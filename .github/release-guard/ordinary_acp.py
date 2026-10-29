"""Original LaunchPlan identity and finite mock-agent/native-fixture launches.

The native fixture has kernel admission and actual reap evidence, never a
fabricated Python READY. Source selection does not grant group-signal authority.
"""
from __future__ import annotations

import gc
import os
from pathlib import Path
import stat
import types

from content_manifest import Refused
from launch_policy import build_expected

PRODUCT = 'src/unrest_harness/acp_runner.py'
TEST = 'tests/test_acp_runner.py'
MOCK = 'tests/mock_acp_agent.py'
PINS = {PRODUCT: '5698d40663b23bf23f832a3e3f69732fe31004d8b1cf305d5bc5870e11f39a2f',
        TEST: '558010a851595fece4c186cb30b717ff38dad4fa075705dbc316cfd8537910b4',
        MOCK: '8141170328ff5fc28acf10dfd70bbf22f4062cceb1b2de8b8ea11ab0c17a48b6'}
CASES = tuple(TEST + '::' + name for name in (
    'test_owned_node_launch_uses_one_identical_plan[work]',
    'test_owned_node_launch_uses_one_identical_plan[validate]',
    'test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling[claude]',
    'test_run_node_with_mock_agent'))
MOCK_CASE=CASES[3]


STARTUP_CASES=tuple(TEST+'::'+name for name in (
    'test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[work]',
    'test_owned_node_real_startup_failure_is_safe_and_starts_no_protocol[validate]',
    'test_terminal_real_startup_failure_is_safe_and_starts_no_protocol'))
TEMPLATE_CASES=tuple(TEST+'::'+name+'['+role+'-'+provider+']'
    for name in ('test_full_jobs_and_handoffs_preserve_complete_format_templates',
                 'test_full_jobs_do_not_infer_credentials_inside_format_fields')
    for role in ('worker','validator') for provider in ('claude','codex'))
BATCH_CASES=tuple(TEST+'::test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success['+provider+']'
                  for provider in ('claude','codex'))
EXECUTION_CASES=(*CASES,*STARTUP_CASES,*TEMPLATE_CASES,*BATCH_CASES)


def environment(case, base, root_environment, ordinal=0):
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


def system_sleep():
    """The one declared system alias, checked from root to regular executable."""
    file = Path('/bin/sleep')
    if os.readlink('/bin') != 'usr/bin' or file.resolve(strict=True) != Path('/usr/bin/sleep'):
        raise Refused('ordinary system fixture alias')
    for member in (Path('/'), Path('/usr'), Path('/usr/bin'), Path('/usr/bin/sleep')):
        info = member.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o6022:
            raise Refused('ordinary system fixture custody')
        if member == Path('/usr/bin/sleep'):
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise Refused('ordinary system fixture executable')
        elif not stat.S_ISDIR(info.st_mode):
            raise Refused('ordinary system fixture directory')
    from source_profile import digest
    return digest(Path('/usr/bin/sleep'))


def template_environment(case,checkout):
    from launch_policy import source_unit,literal,assignment,render_string
    name,parameter=case.split('::')[1].split('[')
    selected,provider=parameter[:-1].split('-')
    role='work' if selected=='worker' else 'validate'
    unit=source_unit(checkout,TEST,PINS[TEST],(name,))
    if case in TEMPLATE_CASES[:4]:
        template=literal(unit,'template')
        return {'LANG':'C','PATH':template+':relative-tools:local-bin',
            f'PAYMENTS_{provider}_{role}_DSN_TEMPLATE_URI_V21'.upper():template}
    secret=f'v22-{provider}-{role}-format-ast-credential'
    value=render_string(assignment(unit,'source_value'),[('secret',-1,secret)]*3)
    return {'LANG':'C','PATH':'/bin:/usr/bin:'+secret,
        f'PAYMENTS_{provider}_{role}_FORMAT_DSN_TEMPLATE_URI_V22'.upper():value}


def expected(case, role, cwd, checkout, native, native_pin, root_environment, owned, *, base=None,ordinal=0):
    if case not in EXECUTION_CASES or role not in (('session-invalid','sleep') if case in STARTUP_CASES else ('mock-acp', 'sleep')):
        raise Refused('ordinary closed launch role')
    if role == 'sleep':
        if cwd != str(checkout):
            raise Refused('ordinary inherited fixture cwd')
        env = {**root_environment, 'PYTEST_VERSION': '9.0.2', 'PYTEST_CURRENT_TEST': case + ' (call)'}
        if case in TEMPLATE_CASES:
            env.update(template_environment(case,checkout))
        if case == CASES[2]:
            env['ANTHROPIC_API_KEY'] = 'batch-crash-known-value'
        if case==MOCK_CASE:
            if base is None:
                raise Refused('mock-agent owned fixture absent')
            leaf=environment(case,base,root_environment)
            env.update({key:leaf[key] for key in ('UNREST_HANDOFF_PATH','UNREST_NODE_ID','UNREST_NODE_TYPE')})
        vector, executable, pin, kind, payload = (('sleep' if case==MOCK_CASE else '/bin/sleep'), '30'), ('/usr/bin/sleep' if case==MOCK_CASE else '/bin/sleep'), system_sleep(), 'native', None
    elif role=='session-invalid':
        from owned_fixture import acquire
        from content_manifest import read_regular
        workspace=Path(cwd)
        base,_=acquire(str(workspace.parent),owned,case.split('::')[1][:30],20000)
        suffix='work' if case==STARTUP_CASES[0] else 'validate' if case==STARTUP_CASES[1] else 'reviewer'
        file=workspace/('invalid-format-'+suffix)
        body,_,pin=read_regular(file,4096,uid=20000,mode=0o700)
        if workspace!=base/'workspace' or body!=b'mode executable, intentionally invalid format\n':
            raise Refused('ordinary exact invalid-format fixture')
        vector=('./'+file.name,)
        executable,kind,payload=str(file),'expected-exec-failure',None
        env=environment(case,base,root_environment)
    else:
        home = Path(cwd)
        if (not home.is_absolute() or str(home.resolve()) != cwd or home.name != 'workspace'
                or not home.parent.is_relative_to(owned / 'pytest') or home.parent == owned / 'pytest'):
            raise Refused('ordinary owned project workspace')
        env = environment(case, home.parent, root_environment,ordinal)
        if case in TEMPLATE_CASES:
            env.update({key:value for key,value in template_environment(case,checkout).items()
                        if key in ('LANG','PATH')})
        vector = (native, str(checkout / MOCK))
        executable, pin, kind, payload = native, native_pin, 'python-script', PINS[MOCK]
    return build_expected(case, executable, pin, vector, tuple(sorted(env.items())), cwd, kind, payload)


def plain_environment(value):
    if type(value) is types.MappingProxyType:
        referents = gc.get_referents(value)
        if len(referents) != 1 or type(referents[0]) is not dict:
            raise Refused('ordinary plan underlying dictionary')
        value = referents[0]
    if type(value) is not dict or any(type(k) is not str or type(v) is not str for k, v in value.items()):
        raise Refused('ordinary environment primitives')
    return dict(value)
