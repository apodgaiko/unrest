"""Finite RunControl workers and the single original owned executor module."""
from pathlib import Path
import json
import os
import re

from content_manifest import Refused, read_regular, native_digest, refuse_if
from control_transport import unique
from git_policy import fixture_root as repository_root, WORKER_REPOSITORIES as SLOTS, FIXTURE_SERVER_INQUIRY as SERVER_INQUIRY
from launch_policy import build_expected,admit_expected,source_unit,literal
from owned_fixture import retain
from content_manifest import _key

CASES={
    SERVER_INQUIRY:'start_project',
    'tests/test_foundation_authority.py::test_tool_error_mapping_is_closed_and_private_details_survive_async_run':'submit_plan',
    'tests/test_foundation_authority.py::test_async_project_lock_contention_is_public_busy_with_private_cause':'end_mission',
}

TEST='tests/test_run_control.py'
PIN='13ad6766039059c212f53d615e7521e67fce69bfd0e329c4ae63ea28a7b88fcf'
NAMES=(
    'admission_returns_quickly_and_terminal_run_has_identity_receipt_and_custody',
    'two_servers_share_idempotency_and_reject_competing_resource',
    'attached_inspect_and_steer_share_body_free_snapshot_without_run_mutation[advance_project]',
    'attached_inspect_and_steer_share_body_free_snapshot_without_run_mutation[end_mission]',
    'cancel_is_idempotent_records_boundaries_and_releases_resource',
    'restart_reattaches_live_worker_and_never_repeats_effect',
    'orphan_becomes_attention_and_retry_does_not_replay_old_effect',
    'recovery_finishes_durable_effect_without_dispatch',
    'receipt_append_recovery_is_byte_idempotent',
    'hash_chain_tamper_fails_closed_without_leaking_record',
    'terminal_attach_preserves_result_and_ownership_when_worker_exit_times_out',
    'recovery_before_worker_cursor_keeps_the_original_live_child',
)
WORKERS={TEST+'::test_'+name: ('end_mission' if name.endswith('[end_mission]') else
         'advance_project' if name.endswith('[advance_project]') else 'start_project') for name in NAMES}
MAXIMUM=dict(zip(WORKERS,(1,1,1,1,2,1,2,1,1,1,1,1),strict=True))
WAITING=tuple('tests/test_waiting_elapsed.py::test_waiting_row_stable_across_ticks_and_attached_projection['+role+']' for role in ('worker','validator','terminal_reviewer'))
WORKERS.update(dict.fromkeys(WAITING,'advance_project'))
MAXIMUM.update(dict.fromkeys(WAITING,1))
MEASUREMENT_EVOLUTION='tests/test_measurement.py::test_evolution_cases_use_real_public_state_machine_and_cold_state'
MEASUREMENT_PROJECT='tests/test_measurement.py::test_project_cases_use_real_run_control_and_nested_acp'
REGISTERED='tests/test_run_cancel_delivery.py::test_cancel_registered_child_drains_before_unlock'
ALL_CASES=(*CASES,*WORKERS,MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT,REGISTERED)
DESCENDANT=TEST+'::test_'+NAMES[5]
DESCENDANTS=(DESCENDANT,REGISTERED)


def fixture(host,home):
    retain(host,home, 20000)
    unit=source_unit(Path(host.meta['checkout']),TEST,PIN)
    body=literal(unit,'_EXECUTOR_SOURCE')
    if host.case==TEST+'::test_'+NAMES[-2]:
        body=body.replace('    counter = Path.cwd()',
            '    import atexit; atexit.register(time.sleep, 0.4)\n    counter = Path.cwd()')
    elif host.case==TEST+'::test_'+NAMES[-1]:
        body="import pathlib,time\nwhile not pathlib.Path(__file__).with_name('allow-start').exists(): time.sleep(0.01)\n"+body
    file=home/'executor_fixture.py'
    actual,info,pin=read_regular(file,16384,uid=20000,forbidden=0o6022)
    refuse_if(actual!=body.encode(), 'worker original executor bytes')
    return {'path':str(file),'sha256':pin,'identity':list(_key(info))}


def install_fixture(policy):
    binding=policy.profile['execution'].get('fixture')
    if binding is None:
        return
    import importlib.abc
    import importlib.util
    import sys
    import types
    delivery=binding.get('kind')=='undeliverable'
    name='unrest_harness.api' if delivery else 'executor_fixture'
    source_path=Path(policy.profile['checkout'])/'src/unrest_harness/api.py' if delivery else Path(binding['path'])
    if name in sys.modules:
        policy.refuse('fixed fixture module imported before its loader')
    class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname==name:
                return importlib.util.spec_from_file_location(fullname,str(source_path),loader=self)
        def create_module(self,spec):
            return None
        def exec_module(self,module):
            try:
                body,info,pin=read_regular(Path(binding['path']),16384,uid=20000,forbidden=0o6022)
                if list(_key(info))!=binding['identity'] or pin!=binding['sha256']:
                    raise Refused('fixed fixture import changed')
                code=compile(body,binding['path'],'exec',dont_inherit=True)
                if delivery:
                    product,_,product_pin=read_regular(source_path,4*1024*1024,uid=0,forbidden=0o6022)
                    if product_pin!=binding['module_sha256']:
                        raise Refused('fixed bootstrap product module changed')
                    exec(compile(product,str(source_path),'exec',dont_inherit=True),module.__dict__)
                    module=types.ModuleType('sitecustomize')
                    module.__file__=binding['path']
                    exec(code,module.__dict__)
                    return
            except BaseException:
                policy.refuse('fixed fixture import refused')
            exec(code,module.__dict__)
    sys.meta_path.insert(0,Loader())


def descendant(host,actor,raw):
    rows=[row for row in host.intents.values() if row.get('run_worker') and row.get('birth')==actor['birth']
          and row['token']==actor['token'] and row['consumed']]
    refuse_if(host.case not in DESCENDANTS or len(rows)!=1, 'worker finite descendant owner')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    script='tests/fixtures/cancel_registered_child.py'
    child_pin='5be8b3003dc4eb36acedce41822e3128cf288ed12b21cf1a5787e39386ae5b7e'
    registered=host.case==REGISTERED
    if registered:
        source_unit(Path(host.meta['checkout']),script,child_pin)
    vector=(native,str(Path(host.meta['checkout'])/script)) if registered else (native,'-c','import time; time.sleep(0.35)')
    value=build_expected(host.case,native,pin,vector,tuple(sorted(rows[0]['environment'].items())),
        rows[0]['cwd'],'python-script' if registered else 'python-command',child_pin if registered else None)
    return admit_expected(host,actor,raw,value,'session-child',[native,'-I','-S',*value.argv[1:]],value.payload_sha256,maximum=1)


def proposal(host,actor,raw):
    host.root_only(actor)
    case=host.case
    if case==REGISTERED:
        checkout=Path(host.meta['checkout'])
        source_unit(checkout,'tests/fixtures/cancel_registered_executor.py','cb49ca5cf474491fcb395407ae0205134b2a0742195448b0f0c792f81bb41b79')
        home=retain(host,Path(raw['cwd']), 20000)
        env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(checkout)+':'+str(checkout/'src')}
        answer=admit_worker(host,actor,raw,home,'advance_project',env,1,executor='tests.fixtures.cancel_registered_executor:execute')
        return {**answer,'wait_at_case_close':True} if answer is not None else None
    if case in (MEASUREMENT_EVOLUTION,MEASUREMENT_PROJECT):
        from git_policy import measurement_worker as worker
        return worker(host,actor,raw)
    custom=case in WORKERS
    ordinal=sum(row['case']==case and row.get('run_worker',False) for row in host.intents.values())
    maximum=MAXIMUM.get(case,1)
    refuse_if(case not in ALL_CASES or ordinal>=maximum, 'async error worker exact case and count')
    home=Path(raw['cwd'])
    binding=fixture(host,home) if custom else None
    if not custom:
        repository_root(host,case,str(home.parent/SLOTS[case][0]))
        refuse_if(home.name!='.unrest' or home.resolve()!=home, 'async error worker original home')
    env={'LANG':'C.UTF-8','PATH':os.defpath,'PYTHONPATH':str(Path(host.meta['checkout'])/'src'),
         'UNREST_APPROVAL_RECOVERY':'0','UNREST_HOME':str(home),'UNREST_PROJECTS_DIR':str(home/'projects')}
    if custom:
        env={key:env[key] for key in ('LANG','PATH','PYTHONPATH')}
    return admit_worker(host,actor,raw,home,(WORKERS if custom else CASES)[case],env,maximum,binding,custom)


def admit_worker(host,actor,raw,home,operation,env,maximum,binding=None,custom=False,executor=None):
    case=host.case
    argv=raw['argv']
    refuse_if(len(argv)!=13 or not re.fullmatch('run:[a-f0-9]{64}',argv[6]), 'async error worker bounded run identity')
    run=argv[6]
    record,_,_=read_regular(home/'.unrest/runs'/run[4:]/'request.json',65536,uid=20000,mode=0o600)
    document=json.loads(record,object_pairs_hook=unique)
    refuse_if(document.get('run_id')!=run or document.get('operation')!=operation or document.get('generation')!=1, 'async error worker exact retained request')
    arguments=document.get('arguments',{})
    refuse_if(type(arguments) is not dict, 'worker retained request arguments')
    refuse_if(case in WAITING and arguments!={'project_id':'project-1','max_steps':99}, 'waiting worker original slow request')
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    vector=[native,'-m','unrest_harness.run_worker','--project-root',str(home),'--run-id',run,
            '--executor',executor or ('executor_fixture:execute' if custom else 'unrest_harness.runtime_executor:execute'),'--custody-root-id','local:unrest-run-control','--generation','1']
    expected=build_expected(case,native,pin,tuple(vector),tuple(sorted(env.items())),str(home),'python-module',native_digest(Path(host.meta['checkout'])/'src/unrest_harness/run_worker.py'))
    answer=admit_expected(host,actor,raw,expected,'fixed-inline',[native,'-I','-S',*vector[1:]],maximum=maximum,
                          fields={'run_worker':True,'execution_fixture':binding,'run_id':run,
                              'run_project':arguments.get('project_id'),
                              'run_control':document.get('control_identity_digest')})
    return {**answer,'wait_at_case_close':True} if answer is not None and case==SERVER_INQUIRY else answer


def self_group(host,actor,payload):
    from source_observer import bound_intent
    from linux_observation import process_identity
    from process_ledger import Birth
    row=bound_intent(host,actor)
    process=host.ledger.process(actor['birth'])
    children=[child for child in host.actors.values() if child['case']==host.case
        and host.ledger.process(child['birth']).parent==actor['birth']]
    refuse_if(host.case!=REGISTERED or actor['case']!=host.case or actor['role']!='fixed-inline' or not actor['body_ready']
            or row is None or not row.get('run_worker') or not host.executed(row)
            or payload!={'signal':15} or type(payload['signal']) is not int or 15 not in actor['signals'] or not process.new_session
            or not process.session_complete or len(children)!=1 or children[0]['role']!='session-child'
            or not children[0]['body_ready'], 'registered worker exact cancellation group')
    actual=process_identity(actor['birth'].pid)
    refuse_if(Birth.read(actual)!=actor['birth'] or (actual['pgid'],actual['sid'])!=(actor['birth'].pid,actor['birth'].pid), 'registered worker actual session')
    from composed_adoption import record_group
    record_group(host,actor,15)
    return {'ok':True}
