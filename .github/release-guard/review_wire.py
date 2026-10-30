"""Original controlled review-wire fixtures; no external reviewer is launched."""
import hashlib
from pathlib import Path

from case_inventory import identity
from content_manifest import Refused, read_regular
from launch_policy import build_expected,source_unit,admit_expected

TEST='tests/test_provider_review.py'
SCRIPT='tests/fixtures/approval_acp_process.py'
PIN='18e5cf246b5e432dca01576b8a9bf463bb80f0a7974f6c2fefafc8ecd683f18d'
NODES=tuple(TEST+'::'+name for name in (
    *(f'test_real_wire_status_and_pinned_mappings[{mapping}-{status}]' for mapping in ('creation','update') for status in ('denied','approved','timedOut','aborted','inProgress')),
    *(f'test_real_wire_invalid_identity_is_blocked_not_authorized[{mutation}]' for mutation in ('session','thread','review','turn','large','status','fields')),
    'test_exact_guardian_objects_inside_ordinary_mcp_results_are_not_reviews',
    'test_duplicate_and_conflicting_reviews_are_monotone',
    'test_write_failure_survives_swallowed_observer_and_restart',
    *(f'test_malformed_and_oversized_wire_never_become_success[{frame}]' for frame in ('{invalid json','x'*70000)),
    'test_credential_in_provider_identity_is_unavailable_not_copied',
    'test_cancellation_closes_owned_transport_and_keeps_record',
))
FRAMES='tests/test_provider_review_frames.py'
FRAMES_PIN='7a061260ee39629f5d529052eeec70ae32fe02ac5c8b9d226ad7c67dfb1377f7'
NODES+=tuple(FRAMES+'::'+name for name in (
    *('test_malformed_frame_cannot_correlate_or_escape_capture['+value+']' for value in (
        'id-None','id-0','id-2_0','id-2_1','id-True','id-value5','id-value6',
        'result-value7','error-value8','both-None','jsonrpc-None','jsonrpc-1.0','method-None','method-other',
        'sessionUpdate-None','sessionUpdate-value15','sessionUpdate-other','params_position-None',
        'update_position-None','wrapper_conflict-None','output_conflict-None')),
    'test_ordinary_response_with_nested_review_is_not_captured',
    *(f'test_prefixed_update_with_malformed_content_blocks[{registered}-{payload}]'
      for registered in ('False','True') for payload in ('None','payload1','payload2','payload3')),
))
COUNT_CASE=TEST+'::test_review_count_bound_and_malformed_action'
NODES+=(*(TEST+'::test_schema_action_variants_do_not_persist_private_payloads[action'+str(i)+']' for i in range(6)),COUNT_CASE)
DENIAL=tuple(TEST+'::test_runner_denial_overrides_handoff_and_reaps_owned_processes['+value+']' for value in ('True','False'))
NODES+=DENIAL
CASES=tuple(identity(node) for node in NODES)
DOUBLE=TEST+'::test_duplicate_and_conflicting_reviews_are_monotone'


def count(case):
    return 2 if case==DOUBLE else 1


def scenario(file,owned,case=None):
    if (str(file.resolve())!=str(file) or file.name!='scenario.json'
            or not file.parent.is_relative_to(owned/'pytest') or file.parent==owned/'pytest'):
        raise Refused('review-wire owned scenario path')
    return read_regular(file,131072,uid=20000,mode=0o644)[0]


RUNNER=tuple(FRAMES+'::test_actual_runner_matching_id_order_and_owned_cleanup['+value+']'
    for value in ('before','after','batch_before','batch_after','eof'))


def runner_scenario(case,base):
    if case not in RUNNER:
        raise Refused('review runner exact case')
    return read_regular(base/'scenario.json',131072,uid=20000,mode=0o644)[0]


def proposal(host,actor,raw):
    if host.case in DENIAL:
        return denial_proposal(host,actor,raw)
    host.root_only(actor)
    case=host.case
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    checkout,owned=Path(host.meta['checkout']),Path(host.meta['owned'])
    argv=raw['argv']
    if case not in CASES or len(argv)!=3 or argv[:2]!=[native,str(checkout/SCRIPT)] or raw['cwd']!=str(checkout) or raw['stdin'] is not None:
        raise Refused('review-wire exact entry')
    records=[row for row in host.intents.values() if row['case']==case]
    if (len(records)>=count(case) or any(row['role']!='review-wire' or not row['consumed']
            or not host.ledger.reaped(row['birth'],row['token']) for row in records)):
        raise Refused('review-wire sequential finite quota')
    if case.startswith(FRAMES+'::'):
        source_unit(checkout,FRAMES,FRAMES_PIN)
    body=scenario(Path(argv[-1]),owned,case)
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    value=build_expected(
        case,
        native, pin,
        tuple(argv),
        tuple(sorted(environment.items())),
        str(checkout), 'python-script', PIN,
    )
    snapshot=host.directory/('review-wire-'+hashlib.sha256((case+str(len(records))).encode()).hexdigest()+'.json')
    vector=[native,'-I','-S',argv[1],str(snapshot)]
    answer=admit_expected(host,actor,raw,value,'review-wire',vector,PIN,maximum=count(case))
    if answer is None:
        return None
    with snapshot.open('xb') as stream:
        stream.write(body)
    snapshot.chmod(0o444)
    return answer


def denial_proposal(host,actor,raw):
    from cleanup_launch import PINS
    from node_environment import environment
    from owned_fixture import retain
    host.root_only(actor)
    case=host.case
    checkout=Path(host.meta['checkout'])
    source_unit(checkout,TEST,PINS[TEST])
    native,pin=host.binding['entry']['path'],host.binding['entry']['sha256']
    records=[row for row in host.intents.values() if row['case']==case]
    if len(records)>1 or raw['stdin'] is not None:
        raise Refused('denial original two-process sequence')
    if any(not host.executed(row) or not host.actors[row['pid']]['body_ready'] for row in records):
        return None
    snapshot=None
    if not records:
        vector=(native,'-c','import time; time.sleep(30)')
        env={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
        cwd,role,kind,payload=str(checkout),'fixed-inline','python-command',None
    else:
        base=retain(host,Path(raw['cwd']).parent,case.split('::')[1].split('[')[0][:30],20000)
        cwd=str(base/'workspace')
        vector=(native,str(checkout/SCRIPT),str(base/'scenario.json'))
        env=environment(host.meta_environment(),base/'home','project','w1','work','attempt-1')
        env.update(INITIAL_AGENT_MODE='agent',CODEX_CONFIG='{"approval_policy":"on-request","model_reasoning_effort":"medium","sandbox_mode":"workspace-write"}')
        body,_,_=read_regular(base/'scenario.json',131072,uid=20000,mode=0o644)
        snapshot=host.directory/('denial-'+hashlib.sha256(case.encode()).hexdigest()+'.json')
        role,kind,payload='review-wire','python-script',PIN
    expected=build_expected(case,native,pin,vector,tuple(sorted(env.items())),cwd,kind,payload)
    translated=[native,'-I','-S',*vector[1:]]
    if snapshot is not None:
        translated[-1]=str(snapshot)
    answer=admit_expected(host,actor,raw,expected,role,translated,payload)
    if answer is not None and snapshot is not None:
        with snapshot.open('xb') as stream:
            stream.write(body)
        snapshot.chmod(0o444)
    return answer
