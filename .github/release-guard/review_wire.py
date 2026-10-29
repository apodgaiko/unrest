"""Original controlled review-wire fixtures; no external reviewer is launched."""
import hashlib
import json
from pathlib import Path

from case_inventory import identity
from content_manifest import Refused, read_regular
from control_transport import unique
from launch_policy import build_expected,source_unit

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
CASES=tuple(identity(node) for node in NODES)
DOUBLE=TEST+'::test_duplicate_and_conflicting_reviews_are_monotone'


def count(case):
    return 2 if case==DOUBLE else 1


def scenario(file,owned):
    if (str(file.resolve())!=str(file) or file.name!='scenario.json'
            or not file.parent.is_relative_to(owned/'pytest') or file.parent==owned/'pytest'):
        raise Refused('review-wire owned scenario path')
    body,info,_=read_regular(file,131072,uid=20000,mode=0o644)
    value=json.loads(body,object_pairs_hook=unique)
    if (len(body)!=info.st_size or type(value) is not dict or set(value)!={'events','delay','raw_frame'}
            or type(value['events']) is not list or len(value['events'])>3
            or type(value['delay']) is not int or value['delay'] not in (0,30)
            or value['raw_frame'] is not None and (type(value['raw_frame']) is not str or len(value['raw_frame'])>70000)
            or type(value['raw_frame']) is str and len(value['raw_frame'].encode())>131072):
        raise Refused('review-wire inert scenario schema or bytes')
    # No handoff, MCP URL, frame program or command fields: these inputs only
    # produce fixture protocol bytes and the original finite sleep.
    return body


def proposal(host,actor,raw):
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
    body=scenario(Path(argv[-1]),owned)
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    value=build_expected(
        case,
        native, pin,
        tuple(argv),
        tuple(sorted(environment.items())),
        str(checkout), 'python-script', PIN,
    )
    if raw['environment']!=environment:
        raise Refused('review-wire original environment')
    snapshot=host.directory/('review-wire-'+hashlib.sha256((case+str(len(records))).encode()).hexdigest()+'.json')
    vector=[native,'-I','-S',argv[1],str(snapshot)]
    answer=host.admit_launch(actor,value,'review-wire',vector,PIN,maximum=count(case))
    if answer is None:
        return None
    with snapshot.open('xb') as stream:
        stream.write(body)
    snapshot.chmod(0o444)
    return {**answer,'translated':vector}
