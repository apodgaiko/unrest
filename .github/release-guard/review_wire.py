"""Original controlled review-wire fixtures; no external reviewer is launched."""
import hashlib
import json
import os
from pathlib import Path
import stat

from case_inventory import identity
from content_manifest import Refused
from control_transport import unique
from native_entry import key
from launch_policy import Rule,render

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
CASES=tuple(identity(node) for node in NODES)
DOUBLE=TEST+'::test_duplicate_and_conflicting_reviews_are_monotone'


def count(case):
    return 2 if case==DOUBLE else 1


def scenario(file,owned):
    if (str(file.resolve())!=str(file) or file.name!='scenario.json'
            or not file.parent.is_relative_to(owned/'pytest') or file.parent==owned/'pytest'):
        raise Refused('review-wire owned scenario path')
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=20000 or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o644 or info.st_size>131072):
            raise Refused('review-wire scenario custody')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            body=stream.read(131073)
        if (len(body)!=info.st_size or len(body)>131072 or key(info)!=key(os.fstat(fd))
                or key(info)!=key(file.lstat())):
            raise Refused('review-wire scenario current bytes')
    finally:
        os.close(fd)
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
    body=scenario(Path(argv[-1]),owned)
    environment={**host.meta_environment(),'PYTEST_VERSION':'9.0.2','PYTEST_CURRENT_TEST':case+' (call)'}
    value=render(Rule('review-wire',TEST+':wire',(case,),native,pin,tuple(argv),tuple(sorted(environment.items())),str(checkout),'python-script',PIN),case,TEST+':wire',{}, {})
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
    host.intents[answer['ticket']]['execution_data']=[[str(snapshot),hashlib.sha256(body).hexdigest()]]
    return {**answer,'translated':vector,'rule':'review-wire'}
