"""Strict reduction of TEST entry records; never an original certificate."""
from __future__ import annotations

import json
import hashlib
import xml.etree.ElementTree as ET

from primary_policy import TEST_CASE


def check(records, mode):
    kernel = json.loads(records['kernel-source.json'])
    provenance = json.loads(records['source-provenance.json'])
    summary = json.loads(records['summary.json'])
    collection = json.loads(records['collection.json'])
    document = ET.fromstring(records['source.xml'])
    cases = list(document.iter('testcase'))
    if (mode not in {'TEST-positive', 'TEST-poison'}
            or kernel['primary_plan']['duty'] != 'TEST-source-' + mode.removeprefix('TEST-')
            or kernel['root_parent_wait_raw'] != 0 or kernel['poison'] or kernel['primary_denials']
            or kernel['native_preinit_refusal'] or kernel['unregistered_processes']
            or kernel['receipt_ledger_poison']
            or kernel['missing_parent_waits'] or not kernel['all_commands_dispatched']
            or collection != [TEST_CASE] or provenance['collection_before'] != collection
            or provenance['collection_after'] != collection or provenance['deselected'] != 0
            or provenance['exitstatus'] != 0 or provenance['invocation_args'] != ['-q', TEST_CASE]
            or len(cases) != 1 or any(list(case) for case in cases)
            or not any(row['kind'] == 'ready' and row['token'] == 'root' for row in summary['events'])):
        raise RuntimeError('primary_source_test_original_case_not_proved')
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']]
    if not births:
        raise RuntimeError('primary_source_test_child_missing')
    for birth in births:
        waits = [row for row in kernel['records']
                 if row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
                 and (row['kind'] == 'original_parent_wait4' or row['reaps'])
                 and row['child'] == birth['child']
                 and row['parent_tgid'] == birth['identity']['ppid']]
        if len(waits) != 1:
            raise RuntimeError('primary_source_test_actual_wait_missing')
    # Require the newly bridged native source-bootstrap route, not merely a
    # primary UV query or source-free child. The original case supplies it.
    starts = [row for row in kernel['primary_records']
              if row['kind'] == 'primary_native_preinit' and row['role'] == 'source-bootstrap']
    children = [row for row in summary['events'] if row['kind'] == 'registered' and row['python']]
    if not starts or not children or not {row['pid'] for row in starts} <= {row['pid'] for row in children}:
        raise RuntimeError('primary_source_test_python_bridge_missing')
    negative = mode == 'TEST-poison'
    if (kernel['guard_poison'] is not negative or summary['ready'] is negative
            or kernel['failure_code'] != ('source_guard_refused' if negative else None)
            or bool(summary['failures']) is not negative):
        raise RuntimeError('primary_source_test_poison_lost')
    forbidden = [row for row in summary['events'] if row['kind'] == 'forbidden']
    unknown = [row for row in summary['events'] if row['kind'] == 'unknown_vector_identity'
               and row['argv_sha256'] == hashlib.sha256(json.dumps(['/bin/true']).encode()).hexdigest()
               and row['source_path'] == '/guard/finite/runtime_guard.py']
    if negative and (len(forbidden) != 1 or forbidden[0]['reason'] != 'unknown_command'
                     or len(unknown) != 1):
        raise RuntimeError('primary_source_test_wrong_refusal')
    return {'schema': 'unrest.v046.primary-source-test-proof.v1', 'mode': mode,
            'original_cases': len(cases), 'native_source_bootstraps': len(starts),
            'actual_parent_waits': len(births), 'poison_retained': negative,
            'eligible_certificate': False}
