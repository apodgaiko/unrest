"""Strict reduction of TEST entry records; never an original certificate."""
from __future__ import annotations

import json
import hashlib
import xml.etree.ElementTree as ET

from primary_policy import TEST_SELECTIONS, TEST_SEAM_CASES
from preflight_policy import CASES as PREFLIGHT_CASES


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
            or tuple(collection) not in TEST_SELECTIONS or provenance['collection_before'] != collection
            or provenance['collection_after'] != collection or provenance['deselected'] != 0
            or provenance['exitstatus'] != 0 or provenance['invocation_args'] != ['-q', *collection]
            or len(cases) != len(collection) or any(list(case) for case in cases)
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
    if tuple(collection) == TEST_SEAM_CASES:
        events = summary['events']
        ordinary = {row['class'] for row in events
                    if row['kind'] == 'source_ordinary_startup_consumption'}
        references = {row['class'] for row in events
                      if row['kind'] == 'source_reference_startup_consumption'}
        consumers = {row['class'] for row in events
                     if row['kind'] == 'source_producer_python_startup_consumption'}
        if ('source-composed-adapter' not in ordinary
                or references != {'reference-integrity:' + name for name in
                                  ('test_skips', 'test_fails', 'test_waits', 'test_passes')}
                or not {'source-checker', 'source-extracted-oracle',
                        'source-installed-provider-matrix'} <= consumers):
            raise RuntimeError('primary_source_affected_seams_missing')
    if tuple(collection) == PREFLIGHT_CASES:
        trackers = [row for row in summary['events'] if row['kind'] == 'registered'
                    and row.get('class') == 'source-multiprocess-tracker']
        if len(trackers) != 1:
            raise RuntimeError('preflight_actual_tracker_missing')
        pid = trackers[0]['pid']
        ready = [row for row in kernel['receipts']
                 if row['request']['kind'] == 'ready' and row.get('ok')]
        registered = [row for row in summary['events'] if row['kind'] == 'registered']
        for child in registered:
            observations = [row for row in ready if row['request']['pid'] == child['pid']]
            if len(observations) != 1:
                raise RuntimeError('preflight_authenticated_ready_missing')
            receipt = observations[0]
            if (receipt['identity'] != receipt['kernel_peer']['birth']
                    or receipt['identity']['uid'] != receipt['kernel_peer']['uid']
                    or receipt['identity']['uid'] != 20000):
                raise RuntimeError('preflight_authenticated_ready_identity')
            complete = [row for row in summary['events']
                        if row['kind'] == 'endpoint_install_complete'
                        and row['owner_pid'] == child['pid']]
            if len(complete) != 1 or complete[0]['nonce'] != receipt['request']['nonce']:
                raise RuntimeError('preflight_authenticated_ready_nonce')
        if not any(row['kind'] == 'raw_actual_parent_waitpid' and row['pid'] == pid
                   and type(row['raw_status']) is int and row['raw_status'] == 0
                   for row in summary['events']):
            raise RuntimeError('preflight_actual_tracker_wait_missing')
        if not any(row['kind'] == 'ready' and row.get('owner_pid') == pid for row in summary['events']):
            raise RuntimeError('preflight_tracker_ready_missing')
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
