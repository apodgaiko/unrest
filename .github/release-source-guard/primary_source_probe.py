"""Strict reduction of TEST entry records; never an original certificate."""
from __future__ import annotations

import json
import hashlib
import xml.etree.ElementTree as ET

from primary_policy import TEST_SELECTIONS, TEST_SEAM_CASES
from preflight_policy import CASES as PREFLIGHT_CASES


def check(records, mode, *, require_faults=False):
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
        refused = check_integration_probes(summary, kernel) if require_faults else None
        settled_trackers = [row for row in trackers if row['pid'] != refused]
        if len(settled_trackers) != (5 if require_faults else 1) or (
                require_faults and len(trackers) != 6):
            raise RuntimeError('preflight_actual_tracker_missing')
        pid = trackers[0]['pid']
        ready = [row for row in kernel['receipts']
                 if row['request']['kind'] == 'ready' and row.get('ok')]
        registered = [row for row in summary['events'] if row['kind'] == 'registered']
        for child in registered:
            if child['python'] is False:
                if (child['class'] != 'source-current-binding-git'
                        or child['case'] != PREFLIGHT_CASES[1]
                        or child.get('owner_READY_required') is not True
                        or child.get('native_child_READY') !=
                        'not applicable only under approved exact ordinary native leaf disposition'):
                    raise RuntimeError('preflight_unexpected_native_leaf')
                # Native leaves retain exact exec/custody and actual-parent
                # waits above; they cannot emit a Python endpoint receipt.
                continue
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
        for tracker in settled_trackers:
            pid = tracker['pid']
            if not any(row['kind'] == 'raw_actual_parent_waitpid' and row['pid'] == pid
                       and type(row['raw_status']) is int and row['raw_status'] == 0
                       for row in summary['events']):
                raise RuntimeError('preflight_actual_tracker_wait_missing')
            if not any(row['kind'] == 'ready' and row.get('owner_pid') == pid for row in summary['events']):
                raise RuntimeError('preflight_tracker_ready_missing')
        if require_faults:
            faults = [row for row in summary['events'] if row['kind'] == 'owned_acquisition_fault']
            if (len(faults) != 4 or {row['operation'] for row in faults}
                    != {'dup', 'fstat', 'get_inheritable', 'set_inheritable'}
                    or len({row['tracker_pid'] for row in faults}) != 4):
                raise RuntimeError('preflight_acquisition_faults_missing')
            for fault in faults:
                birth = next((row for row in births if row['child'] == fault['tracker_pid']), None)
                if (birth is None or birth['identity']['ppid'] != fault['parent']
                        or fault['tracker_pid'] not in {row['pid'] for row in trackers}
                        or fault['before_fds'] != fault['after_fds']
                        or fault['original_exception_preserved'] is not True or fault['errno'] != 24
                        or len(fault['pipe_identity']) != 3):
                    raise RuntimeError('preflight_acquisition_fault_binding')
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


def check_integration_probes(summary, kernel):
    """New own-identity probes supplement all five original successful trackers."""
    events = summary['events']
    refused = [row for row in events if row['kind'] == 'guard_refused_acquisition_proof']
    rollbacks = [row for row in events if row['kind'] == 'multiprocess_refused_acquisition_wait']
    if len(refused) != 1 or len(rollbacks) != 1:
        raise RuntimeError('preflight_refused_acquisition_missing')
    proof, rollback = refused[0], rollbacks[0]
    pid = proof['child_pid']
    if (rollback['pid'] != pid or rollback['raw_status'] != 9
            or rollback['numeric_returncode'] != -9
            or proof['before_fds'] != proof['after_fds']
            or proof['original_exception_preserved'] is not True
            or rollback['original_exception_preserved'] is not True):
        raise RuntimeError('preflight_refused_acquisition_binding')
    waits = [row for row in events if row['kind'] == 'raw_actual_parent_waitpid' and row['pid'] == pid]
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['child'] == pid and row['identity']['tgid'] == pid]
    if (len(waits) != 1 or waits[0]['raw_status'] != 9 or len(births) != 1
            or births[0]['identity']['ppid'] != rollback['owner_pid']):
        raise RuntimeError('preflight_refused_acquisition_actual_wait')
    leases = [row for row in events if row['kind'] == 'guard_lease_factory_proof']
    if len(leases) != 4 or {row['mode'] for row in leases} != {'ignore', 'cleanup', 'spawn', 'registration'}:
        raise RuntimeError('preflight_lease_factory_missing')
    for lease in leases:
        child = lease['child_pid']
        if (lease['child_returncode'] != (-9 if lease['mode'] == 'ignore' else -15) or lease['before_fds'] != lease['after_fds']
                or lease['closed'] is not True or lease['quarantine'] is not (lease['mode'] == 'cleanup')):
            raise RuntimeError('preflight_lease_factory_binding')
        consumption = [row for row in events if row['kind'] == 'source_lease_startup_consumption'
                       and row['factory']['mode'] == lease['mode']]
        if len(consumption) != 1 or consumption[0]['environment'] != {}:
            raise RuntimeError('preflight_lease_consumption_missing')
        consumed = consumption[0]
        registered = [row for row in events if row['kind'] == 'registered'
                      and row['pid'] == child and row['token'] == consumed['launch_token']
                      and row['class'] == 'source-lease-owned-child']
        if len(registered) != 1:
            raise RuntimeError('preflight_lease_consumption_binding')
    shared = [row for row in events if row['kind'] == 'guard_shared_binding_probe']
    routes = [row for row in events if row['kind'] == 'exact_current_binding_registration']
    if (len(shared) != 1 or shared[0]['path_count'] < 2 or len(routes) != 2
            or {row['source_binding']['line'] for row in routes} != {36, 57}
            or any(row['source_binding']['path'] != '/source/tools/release_binding.py'
                   or row['source_binding']['sha256'] != shared[0]['original_source_sha256']
                   or row['owner'] != PREFLIGHT_CASES[1] for row in routes)):
        raise RuntimeError('preflight_shared_route_missing')
    return pid
