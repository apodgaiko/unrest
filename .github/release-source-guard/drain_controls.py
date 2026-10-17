"""Check the actual failed source run; a control pass is not source acceptance."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET


def check(raw: dict[str, bytes], source_exit: int) -> dict:
    assert source_exit == 2
    kernel = json.loads(raw['kernel-source.json'])
    summary = json.loads(raw['summary.json'])
    cases = ET.fromstring(raw['source.xml']).findall('.//testcase')
    assert len(cases) == 1
    assert cases[0].get('name') == 'test_composed_restart_stop_replacement_and_cancel_are_distinct'
    assert cases[0].find('failure') is not None
    assert cases[0].find('skipped') is None and cases[0].find('error') is None
    assert summary['original_pytest_exit_code'] == 1 and summary['actual_custodian_status'] == 1
    assert kernel['root_parent_wait_raw'] == 2 << 8
    assert kernel['guard_poison'] is True and kernel['poison'] == [] and 'failure' not in kernel
    assert 'stale_or_foreign_receipt_binding' in kernel['receipt_ledger_poison']
    events = kernel['source_events']
    expected = {'stale', 'foreign', 'late', 'source', 'identity'}
    for kind in ('preexit_adversarial_refusal', 'preexit_caught_refusal_poison'):
        rows = [event for event in events if event['kind'] == kind]
        assert len(rows) == 5 and {row['control'] for row in rows} == expected
    drains = [event for event in events if event['kind'] == 'actual_parent_preexit_drain']
    assert len(drains) == 1
    drain = drains[0]
    assert drain['original_return'] == 2 and drain['poison_preserved'] is True
    assert len(drain['children']) == 2
    assert drain['numeric_returncodes'] == {str(pid): -15 for pid in drain['children']}
    registered = [event for event in events if event['kind'] == 'registered']
    raw_waits = [event for event in events if event['kind'] == 'raw_actual_parent_waitpid']
    numeric = [event for event in events if event['kind'] == 'actual_waitpid']
    kernel_waits = [event for event in kernel['records'] if event['kind'] == 'original_parent_wait4']
    for registration in registered:
        owner, child = registration['owner_pid'], registration['pid']
        raw_matches = [event for event in raw_waits if event['owner_pid'] == owner and event['pid'] == child]
        waits = [event for event in numeric if event['owner_pid'] == owner and event['pid'] == child]
        actual = [event for event in kernel_waits if event['parent_tgid'] == owner and event['child'] == child]
        assert len(raw_matches) == len(waits) == len(actual) == 1
        raw_wait, waited, observed = raw_matches[0], waits[0], actual[0]
        assert raw_wait['child_token'] == registration['token']
        assert raw_wait['raw_status'] == observed['raw']
        assert raw_wait['numeric_returncode'] == waited['numeric_returncode'] == observed['normalized']
        if owner == drain['owner_pid'] and child in drain['children']:
            assert raw_wait['raw_status'] == 15 and raw_wait['numeric_returncode'] == -15
    assert len(registered) >= 7
    processes = [event for event in kernel['records'] if event['kind'] == 'kernel_child'
                 and event['identity']['tgid'] == event['child']]
    for birth in processes:
        actual = [event for event in kernel_waits if event['child'] == birth['child']
                  and event['parent_tgid'] == birth['identity']['ppid']]
        assert len(actual) == 1
    return {'scope': 'negative failure-drain controls; original source FAILED',
            'controls': sorted(expected), 'original_pytest_exit_code': 1,
            'original_source_exit_code': source_exit, 'custodian_returncode': 1,
            'worker_original_return': 2, 'registered_actual_waits': len(registered),
            'kernel_process_actual_waits': len(processes), 'sticky_poison': True,
            'source_checkpoint_ready': False, 'selected_carrier': None}
