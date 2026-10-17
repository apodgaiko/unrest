"""Verify a caught producer refusal before the unchanged original query body.

The source JUnit remains failed. Only this negative guard control may pass.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def check(log: Path, source_exit: int) -> dict:
    lines = [line for line in log.read_text().splitlines() if line.startswith('PRIVATE-EVIDENCE:')]
    assert len(lines) == 1 and source_exit == 2
    raw = {name: base64.b64decode(body, validate=True)
           for name, body in json.loads(lines[0].split(':', 1)[1]).items()}
    kernel = json.loads(raw['kernel-source.json'])
    assert kernel['guard_poison'] is True and kernel['poison'] == [] and 'failure' not in kernel
    events = kernel['source_events']
    refusals = [row for row in events if row['kind'] == 'native_producer_caught_refusal']
    assert len(refusals) == 1 and refusals[0]['role'] == 'isolated-uv-query'
    forbidden = {'query_original_dispatch', 'query_actual_main_call', 'query_actual_main_return',
                 'isolated_original_dispatch', 'operation_settled'}
    assert not any(row['kind'] in forbidden for row in events)
    child = refusals[0]['owner_pid']
    assert any(row['kind'] == 'descriptor_closure' and row['owner_pid'] == child
               and row['nonstdio_open_count'] == 0 for row in events)
    native = [row for row in kernel['native_source_records'] if row['kind'] == 'native_source_child']
    assert len(native) == 1 and native[0]['pid'] == child
    waits = [row for row in kernel['records'] if row['kind'] == 'original_parent_wait4']
    matching = [row for row in waits if row['child'] == child
                and row['parent_tgid'] == native[0]['parent']]
    assert len(matching) == 1 and matching[0]['raw'] == 86 << 8 and matching[0]['normalized'] == 86
    births = [row for row in kernel['records'] if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']]
    for birth in births:
        assert len([row for row in waits if row['child'] == birth['child']
                    and row['parent_tgid'] == birth['identity']['ppid']]) == 1
    assert kernel['root_parent_wait_raw'] == 2 << 8
    cases = ET.fromstring(raw['source.xml']).findall('.//testcase')
    assert len(cases) == 1 and cases[0].find('error') is not None
    assert cases[0].find('skipped') is None
    summary = json.loads(raw['summary.json'])
    assert summary['original_pytest_exit_code'] == 1
    return {'scope': 'caught unknown producer launch refused before original query; source FAILED',
            'original_source_exit_code': source_exit, 'query_exit_raw': matching[0]['raw'],
            'query_exit_normalized': matching[0]['normalized'], 'source_body_dispatched': False,
            'all_kernel_process_parent_waits': len(births), 'guard_poison_retained': True,
            'source_checkpoint_ready': False, 'selected_carrier': None}
