"""Read-only lifecycle observations; absence never supplies a numeric wait."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from approval_orphan_custody import CASES, CLASSES
from finite.linux_identity import identity


def snapshot(pid):
    before = identity(pid)
    status = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines())
    after = identity(pid)
    if before != after:
        raise RuntimeError('approval_exit_observation_identity_changed')
    return {**before, 'uids': [int(value) for value in status['Uid'].split()]}


def process_absent(pid):
    return not Path('/proc', str(pid)).exists()


def collect(authority, trace):
    start = getattr(authority, '_approval_exit_observation_index', 0)
    end = len(trace.records)
    if start > end:
        raise RuntimeError('approval_exit_observation_trace_rewound')
    for index in range(start, end):
        row = trace.records[index]
        if row['kind'] not in {'kernel_exit', 'tracer_terminal_wait'}:
            continue
        pid = row['pid']
        selected = getattr(authority, 'bound', {}).get(pid)
        if selected is None or selected['registration'].get('class') not in CLASSES:
            continue
        registrations = [event for event in authority.supervisor.events()
                         if event['kind'] == 'registered' and event['pid'] == pid]
        if len(registrations) != 1 or registrations[0].get('case') not in CASES:
            continue
        evidence = {'kind': 'approval_exit_observation', 'pid': pid,
                    'phase': row['kind'], 'case': registrations[0]['case'],
                    'class': selected['registration']['class'],
                    'observer_pid': os.getpid(), 'observer_uid': os.getuid(),
                    'trace_index': index,
                    'trace_row_sha256': hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest(),
                    'raw': row['raw'], 'numeric_wait_observed': row['kind'] == 'tracer_terminal_wait',
                    'eligible_certificate': False}
        if row['kind'] == 'kernel_exit':
            try:
                evidence['current_identity'] = snapshot(pid)
            except (OSError, ValueError, RuntimeError) as error:
                evidence['unavailable'] = type(error).__name__
        else:
            evidence['process_absent_after_actual_wait'] = process_absent(pid)
        authority.pipe_records.append(evidence)
    authority._approval_exit_observation_index = end
