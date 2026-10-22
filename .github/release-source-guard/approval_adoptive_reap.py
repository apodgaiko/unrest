"""Reap only kernel-proven controlled zombies actually adopted by this observer."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from approval_orphan_custody import CLASSES, proof
from finite.linux_identity import identity


def zombie(pid):
    rows = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines())
    return rows['State'].split()[0] == 'Z' and [int(value) for value in rows['Uid'].split()] == [20000] * 4


def reap(authority, trace):
    start = getattr(authority, '_adoptive_record_count', 0)
    end = len(trace.records)
    if start == end and not getattr(authority, '_adoptive_pending', {}):
        return
    now = time.monotonic()
    if start == end and now < getattr(authority, '_adoptive_retry_at', 0):
        return
    authority._adoptive_retry_at = now + 0.02
    if start > end:
        raise RuntimeError('approval_adoptive_trace_rewound')
    pending = getattr(authority, '_adoptive_pending', {})
    terminal = getattr(authority, '_adoptive_terminal', {})
    for index in range(start, end):
        row = trace.records[index]
        if row['kind'] == 'tracer_terminal_wait':
            terminal[row['pid']] = index
            selected = getattr(authority, 'bound', {}).get(row['pid'])
            if selected is not None and selected['registration'].get('class') in CLASSES:
                pending[row['pid']] = index
        elif (row['kind'] == 'original_parent_wait4'
              or row['kind'] == 'original_parent_waitid' and row['reaps']):
            pending.pop(row['child'], None)
    authority._adoptive_record_count = end
    authority._adoptive_pending, authority._adoptive_terminal = pending, terminal
    for pid, index in sorted(list(pending.items())):
        saved = authority.supervisor.registered.get(pid)
        if saved is None or pid in trace.active:
            continue
        parent = saved['identity']['ppid']
        if parent not in terminal:
            continue
        try:
            current = identity(pid)
        except FileNotFoundError:
            pending.pop(pid)
            continue  # Absence never creates a numeric wait record.
        if current['ppid'] != os.getpid():
            continue  # The original parent retains its own wait authority.
        evidence = proof(authority.supervisor, pid, saved['identity'], current, 'drain_child')
        if evidence is None or not zombie(pid) or identity(pid) != current:
            continue
        waited, raw = os.waitpid(pid, os.WNOHANG)
        if waited == 0:
            continue
        row = trace.records[index]
        record = {'kind': 'actual_adoptive_parent_wait4', 'pid': waited,
                  'observer_pid': os.getpid(), 'observer_uid': os.getuid(),
                  'raw': raw, 'normalized': os.waitstatus_to_exitcode(raw),
                  'current_identity': current, 'original_birth': saved['identity'],
                  'parent_death': evidence, 'tracer_wait_index': index,
                  'trace_record_count_at_actual_wait': end,
                  'tracer_wait_sha256': hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest(),
                  'process_absent_after_actual_wait': not Path('/proc', str(pid)).exists(),
                  'source_checkpoint_ready': False}
        authority.pipe_records.append(record)
        pending.pop(pid)
        if (waited != pid or raw != row['raw']
                or record['normalized'] != row['normalized']):
            raise RuntimeError('approval_adoptive_actual_wait_status_drift')
