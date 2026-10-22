"""Verify real adoptive waits for the six controlled owner-death cases.

The original missing-parent inventory stays intact. A disappearance or a tracer
status alone never proves a legal parent wait.
"""
from __future__ import annotations

import hashlib
import json
import os

# This reducer also runs on the host before the source-only capsule starts.
# Import no runtime guard/finite modules here: their bytecode cache would poison
# the later source-only support mount. Controls bind these literals to policy.
CLASSES = frozenset({'source-approval-adapter', 'source-approval-relay',
                     'source-approval-python-backend', 'source-approval-mcp'})
CASES = frozenset('tests/test_approval_recovery.py::test_durable_run_owner_and_restart_never_revives[' + mode + ']'
                  for mode in ('cancel', 'crash', 'cancel_after_send', 'crash_after_send',
                               'cancel_after_continue', 'crash_after_continue'))


IMMUTABLE = ('pid', 'start_ticks', 'boot_id', 'clock_ticks_per_second')


def unique(rows):
    if len(rows) != 1:
        raise ValueError('unique custody evidence required')
    return rows[0]


def digest(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()


def original_missing(kernel):
    rows = kernel['records']
    births = [row for row in rows if row['kind'] == 'kernel_child'
              and row['identity']['tgid'] == row['child']]
    return sorted(birth['child'] for birth in births if len([
        row for row in rows if row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
        and (row['kind'] == 'original_parent_wait4' or row['reaps'])
        and row['child'] == birth['child']
        and row['parent_tgid'] == birth['identity']['ppid']]) != 1)


def verify(kernel, pid):
    rows, events = kernel['records'], kernel['source_events']
    if any(row['kind'] in {'original_parent_wait4', 'original_parent_waitid'}
           and row.get('child') == pid for row in rows):
        return None  # Adoption never repairs duplicate or contradictory parent waits.
    pipes = kernel['source_pipe_records']
    birth_index, birth_row = unique([(i, r) for i, r in enumerate(rows)
        if r['kind'] == 'kernel_child' and r['child'] == pid and r['identity']['tgid'] == pid])
    birth = birth_row['identity']
    registration = unique([r for r in events if r['kind'] == 'registered' and r['pid'] == pid])
    ready = unique([r for r in events if r['kind'] == 'ready' and r['owner_pid'] == pid])
    installed = unique([r for r in events if r['kind'] == 'endpoint_install_complete'
                        and r['owner_pid'] == pid])
    saved = installed['identity']
    case = registration['case']
    if not (case in CASES and registration['class'] in CLASSES
            and ready['case'] == installed['case'] == case
            and ready['class'] == registration['class']
            and ready['token'] == installed['token'] == registration['token']
            and registration['owner_pid'] == ready['parent_pid'] == saved['ppid'] == birth['ppid']
            and all(saved[key] == birth[key] for key in IMMUTABLE)
            and saved['uid'] == 20000 and birth['uids'] == [20000] * 4):
        return None
    for phase in ('setup', 'call', 'teardown'):
        outcome = unique([r for r in events if r['kind'] == 'test_outcome'
                          and r['nodeid'] == case and r['phase'] == phase])
        if outcome['outcome'] != 'passed':
            return None
    parent = saved['ppid']
    parent_registration = unique([r for r in events if r['kind'] == 'registered' and r['pid'] == parent])
    parent_birth_index, parent_birth_row = unique([(i, r) for i, r in enumerate(rows)
        if r['kind'] == 'kernel_child' and r['child'] == parent])
    parent_birth = parent_birth_row['identity']
    parent_terminal_index, parent_terminal = unique([(i, r) for i, r in enumerate(rows)
        if r['kind'] == 'tracer_terminal_wait' and r['pid'] == parent])
    parent_exit_index, parent_exit = unique([(i, r) for i, r in enumerate(rows)
        if r['kind'] == 'kernel_exit' and r['pid'] == parent])
    raw = parent_terminal['raw']
    if not (type(raw) is int and os.WIFSIGNALED(raw) and os.WTERMSIG(raw) in (9, 15)
            and parent_birth_index < birth_index < parent_exit_index < parent_terminal_index
            and parent_exit['raw'] == raw
            and parent_terminal['normalized'] == os.waitstatus_to_exitcode(raw)
            and parent_registration['case'] == case
            and all(parent_terminal['identity'][key] == parent_birth[key] for key in IMMUTABLE)
            and parent_terminal['identity']['uids'] == [20000] * 4):
        return None
    if ((os.WTERMSIG(raw) == 9 and (parent_registration['class'] != 'source-run-worker' or '[crash' not in case))
            or (os.WTERMSIG(raw) == 15 and '[cancel' not in case)):
        return None
    terminal_index, terminal = unique([(i, r) for i, r in enumerate(rows)
                                      if r['kind'] == 'tracer_terminal_wait' and r['pid'] == pid])
    child_exit_index, child_exit = unique([(i, r) for i, r in enumerate(rows)
                                          if r['kind'] == 'kernel_exit' and r['pid'] == pid])
    if not (type(terminal['raw']) is int and child_exit['raw'] == terminal['raw']
            and terminal['normalized'] == os.waitstatus_to_exitcode(terminal['raw'])
            and birth_index < child_exit_index < terminal_index
            and all(terminal['identity'][key] == saved[key] for key in IMMUTABLE)):
        return None
    second = [r for r in pipes if r['kind'] == 'actual_adoptive_parent_wait4' and r['pid'] == pid]
    if second:
        wait = unique(second)
        current = wait['current_identity']
        valid = (wait['original_birth'] == saved and wait['observer_pid'] == current['ppid'] == 1
                 and wait['observer_uid'] == 20001
                 and type(wait['pid']) is int and type(wait['normalized']) is int
                 and type(wait['raw']) is int and wait['raw'] == terminal['raw'] and wait['normalized'] == terminal['normalized']
                 and type(wait['trace_record_count_at_actual_wait']) is int
                 and max(terminal_index, parent_terminal_index) < wait['trace_record_count_at_actual_wait'] <= len(rows)
                 and wait['tracer_wait_index'] == terminal_index
                 and wait['tracer_wait_sha256'] == digest(terminal)
                 and wait['process_absent_after_actual_wait'] is True
                 and set(current) == set(saved)
                 and all(current[key] == saved[key] for key in saved if key != 'ppid')
                 and wait['parent_death']['parent_terminal'] == parent_terminal
                 and wait['parent_death']['parent_kernel_exit'] == parent_exit
                 and wait['parent_death']['case'] == case)
        return {'pid': pid, 'method': 'actual_adoptive_parent_wait4', 'raw': terminal['raw']} if valid else None
    exited = unique([r for r in pipes if r['kind'] == 'approval_exit_observation'
                     and r['pid'] == pid and r['phase'] == 'kernel_exit'])
    waited = unique([r for r in pipes if r['kind'] == 'approval_exit_observation'
                     and r['pid'] == pid and r['phase'] == 'tracer_terminal_wait'])
    current = exited['current_identity']
    valid = (parent_exit_index < child_exit_index and parent_terminal_index < terminal_index
             and exited['numeric_wait_observed'] is False
             and type(exited['raw']) is int and exited['raw'] == child_exit['raw']
             and type(waited['raw']) is int and waited['raw'] == terminal['raw']
             and exited['trace_index'] == child_exit_index and exited['trace_row_sha256'] == digest(child_exit)
             and waited['trace_index'] == terminal_index and waited['trace_row_sha256'] == digest(terminal)
             and exited['observer_pid'] == waited['observer_pid'] == current['ppid'] == 1
             and exited['observer_uid'] == waited['observer_uid'] == 20001
             and exited['case'] == waited['case'] == case
             and exited['class'] == waited['class'] == registration['class']
             and current['uids'] == [20000] * 4
             and all(current[key] == saved[key] for key in saved if key != 'ppid')
             and waited['numeric_wait_observed'] is True
             and waited['process_absent_after_actual_wait'] is True)
    return {'pid': pid, 'method': 'adoptive_tracer_terminal_wait', 'raw': terminal['raw']} if valid else None


def adopted_waits(kernel):
    result = {}
    for pid in original_missing(kernel):
        try:
            proof = verify(kernel, pid)
        except (KeyError, TypeError, ValueError, IndexError):
            proof = None
        if proof is not None:
            result[pid] = proof
    return result


def unresolved(kernel):
    try:
        missing = original_missing(kernel)
    except (KeyError, TypeError, ValueError):
        return [-1]
    recorded = kernel.get('missing_parent_waits')
    if (type(recorded) is not list or any(type(pid) is not int or pid <= 0 for pid in recorded)
            or recorded != missing):
        return [-1]  # An inconsistent raw inventory cannot be reconciled.
    return sorted(set(missing) - set(adopted_waits(kernel)))


def summary_closed(summary, kernel):
    if unresolved(kernel):
        return False
    if summary['ready'] is True and summary['failures'] == []:
        return True
    failures = summary['failures']
    adopted = adopted_waits(kernel)
    return (summary.get('original_pytest_exit_code') == 0 and bool(failures)
            and all(set(row) == {'kind', 'owner_pid', 'pid'} and row['kind'] == 'missing_wait'
                    and row['pid'] in adopted
                    and any(event['kind'] == 'registered' and event['pid'] == row['pid']
                            and event['owner_pid'] == row['owner_pid'] for event in kernel['source_events'])
                    for row in failures)
            and len({row['pid'] for row in failures}) == len(failures))
