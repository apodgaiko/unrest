"""No journal decision is consumed by a skipped empty service callback."""
from __future__ import annotations

from contextlib import contextmanager
import select
import socket
import time

from trace_tick_schedule import IDLE_SECONDS, resolver_owned_exec, root_static_table

EXEC = frozenset({'exec_memory_boundary', 'exec_attempt', 'exec_syscall_return', 'kernel_exec'})
KNOWN = EXEC | {'kernel_root', 'kernel_child', 'kernel_vfork_done', 'kernel_exit',
                'original_parent_wait4', 'original_parent_waitid', 'tracer_terminal_wait'}


def composed(owner):
    from journal_supervisor import JournalSupervisor
    from approval_orphan_custody import ApprovalSupervisor
    return type(owner) in (JournalSupervisor, ApprovalSupervisor)


@contextmanager
def fresh_census(owner):
    if not composed(owner):
        yield
        return
    previous = getattr(owner, '_journal_census_depth', 0)
    if type(previous) is not int or previous < 0:
        raise RuntimeError('journal_census_context_refused')
    owner._journal_census_depth = previous + 1
    try:
        yield
    finally:
        owner._journal_census_depth = previous


def no_producer_context(owner):
    from owned_multiprocess_authority import SourceAuthority, DependencySourceAuthority
    from linux_producers import NativeProducers
    source = getattr(owner, 'source_census_owner', None)
    if type(source) not in (SourceAuthority, DependencySourceAuthority) or source.supervisor is not owner:
        return False
    producer = source.producers
    return (type(producer) is NativeProducers and type(producer.uv) is dict
            and not producer.uv and type(producer.children) is dict and not producer.children)


def due(owner):
    trace = getattr(owner, 'owned_trace', None)
    if (not composed(owner) or not no_producer_context(owner) or not root_static_table(trace)
            or type(owner.channel) is not socket.socket or type(owner.clients) is not dict):
        return True
    if (getattr(owner, '_journal_census_depth', 0) != 0 or not trace.active
            or trace.poison or owner.poisoned or owner.clients):
        return True
    for pid, row in trace.pending.items():
        if type(row) is not dict or type(row.get('syscall')) is not int:
            return True
        number = row['syscall']
        if number not in (61, 247) and not (number == 59 and resolver_owned_exec(trace, pid)):
            return True
    if trace.records:
        row = trace.records[-1]
        if type(row) is not dict or type(row.get('kind')) is not str or row['kind'] not in KNOWN:
            return True
        if row['kind'] in EXEC and not resolver_owned_exec(trace, row.get('pid')):
            return True
    now = time.monotonic()
    previous = getattr(owner, '_journal_census_completed', None)
    if previous is not None and now < previous:
        raise RuntimeError('journal_census_clock_reversed')
    return (previous is None or now - previous >= IDLE_SECONDS
            or bool(select.select([owner.channel], [], [], 0)[0]))


def complete(owner):
    owner._journal_census_completed = time.monotonic()
