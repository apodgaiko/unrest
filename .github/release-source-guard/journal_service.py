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
    if (type(producer) is not NativeProducers or type(producer.uv) is not dict
            or type(producer.children) is not dict):
        return False
    if not producer.uv and not producer.children:
        return True
    # Completed entries remain in the original producer maps. Recompute from
    # live maps on every callback; completion grants no launch authority.
    if (type(getattr(producer, 'common', None)) is not dict or type(getattr(producer, 'cache_completed', None)) is not set
            or type(getattr(producer, 'response_receipts', None)) is not dict
            or (producer.cache_current is not None and type(producer.cache_current) is not dict)
            or (producer.common.get('primary_producer') is not None
                and type(producer.common['primary_producer']) is not dict)
            or any(type(pid) is not int for pid in producer.cache_completed)
            or any(type(pid) is not int for pid in producer.response_receipts)):
        return False
    uv_fields = {'pid', 'identity', 'owner_pid', 'launch_token', 'token', 'operation',
                 'record_sha256', 'profile', 'binding', 'seen_requests', 'children'}
    child_fields = {'kind', 'pid', 'parent', 'identity', 'role', 'helper', 'token',
                    'profile_sha256', 'original_argv_sha256', 'environment_sha256',
                    'flags', 'cwd', 'source_operation_token'}
    for pid, context in producer.uv.items():
        if (type(pid) is not int or type(context) is not dict or set(context) != uv_fields
                or type(context['pid']) is not int or context['pid'] != pid
                or type(context['children']) is not list
                or type(context['seen_requests']) is not set
                or any(type(context[key]) is not dict for key in ('identity', 'profile', 'binding'))
                or type(context['operation']) is not str
                or context['operation'] not in {'source-build', 'source-install'}
                or any(type(child) is not dict or type(child.get('pid')) is not int
                       or producer.children.get(child['pid']) != child
                       for child in context['children'])):
            return False
    for pid, child in producer.children.items():
        if (type(pid) is not int or type(child) is not dict or set(child) != child_fields
                or type(child['pid']) is not int or child['pid'] != pid or type(child['parent']) is not int
                or child['parent'] not in producer.uv
                or child not in producer.uv[child['parent']]['children']
                or type(child['role']) is not str
                or child['role'] not in {'isolated-uv-helper', 'isolated-uv-query'}):
            return False
    return ((producer.cache_current is None or all(pid in producer.cache_completed for pid in producer.uv))
            and (not producer.common.get('primary_producer')
                 or all(child['role'] != 'isolated-uv-helper' or pid in producer.response_receipts
                        for pid, child in producer.children.items())))


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


@contextmanager
def producer_census(owner):
    """A pending producer keeps original service even if this tick completes it."""
    if no_producer_context(owner):
        yield
    else:
        with fresh_census(owner):
            yield
