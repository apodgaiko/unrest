"""Idle source callback scheduling, with explicit decision and final barriers."""
from __future__ import annotations

import select
import time

IDLE_SECONDS = 0.100


def root_static_table(trace):
    from linux_trace import OwnedTrace
    return (type(trace) is OwnedTrace and type(trace.child) is int
            and type(trace.allowed) is list and bool(trace.allowed)
            and all(type(row) is dict and type(row.get('pid')) is int
                    and row['pid'] == trace.child for row in trace.allowed))


def resolver_owned_exec(trace, pid):
    """The current primary static table cannot admit this nonroot PID."""
    return root_static_table(trace) and type(pid) is int and pid != trace.child


def record_progress(trace):
    """Ignore only a short trailing suffix already covered by source admission."""
    end = len(trace.records)
    while end:
        row = trace.records[end - 1]
        if type(row) is not dict or not resolver_owned_exec(trace, row.get('pid')):
            break
        kind = row.get('kind')
        if type(kind) is not str:
            break
        if (kind == 'exec_memory_boundary'
                and set(row) == {'kind', 'pid', 'path_address', 'argv_address',
                                 'environment_address', 'observer_identity', 'tracee_identity'}
                and all(type(row[key]) is int for key in (
                    'path_address', 'argv_address', 'environment_address'))
                and type(row['observer_identity']) is dict and type(row['tracee_identity']) is dict):
            pass
        elif (kind == 'exec_attempt' and row.get('accepted') is True
              and set(row) == {'kind', 'pid', 'path', 'argv', 'cwd', 'environment', 'accepted'}
              and type(row['path']) is str and type(row['argv']) is list
              and type(row['cwd']) is str and type(row['environment']) is dict):
            pass
        elif (kind == 'exec_syscall_return' and set(row) == {'kind', 'pid', 'return'}
              and type(row.get('return')) is int and row['return'] == 0):
            pass
        else:
            break
        end -= 1
    return end


def progress(trace):
    # The tracer still observes both stops and the actual result of every wait.
    # Merely entering/leaving wait4 or waitid grants no launch authority. An
    # actual result, image transition, receipt, child change or poison remains immediate;
    # otherwise use the bounded hundred-millisecond idle acquisition period.
    pending = frozenset(pid for pid, row in trace.pending.items()
                        if type(row) is not dict or type(row.get('syscall')) is not int
                        or row['syscall'] not in (61, 247)
                        and not (row['syscall'] == 59 and resolver_owned_exec(trace, pid)))
    return (record_progress(trace), frozenset(trace.active), pending, tuple(trace.poison))


class TickSchedule:
    def __init__(self):
        self.last = None
        self.observed = None

    def due(self, trace, supervisor):
        now = time.monotonic()
        if self.last is not None and now < self.last:
            raise RuntimeError('source_poll_clock_reversed')
        return (self.last is None or not trace.active or supervisor.poisoned
                or bool(supervisor.clients) or progress(trace) != self.observed
                or bool(select.select([supervisor.channel], [], [], 0)[0])
                or now - self.last >= IDLE_SECONDS)

    def complete(self, trace):
        self.observed = progress(trace)
        self.last = time.monotonic()
