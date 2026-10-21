"""Idle source callback scheduling, with explicit decision and final barriers."""
from __future__ import annotations

import select
import time

IDLE_SECONDS = 0.010


def progress(trace):
    return (len(trace.records), frozenset(trace.active), frozenset(trace.pending), tuple(trace.poison))


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
