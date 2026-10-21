"""Service every kernel stop; avoid full censuses on empty wait-loop spins."""
from __future__ import annotations

import time

IDLE_SECONDS = 0.010


class TickSchedule:
    def __init__(self, callback, owner):
        self.callback, self.owner = callback, owner
        self.last = None

    def service(self, *, kernel_event=False):
        if self.callback is None:
            return
        now = time.monotonic()
        if self.last is not None and now < self.last:
            raise RuntimeError('trace_service_clock_reversed')
        if not kernel_event and self.last is not None and now - self.last < IDLE_SECONDS:
            return
        # The callback and its current-byte acquisitions finish before policy,
        # effect dispatch or child resume. A failure propagates to trace cleanup.
        self.callback(self.owner)
        self.last = time.monotonic()
