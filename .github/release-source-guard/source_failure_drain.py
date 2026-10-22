"""Enter the existing owned failure drain only after the real root has failed."""
from __future__ import annotations

import os


def check(trace):
    raw = getattr(trace, 'root_parent_wait', None)
    if raw is None or raw == 0 or not trace.active:
        return
    rows = [row for row in trace.records if row['kind'] == 'tracer_terminal_wait'
            and row['pid'] == trace.child]
    if (type(raw) is not int or not (os.WIFEXITED(raw) or os.WIFSIGNALED(raw))
            or len(rows) != 1 or rows[0]['raw'] != raw
            or rows[0]['normalized'] != os.waitstatus_to_exitcode(raw)):
        raise RuntimeError('failed_source_root_wait_binding')
    # OwnedTrace's unchanged finally block kills/reaps its attached tasks and
    # retains their actual statuses. No passing or live root takes this path.
    raise RuntimeError('failed_source_root_has_live_owned_descendants')
