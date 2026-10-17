"""Observe real role lock contention without substituting calls or outcomes."""
import inspect
import os
import threading
from pathlib import Path

from unrest_harness import supervision
from unrest_harness.server import main

barrier = Path(os.environ["SUPERVISION_TEST_BARRIER"])
lines, start = inspect.getsourcelines(supervision._supervision_transaction)
contended_line = start + next(
    i for i, line in enumerate(lines) if '_fault(fault, "supervision_transaction_contended")' in line
)
lines, start = inspect.getsourcelines(supervision._recover_supervision_locked)
pending_line = start + next(
    i for i, line in enumerate(lines) if "pending = _append_receipt(" in line
)


def observe(frame, event, arg):
    if event == "line":
        if (
            frame.f_code is supervision._supervision_transaction.__wrapped__.__code__
            and frame.f_lineno == contended_line
        ):
            (barrier / "contended").touch()
        if (
            frame.f_code is supervision._recover_supervision_locked.__code__
            and frame.f_lineno == pending_line
        ):
            (barrier / "missing-pending").touch()
    return observe


threading.settrace(observe)
main()
