"""Pause a real role call after admission, before transaction acquisition."""
import os
from pathlib import Path
import threading
import time

from unrest_harness import supervision
from unrest_harness.server import main

barrier = Path(os.environ['SUPERVISION_TEST_BARRIER'])


def observe(frame, event, arg):
    if event == 'call' and frame.f_code is supervision.report_supervision_checkpoint.__code__:
        (barrier / 'admitted').touch()
        cutoff = time.monotonic() + 15
        while not (barrier / 'release').exists():
            if time.monotonic() >= cutoff:
                raise RuntimeError('test admission barrier expired')
            time.sleep(.005)
    return observe


threading.settrace(observe)
main()
