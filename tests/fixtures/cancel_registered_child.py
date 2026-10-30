"""A direct child whose cancellation cleanup has an explicit test barrier."""
from pathlib import Path
import signal
import time


def stop(signum, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path('child-cleanup-started').write_text('started')
    while not Path('allow-child-exit').exists():
        time.sleep(0.01)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
Path('child-ready').write_text('ready')
while True:
    time.sleep(0.01)
