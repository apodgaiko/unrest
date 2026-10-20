"""Own-identity constructor probe through the unchanged production guard."""
from __future__ import annotations

import os
import subprocess
import sys


def probe():
    guard = sys.modules['runtime_guard']
    before = len(os.listdir('/proc/self/fd'))
    result = subprocess.run([sys.executable, '-I', '-S', '-c', 'pass'], check=True)
    assert result.returncode == 0
    after = len(os.listdir('/proc/self/fd'))
    assert before == after
    rows = guard.summarize(guard._STATE['manifest_path'])['events']
    selected = [row for row in rows if row['kind'] == 'child_relative_constructor'
                and row['class'] == 'source-child-relative-probe']
    assert len(selected) == 1
    guard.append({'kind': 'guard_child_relative_probe', 'token': selected[0]['token'],
                  'before_fds': before, 'after_fds': after, 'returncode': result.returncode})
