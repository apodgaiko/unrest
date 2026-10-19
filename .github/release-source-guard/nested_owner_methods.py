"""Supplementary own-identity nested execution; never an original source case."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def test_nested_owner():
    guard = sys.modules['runtime_guard']
    state = guard._STATE
    assert state['case'] == ('.github/release-source-guard/multiprocess_guard_methods.py'
                             '::test_owned_exit17_keeps_raw_status')
    directory = Path(state['owned_root']) / 'execution-owner-probe'
    assert directory.is_dir()
    before = len(os.listdir('/proc/self/fd'))
    completed = subprocess.run([sys.executable, '-I', '-S', '-c', 'pass'],
                               cwd=Path(state['checkout']), check=True)
    assert completed.returncode == 0
    assert before == len(os.listdir('/proc/self/fd'))
    guard.append({'kind': 'guard_nested_execution_owner_leaf',
                  'custody_case': state['case'], 'returncode': completed.returncode,
                  'before_fds': before, 'after_fds': len(os.listdir('/proc/self/fd'))})
