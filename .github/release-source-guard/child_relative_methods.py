"""Own-identity constructor probe through the unchanged production guard."""
from __future__ import annotations

import os
import subprocess
import sys


def probe():
    guard = sys.modules['runtime_guard']
    before = len(os.listdir('/proc/self/fd'))
    outcomes = []
    for mode in ('constructor-error', 'positive'):
        options = {'pass_fds': (-1,)} if mode == 'constructor-error' else {}
        try:
            result = subprocess.run([sys.executable, '-I', '-S', '-c', 'pass'],
                                    check=True, **options)
        except ValueError as error:
            assert mode == 'constructor-error' and 'fds_to_keep' in str(error)
            outcomes.append({'mode': mode, 'error_type': type(error).__name__})
        else:
            assert mode == 'positive' and result.returncode == 0
            outcomes.append({'mode': mode, 'returncode': result.returncode})
        assert before == len(os.listdir('/proc/self/fd'))
    after = len(os.listdir('/proc/self/fd'))
    rows = guard.summarize(guard._STATE['manifest_path'])['events']
    selected = [row for row in rows if row['kind'] == 'child_relative_constructor'
                and row['class'] == 'source-child-relative-probe']
    assert len(selected) == 2 and len({row['token'] for row in selected}) == 2
    guard.append({'kind': 'guard_child_relative_probe', 'tokens': [row['token'] for row in selected],
                  'before_fds': before, 'after_fds': after, 'outcomes': outcomes})
