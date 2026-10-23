"""Finite TEST-only inert journal load; no registration or authority witnesses."""
from __future__ import annotations

import json
from pathlib import Path

from primary_policy import TEST_JOURNAL_CONTEXT_CASES, sha

FILES = 512
ROWS_PER_FILE = 80
KIND = 'startup_journal_load_control'


def selected(spec):
    command = ['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q', *TEST_JOURNAL_CONTEXT_CASES]
    return (spec.get('source_mode') == 'TEST-positive'
            and spec.get('duty') == 'TEST-source-positive'
            and spec.get('commands') == [command]
            and spec.get('script_sha256') == sha(' '.join(command).encode())
            and spec.get('source_checkpoint_ready') is False
            and spec.get('selected_carrier') is None)


def seed(spec, directory: Path):
    if not selected(spec):
        return
    # Bootstrap calls this before source execution. Exclusively create inert
    # files; never replace process journals or manufacture READY/wait evidence.
    for group in range(FILES):
        path = directory / f'startup-context-{group:04d}.jsonl'
        with path.open('x') as stream:
            for item in range(ROWS_PER_FILE):
                row = {'kind': KIND, 'ordinal': group * ROWS_PER_FILE + item,
                       'diagnostic_only': True, 'eligible_certificate': False,
                       'padding': 'x' * 256, 'values': list(range(16))}
                stream.write(json.dumps(row, sort_keys=True) + '\n')
