"""Exact TEST-only inert journal loads; no registration or authority witnesses."""
from __future__ import annotations

import json
from pathlib import Path

from primary_policy import TEST_JOURNAL_CONTEXT_CASES, TEST_C1_WITNESS_CASES, TEST_RELEASE_PREFLIGHT_CASES, TEST_RELEASE_BUILD_PREFLIGHT_CASES, sha

FILES = 512
ROWS_PER_FILE = 80
KIND = 'startup_journal_load_control'


def selected(spec):
    commands = [['env', '-u', 'CODEX_PATH', 'uv', 'run', 'pytest', '-q', *cases]
                for cases in (TEST_JOURNAL_CONTEXT_CASES, TEST_C1_WITNESS_CASES, TEST_RELEASE_PREFLIGHT_CASES, TEST_RELEASE_BUILD_PREFLIGHT_CASES)]
    command = spec.get('commands', [None])[0] if type(spec.get('commands')) is list and len(spec['commands']) == 1 else None
    return (spec.get('source_mode') == 'TEST-positive'
            and spec.get('duty') == 'TEST-source-positive'
            and command in commands
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
