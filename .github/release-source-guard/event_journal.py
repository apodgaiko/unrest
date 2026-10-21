"""Observer-only JSON decoding reuse after complete current-byte reads.

No stat/mtime shortcut and no stale fallback: every acquisition reads every
current journal. Public consumers receive fresh JSON objects. No policy result or parsed mutable object is retained between consumers.
"""
from __future__ import annotations

import json
from pathlib import Path


class EventJournal:
    def __init__(self):
        self._snapshots = {}

    def _current(self, directory):
        current = []
        retained = {}
        for path in sorted(Path(directory).glob('*.jsonl')):
            body = path.read_bytes()
            snapshot = self._snapshots.get(path)
            if snapshot is None or snapshot[0] != body:
                text = body.decode('utf-8')
                lines = []
                for line in text.splitlines():
                    try:
                        json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    lines.append(line)
                snapshot = (body, lines, '[' + ','.join(lines) + ']')
            retained[path] = snapshot
            current.append(snapshot)
        self._snapshots = retained
        return current

    def events(self, directory):
        """Current values with fresh mutable identities, as before caching."""
        result = []
        for snapshot in self._current(directory):
            try:
                rows = json.loads(snapshot[2])
            except RecursionError:
                # The array envelope adds one level; retain the original
                # per-line semantics for a current record near that limit.
                rows = [json.loads(line) for line in snapshot[1]]
            result.extend(rows)
        return result
