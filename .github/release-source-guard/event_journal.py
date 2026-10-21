"""Observer-only JSON decoding reuse after complete current-byte reads.

No stat/mtime shortcut and no stale fallback: every acquisition reads every
current journal. Public consumers receive fresh JSON objects. Only the trusted
refresh loop borrows parsed rows; policy decisions read fresh objects again.
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
                rows, lines = [], []
                for line in text.splitlines():
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rows.append(value)
                    lines.append(line)
                snapshot = (body, rows, '[' + ','.join(lines) + ']')
            retained[path] = snapshot
            current.append(snapshot)
        self._snapshots = retained
        return current

    def for_refresh(self, directory):
        """Private borrowed rows: the refresh loop only reads these values."""
        return [row for snapshot in self._current(directory) for row in snapshot[1]]

    def events(self, directory):
        """Current values with fresh mutable identities, as before caching."""
        return [row for snapshot in self._current(directory) for row in json.loads(snapshot[2])]
