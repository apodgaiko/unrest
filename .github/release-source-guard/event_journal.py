"""Current-byte journal snapshots; only immutable parsing metadata crosses reads."""
from __future__ import annotations

from collections.abc import Sequence
import json
from pathlib import Path

TIMED = frozenset({'admitted', 'actual_launch_binding', 'ready', 'source_entry',
                   'test_outcome', 'actual_parent_preexit_drain',
                   'custody_IPC_listener_ready', 'custodian_stage'})
MARKER = ('owner_pid', 'kind', 'token', 'pid', 'phase', 'outcome', 'class')


def descriptor(row):
    """Index original refresh's existing no-effect predicates, never an admission."""
    try:
        kind = row['kind']
        hash(kind)
        marker = tuple(row.get(key) for key in MARKER) if kind in TIMED else None
        if marker is not None:
            hash(marker)
        enabled = kind == 'registered' and bool(row.get('python', True))
        pid = row['pid'] if enabled else None
        hash(pid)
        return kind, marker, pid, enabled
    except (KeyError, TypeError):
        # Let the complete original loop establish error order and side effects.
        return None


class JournalSnapshot(Sequence):
    """One current acquisition; mutable JSON values never cross snapshots."""
    def __init__(self, chunks):
        self.chunks = chunks
        self.count = sum(len(chunk[1]) for chunk in chunks)
        self.parsed = {}
        self.full = None

    def __len__(self):
        return self.count

    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.materialize()[index]
        if index < 0:
            index += self.count
        if not 0 <= index < self.count:
            raise IndexError(index)
        if self.full is not None:
            return self.full[index]
        if index not in self.parsed:
            offset = index
            for chunk in self.chunks:
                if offset < len(chunk[1]):
                    self.parsed[index] = json.loads(chunk[1][offset])
                    break
                offset -= len(chunk[1])
        return self.parsed[index]

    def __iter__(self):
        return iter(self.materialize())

    def materialize(self):
        if self.full is None:
            rows = []
            for chunk in self.chunks:
                try:
                    current = json.loads(chunk[2])
                except RecursionError:
                    current = [json.loads(line) for line in chunk[1]]
                rows.extend(current)
            for index, row in self.parsed.items():
                rows[index] = row
            self.full = rows
        return self.full

    def census(self, registered, timed):
        """Keep every effectful original refresh row and its lifecycle witnesses."""
        selected, lifecycles, pending = [], [], False
        index = 0
        for chunk in self.chunks:
            for item in chunk[3]:
                if item is None:
                    return self.materialize()
                kind, marker, pid, enabled = item
                unresolved = enabled and pid not in registered
                if kind == 'forbidden' or unresolved or marker is not None and marker not in timed:
                    selected.append(index)
                if unresolved:
                    pending = True
                if kind == 'launch_lifecycle_binding':
                    lifecycles.append(index)
                index += 1
        if pending:
            selected = sorted(set(selected) | set(lifecycles))
        return [self[index] for index in selected]


class EventJournal:
    def __init__(self):
        self._snapshots = {}

    def snapshot(self, directory):
        current, retained = [], {}
        for path in sorted(Path(directory).glob('*.jsonl')):
            body = path.read_bytes()
            chunk = self._snapshots.get(path)
            if chunk is None or chunk[0] != body:
                prefix, count = b'', 0
                if chunk is not None and body.startswith(chunk[4]):
                    prefix, count = chunk[4], chunk[5]
                lines = list(chunk[1][:count]) if count else []
                metadata = list(chunk[3][:count]) if count else []
                tail = body[len(prefix):].decode('utf-8')
                pieces = tail.splitlines(keepends=True)
                stable_count = len(lines)
                for index, line in enumerate(tail.splitlines()):
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        pass
                    else:
                        lines.append(line)
                        metadata.append(descriptor(row))
                    if index < len(pieces) - 1:
                        stable_count = len(lines)
                stable_bytes = body[:len(body) - len(pieces[-1].encode('utf-8'))] if pieces else body
                chunk = (body, tuple(lines), '[' + ','.join(lines) + ']', tuple(metadata),
                         stable_bytes, stable_count)
            retained[path] = chunk
            current.append(chunk)
        self._snapshots = retained
        return JournalSnapshot(tuple(current))

    def events(self, directory):
        return self.snapshot(directory).materialize()
