"""Current-byte journal snapshots; only immutable parsing metadata crosses reads."""
from __future__ import annotations

from collections.abc import Sequence
import json
import math
import marshal
import sys
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
        values = (kind, pid, *(marker or ()))
        if any(type(value) is float and not math.isfinite(value) for value in values):
            return None
        return kind, marker, pid, enabled
    except (KeyError, TypeError):
        # Let the complete original loop establish error order and side effects.
        return None


_JSON_LOADS = json.loads
_JSON_DECODER = json._default_decoder
_JSON_POLICY = vars(_JSON_DECODER).copy()
BLOCK = 64


def shallow_json(value):
    """Only decoder-policy-independent scalar ranges and shallow containers."""
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 16:
            return False
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is int:
            if item.bit_length() > 64:
                return False
        elif type(item) is float:
            if not math.isfinite(item):
                return False
        elif type(item) not in (str, bool, type(None)):
            return False
    return True


class ParseBlocks:
    """Immutable encodings of bounded JSON parsing, never retained authority."""
    def __init__(self, previous=None):
        self.blocks = previous.blocks if previous is not None else ()

    def materialize(self, chunk):
        frame, depth = sys._getframe(), 0
        while frame is not None:
            depth += 1
            frame = frame.f_back
        if (sys.getrecursionlimit() - depth < 128 or json.loads is not _JSON_LOADS
                or json._default_decoder is not _JSON_DECODER
                or vars(_JSON_DECODER) != _JSON_POLICY):
            return None
        lines = chunk[1]
        rows, retained = [], []
        for offset in range(0, len(lines), BLOCK):
            part = lines[offset:offset + BLOCK]
            index = offset // BLOCK
            old = self.blocks[index] if index < len(self.blocks) else None
            if old is not None and old[0] == part:
                current = marshal.loads(old[1])
                encoded = old[1]
            else:
                try:
                    current = json.loads('[' + ','.join(part) + ']')
                except RecursionError:
                    return None
                if not shallow_json(current):
                    return None
                encoded = marshal.dumps(current)
            retained.append((part, encoded))
            rows.extend(current)
        self.blocks = tuple(retained)
        return rows


class JournalSnapshot(Sequence):
    """One current acquisition; mutable JSON values never cross snapshots."""
    def __init__(self, chunks, index=None):
        self.index = index if index is not None else CensusIndex()
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
                current = chunk[6].materialize(chunk)
                if current is None:
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
        selected = self.index.select(self.chunks, registered, timed)
        return self.materialize() if selected is None else [self[index] for index in selected]


class CensusIndex:
    """Immutable no-effect indices; original refresh still makes every decision."""
    def __init__(self):
        self.key = None
        self.selected = None

    def select(self, chunks, registered, timed):
        key = (chunks, frozenset(registered), frozenset(timed))
        if self.key != key:
            self.selected = self.build(chunks, registered, timed)
            self.key = key
        return self.selected

    @staticmethod
    def build(chunks, registered, timed):
        selected, lifecycles, pending = [], [], False
        index = 0
        for chunk in chunks:
            for item in chunk[3]:
                if item is None:
                    return None
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
        return tuple(selected)


class EventJournal:
    def __init__(self):
        self._snapshots = {}
        self._index = CensusIndex()

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
                parsed = ParseBlocks(chunk[6] if chunk is not None else None)
                chunk = (body, tuple(lines), '[' + ','.join(lines) + ']', tuple(metadata),
                         stable_bytes, stable_count, parsed)
            retained[path] = chunk
            current.append(chunk)
        self._snapshots = retained
        return JournalSnapshot(tuple(current), self._index)

    def events(self, directory):
        return self.snapshot(directory).materialize()
