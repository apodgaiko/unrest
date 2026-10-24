"""Fresh journal membership and bytes; reuse only normalized path spelling."""
from __future__ import annotations

import io
import os
from pathlib import Path, PosixPath

_GLOB = Path.glob
_READ = Path.read_bytes
_OPEN = Path.open
_FSPATH = Path.__fspath__
_STRING = PosixPath.__str__
_LESS = PosixPath.__lt__
_PARTS = PosixPath._parts_normcase
_EQUAL = PosixPath.__eq__
_JOIN = PosixPath.__truediv__
_IO_OPEN = io.open
_SCANDIR = os.scandir


def default_policy(root):
    return (type(root) is PosixPath and Path.glob is _GLOB
            and Path.read_bytes is _READ and Path.open is _OPEN
            and Path.__fspath__ is _FSPATH and PosixPath.__str__ is _STRING
            and PosixPath.glob is _GLOB and PosixPath.read_bytes is _READ
            and PosixPath.open is _OPEN and PosixPath.__fspath__ is _FSPATH
            and Path.__lt__ is _LESS and PosixPath.__lt__ is _LESS
            and PosixPath._parts_normcase is _PARTS
            and Path.__eq__ is _EQUAL and PosixPath.__eq__ is _EQUAL
            and Path.__truediv__ is _JOIN and PosixPath.__truediv__ is _JOIN
            and io.open is _IO_OPEN and os.scandir is _SCANDIR)


class CurrentFiles:
    def __init__(self):
        self.root = None
        self.spelling = {}

    def acquire(self, root):
        # The real glob call preserves its audit event, audit-hook exceptions,
        # and any policy edits made by the hook before selecting a fast path.
        original = root.glob('*.jsonl')
        if not default_policy(root):
            for path in sorted(original):
                yield path, path.read_bytes()
            return
        try:
            with os.scandir(root) as stream:
                names = sorted(entry.name for entry in stream if entry.name.endswith('.jsonl'))
        except OSError:
            # CPython glob discards incomplete scans. Read failures below still
            # propagate, including matching directories and dangling links.
            names = []
        if not default_policy(root):
            # A scan audit hook can change path policy. Consume the already
            # audited original iterator before touching cached path spelling.
            for path in sorted(original):
                yield path, path.read_bytes()
            return
        previous = self.spelling if self.root == root else {}
        current = {}
        for name in names:
            if name in previous:
                current[name] = previous[name]
            else:
                path = root / name
                current[name] = path, str(path)
        self.root, self.spelling = root, current
        for name in names:
            path, spelling = current[name]
            if not default_policy(root):
                body = path.read_bytes()
            else:
                with io.open(spelling, 'rb', buffering=0) as stream:
                    body = stream.read()
            yield path, body
