"""Verify complete runtime-copy bytes before the owned read-only Linux control."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys


def inventory(root):
    root = root.resolve(strict=True)
    rows = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            target = path.readlink()
            if target.is_absolute() or not path.resolve(strict=True).is_relative_to(root):
                raise RuntimeError("runtime copy has an external alias")
            rows[name] = {"kind": "symlink", "target": str(target)}
        elif stat.S_ISDIR(info.st_mode):
            rows[name] = {"kind": "directory"}
        elif stat.S_ISREG(info.st_mode):
            rows[name] = {
                "kind": "file",
                "bytes": info.st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        else:
            raise RuntimeError("runtime copy has a nonregular resource")
    return rows


if __name__ == "__main__":
    destination, output = sys.argv[1:]
    source = inventory(Path(sys.base_prefix))
    copied = inventory(Path(destination))
    if copied != source:
        raise RuntimeError("runtime copy bytes or membership mismatch")
    Path(output).write_text(
        json.dumps(
            {"schema": "owned-runtime-copy-v1", "members": source, "source_equals_copy": True},
            sort_keys=True,
        )
    )
