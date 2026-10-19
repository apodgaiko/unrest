"""Verify the complete public source projection at its owned serving path."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys


def verify(repository, destination):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=repository).decode().split("\0")
    rows = {}
    for name in sorted(filter(None, names)):
        source = repository / name
        copy = destination / name
        before = source.lstat()
        current = copy.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or copy.read_bytes() != source.read_bytes()
            or stat.S_IMODE(before.st_mode) != stat.S_IMODE(current.st_mode)
            or current.st_nlink != 1
        ):
            raise RuntimeError("owned source bytes, mode or physical membership mismatch")
        rows[name] = {
            "sha256": hashlib.sha256(copy.read_bytes()).hexdigest(),
            "mode": stat.S_IMODE(current.st_mode),
        }
    return rows


if __name__ == "__main__":
    destination, output = sys.argv[1:]
    repository = Path(__file__).resolve().parent.parent.parent
    rows = verify(repository, Path(destination))
    Path(output).write_text(
        json.dumps(
            {
                "schema": "owned-source-copy-v1",
                "members": rows,
                "head": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=repository, text=True
                ).strip(),
                "all_tracked_bytes_equal": True,
            },
            sort_keys=True,
        )
    )
