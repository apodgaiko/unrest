"""Complete installed dependency bytes, independently checked at every boot."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


def inventory(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    result: dict[str, Any] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = str(path.relative_to(root))
        if stat.S_ISDIR(info.st_mode):
            result[name] = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            result[name] = {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                            "size": info.st_size,
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        elif stat.S_ISLNK(info.st_mode):
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root) and resolved != Path("/usr/local/bin/python3.13"):
                raise RuntimeError("dependency symlink escapes its finite runtime closure")
            result[name] = {"type": "symlink", "target": os.readlink(path)}
            if resolved.is_file():
                result[name]["resolved_sha256"] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        else:
            raise RuntimeError("nonregular dependency closure member")
    return result


if __name__ == "__main__":
    root, output = map(Path, sys.argv[1:])
    output.write_text(json.dumps(inventory(root), sort_keys=True, separators=(",", ":")) + "\n")
