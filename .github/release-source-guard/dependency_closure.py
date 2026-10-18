"""Complete installed dependency bytes, independently checked at every boot."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


def inventory(root: Path, *, on_escape: Any = None) -> dict[str, Any]:
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
                if on_escape is not None:
                    on_escape(root, path, resolved, info)
                raise RuntimeError("dependency symlink escapes its finite runtime closure")
            result[name] = {"type": "symlink", "target": os.readlink(path)}
            if resolved.is_file():
                result[name]["resolved_sha256"] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        else:
            raise RuntimeError("nonregular dependency closure member")
    return result


def verify_source_view(expected_bytes: bytes, console: bytes | None = None) -> dict[str, Any]:
    expected = json.loads(expected_bytes)
    observed = inventory(Path('/opt/deps'))
    observed_count = len(observed)
    if console is not None:
        if observed.pop('bin/unrest', None) != {
            'type': 'file', 'mode': 0o444, 'size': len(console),
            'sha256': hashlib.sha256(console).hexdigest()}:
            raise RuntimeError('finite declared source console drift')
    if observed != expected:
        raise RuntimeError('installed dependency closure drift')
    name = 'lib/python3.13/site-packages/unrest-source.pth'
    body = b'/source/src\n'
    if expected.pop(name, None) != {'type': 'file', 'mode': 0o644, 'size': len(body),
                                    'sha256': hashlib.sha256(body).hexdigest()}:
        raise RuntimeError('read-only source view mapping drift')
    base = (json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if hashlib.sha256(base).hexdigest() != 'adac11fb5bbc8307263d775b8b89c776d1d71ee238ded6a764e480d862c34fac':
        raise RuntimeError('pinned dependency base changed')
    return {'sha256': hashlib.sha256(expected_bytes).hexdigest(),
            'members': observed_count,
            'source_console_sha256': hashlib.sha256(console).hexdigest() if console is not None else None, 'base_sha256': hashlib.sha256(base).hexdigest(),
            'source_view_sha256': hashlib.sha256(body).hexdigest(), 'verified': True}


if __name__ == "__main__":
    root, output = map(Path, sys.argv[1:])
    output.write_text(json.dumps(inventory(root), sort_keys=True, separators=(",", ":")) + "\n")
