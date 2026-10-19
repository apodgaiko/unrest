"""Retain named controlled evidence even when dependency preparation fails."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
import tarfile

CAP = 64 * 1024 * 1024
EXPANDED = 128 * 1024 * 1024


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def retain(root, output, owned=None):
    files = []
    missing = []
    for name in (
        "preparation.log",
        "preparation-status",
        "runtime-copy.json",
        "source-copy.json",
        "ownership.log",
        "ownership-status",
    ):
        path = root / name
        if path.is_file():
            files.append((path, name))
        else:
            missing.append(name)
    owned = root / "owned-multiprocess" if owned is None else owned
    nonregular = []
    if owned.exists():
        for path in sorted(owned.rglob("*")):
            relative = path.relative_to(owned)
            if "pytest" in relative.parts:
                continue  # Product fixture trees; transport records are outside.
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                files.append((path, "owned-multiprocess/" + str(relative)))
            elif not stat.S_ISDIR(info.st_mode):
                nonregular.append(
                    {"path": "owned-multiprocess/" + str(relative), "mode": info.st_mode}
                )
    rows = []
    total = 0
    for path, arcname in sorted(files):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > CAP:
            raise RuntimeError("controlled evidence carrier refused")
        body = path.read_bytes()
        if identity(path.lstat()) != identity(info) or len(body) != info.st_size:
            raise RuntimeError("controlled evidence changed while retaining")
        total += len(body)
        if total > EXPANDED or len(rows) >= 8191:
            raise RuntimeError("controlled evidence exceeds unchanged archive bounds")
        rows.append(
            {
                "path": arcname,
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
        )
    index = root / "control-retention.json"
    index.write_text(
        json.dumps(
            {
                "members": rows,
                "missing_named_records": missing,
                "nonregular_transport_nodes": nonregular,
            },
            sort_keys=True,
        )
    )
    if index.stat().st_size > CAP or total + index.stat().st_size > EXPANDED:
        raise RuntimeError("controlled index exceeds unchanged archive bounds")
    with tarfile.open(output, "x:gz") as archive:
        for path, arcname in [(index, "control-retention.json"), *sorted(files)]:
            archive.add(path, arcname=arcname, recursive=False)
    if output.stat().st_size > CAP:
        raise RuntimeError("controlled archive exceeds unchanged carrier bound")


if __name__ == "__main__":
    root, output, *owned = sys.argv[1:]
    assert len(owned) <= 1
    retain(Path(root), Path(output), Path(owned[0]) if owned else None)
