"""Compute the release binding from Git-tracked regular files only."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


SURFACE_ROOTS = ("src", "tests", "tools")
SURFACE_FILES = ("pyproject.toml", "uv.lock")
REGULAR_GIT_MODES = {"100644", "100755"}


def _in_surface(relative: str) -> bool:
    path = PurePosixPath(relative)
    return relative in SURFACE_FILES or (
        len(path.parts) > 1 and path.parts[0] in SURFACE_ROOTS
    )


def tracked_regular_paths(repository: Path, revision: str | None = None) -> list[str]:
    """Return the sorted tracked regular-file inventory for the release surface."""
    command: Sequence[str]
    if revision is None:
        command = ("git", "ls-files", "--stage", "-z")
    else:
        command = ("git", "ls-tree", "-r", "-z", revision)
    output = subprocess.run(
        command,
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    paths: set[str] = set()
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        relative = raw_path.decode("utf-8")
        if mode in REGULAR_GIT_MODES and _in_surface(relative):
            paths.add(relative)
    return sorted(paths, key=lambda value: value.encode("utf-8"))


def inventory(root: Path, relative_paths: Iterable[str]) -> dict[str, object]:
    """Hash exact bytes for an already-authoritative tracked path inventory."""
    digest = hashlib.sha256()
    files: list[dict[str, object]] = []
    for relative in sorted(set(relative_paths), key=lambda value: value.encode("utf-8")):
        path = root / relative
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise ValueError(f"tracked binding file is missing: {relative}") from error
        if not stat.S_ISREG(mode):
            raise ValueError(f"tracked binding path is not a regular file: {relative}")
        content = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
        files.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {
        "algorithm": "sha256(sorted(utf8_relative_path + NUL + raw_bytes + NUL))",
        "files": len(files),
        "sha256": digest.hexdigest(),
        "entries": files,
    }


def declared_binding(manifest: dict[str, object]) -> dict[str, object]:
    source = manifest["source"]
    assert isinstance(source, dict)
    declaration = source["final_product_package_test"]
    assert isinstance(declaration, dict)
    return declaration


def assert_declaration_matches(
    declaration: dict[str, object], computed: dict[str, object]
) -> None:
    actual = {"files": computed["files"], "sha256": computed["sha256"]}
    expected = {"files": declaration["files"], "sha256": declaration["sha256"]}
    if actual != expected:
        raise ValueError(f"binding declaration mismatch: declared={expected}, computed={actual}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--root", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--check-manifest", type=Path)
    args = parser.parse_args()

    repository = args.repository.resolve()
    root = (args.root or repository).resolve()
    result = inventory(root, tracked_regular_paths(repository, args.revision))
    if args.check_manifest is not None:
        manifest = json.loads(args.check_manifest.read_text(encoding="utf-8"))
        assert_declaration_matches(declared_binding(manifest), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
