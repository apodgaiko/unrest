"""Closed content measurements, separate from host trust and launch authority.

The host must independently pin both the manifest digest and its file inventory.
These point-in-time measurements do not establish immutable mount custody.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Sequence, TypedDict

SCHEMA = "unrest.guard-content.v1"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 20_000
MAX_PATH_BYTES = 4096
MAX_PATH_DEPTH = 32
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class Refused(ValueError):
    """A closed refusal code; never includes source bytes or exception bodies."""


class Member(TypedDict):
    path: str
    mode: int
    size: int
    sha256: str


class Manifest(TypedDict):
    schema: str
    files: list[Member]


def _path(value: object) -> str:
    if (type(value) is not str or not value or "\x00" in value or "\\" in value
            or len(value.split("/")) > MAX_PATH_DEPTH
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise Refused("noncanonical_path")
    try:
        if len(value.encode("utf-8")) > MAX_PATH_BYTES:
            raise Refused("path_bound")
    except UnicodeError:
        raise Refused("path_encoding") from None
    return value


def _inventory(paths: Sequence[str]) -> list[str]:
    if type(paths) not in (list, tuple):
        raise Refused("inventory_type")
    values = list(paths)
    if not values or len(values) > MAX_FILES:
        raise Refused("inventory_bound")
    values = [_path(value) for value in values]
    if len(set(values)) != len(values):
        raise Refused("duplicate_path")
    return sorted(values)


def _key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _root(stack: ExitStack, path: Path) -> tuple[int, list[tuple[int, str, int, tuple[int, ...]]]]:
    path = path.absolute()
    if ".." in path.parts:
        raise Refused("noncanonical_root")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stack.callback(os.close, parent)
    chain = []
    for part in path.parts[1:]:
        before = os.stat(part, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise Refused("noncanonical_root")
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, child)
        if _directory_key(before) != _directory_key(os.fstat(child)):
            raise Refused("root_acquisition_race")
        chain.append((parent, part, child, _directory_key(before)))
        parent = child
    return parent, chain


def _member(root: int, name: str, line_counts: dict[str, int] | None,
            file_bound: int = MAX_FILE_BYTES, *, collected=None, uid=None, mode=None,
            minimum=0, forbidden=0o7000) -> Member:
    parts = name.split("/")
    directories: list[tuple[int, str, int, tuple[int, ...]]] = []
    with ExitStack() as stack:
        parent = root
        for part in parts[:-1]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise Refused("non_directory_component")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            stack.callback(os.close, child)
            if _key(before) != _key(os.fstat(child)):
                raise Refused("directory_acquisition_race")
            directories.append((parent, part, child, _key(before)))
            parent = child
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & forbidden or uid is not None and before.st_uid!=uid
                or mode is not None and stat.S_IMODE(before.st_mode)!=mode
                or before.st_size<minimum):
            raise Refused("nonregular_or_aliased_file")
        if before.st_size > file_bound:
            raise Refused("file_bound")
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        stack.callback(os.close, fd)
        if _key(before) != _key(os.fstat(fd)):
            raise Refused("file_acquisition_race")
        digest = hashlib.sha256()
        counted_bytes = bytearray()
        size = 0
        while block := os.read(fd, min(65536, file_bound-size+1)):
            size += len(block)
            if size > file_bound or size > before.st_size:
                raise Refused("file_read_bound")
            digest.update(block)
            if line_counts is not None or collected is not None and collected['retain']:
                counted_bytes.extend(block)
        if (size != before.st_size or _key(before) != _key(os.fstat(fd))
                or _key(before) != _key(os.stat(parts[-1], dir_fd=parent,
                                                 follow_symlinks=False))):
            raise Refused("file_read_race")
        for ancestor, part, child, expected in reversed(directories):
            if (expected != _key(os.fstat(child))
                    or expected != _key(os.stat(part, dir_fd=ancestor,
                                                follow_symlinks=False))):
                raise Refused("directory_read_race")
        if line_counts is not None:
            try:
                line_counts[name] = len(counted_bytes.decode("utf-8").splitlines())
            except UnicodeError:
                raise Refused("opaque_guard_payload") from None
        if collected is not None:
            collected.update(body=bytes(counted_bytes) if collected['retain'] else None,info=before)
        return {"path": name, "mode": stat.S_IMODE(before.st_mode),
                "size": size, "sha256": digest.hexdigest()}


def _capture(root: Path, paths: Sequence[str], line_counts: dict[str, int] | None,
             file_bound: int = MAX_FILE_BYTES) -> Manifest:
    names = _inventory(paths)
    try:
        with ExitStack() as stack:
            fd, chain = _root(stack, root)
            before = _key(os.fstat(fd))
            files = []
            total = 0
            for name in names:
                member = _member(fd, name, line_counts, file_bound)
                total += member["size"]
                if total > MAX_TOTAL_BYTES:
                    raise Refused("total_byte_bound")
                files.append(member)
            if before != _key(os.fstat(fd)):
                raise Refused("root_read_race")
            for parent, part, child, expected in reversed(chain):
                if (expected != _directory_key(os.fstat(child))
                        or expected != _directory_key(os.stat(part, dir_fd=parent,
                                                             follow_symlinks=False))):
                    raise Refused("root_read_race")
    except OSError:
        raise Refused("filesystem_acquisition_refused") from None
    return {"schema": SCHEMA, "files": files}


def capture(root: Path, paths: Sequence[str]) -> Manifest:
    """Measure exactly the supplied inventory without importing or running it."""
    return _capture(root, paths, None)


def read_regular(file: Path, maximum: int, *, uid=None, mode=None, minimum=0,
                 forbidden=0o7000, retain=True) -> tuple[bytes | None, os.stat_result, str]:
    """Acquire one complete bounded file through held nofollow directory FDs."""
    observed = {'retain':retain}
    with ExitStack() as stack:
        parent, chain = _root(stack, file.parent)
        member=_member(parent, _path(file.name), None, maximum, collected=observed,
                uid=uid, mode=mode, minimum=minimum, forbidden=forbidden)
        for ancestor, part, child, expected in reversed(chain):
            if (expected != _directory_key(os.fstat(child))
                    or expected != _directory_key(os.stat(part, dir_fd=ancestor, follow_symlinks=False))):
                raise Refused('regular file ancestor changed')
    return observed['body'], observed['info'], member['sha256']


def native_digest(path: Path) -> str:
    """Measure a native executable, retaining source manifests' smaller limit."""
    return _capture(path.parent, [path.name], None, 16 * 1024 * 1024)['files'][0]['sha256']


def measure_lines(root: Path, paths: Sequence[str]) -> tuple[Manifest, dict[str, int]]:
    """Count text lines from the same bounded nofollow reads as content hashes."""
    counts: dict[str, int] = {}
    return _capture(root, paths, counts), counts


def is_sha256(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def validate(value: object, paths: Sequence[str]) -> Manifest:
    names = _inventory(paths)
    if (type(value) is not dict or set(value) != {"schema", "files"}
            or value["schema"] != SCHEMA or type(value["files"]) is not list
            or len(value["files"]) != len(names)):
        raise Refused("manifest_schema")
    files: list[Member] = []
    total = 0
    for name, member in zip(names, value["files"], strict=True):
        if (type(member) is not dict or set(member) != {"path", "mode", "size", "sha256"}
                or member["path"] != name or type(member["mode"]) is not int
                or not 0 <= member["mode"] <= 0o777 or type(member["size"]) is not int
                or not 0 <= member["size"] <= MAX_FILE_BYTES
                or not is_sha256(member["sha256"])):
            raise Refused("manifest_member")
        files.append({"path": name, "mode": member["mode"], "size": member["size"],
                      "sha256": member["sha256"]})
        total += member["size"]
        if total > MAX_TOTAL_BYTES:
            raise Refused("total_byte_bound")
    return {"schema": SCHEMA, "files": files}


def encode(manifest: Manifest) -> bytes:
    if (type(manifest) is not dict or type(manifest.get("files")) is not list
            or any(type(member) is not dict or "path" not in member
                   for member in manifest["files"])):
        raise Refused("manifest_schema")
    checked = validate(manifest, [member["path"] for member in manifest["files"]])
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    for chunk in encoder.iterencode(checked):
        block = chunk.encode("ascii")
        if len(result) + len(block) + 1 > MAX_MANIFEST_BYTES:
            raise Refused("manifest_byte_bound")
        result.extend(block)
    return bytes(result) + b"\n"


def verify(root: Path, body: bytes, expected_sha256: str,
           paths: Sequence[str]) -> Manifest:
    """Require an external digest and inventory, then remeasure current files."""
    from control_transport import unique
    names = _inventory(paths)
    if (type(body) is not bytes or len(body) > MAX_MANIFEST_BYTES
            or not is_sha256(expected_sha256)
            or hashlib.sha256(body).hexdigest() != expected_sha256):
        raise Refused("manifest_reference")
    try:
        value = json.loads(body, object_pairs_hook=unique)
    except Refused:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("manifest_encoding") from None
    manifest = validate(value, names)
    if body != encode(manifest):
        raise Refused("noncanonical_manifest")
    if manifest != capture(root, names):
        raise Refused("content_drift")
    return manifest
