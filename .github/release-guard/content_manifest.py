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


def _descend(stack, parent, parts, identity):
    chain=[]
    for part in parts:
        before=os.stat(part,dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise Refused('noncanonical_root' if identity is _directory_key else 'non_directory_component')
        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        stack.callback(os.close,child)
        if identity(before)!=identity(os.fstat(child)):
            raise Refused('directory_acquisition_race')
        chain.append((parent,part,child,identity(before)))
        parent=child
    return parent,chain


def _verify(chain,identity,code):
    for parent,part,child,expected in reversed(chain):
        if (expected!=identity(os.fstat(child))
                or expected!=identity(os.stat(part,dir_fd=parent,follow_symlinks=False))):
            raise Refused(code)


def _root(stack: ExitStack, path: Path):
    path=path.absolute()
    if '..' in path.parts:
        raise Refused('noncanonical_root')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    stack.callback(os.close,parent)
    return _descend(stack,parent,path.parts[1:],_directory_key)


def _member(root: int, name: str, line_counts: dict[str, int] | None,
            file_bound: int | None = None, *, collected=None, uid=None, mode=None,
            minimum=0, forbidden=0o7000) -> Member:
    parts = name.split("/")
    with ExitStack() as stack:
        parent,directories=_descend(stack,root,parts[:-1],_key)
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
        _verify(directories,_key,'directory_read_race')
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
             file_bound: int | None = None) -> Manifest:
    file_bound=MAX_FILE_BYTES if file_bound is None else file_bound
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
            _verify(chain,_directory_key,'root_read_race')
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
        _verify(chain,_directory_key,'regular file ancestor changed')
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


def encode(manifest: Manifest) -> bytes:
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    for chunk in encoder.iterencode(manifest):
        block = chunk.encode("ascii")
        if len(result) + len(block) + 1 > MAX_MANIFEST_BYTES:
            raise Refused("manifest_byte_bound")
        result.extend(block)
    return bytes(result) + b"\n"
