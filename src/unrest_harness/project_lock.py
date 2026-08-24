"""Cross-process exclusion for one project's mutating MCP calls."""
from __future__ import annotations

import errno
import importlib
import os
import stat
import threading
from pathlib import Path
from typing import Any, BinaryIO

from .storage import ProjectStore


class ProjectLockError(RuntimeError):
    """The project lock could not be safely inspected or acquired."""


_HELD_LOCKS = threading.local()


def _held_paths() -> set[str]:
    paths = getattr(_HELD_LOCKS, "paths", None)
    if paths is None:
        paths = set()
        _HELD_LOCKS.paths = paths
    return paths


def project_mutation_lock_held(path: Path) -> bool:
    return str(path.resolve(strict=False)) in _held_paths()


def project_lock_path(store: ProjectStore, project_id: str) -> Path | None:
    """Return the lock path for a real project, or ``None`` for a missing one.

    Missing and malformed projects retain their existing controller error path.
    Any failure while inspecting an otherwise plausible project fails closed.
    """
    project_record = store.unrest_runtime_dir(project_id) / "project.json"
    try:
        record_stat = project_record.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProjectLockError from exc
    if not stat.S_ISREG(record_stat.st_mode):
        return None
    return store.mutation_lock_path(project_id)


class ProjectMutationLock:
    """A non-blocking OS lock whose lifetime is owned by an open file handle."""

    def __init__(self, path: Path):
        self.path = path
        self._file: BinaryIO | None = None

    def try_acquire(self) -> bool:
        if self._file is not None:
            raise ProjectLockError
        flags = os.O_CREAT | os.O_RDWR
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise ProjectLockError from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ProjectLockError
            lock_file = os.fdopen(fd, "r+b", buffering=0)
        except Exception:
            os.close(fd)
            raise
        try:
            if os.name == "nt":
                _prepare_windows_lockfile(lock_file)
                acquired = _try_lock_windows(lock_file)
            else:
                acquired = _try_lock_posix(lock_file)
        except OSError as exc:
            lock_file.close()
            raise ProjectLockError from exc
        if not acquired:
            lock_file.close()
            return False
        self._file = lock_file
        _held_paths().add(str(self.path.resolve(strict=False)))
        return True

    def release(self) -> None:
        lock_file, self._file = self._file, None
        if lock_file is None:
            return
        _held_paths().discard(str(self.path.resolve(strict=False)))
        try:
            # Closing the handle releases both flock and Windows byte-range locks,
            # including automatically when the owning process exits abruptly.
            lock_file.close()
        except OSError as exc:
            raise ProjectLockError from exc


def _try_lock_posix(lock_file: BinaryIO) -> bool:
    import fcntl

    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
            return False
        raise
    return True


def _prepare_windows_lockfile(lock_file: BinaryIO) -> None:
    if os.fstat(lock_file.fileno()).st_size == 0:
        lock_file.write(b"\0")
    lock_file.seek(0)


def _try_lock_windows(lock_file: BinaryIO, module: Any | None = None) -> bool:
    locking_module = module if module is not None else importlib.import_module("msvcrt")

    try:
        locking_module.locking(lock_file.fileno(), locking_module.LK_NBLCK, 1)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            return False
        raise
    return True
