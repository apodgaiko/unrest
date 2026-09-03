"""Cross-process exclusion for one project's mutating MCP calls."""
from __future__ import annotations

import errno
import importlib
import os
import stat
import threading
from contextlib import contextmanager
from collections.abc import Iterator
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
    lock_path = store.mutation_lock_path(project_id)
    try:
        lock_stat = lock_path.lstat()
    except FileNotFoundError:
        # Legacy projects predate mutation.lock. The project runtime directory
        # is a stable, project-scoped POSIX lock carrier: decision transactions
        # replace project.json and the other generation files, but not their
        # containing directory. Locking the directory also preserves the
        # legacy no-file/no-byte inspection guarantee.
        return store.unrest_runtime_dir(project_id)
    except OSError as exc:
        raise ProjectLockError from exc
    if not stat.S_ISREG(lock_stat.st_mode):
        raise ProjectLockError
    return lock_path


class ProjectMutationLock:
    """A non-blocking OS lock whose lifetime is owned by an open file handle."""

    def __init__(self, path: Path, *, create: bool = True):
        self.path = path
        self.create = create
        self._file: BinaryIO | None = None
        self._directory_fd: int | None = None

    def try_acquire(self) -> bool:
        return self.acquire(blocking=False)

    def acquire(self, *, blocking: bool = True) -> bool:
        if self._file is not None or self._directory_fd is not None:
            raise ProjectLockError
        try:
            existing_stat = self.path.lstat()
        except FileNotFoundError:
            existing_stat = None
        except OSError as exc:
            raise ProjectLockError from exc
        if existing_stat is not None and stat.S_ISDIR(existing_stat.st_mode):
            return self._acquire_directory(blocking=blocking)
        flags = os.O_RDWR
        if self.create:
            flags |= os.O_CREAT
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
                acquired = _lock_posix(lock_file, blocking=blocking)
        except OSError as exc:
            lock_file.close()
            raise ProjectLockError from exc
        if not acquired:
            lock_file.close()
            return False
        self._file = lock_file
        _held_paths().add(str(self.path.resolve(strict=False)))
        return True

    def _acquire_directory(self, *, blocking: bool) -> bool:
        if os.name != "posix":
            raise ProjectLockError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise ProjectLockError from exc
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise ProjectLockError
            acquired = _lock_posix(descriptor, blocking=blocking)
        except Exception:
            os.close(descriptor)
            raise
        if not acquired:
            os.close(descriptor)
            return False
        self._directory_fd = descriptor
        _held_paths().add(str(self.path.resolve(strict=False)))
        return True

    def release(self) -> None:
        lock_file, self._file = self._file, None
        directory_fd, self._directory_fd = self._directory_fd, None
        if lock_file is None and directory_fd is None:
            return
        _held_paths().discard(str(self.path.resolve(strict=False)))
        try:
            # Closing the handle releases both flock and Windows byte-range locks,
            # including automatically when the owning process exits abruptly.
            if lock_file is not None:
                lock_file.close()
            if directory_fd is not None:
                os.close(directory_fd)
        except OSError as exc:
            raise ProjectLockError from exc


def _try_lock_posix(lock_file: BinaryIO) -> bool:
    return _lock_posix(lock_file, blocking=False)


def _lock_posix(lock_file: BinaryIO | int, *, blocking: bool) -> bool:
    import fcntl

    try:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        descriptor = lock_file if isinstance(lock_file, int) else lock_file.fileno()
        fcntl.flock(descriptor, flags)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
            return False
        raise
    return True


@contextmanager
def project_access_guard(store: ProjectStore, project_id: str) -> Iterator[None]:
    """Hold the project lock across recovery and one controller operation.

    Server and runtime-executor callers already hold the same lock. That
    in-process nesting is recognized explicitly; independent direct-library
    callers still serialize through the OS lock.
    """
    path = project_lock_path(store, project_id)
    if path is None or project_mutation_lock_held(path):
        yield
        return
    lock = ProjectMutationLock(
        path,
        create=path == store.mutation_lock_path(project_id),
    )
    if not lock.acquire(blocking=True):  # pragma: no cover - POSIX blocks
        raise ProjectLockError
    try:
        yield
    finally:
        lock.release()


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
