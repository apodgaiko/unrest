"""Original-parent ownership for the finite spawn-based test resource scopes."""
from __future__ import annotations

import inspect
import multiprocessing
from multiprocessing import resource_tracker, synchronize, util
import os
from pathlib import Path
import stat
import weakref
from types import TracebackType
from typing import Any, cast


_process_owners: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()
_process_bindings: weakref.WeakKeyDictionary[Any, Any] = weakref.WeakKeyDictionary()

def _source_bound(function: Any, module: Any) -> None:
    """Refuse a replaced callable before using a private CPython lifecycle API."""
    source = module.__file__
    if function.__globals__ is not vars(module):
        raise RuntimeError('multiprocessing lifecycle differs from stdlib globals')
    if source is None:
        raise RuntimeError('multiprocessing lifecycle has no source')
    compiled = compile(Path(source).read_bytes(), source, 'exec', dont_inherit=True)
    pending = [compiled]
    while pending:
        code = pending.pop()
        if code == function.__code__:
            return
        pending.extend(value for value in code.co_consts if inspect.iscode(value))
    raise RuntimeError('multiprocessing lifecycle code differs from stdlib source')


def _case() -> str:
    return os.environ.get('PYTEST_CURRENT_TEST', '').rsplit(' (', 1)[0]


class SpawnResources:
    """Close only acquired resources; never join, kill or adopt an unfinished child.

    Actual Process.join calls stay in their original tests. The tracker stop is
    CPython's own bound close/wait path, called while this original parent lives.
    """

    def __init__(self) -> None:
        self.parent = os.getpid()
        self.case = _case()
        self.tracker: Any = cast(Any, resource_tracker._resource_tracker)
        self.identity: tuple[int, int, int] | None = None
        self.custody: int | None = None
        self.fd: int | None = None
        self.pid: int | None = None
        self.processes: list[Any] = []
        self.queues: list[Any] = []
        self.connections: list[Any] = []
        self.finalizers: list[Any] = []
        self.closed = False
        self.stop = self.tracker._stop
        self.cleanup = cast(Any, synchronize.SemLock)._cleanup

    def __enter__(self) -> SpawnResources:
        return self

    def context(self, context: Any) -> _OwnedContext:
        if self.closed or os.getpid() != self.parent or _case() != self.case:
            raise RuntimeError('multiprocessing owner scope changed')
        if context is not multiprocessing.get_context('spawn'):
            raise RuntimeError('only the original spawn context is owned')
        if self.identity is None:
            if self.tracker is not resource_tracker._resource_tracker:
                raise RuntimeError('multiprocessing tracker instance changed')
            if self.tracker._fd is not None or self.tracker._pid is not None:
                raise RuntimeError('refusing preexisting multiprocessing tracker')
            if type(self.tracker) is not resource_tracker.ResourceTracker:
                raise RuntimeError('multiprocessing tracker class changed')
            tracker = cast(Any, self.tracker)
            for function, module in (
                (self.stop.__func__, resource_tracker),
                (tracker.ensure_running.__func__, resource_tracker),
                (tracker._stop_locked.__func__, resource_tracker),
                (self.cleanup, synchronize), (util.Finalize.__call__, util),
            ):
                _source_bound(function, module)
            try:
                tracker.ensure_running()
                self.fd, self.pid = tracker._fd, tracker._pid
                self._acquired_pipe()
                # Retain this pipe generation against descriptor-number reuse.
                self.custody = os.dup(self.fd)
                os.set_inheritable(self.custody, False)
            except BaseException as error:
                try:
                    # ensure_running may fail after publishing its owned child.
                    self.fd, self.pid = tracker._fd, tracker._pid
                    if self.fd is not None or self.pid is not None:
                        self._acquired_pipe()
                        self._close(acquiring=True)
                    else:
                        self.closed = True
                except BaseException as cleanup_error:
                    raise BaseExceptionGroup('multiprocessing acquisition and rollback failed',
                                             [error, cleanup_error]) from None
                raise
        return _OwnedContext(self, context)

    def _acquired_pipe(self) -> None:
        if self.fd is None or self.pid is None:
            raise RuntimeError('tracker has no original-parent ownership')
        info = os.fstat(self.fd)
        if not stat.S_ISFIFO(info.st_mode) or os.get_inheritable(self.fd):
            raise RuntimeError('tracker descriptor is not a private pipe')
        identity = (info.st_dev, info.st_ino, info.st_mode)
        if self.identity is not None and self.identity != identity:
            raise RuntimeError('multiprocessing pipe generation changed')
        self.identity = identity

    def _semaphore(self, semaphore: Any) -> None:
        name = semaphore._semlock.name
        if name is None:
            raise RuntimeError('spawn semaphore has no registered name')
        matches = [finalizer for finalizer in tuple(getattr(util, '_finalizer_registry').values())
                   if getattr(finalizer, '_weakref', None) is not None
                   and finalizer._weakref() is semaphore
                   and finalizer._callback is self.cleanup
                   and finalizer._args == (name,)
                   and finalizer._pid == self.parent]
        if len(matches) != 1:
            raise RuntimeError('owned semaphore has no exact original finalizer')
        if matches[0] not in self.finalizers:
            self.finalizers.append(matches[0])

    def close(self) -> None:
        self._close()

    def _close(self, *, acquiring: bool = False) -> None:
        if self.closed:
            return
        if os.getpid() != self.parent or _case() != self.case:
            raise RuntimeError('multiprocessing teardown left original case/parent')
        if self.identity is None:
            self.closed = True
            return
        if (self.tracker is not resource_tracker._resource_tracker
                or self.tracker._fd != self.fd or self.tracker._pid != self.pid
                or self.tracker._stop.__func__ is not self.stop.__func__):
            raise RuntimeError('multiprocessing tracker ownership changed')
        if self.fd is None or (self.custody is None and not acquiring):
            raise RuntimeError('multiprocessing pipe custody is missing')
        for descriptor in (self.fd, self.custody):
            if descriptor is None:
                continue
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino, info.st_mode) != self.identity:
                raise RuntimeError('multiprocessing pipe generation changed')
        for process in self.processes:
            if not process._closed and process._popen is not None:
                if process._popen.returncode is None:
                    raise RuntimeError('original child has not been joined')
        # Do not release semaphores while a child may still be using them.
        for queue in self.queues:
            queue.close()
            queue.join_thread()
            if queue._thread is None:
                queue._reader.close()
                queue._writer.close()
        for connection in self.connections:
            connection.close()
        for process in self.processes:
            if not process._closed:
                process.close()
            _process_owners.pop(process, None)
            _process_bindings.pop(process, None)
        for finalizer in reversed(self.finalizers):
            finalizer()
        self.finalizers.clear()
        self.processes.clear()
        self.queues.clear()
        self.connections.clear()
        if self.custody is not None:
            os.close(self.custody)
            self.custody = None
        # Closing the last owned writer lets the tracker finish naturally.
        # CPython performs waitpid here, in the original parent, before pytest
        # can produce a summary or the finite guard can finalize.
        self.stop()
        self.closed = True
        if self.tracker._fd is not None or self.tracker._pid is not None:
            raise RuntimeError('original tracker stop did not settle ownership')
        if self.tracker._exitcode != 0:
            raise RuntimeError('original tracker did not exit cleanly')

    def __exit__(self, kind: Any, error: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            self.close()
        except BaseException as cleanup_error:
            if error is not None:
                raise BaseExceptionGroup('test and multiprocessing teardown failed',
                                         [error, cleanup_error]) from None
            raise


class _OwnedContext:
    def __init__(self, owner: SpawnResources, context: Any) -> None:
        self.owner, self.original = owner, context

    def Process(self, *args: Any, **kwargs: Any) -> Any:
        process = self.original.Process(*args, **kwargs)
        self.owner.processes.append(process)
        _process_owners[process] = weakref.ref(self.owner)
        _process_bindings[process] = (process._target, process._args, process._kwargs)
        return process

    def Pipe(self, *args: Any, **kwargs: Any) -> Any:
        pair = self.original.Pipe(*args, **kwargs)
        self.owner.connections.extend(pair)
        return pair

    def Queue(self, *args: Any, **kwargs: Any) -> Any:
        queue = self.original.Queue(*args, **kwargs)
        self.owner.queues.append(queue)
        for semaphore in (queue._rlock, queue._wlock, queue._sem):
            self.owner._semaphore(semaphore)
        return queue

    def Event(self, *args: Any, **kwargs: Any) -> Any:
        event = self.original.Event(*args, **kwargs)
        condition = event._cond
        for semaphore in (condition._lock, condition._sleeping_count,
                          condition._woken_count, condition._wait_semaphore, event._flag):
            self.owner._semaphore(semaphore)
        return event

    def Value(self, *args: Any, **kwargs: Any) -> Any:
        value = self.original.Value(*args, **kwargs)
        self.owner._semaphore(value.get_lock())
        return value
