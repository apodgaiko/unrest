"""Cancellation follows the owned role task; cleanup tasks keep their lifetime."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from collections.abc import Coroutine
import threading
from typing import Any


class EffectCancellation:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requested = False
        self._binding: tuple[asyncio.AbstractEventLoop, asyncio.Task[Any]] | None = None

    def cancel(self) -> None:
        with self._lock:
            if self._requested:
                return
            self._requested = True
            if self._binding is not None:
                loop, task = self._binding
                loop.call_soon_threadsafe(task.cancel)

    async def run(self, coroutine: Coroutine[Any, Any, Any]) -> Any:
        loop, task = asyncio.get_running_loop(), asyncio.current_task()
        assert task is not None
        with self._lock:
            if self._binding is not None:
                coroutine.close()
                raise RuntimeError("role cancellation owner already has an async task")
            if self._requested:
                coroutine.close()
                raise asyncio.CancelledError
            self._binding = loop, task
        try:
            return await coroutine
        finally:
            with self._lock:
                self._binding = None


current_effect: ContextVar[EffectCancellation | None] = ContextVar("unrest_role_effect", default=None)
