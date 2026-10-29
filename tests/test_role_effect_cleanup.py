"""Main-thread interruption must not abandon a role's owned cleanup."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future
import threading

import pytest

import unrest_harness.coordinator as coordinator
from unrest_harness.run_worker import WorkerCancelled
from unrest_harness.acp_runner import _finish_owned_cleanup, _run_coro_blocking
from unrest_harness.effect_cancellation import EffectCancellation


@pytest.mark.parametrize("interruption", [WorkerCancelled, KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.parametrize("repeated", [0, 2])
def test_interrupted_wait_joins_role_cleanup_before_return(monkeypatch, interruption, repeated):
    started = threading.Event()
    release = threading.Event()
    joining = threading.Event()
    returned = threading.Event()
    cleaned = threading.Event()
    error = interruption()
    caught: list[BaseException] = []

    class InterruptedFuture(Future):
        def result(self, timeout=None):
            assert started.wait(2)
            raise error

    original_join = threading.Thread.join

    def join(thread, timeout=None):
        nonlocal repeated
        if thread.name == "unrest-role-effect":
            if repeated:
                repeated -= 1
                raise KeyboardInterrupt
            joining.set()
        return original_join(thread, timeout)

    monkeypatch.setattr(coordinator.concurrent.futures, "Future", InterruptedFuture)
    monkeypatch.setattr(threading.Thread, "join", join)

    def effect():
        started.set()
        assert release.wait(3)
        cleaned.set()

    def invoke():
        try:
            owner = object.__new__(coordinator.MissionCoordinator)
            owner._await_role_effect("mission-001", effect)
        except BaseException as exc:
            caught.append(exc)
        finally:
            returned.set()

    caller = threading.Thread(target=invoke)
    caller.start()
    try:
        assert joining.wait(2), "interrupted caller abandoned its owned role thread"
        assert not returned.is_set() and not cleaned.is_set()
    finally:
        release.set()
        original_join(caller, 3)
    assert not caller.is_alive()
    assert cleaned.is_set() and returned.is_set()
    assert caught == [error]


def test_cancellation_before_async_registration_never_starts_body():
    owner = EffectCancellation()
    owner.cancel()
    entered = []

    async def body():
        entered.append(True)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(owner.run(body()))
    assert entered == []


def test_repeated_cancellation_keeps_actual_async_cleanup_owner_alive():
    owner = EffectCancellation()
    started = asyncio.Event()
    cleaning = asyncio.Event()
    release = asyncio.Event()
    finished = []

    async def close_child():
        cleaning.set()
        await release.wait()
        finished.append("numeric wait completed")

    async def role():
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            await _finish_owned_cleanup([close_child])

    async def exercise():
        task = asyncio.create_task(owner.run(role()))
        await started.wait()
        owner.cancel()
        await cleaning.wait()
        owner.cancel()
        await asyncio.sleep(0)
        assert not task.done() and finished == []
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished == ["numeric wait completed"]

    asyncio.run(exercise())


def test_interrupted_coordinator_cancels_role_task_and_joins_its_cleanup(monkeypatch):
    started = threading.Event()
    cleaning = threading.Event()
    release = threading.Event()
    returned = threading.Event()
    finished = threading.Event()
    error = WorkerCancelled()
    caught = []

    class InterruptedFuture(Future):
        def result(self, timeout=None):
            assert started.wait(2)
            raise error

    monkeypatch.setattr(coordinator.concurrent.futures, "Future", InterruptedFuture)

    async def close_child():
        cleaning.set()
        while not release.is_set():
            await asyncio.sleep(0.001)
        finished.set()

    async def role():
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            await _finish_owned_cleanup([close_child])

    def invoke():
        try:
            owner = object.__new__(coordinator.MissionCoordinator)
            owner._await_role_effect("mission-001", lambda: _run_coro_blocking(role()))
        except BaseException as exc:
            caught.append(exc)
        finally:
            returned.set()

    caller = threading.Thread(target=invoke)
    caller.start()
    try:
        assert cleaning.wait(2)
        assert not returned.is_set() and not finished.is_set()
    finally:
        release.set()
        caller.join(3)
    assert not caller.is_alive() and finished.is_set()
    assert caught == [error]
