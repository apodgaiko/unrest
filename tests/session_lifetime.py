"""Deterministic ownership for the synchronous experimental session factories."""
from __future__ import annotations

from asyncio import Runner
from typing import cast

import pytest
import pytest_asyncio

from unrest_harness.experimental_session import _SessionOwner


def own_session_fixture(request: pytest.FixtureRequest, name: str) -> None:
    if name not in request.fixturenames:
        return
    # Acquire the test's existing runner first. A failed loop setup must never
    # strand an owner or require constructing a replacement loop for cleanup.
    runner = None
    if pytest_asyncio.is_async_test(request.node):
        runner = cast(Runner, request.getfixturevalue('_function_scoped_runner'))
        runner.get_loop()
    owner = cast(_SessionOwner, request.getfixturevalue(name))

    def finish() -> None:
        if owner._close_task is not None and owner._close_task.done():
            return  # Explicit test teardown has already observed its result.
        if (owner._server_task is None and owner._listener is None
                and not owner._launches and not owner.roles and not owner.backends
                and owner._close_task is None):
            owner.close_unstarted()
        else:
            if runner is None:
                raise RuntimeError('started session has no owning test runner')
            runner.run(owner.close())

    request.addfinalizer(finish)
