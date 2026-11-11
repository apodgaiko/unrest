"""Pytest plugin for SAFE-INPROC lanes: every child-process launch is blocked.

Load with ``python -m pytest -p tests.governed_no_launch``. The guard installs
at configure time, before collection and before any test worker exists. An
intercepted launch raises ``AssertionError("launch blocked")``, is recorded,
and makes the session exit non-zero: an intercept is a lane misclassification,
not a product failure and never a launch. The JUnit report carries the global
properties ``governed_no_launch=active`` and ``governed_no_launch_intercepts``.
"""
from __future__ import annotations

import asyncio
import asyncio.base_events
import importlib
import multiprocessing.process
import os
import pty
import subprocess
from typing import Any

import pytest

_OS_NAMES = (
    "fork", "forkpty", "posix_spawn", "posix_spawnp", "system", "popen",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
)

INTERCEPTS: list[tuple[str, str]] = []
INSTALLED: list[str] = []
_CURRENT: list[str] = [""]


def _blocked(name: str) -> Any:
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        INTERCEPTS.append((name, _CURRENT[0]))
        raise AssertionError("launch blocked")

    return blocked


def _async_blocked(name: str) -> Any:
    async def blocked(*_args: Any, **_kwargs: Any) -> Any:
        INTERCEPTS.append((name, _CURRENT[0]))
        raise AssertionError("launch blocked")

    return blocked


def _install() -> None:
    if INSTALLED:
        return
    subprocess.Popen.__init__ = _blocked("subprocess.Popen.__init__")  # type: ignore[method-assign]
    INSTALLED.append("subprocess.Popen.__init__")
    posix = importlib.import_module("_posixsubprocess")
    posix.fork_exec = _blocked("_posixsubprocess.fork_exec")  # type: ignore[attr-defined]
    INSTALLED.append("_posixsubprocess.fork_exec")
    for name in _OS_NAMES:
        if hasattr(os, name):
            setattr(os, name, _blocked(f"os.{name}"))
            INSTALLED.append(f"os.{name}")
    pty.fork = _blocked("pty.fork")
    INSTALLED.append("pty.fork")
    asyncio.create_subprocess_exec = _async_blocked("asyncio.create_subprocess_exec")  # type: ignore[assignment]
    asyncio.create_subprocess_shell = _async_blocked("asyncio.create_subprocess_shell")  # type: ignore[assignment]
    loop = asyncio.base_events.BaseEventLoop
    loop.subprocess_exec = _async_blocked("BaseEventLoop.subprocess_exec")  # type: ignore[method-assign]
    loop.subprocess_shell = _async_blocked("BaseEventLoop.subprocess_shell")  # type: ignore[method-assign]
    INSTALLED.extend([
        "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
        "BaseEventLoop.subprocess_exec", "BaseEventLoop.subprocess_shell",
    ])
    multiprocessing.process.BaseProcess.start = _blocked(  # type: ignore[method-assign]
        "multiprocessing.process.BaseProcess.start"
    )
    INSTALLED.append("multiprocessing.process.BaseProcess.start")
    acp_runner = importlib.import_module("unrest_harness.acp_runner")
    acp_runner.spawn_launch = _async_blocked("unrest_harness.acp_runner.spawn_launch")  # type: ignore[attr-defined]
    INSTALLED.append("unrest_harness.acp_runner.spawn_launch")


def pytest_configure(config: pytest.Config) -> None:
    _install()


def pytest_sessionstart(session: pytest.Session) -> None:
    _record(session.config, "governed_no_launch", "active")
    _record(session.config, "governed_no_launch_installed", str(len(INSTALLED)))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: Any) -> Any:
    _CURRENT[0] = item.nodeid
    before = len(INTERCEPTS)
    yield
    if len(INTERCEPTS) != before:
        item.user_properties.append(("governed_no_launch_intercepted", "true"))
    _CURRENT[0] = ""


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    _record(session.config, "governed_no_launch_intercepts", str(len(INTERCEPTS)))
    if INTERCEPTS:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: Any) -> None:
    terminalreporter.write_line(
        f"governed_no_launch=active installed={len(INSTALLED)} intercepts={len(INTERCEPTS)}"
    )
    for name, nodeid in INTERCEPTS:
        terminalreporter.write_line(f"governed_no_launch intercept: {name} in {nodeid}")


def _record(config: pytest.Config, name: str, value: str) -> None:
    xml = getattr(config, "stash", None)
    plugin = None
    if xml is not None:
        from _pytest.junitxml import xml_key

        plugin = config.stash.get(xml_key, None)
    if plugin is not None:
        plugin.add_global_property(name, value)
