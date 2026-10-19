"""Explicit new methods requiring the real inherited Linux certification guard."""

from __future__ import annotations

import multiprocessing
from multiprocessing import util, popen_spawn_posix
import os
import sys
import types

import pytest

from tests.multiprocess_lifetime import SpawnResources
from tests.test_multiprocess_resource_ownership import _exit_with_status, _publish


def test_owned_exit17_keeps_raw_status():
    guard = sys.modules["runtime_guard"]
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context("spawn"))
        process = context.Process(target=_exit_with_status, args=(17,))
        process.start()
        child = process.pid
        process.join(10)
        assert process.exitcode == 17
    assert owner.closed and owner.tracker._pid is None and owner.tracker._exitcode == 0
    rows = guard.summarize(guard._STATE["manifest_path"])["events"]
    assert any(
        row["kind"] == "raw_actual_parent_waitpid"
        and row["pid"] == child
        and row["raw_status"] == 17 << 8
        for row in rows
    )


@pytest.mark.parametrize("kind", ["globals", "arguments", "case", "descriptor", "caller"])
def test_refusal_is_sticky(kind):
    guard = sys.modules["runtime_guard"]
    original_case = guard._STATE["case"]
    with SpawnResources() as owner:
        context = owner.context(multiprocessing.get_context("spawn"))
        queue = context.Queue()
        gate = context.Event()
        value = context.Value("i", 0)
        process = context.Process(target=_publish, args=(queue, gate, value))
        extra = []
        original_launch = None
        try:
            if kind == "globals":
                original_launch = popen_spawn_posix.Popen._launch
                popen_spawn_posix.Popen._launch = types.FunctionType(
                    original_launch.__code__,
                    dict(original_launch.__globals__),
                    original_launch.__name__,
                    original_launch.__defaults__,
                    original_launch.__closure__,
                )

            elif kind == "arguments":
                process._args = tuple(list(process._args))
            elif kind == "case":
                guard._STATE["case"] = "outside-current-finite-case"
            elif kind == "descriptor":
                other = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(other, owner.fd, inheritable=False)
                finally:
                    os.close(other)
            with pytest.raises(guard.GuardRefusal):
                if kind == "caller":
                    read, write = os.pipe()
                    extra.extend((read, write))
                    util.spawnv_passfds(
                        sys.executable,
                        [
                            sys.executable,
                            "-B",
                            "-c",
                            "from multiprocessing.resource_tracker import main;main("
                            + str(read)
                            + ")",
                        ],
                        [sys.stderr.fileno(), read],
                    )
                else:
                    process.start()
            assert process.pid is None
        finally:
            if original_launch is not None:
                popen_spawn_posix.Popen._launch = original_launch
            guard._STATE["case"] = original_case
            if kind == "descriptor":
                os.dup2(owner.custody, owner.fd, inheritable=False)
            for descriptor in extra:
                os.close(descriptor)
    summary = guard.summarize(guard._STATE["manifest_path"])
    assert not summary["ready"]
    assert any(
        row["kind"] == "forbidden" and "multiprocess_binding:" in row["reason"]
        for row in summary["failures"]
    )
    assert not any(row["kind"] == "missing_wait" for row in summary["failures"])
