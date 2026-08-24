"""Subprocess entry point for one durable asynchronous Mission mutation."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import os
from pathlib import Path
import signal
import time
from typing import Any, NoReturn

from .run_control import RunControl, RunControlError, load_executor


class WorkerCancelled(Exception):
    """Private control-flow signal; its message is never persisted."""


class WorkerContext:
    """Executor context for descendants that must drain before lock release."""

    def __init__(self) -> None:
        self._descendant_pids: set[int] = set()

    def register_descendant(self, pid: int) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise ValueError("descendant pid is invalid")
        try:
            if os.getpgid(pid) != os.getpgrp():
                raise ValueError("descendant must share the worker process group")
        except ProcessLookupError as exc:
            raise ValueError("descendant is not live") from exc
        self._descendant_pids.add(pid)

    def drain_descendants(self) -> None:
        for pid in sorted(self._descendant_pids):
            while True:
                try:
                    waited, _ = os.waitpid(pid, 0)
                    if waited == pid:
                        break
                except ChildProcessError:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                except InterruptedError:
                    continue


def _cancel(_: int, __: Any) -> NoReturn:
    raise WorkerCancelled()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--executor", required=True)
    parser.add_argument("--custody-root-id", required=True)
    parser.add_argument("--generation", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    control: RunControl | None = None
    try:
        project_root = Path(options.project_root).resolve(strict=True)
        control = RunControl(
            project_root,
            executor_ref=options.executor,
            custody_root_id=options.custody_root_id,
            owner_id=f"worker:{os.getpid()}:{options.generation}",
            recover=False,
        )
        executor = load_executor(options.executor)
        with control.resource_lock(options.run_id):
            if not control.worker_start(
                options.run_id,
                pid=os.getpid(),
                pgid=os.getpgrp(),
                generation=options.generation,
            ):
                return 0
            operation, arguments = control.request_payload(options.run_id)
            context = WorkerContext()
            result = executor(operation, arguments, context)
            if not isinstance(result, Mapping):
                raise TypeError("executor result must be an object")
            context.drain_descendants()
            control.worker_effect_complete(options.run_id, result)
            control.worker_report_complete(options.run_id)
            control.worker_succeeded(options.run_id)
        return 0
    except WorkerCancelled:
        if control is not None:
            try:
                control.worker_draining(options.run_id)
                control.worker_cancelled(options.run_id)
            except RunControlError:
                pass
        return 2
    except Exception:
        if control is not None:
            try:
                control.worker_failed(options.run_id)
            except RunControlError:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["WorkerContext", "main"]
