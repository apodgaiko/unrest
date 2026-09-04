"""Subprocess entry point for one durable asynchronous Mission mutation."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import os
from pathlib import Path
import signal
import time
from typing import Any, NoReturn

from .config import HarnessConfig
from .models import MissionRunning
from .run_control import RunControl, RunControlError, load_executor
from .storage import ProjectStore
from .supervision import (
    load_project_active_attempts,
    save_snapshot,
    terminal_snapshot,
)


class WorkerCancelled(BaseException):
    """Private hard-cancel signal that ordinary effect handlers must not catch.

    Coordinator dispatch boundaries deliberately convert ordinary ``Exception``
    failures into task attention.  A process-group cancellation is separate
    authority, so it must unwind past those boundaries to the run worker.
    """


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


def _terminalize_cancelled_attempts(arguments: Mapping[str, Any]) -> None:
    """Hide exact active snapshots without publishing task or attention effects."""
    project_id = arguments.get("project_id")
    if not isinstance(project_id, str):
        return
    store = ProjectStore(HarnessConfig.discover())
    state = store.load_state(project_id)
    if not isinstance(state, MissionRunning):
        return
    task_list = store.load_task_list(project_id, state.mission_id)
    targets_by_node = {task.id: task.targets for task in task_list.tasks}
    all_targets = list(
        dict.fromkeys(target for task in task_list.tasks for target in task.targets)
    )
    for snapshot in load_project_active_attempts(
        store, project_id, state.mission_id, task_list
    ):
        assigned = (
            all_targets
            if snapshot.node_id is None
            else targets_by_node[snapshot.node_id]
        )
        save_snapshot(
            store,
            terminal_snapshot(snapshot),
            assigned_target_ids=assigned,
        )


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    control: RunControl | None = None
    arguments: Mapping[str, Any] = {}
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
            if control.inspect_run(options.run_id).state == "cancel_requested":
                raise WorkerCancelled
            control.worker_effect_complete(options.run_id, result)
            control.worker_report_complete(options.run_id)
            control.worker_succeeded(options.run_id)
        return 0
    except WorkerCancelled:
        if control is not None:
            try:
                _terminalize_cancelled_attempts(arguments)
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
