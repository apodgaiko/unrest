"""Production executor for durable asynchronous Mission mutations.

Run control owns admission and lifecycle custody.  This module is the only
bridge from a run worker back into the existing ``ProjectController``
authority.  It deliberately contains no alternative Mission semantics.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
from .config import HarnessConfig
from .controller import ProjectController, ToolError
from .models import Decision, TaskList
from .project_lock import ProjectLockError, ProjectMutationLock, project_lock_path


def _payload(value: Any) -> dict[str, Any]:
    if isinstance(value, ToolError):
        return {
            "error": value.code,
            "message": value.message,
            "details": [str(item) for item in (value.details or [])],
        }
    dumped = value.model_dump(mode="json", by_alias=True)
    if not isinstance(dumped, dict):
        raise TypeError("Mission executor returned a non-object")
    return dumped


def _invoke(controller: ProjectController, operation: str, arguments: Mapping[str, Any]) -> Any:
    if operation == "start_project":
        return controller.start_project(
            str(arguments["brief"]),
            str(arguments["workspace_dir"]),
            arguments.get("worker_model"),
            arguments.get("worker_reasoning_effort"),
        )
    if operation == "submit_plan":
        return controller.submit_plan(
            str(arguments["project_id"]),
            TaskList.model_validate(arguments["task_list"]),
        )
    if operation == "advance_project":
        return controller.advance_project(
            str(arguments["project_id"]), arguments.get("max_steps")
        )
    if operation == "end_mission":
        return controller.end_mission(
            str(arguments["project_id"]), arguments.get("deliverable_roots")
        )
    if operation == "decide_attention":
        return controller.decide_attention(
            str(arguments["project_id"]),
            [Decision.model_validate(item) for item in arguments["decisions"]],
        )
    if operation == "abort_project":
        return controller.abort_project(
            str(arguments["project_id"]), str(arguments["reason"])
        )
    raise ValueError("unsupported Mission operation")


def execute(operation: str, arguments: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    """Route one admitted operation exactly once through ``ProjectController``."""

    config = HarnessConfig.discover()
    dispatcher = ACPNodeDispatcher(config)
    reviewer = ACPTerminalReviewer(config)
    controller = ProjectController(config, dispatcher, reviewer)
    project_id = arguments.get("project_id")
    if operation == "start_project" or not isinstance(project_id, str):
        try:
            return _payload(_invoke(controller, operation, arguments))
        except ToolError as exc:
            return _payload(exc)

    try:
        lock_path = project_lock_path(controller.store, project_id)
    except ProjectLockError as exc:
        raise RuntimeError("project mutation lock unavailable") from exc
    if lock_path is None:
        try:
            return _payload(_invoke(controller, operation, arguments))
        except ToolError as exc:
            return _payload(exc)

    mutation_lock = ProjectMutationLock(lock_path)
    try:
        if not mutation_lock.try_acquire():
            raise RuntimeError("project mutation is busy")
        try:
            return _payload(_invoke(controller, operation, arguments))
        except ToolError as exc:
            return _payload(exc)
    finally:
        mutation_lock.release()


__all__ = ["execute"]
