"""Shared in-process fixtures for governed S1 tests (no child processes)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    Task,
    TaskList,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore

BUNDLED = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
REQUEST = {
    "schema": "unrest.governed-admission-request.v1",
    "idempotency_key": "key-1",
    "criterion_identity_policy": "internal_digest_with_plaintext",
}


def abandon_request(key: str = "abandon-1") -> dict[str, str]:
    return {"schema": "unrest.governed-abandon-request.v1", "idempotency_key": key}


def request(key: str = "key-1") -> dict[str, str]:
    return {**REQUEST, "idempotency_key": key}


def make_config(tmp_path: Path, *, max_parallel_nodes: int = 1) -> HarnessConfig:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    return HarnessConfig(
        bundled_dir=BUNDLED,
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=max_parallel_nodes,
    )


def done_handoff(request: DispatchRequest) -> NodeHandoff:
    if request.task.type == "validate":
        return ValidateHandoff(
            node_id=request.task.id, done=True, report="ok", items=[], passed=True
        )
    return WorkHandoff(node_id=request.task.id, done=True, report="ok")


class CapableDispatcher(MockDispatcher):
    """In-process fake declaring governed delivery; never launches anything."""

    supports_governed_delivery = True


def make_controller(
    tmp_path: Path,
    *,
    responder: Callable[[DispatchRequest], NodeHandoff] = done_handoff,
    capable: bool = True,
    max_parallel_nodes: int = 1,
) -> ProjectController:
    config = make_config(tmp_path, max_parallel_nodes=max_parallel_nodes)
    dispatcher = (CapableDispatcher if capable else MockDispatcher)(responder)
    reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True, report="ok"))
    return ProjectController(config, dispatcher, reviewer)


def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def start(controller: ProjectController, tmp_path: Path, brief: str = "Governed demo") -> str:
    envelope = controller.start_project(brief, str(workspace(tmp_path)))
    return envelope.projectId


def write_criteria(
    store: ProjectStore, project_id: str, mission_id: str, criteria: dict[str, bytes | str]
) -> Path:
    directory = store.mission_dir(project_id, mission_id) / "contract"
    directory.mkdir(parents=True, exist_ok=True)
    for aid, body in criteria.items():
        data = body.encode() if isinstance(body, str) else body
        (directory / f"{aid}.md").write_bytes(data)
    return directory


def work_plan(aids: list[str], *, validate: bool = False, prefix: str = "w") -> TaskList:
    tasks = [
        Task(id=f"{prefix}{index}", type="work", body="do", targets=[aid], skill="s")
        for index, aid in enumerate(aids)
    ]
    if validate:
        tasks.append(Task(id="v0", type="validate", body="check", targets=list(aids),
                          skill="s", depends_on=[task.id for task in tasks]))
    return TaskList(tasks=tasks)


def governed_project(
    tmp_path: Path,
    *,
    criteria: dict[str, bytes | str] | None = None,
    plan: TaskList | None = None,
    admit: bool = True,
    **controller_kwargs: Any,
) -> tuple[ProjectController, str, str]:
    controller = make_controller(tmp_path, **controller_kwargs)
    project_id = start(controller, tmp_path)
    mission_id = "mission-001"
    criteria = criteria or {"VAL-A": "Criterion A body.\n"}
    write_criteria(controller.store, project_id, mission_id, criteria)
    if admit:
        controller.submit_governed_plan(
            project_id, mission_id, plan or work_plan(sorted(criteria)), request()
        )
    return controller, project_id, mission_id


def governed_dir(store: ProjectStore, project_id: str, mission_id: str) -> Path:
    return store.mission_dir(project_id, mission_id) / "governed"


def tree_snapshot(root: Path, *, exclude: tuple[str, ...] = ("mutation.lock",)) -> dict[str, Any]:
    """Bytes, inode, mtime_ns and mode of every entry (atime excluded)."""
    result: dict[str, Any] = {}
    if not root.exists():
        return result
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames) + sorted(dirnames):
            path = Path(dirpath) / name
            if name in exclude:
                continue
            info = path.lstat()
            entry: tuple[Any, ...] = (info.st_ino, info.st_mtime_ns, info.st_mode)
            if path.is_file() and not path.is_symlink():
                entry += (hashlib.sha256(path.read_bytes()).hexdigest(),)
            result[str(path.relative_to(root))] = entry
    return result
