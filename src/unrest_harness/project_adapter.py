"""Typed, bounded declarative DAG composition for ``MissionCoordinator``.

The adapter deliberately does not own project or mission lifecycle.  Callers
submit :meth:`ProjectDag.task_list` through the accepted controller, then pass
the resulting coordinator to :func:`run_project`.  Dispatch, workspace
leasing, patch return, integration, failure, and cleanup therefore remain in
``MissionCoordinator`` and ``WorkspaceManager``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
from typing import Literal, Protocol

from .canonical_identity import canonical_json_bytes
from .coordinator import MissionCoordinator
from .models import AttentionNeeded, Task, TaskList


_MAX_PROJECT_NODES = 256
_WRITES_LINE = re.compile(r"(?im)^writes:\s*")
_PROTECTED_PATHS = (".git", ".unrest", ".unrest-runtime")


class ProjectAdapterError(ValueError):
    """A stable, content-free adapter rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CancellationSignal(Protocol):
    """The subset of ``threading.Event`` used at coordinator boundaries."""

    def is_set(self) -> bool: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _normalized_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ProjectAdapterError("invalid_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProjectAdapterError("invalid_path")
    normalized = path.as_posix()
    if normalized == ".":
        raise ProjectAdapterError("invalid_path")
    return normalized


def _contains(root: str, path: str) -> bool:
    return path == root or path.startswith(root + "/")


@dataclass(frozen=True)
class ProjectNode:
    """One declarative work node in a project DAG.

    ``writes`` is compiled into the coordinator's accepted ``Writes:`` task
    declaration. ``result_path`` is optional, repository-relative, and is only
    observed after the coordinator has returned or integrated the work.
    """

    id: str
    body: str
    needs: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    result_path: str | None = None
    targets: tuple[str, ...] = ()
    skill: str = "engineering-mission-playbook"
    auto_merge: bool = True

    def __post_init__(self) -> None:
        if not self.id or not self.body.strip() or not self.skill:
            raise ProjectAdapterError("invalid_node")
        if _WRITES_LINE.search(self.body):
            raise ProjectAdapterError("reserved_writes_declaration")
        needs = tuple(sorted(self.needs))
        writes = tuple(sorted(_normalized_path(path) for path in self.writes))
        targets = tuple(sorted(self.targets))
        if (
            len(needs) != len(set(needs))
            or len(writes) != len(set(writes))
            or len(targets) != len(set(targets))
        ):
            raise ProjectAdapterError("duplicate_node_field")
        if self.id in needs:
            raise ProjectAdapterError("self_dependency")
        if any(
            _contains(protected, write) or _contains(write, protected)
            for protected in _PROTECTED_PATHS
            for write in writes
        ):
            raise ProjectAdapterError("protected_write_path")
        result_path = (
            None if self.result_path is None else _normalized_path(self.result_path)
        )
        if result_path is not None and not any(
            _contains(write, result_path) for write in writes
        ):
            raise ProjectAdapterError("result_outside_write_scope")
        object.__setattr__(self, "needs", needs)
        object.__setattr__(self, "writes", writes)
        object.__setattr__(self, "targets", targets)
        object.__setattr__(self, "result_path", result_path)

    def task(self) -> Task:
        body = self.body.rstrip()
        if self.writes:
            body += "\n\nWrites: " + ", ".join(self.writes)
        return Task(
            id=self.id,
            type="work",
            body=body,
            targets=list(self.targets),
            skill=self.skill,
            auto_merge=self.auto_merge,
            depends_on=list(self.needs),
        )

    def canonical_record(self) -> dict[str, object]:
        return {
            "auto_merge": self.auto_merge,
            "body_sha256": _sha256(self.body.encode("utf-8")),
            "id": self.id,
            "needs": list(self.needs),
            "result_path": self.result_path,
            "skill": self.skill,
            "targets": list(self.targets),
            "writes": list(self.writes),
        }


@dataclass(frozen=True)
class ProjectDag:
    """A finite DAG compiled to the coordinator's accepted ``TaskList``."""

    nodes: tuple[ProjectNode, ...]

    def __post_init__(self) -> None:
        if not self.nodes or len(self.nodes) > _MAX_PROJECT_NODES:
            raise ProjectAdapterError("invalid_project_size")
        ids = [node.id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ProjectAdapterError("duplicate_node")
        known = set(ids)
        if any(dependency not in known for node in self.nodes for dependency in node.needs):
            raise ProjectAdapterError("unknown_dependency")
        self.ordered_nodes()

    def ordered_nodes(self) -> tuple[ProjectNode, ...]:
        """Return lexical topological order, independent of input ordering."""

        by_id = {node.id: node for node in self.nodes}
        remaining = {node.id: set(node.needs) for node in self.nodes}
        ordered: list[ProjectNode] = []
        while remaining:
            ready = sorted(node_id for node_id, needs in remaining.items() if not needs)
            if not ready:
                raise ProjectAdapterError("cyclic_project")
            for node_id in ready:
                ordered.append(by_id[node_id])
                del remaining[node_id]
            for needs in remaining.values():
                needs.difference_update(ready)
        return tuple(ordered)

    def task_list(self) -> TaskList:
        return TaskList(tasks=[node.task() for node in self.ordered_nodes()])

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "nodes": [node.canonical_record() for node in self.ordered_nodes()],
                "schema": "unrest.project-dag.v1",
            }
        )


NodeStatus = Literal["pending", "running", "cleared", "failed", "superseded"]
ProjectRunStatus = Literal["completed", "failed", "cancelled", "bounded"]


@dataclass(frozen=True)
class ProjectNodeResult:
    id: str
    status: NodeStatus
    result_path: str | None
    result_bytes: int | None
    result_sha256: str | None

    def canonical_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "result_bytes": self.result_bytes,
            "result_path": self.result_path,
            "result_sha256": self.result_sha256,
            "status": self.status,
        }


@dataclass(frozen=True)
class ProjectRunResult:
    status: ProjectRunStatus
    steps: int
    ready_order: tuple[tuple[str, ...], ...]
    dispatch_batches: tuple[tuple[str, ...], ...]
    nodes: tuple[ProjectNodeResult, ...]
    blocked: tuple[str, ...]

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "blocked": list(self.blocked),
                "dispatch_batches": [list(batch) for batch in self.dispatch_batches],
                "nodes": [node.canonical_record() for node in self.nodes],
                "ready_order": [list(ready) for ready in self.ready_order],
                "schema": "unrest.project-result.v1",
                "status": self.status,
                "steps": self.steps,
            }
        )


def _node_results(
    coordinator: MissionCoordinator,
    mission_id: str,
    project: ProjectDag,
) -> tuple[ProjectNodeResult, ...]:
    task_state = coordinator.store.load_task_state(coordinator.project_id, mission_id)
    workspace = coordinator.store.workspace_dir(coordinator.project_id)
    results: list[ProjectNodeResult] = []
    for node in project.ordered_nodes():
        size: int | None = None
        digest: str | None = None
        if node.result_path is not None:
            candidate = workspace / node.result_path
            if candidate.is_file() and not candidate.is_symlink():
                content = candidate.read_bytes()
                size = len(content)
                digest = _sha256(content)
        results.append(
            ProjectNodeResult(
                id=node.id,
                status=task_state.status_of(node.id),
                result_path=node.result_path,
                result_bytes=size,
                result_sha256=digest,
            )
        )
    return tuple(results)


def run_project(
    coordinator: MissionCoordinator,
    mission_id: str,
    project: ProjectDag,
    *,
    max_steps: int,
    cancel: CancellationSignal | None = None,
) -> ProjectRunResult:
    """Run at most ``max_steps`` accepted coordinator transitions.

    Cancellation is checked between coordinator steps.  A coordinator step is
    intentionally indivisible: an isolated batch returns, integrates or
    withholds, and cleans its leases before control comes back to this adapter.
    """

    if isinstance(max_steps, bool) or max_steps <= 0:
        raise ProjectAdapterError("invalid_step_bound")
    task_list = coordinator.store.load_task_list(coordinator.project_id, mission_id)
    expected = project.task_list()
    if task_list.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise ProjectAdapterError("project_task_list_mismatch")

    ready_order: list[tuple[str, ...]] = []
    dispatch_batches: list[tuple[str, ...]] = []
    steps = 0
    status: ProjectRunStatus = "bounded"
    while steps < max_steps:
        if cancel is not None and cancel.is_set():
            status = "cancelled"
            break
        task_state = coordinator.store.load_task_state(coordinator.project_id, mission_id)
        statuses = [task_state.status_of(node.id) for node in project.ordered_nodes()]
        if all(node_status == "cleared" for node_status in statuses):
            status = "completed"
            break
        if any(node_status == "failed" for node_status in statuses) or isinstance(
            coordinator.store.load_state(coordinator.project_id), AttentionNeeded
        ):
            status = "failed"
            break
        runnable = coordinator._all_runnable_tasks(task_list, task_state)
        if not runnable:
            status = "failed"
            break
        selected = coordinator._select_dispatch_tasks(task_list, task_state, runnable)
        ready_order.append(tuple(task.id for task in runnable))
        dispatch_batches.append(tuple(task.id for task in selected))
        step = coordinator.step()
        steps += 1
        if step.kind == "attention_needed":
            status = "failed"
            break
        if step.kind == "terminal":
            task_state = coordinator.store.load_task_state(
                coordinator.project_id, mission_id
            )
            status = (
                "completed"
                if all(
                    task_state.status_of(node.id) == "cleared"
                    for node in project.ordered_nodes()
                )
                else "failed"
            )
            break
        if step.kind == "idle":
            status = "failed"
            break
    else:
        task_state = coordinator.store.load_task_state(coordinator.project_id, mission_id)
        if all(
            task_state.status_of(node.id) == "cleared"
            for node in project.ordered_nodes()
        ):
            status = "completed"

    results = _node_results(coordinator, mission_id, project)
    blocked = tuple(node.id for node in results if node.status in {"pending", "running"})
    return ProjectRunResult(
        status=status,
        steps=steps,
        ready_order=tuple(ready_order),
        dispatch_batches=tuple(dispatch_batches),
        nodes=results,
        blocked=blocked,
    )


__all__ = [
    "CancellationSignal",
    "ProjectAdapterError",
    "ProjectDag",
    "ProjectNode",
    "ProjectNodeResult",
    "ProjectRunResult",
    "run_project",
]
