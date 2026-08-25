from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess
import threading
import time
from typing import Callable

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
)
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff
from unrest_harness.project_adapter import (
    ProjectAdapterError,
    ProjectDag,
    ProjectNode,
    run_project,
)


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Project Adapter Test")
    _git(root, "config", "user.email", "project-adapter@example.test")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        ".agents/\n.claude/\n.codex/\n.unrest/\n.unrest-runtime/\nAGENTS.md\n",
        encoding="utf-8",
    )
    _git(root, "add", "README.md", ".gitignore")
    _git(root, "commit", "-m", "base")
    return root


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=2,
    )


def _project() -> ProjectDag:
    return ProjectDag(
        nodes=(
            ProjectNode(
                "join",
                "Join the leaf artifacts.",
                needs=("leaf-b", "leaf-a"),
                writes=("result/join.txt",),
                result_path="result/join.txt",
                targets=("VAL-PROJECT",),
            ),
            ProjectNode(
                "leaf-b",
                "Produce B.",
                writes=("result/b.txt",),
                result_path="result/b.txt",
            ),
            ProjectNode(
                "leaf-a",
                "Produce A.",
                writes=("result/a.txt",),
                result_path="result/a.txt",
            ),
        )
    )


@dataclass
class _Runtime:
    coordinator: MissionCoordinator
    project_id: str
    mission_id: str


def _runtime(
    config: HarnessConfig,
    repository: Path,
    project: ProjectDag,
    responder: Callable[[DispatchRequest], WorkHandoff],
) -> _Runtime:
    dispatcher = MockDispatcher(responder)
    dispatcher.supports_isolated_workspaces = True
    controller = ProjectController(
        config,
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    controller.start_project("Provider-free project adapter test.", str(repository))
    project_id = controller.store.list_projects()[0].id
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-PROJECT.md").write_text(
        "# VAL-PROJECT\n\nProvider-free project adapter behavior.\n",
        encoding="utf-8",
    )
    controller.submit_plan(project_id, project.task_list())
    mission_id = "mission-001"
    return _Runtime(
        MissionCoordinator(
            controller.store,
            project_id,
            dispatcher,
            controller.terminal_reviewer,
        ),
        project_id,
        mission_id,
    )


def test_two_isolated_leaves_join_in_deterministic_order_and_serialize(
    config: HarnessConfig,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project()
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    active: set[Path] = set()
    leaf_workspaces: dict[str, Path] = {}
    provider_effects = 0
    external_effects = 0

    def reject_network(*_args: object, **_kwargs: object) -> None:
        nonlocal external_effects
        external_effects += 1
        raise AssertionError("network effect")

    monkeypatch.setattr(socket.socket, "connect", reject_network)

    def responder(request: DispatchRequest) -> WorkHandoff:
        path = Path(request.cwd) if request.cwd is not None else repository
        with lock:
            assert path not in active
            active.add(path)
        try:
            if request.task.id.startswith("leaf-"):
                assert request.cwd is not None
                leaf_workspaces[request.task.id] = path
                barrier.wait(timeout=2)
                time.sleep(0.02)
                output = "A\n" if request.task.id == "leaf-a" else "B\n"
                destination = path / (
                    "result/a.txt" if request.task.id == "leaf-a" else "result/b.txt"
                )
            else:
                assert request.cwd is None
                output = (
                    (repository / "result/a.txt").read_text(encoding="utf-8").strip()
                    + "+"
                    + (repository / "result/b.txt").read_text(encoding="utf-8").strip()
                    + "\n"
                )
                destination = repository / "result/join.txt"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output, encoding="utf-8")
            return WorkHandoff(node_id=request.task.id, done=True, report="local")
        finally:
            with lock:
                active.remove(path)

    runtime = _runtime(config, repository, project, responder)
    result = run_project(runtime.coordinator, runtime.mission_id, project, max_steps=2)

    assert result.status == "completed"
    assert result.steps == 2
    assert result.ready_order == (("leaf-a", "leaf-b"), ("join",))
    assert result.dispatch_batches == (("leaf-a", "leaf-b"), ("join",))
    assert [node.id for node in result.nodes] == ["leaf-a", "leaf-b", "join"]
    assert [
        (repository / node.result_path).read_text(encoding="utf-8").strip()
        for node in result.nodes
        if node.result_path is not None
    ] == ["A", "B", "A+B"]
    assert leaf_workspaces["leaf-a"] != leaf_workspaces["leaf-b"]
    assert repository not in leaf_workspaces.values()
    assert active == set()
    assert provider_effects == 0
    assert external_effects == 0

    reversed_project = ProjectDag(nodes=tuple(reversed(project.nodes)))
    assert project.canonical_bytes() == reversed_project.canonical_bytes()
    assert result.canonical_bytes() == result.canonical_bytes()


def test_leaf_failure_blocks_join_and_withholds_integration(
    config: HarnessConfig,
    repository: Path,
) -> None:
    project = _project()

    def responder(request: DispatchRequest) -> WorkHandoff:
        if request.task.id == "leaf-a":
            return WorkHandoff(node_id=request.task.id, done=False, report="failed")
        path = Path(request.cwd or repository)
        destination = path / "result/b.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("B\n", encoding="utf-8")
        return WorkHandoff(node_id=request.task.id, done=True, report="local")

    runtime = _runtime(config, repository, project, responder)
    result = run_project(runtime.coordinator, runtime.mission_id, project, max_steps=3)

    assert result.status == "failed"
    assert result.ready_order == (("leaf-a", "leaf-b"),)
    assert result.blocked == ("join",)
    assert [node.status for node in result.nodes] == ["failed", "failed", "pending"]
    assert not (repository / "result/a.txt").exists()
    assert not (repository / "result/b.txt").exists()
    assert not (repository / "result/join.txt").exists()


def test_cancellation_stops_after_atomic_leaf_batch(
    config: HarnessConfig,
    repository: Path,
) -> None:
    project = _project()
    cancelled = threading.Event()
    calls: list[str] = []

    def responder(request: DispatchRequest) -> WorkHandoff:
        calls.append(request.task.id)
        path = Path(request.cwd or repository)
        destination = path / (
            "result/a.txt" if request.task.id == "leaf-a" else "result/b.txt"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(request.task.id + "\n", encoding="utf-8")
        cancelled.set()
        return WorkHandoff(node_id=request.task.id, done=True, report="local")

    runtime = _runtime(config, repository, project, responder)
    result = run_project(
        runtime.coordinator,
        runtime.mission_id,
        project,
        max_steps=3,
        cancel=cancelled,
    )

    assert result.status == "cancelled"
    assert sorted(calls) == ["leaf-a", "leaf-b"]
    assert result.blocked == ("join",)
    assert not (repository / "result/join.txt").exists()


def test_execution_bound_leaves_join_pending(
    config: HarnessConfig,
    repository: Path,
) -> None:
    project = _project()

    def responder(request: DispatchRequest) -> WorkHandoff:
        path = Path(request.cwd or repository)
        destination = path / (
            "result/a.txt" if request.task.id == "leaf-a" else "result/b.txt"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(request.task.id + "\n", encoding="utf-8")
        return WorkHandoff(node_id=request.task.id, done=True, report="local")

    runtime = _runtime(config, repository, project, responder)
    result = run_project(runtime.coordinator, runtime.mission_id, project, max_steps=1)

    assert result.status == "bounded"
    assert result.steps == 1
    assert result.dispatch_batches == (("leaf-a", "leaf-b"),)
    assert result.blocked == ("join",)


def test_invalid_graphs_and_mismatched_runtime_fail_closed(
    config: HarnessConfig,
    repository: Path,
) -> None:
    with pytest.raises(ProjectAdapterError, match="cyclic_project"):
        ProjectDag(
            (
                ProjectNode("a", "a", needs=("b",)),
                ProjectNode("b", "b", needs=("a",)),
            )
        )
    with pytest.raises(ProjectAdapterError, match="protected_write_path"):
        ProjectNode("a", "a", writes=(".git/config",))
    with pytest.raises(ProjectAdapterError, match="result_outside_write_scope"):
        ProjectNode("a", "a", writes=("safe",), result_path="other/result.txt")

    project = _project()
    runtime = _runtime(
        config,
        repository,
        project,
        lambda request: WorkHandoff(node_id=request.task.id, done=True, report="local"),
    )
    different = ProjectDag(
        nodes=(ProjectNode("only", "Different project.", writes=("only.txt",)),)
    )
    with pytest.raises(ProjectAdapterError, match="project_task_list_mismatch"):
        run_project(runtime.coordinator, runtime.mission_id, different, max_steps=1)
    with pytest.raises(ProjectAdapterError, match="invalid_step_bound"):
        run_project(runtime.coordinator, runtime.mission_id, project, max_steps=0)
