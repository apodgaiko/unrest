"""Focused integration coverage for the accepted v0.3.1 public foundation."""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import subprocess
import threading
import time

import pytest

from unrest_harness import api
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.foundation_tools import FoundationTools
from unrest_harness.foundation_tools import FoundationToolError
from unrest_harness.models import Task, TaskList, TerminalReviewHandoff, WorkHandoff
from unrest_harness.server import create_orchestrator_server


class _IsolatedDispatcher(MockDispatcher):
    supports_isolated_workspaces = True


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _config(harness_home: Path, *, parallel: int = 2) -> HarnessConfig:
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
        max_parallel_nodes=parallel,
    )


def _repository(path: Path) -> Path:
    path.mkdir()
    _git(path, "init")
    _git(path, "config", "user.name", "Foundation Integration")
    _git(path, "config", "user.email", "foundation@example.test")
    (path / ".gitignore").write_text(
        "/.agents\n/.claude\n/.codex\n/.unrest\n/.unrest-runtime\n/AGENTS.md\n"
    )
    (path / "a.txt").write_text("old-a\n")
    (path / "b.txt").write_text("old-b\n")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "base")
    return path


def _prepare(
    config: HarnessConfig,
    repository: Path,
    dispatcher: _IsolatedDispatcher,
) -> tuple[ProjectController, str]:
    controller = ProjectController(
        config,
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    envelope = controller.start_project("parallel foundation", str(repository))
    project_id = envelope.projectId
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-A.md").write_text("# VAL-A\n\nA.\n")
    (contract / "VAL-B.md").write_text("# VAL-B\n\nB.\n")
    return controller, project_id


async def test_catalog_names_equal_mcp_and_library(harness_home: Path) -> None:
    config = _config(harness_home)
    catalog = json.loads(
        (Path(__file__).resolve().parents[1] / "docs" / "v03" / "v0.3.1" / "public-surface.v1.json").read_text()
    )
    names = {item["name"] for item in catalog["mcp_methods"]}
    cli_library_names = {
        item["library_callable"].rsplit(".", 1)[-1]
        for item in catalog["cli_commands"]
    }
    server_names = {tool.name for tool in await create_orchestrator_server(config).list_tools()}
    assert names <= server_names
    assert names == (set(api.__all__) | {"steer_attempt"}) - cli_library_names - {
        "run_improvement",
        "run_project",
        "run_task",
    }
    assert cli_library_names == {"measure_baseline"}
    assert callable(api.measure_baseline)
    assert callable(api.steer_attempt)
    assert "steer_attempt" not in api.__all__
    for item in catalog["mcp_methods"]:
        callable_name = item["library_callable"].rsplit(".", 1)[-1]
        assert callable(getattr(api, callable_name))
        assert inspect.signature(getattr(api, callable_name))


def test_library_schema_validation_precedes_effect_and_blocks_bad_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeTools:
        calls = 0
        invalid_output = False

        def inspect_run(self, run_id: str) -> dict[str, object]:
            self.calls += 1
            result: dict[str, object] = {
                "run_id": run_id,
                "operation": "start_project",
                "state": "queued",
                "resource_key": "workspace:/tmp/example",
                "idempotency_key": "library-schema",
                "project_id": None,
                "created_at": "2026-08-24T00:00:00Z",
                "updated_at": "2026-08-24T00:00:00Z",
                "result": None,
                "error": None,
                "receipt_id": None,
                "active_attempts": [],
            }
            if self.invalid_output:
                result["private_detail"] = "must not escape"
            return result

    tools = FakeTools()
    monkeypatch.setattr(api, "_tools", lambda: tools)

    with pytest.raises(FoundationToolError) as invalid:
        api.inspect_run("")
    assert invalid.value.code == "invalid_argument"
    assert tools.calls == 0

    tools.invalid_output = True
    with pytest.raises(FoundationToolError) as internal:
        api.inspect_run("run:1")
    assert internal.value.as_envelope() == {
        "error": {"code": "internal_error", "message": "internal error"}
    }
    assert tools.calls == 1


def test_production_run_executor_routes_start_once_and_attaches(
    workspace: Path,
    harness_home: Path,
) -> None:
    config = _config(harness_home)
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id, done=True, report="unused"
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    tools = FoundationTools(config, controller)

    admitted = tools.submit_run(
        "start_project",
        {"brief": "durable async admission", "workspace_dir": str(workspace)},
        "production-executor-start-once",
    )
    replay = tools.submit_run(
        "start_project",
        {"brief": "durable async admission", "workspace_dir": str(workspace)},
        "production-executor-start-once",
    )
    terminal = tools.attach_run(admitted["run_id"])

    assert admitted["state"] == "queued"
    assert replay["run_id"] == admitted["run_id"]
    assert terminal["state"] == "succeeded"
    assert len(controller.store.list_projects()) == 1


def test_two_disjoint_mutable_tasks_use_distinct_worktrees_and_integrate(
    tmp_path: Path,
    harness_home: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    starts: dict[str, float] = {}
    finishes: dict[str, float] = {}
    roots: dict[str, Path] = {}
    lock = threading.Lock()

    def respond(request):
        assert request.cwd is not None
        root = Path(request.cwd)
        with lock:
            roots[request.task.id] = root
            starts[request.task.id] = time.monotonic()
        time.sleep(0.08)
        (root / f"{request.task.id}.txt").write_text(f"new-{request.task.id}\n")
        with lock:
            finishes[request.task.id] = time.monotonic()
        return WorkHandoff(node_id=request.task.id, done=True, report="done")

    dispatcher = _IsolatedDispatcher(respond)
    controller, project_id = _prepare(
        _config(harness_home), repository, dispatcher
    )
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(id="a", type="work", body="Edit A.\nWrites: a.txt", targets=["VAL-A"], skill="s"),
                Task(id="b", type="work", body="Edit B.\nWrites: b.txt", targets=["VAL-B"], skill="s"),
            ]
        ),
    )

    result = controller.advance_project(project_id, max_steps=1)

    assert result.state.state == "mission_running"
    assert roots["a"] != roots["b"]
    assert roots["a"] != repository and roots["b"] != repository
    assert max(starts.values()) < min(finishes.values())
    assert (repository / "a.txt").read_text() == "new-a\n"
    assert (repository / "b.txt").read_text() == "new-b\n"
    assert controller.store.load_task_state(project_id, "mission-001").status_of("a") == "cleared"
    assert controller.store.load_task_state(project_id, "mission-001").status_of("b") == "cleared"


def test_scope_escape_withholds_entire_parallel_batch(
    tmp_path: Path,
    harness_home: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    base = _git(repository, "rev-parse", "HEAD")

    def respond(request):
        assert request.cwd is not None
        root = Path(request.cwd)
        target = "a.txt" if request.task.id == "a" else "a.txt"
        (root / target).write_text(f"new-{request.task.id}\n")
        return WorkHandoff(node_id=request.task.id, done=True, report="done")

    controller, project_id = _prepare(
        _config(harness_home), repository, _IsolatedDispatcher(respond)
    )
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(id="a", type="work", body="Edit A.\nWrites: a.txt", targets=["VAL-A"], skill="s"),
                Task(id="b", type="work", body="Edit B.\nWrites: b.txt", targets=["VAL-B"], skill="s"),
            ]
        ),
    )

    result = controller.advance_project(project_id, max_steps=1)

    assert result.state.state == "attention_needed"
    assert _git(repository, "rev-parse", "HEAD") == base
    assert (repository / "a.txt").read_text() == "old-a\n"
    assert (repository / "b.txt").read_text() == "old-b\n"
