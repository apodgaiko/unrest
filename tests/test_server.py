"""MCP server tests — tool surface per mode + in-process integration."""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import unrest_harness.acp_runner as acp_runner
import unrest_harness.server as server_module
from unrest_harness.capability_policy import (
    UNSAFE_DEVELOPMENT_PROFILE,
    credential_source_values,
)
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
)
from unrest_harness.models import (
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from unrest_harness.server import (
    create_orchestrator_server,
    create_terminal_reviewer_server,
    create_worker_server,
)
from unrest_harness.storage import ProjectStore


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
        max_parallel_nodes=1,
    )


async def _tool_names(server) -> set[str]:
    return {t.name for t in await server.list_tools()}


# ---------------------------------------------------------------------------
# Tool surface per mode (structural isolation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_tools_registered(config: HarnessConfig) -> None:
    server = create_orchestrator_server(config)
    names = await _tool_names(server)
    assert names == {
        "start_project",
        "submit_plan",
        "advance_project",
        "end_mission",
        "decide_attention",
        "inspect_project",
        "abort_project",
    }


@pytest.mark.asyncio
async def test_start_project_persists_validated_worker_overrides(
    config: HarnessConfig, workspace: Path
) -> None:
    config = replace(
        config,
        worker_provider_name="codex",
        worker_acp_command="codex-acp",
    )
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)

    await server.call_tool(
        "start_project",
        {
            "brief": "Ship it.",
            "workspace_dir": str(workspace),
            "worker_model": "gpt-test",
            "worker_reasoning_effort": "high",
        },
    )

    record = controller.store.list_projects()[0]
    assert record.worker_model == "gpt-test"
    assert record.worker_reasoning_effort == "high"


def test_start_project_rejects_override_for_non_codex_worker_without_persisting(
    config: HarnessConfig, workspace: Path
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )

    with pytest.raises(ToolError, match="invalid_worker_override_provider"):
        controller.start_project(
            "Ship it.",
            str(workspace),
            worker_reasoning_effort="high",
        )
    assert controller.store.list_projects() == []


def test_start_project_rejects_invalid_codex_worker_effort_without_persisting(
    config: HarnessConfig, workspace: Path
) -> None:
    config = replace(
        config,
        worker_provider_name="codex",
        worker_acp_command="codex-acp",
    )
    controller = ProjectController(
        config,
        MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True)),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )

    with pytest.raises(ToolError, match="invalid_worker_reasoning_effort"):
        controller.start_project(
            "Ship it.",
            str(workspace),
            worker_reasoning_effort="ultra",
        )
    assert controller.store.list_projects() == []


@pytest.mark.asyncio
async def test_worker_tool_isolated() -> None:
    server = create_worker_server()
    assert await _tool_names(server) == {"end_node"}


@pytest.mark.asyncio
async def test_terminal_reviewer_tool_isolated() -> None:
    server = create_terminal_reviewer_server()
    assert await _tool_names(server) == {"submit_terminal_review"}


# ---------------------------------------------------------------------------
# CLI startup boundary
# ---------------------------------------------------------------------------


_STARTUP_REJECTION = "unrest-server: startup configuration rejected\n"


def _install_startup_rejection_traps(
    monkeypatch: pytest.MonkeyPatch,
    markers: list[str],
) -> None:
    def fastmcp_trap(*args, **kwargs):
        markers.append("fastmcp")
        raise AssertionError("FastMCP construction reached after startup rejection")

    def dispatcher_trap(*args, **kwargs):
        markers.append("dispatch")
        raise AssertionError("dispatch construction reached after startup rejection")

    monkeypatch.setattr(server_module, "FastMCP", fastmcp_trap)
    monkeypatch.setattr(acp_runner, "ACPNodeDispatcher", dispatcher_trap)
    monkeypatch.setattr(acp_runner, "ACPTerminalReviewer", dispatcher_trap)


@pytest.mark.parametrize(
    "provider_selector",
    (
        "UNREST_ORCHESTRATOR_PROVIDER",
        "UNREST_WORKER_PROVIDER",
        "UNREST_VALIDATOR_PROVIDER",
        "UNREST_TERMINAL_REVIEWER_PROVIDER",
    ),
)
def test_orchestrator_rejects_every_unknown_provider_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    provider_selector: str,
) -> None:
    secret = "known-provider-credential-value"
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    monkeypatch.setenv(provider_selector, secret)
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", "orchestrator", "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert secret not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert markers == []


@pytest.mark.parametrize("mode", ("orchestrator", "worker", "terminal-reviewer"))
@pytest.mark.parametrize(
    "invalid_environment",
    (
        {"UNREST_CAPABILITY_PROFILE": "known-profile-credential-value"},
        {"UNREST_CAPABILITY_POLICY_VERSION": "known-version-credential-value"},
        {"UNREST_CAPABILITY_POLICY_VERSION": "2"},
        {"UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED": "0"},
        {"UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED": "1"},
        {"UNREST_CAPABILITY_PROFILE": UNSAFE_DEVELOPMENT_PROFILE},
        {"UNREST_UNKNOWN_UNSAFE_OPT_IN": "1"},
    ),
)
def test_every_mode_rejects_invalid_capability_startup_before_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    invalid_environment: dict[str, str],
) -> None:
    markers: list[str] = []
    _install_startup_rejection_traps(monkeypatch, markers)
    for name, value in invalid_environment.items():
        monkeypatch.setenv(name, value)
    supplied = next(iter(invalid_environment.values()))
    monkeypatch.setenv("OPENAI_API_KEY", supplied)
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == _STARTUP_REJECTION
    assert supplied not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert markers == []


class _RunRecordingServer:
    def __init__(self, markers: list[str], mode: str) -> None:
        self._markers = markers
        self._mode = mode

    def run(self, **kwargs) -> None:
        self._markers.append(f"run:{self._mode}:{kwargs['transport']}")


@pytest.mark.parametrize("mode", ("orchestrator", "worker", "terminal-reviewer"))
@pytest.mark.parametrize("profile", ("safe", UNSAFE_DEVELOPMENT_PROFILE))
def test_every_mode_reaches_server_run_for_supported_profiles(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    profile: str,
) -> None:
    markers: list[str] = []
    monkeypatch.setenv("UNREST_CAPABILITY_PROFILE", profile)
    if profile == UNSAFE_DEVELOPMENT_PROFILE:
        monkeypatch.setenv("UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        ["unrest-server", "--mode", mode, "--transport", "stdio"],
    )

    def server_factory(*args, **kwargs):
        markers.append(f"construct:{mode}")
        return _RunRecordingServer(markers, mode)

    monkeypatch.setattr(server_module, f"create_{mode.replace('-', '_')}_server", server_factory)
    if mode == "orchestrator":
        monkeypatch.setattr(
            acp_runner,
            "ACPNodeDispatcher",
            lambda config: markers.append("dispatch") or object(),
        )
        monkeypatch.setattr(
            acp_runner,
            "ACPTerminalReviewer",
            lambda config: markers.append("reviewer") or object(),
        )

    server_module.main()

    if mode == "orchestrator":
        assert markers == [
            "dispatch",
            "reviewer",
            "construct:orchestrator",
            "run:orchestrator:stdio",
        ]
    else:
        assert markers == [f"construct:{mode}", f"run:{mode}:stdio"]


# ---------------------------------------------------------------------------
# end_node writes to UNREST_HANDOFF_PATH
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_node_writes_handoff_file(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.setenv("UNREST_NODE_ID", "w1")
    server = create_worker_server()
    await server.call_tool(
        "end_node",
        {"done": True, "report": "ok"},
    )
    assert handoff_path.exists()
    data = json.loads(handoff_path.read_text())
    assert data == {
        "node_id": "w1",
        "attempt_id": "handoff",
        "done": True,
        "report": "ok",
        "request_attention": False,
    }


@pytest.mark.asyncio
async def test_end_node_validate_writes_items(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "validate")
    monkeypatch.setenv("UNREST_NODE_ID", "v1")
    server = create_worker_server()
    await server.call_tool(
        "end_node",
        {
            "done": True,
            "report": "audited",
            "items": [{"item_id": "VAL-001", "passed": True}],
            "passed": True,
        },
    )
    data = json.loads(handoff_path.read_text())
    assert data["items"][0]["item_id"] == "VAL-001"
    assert data["passed"] is True


@pytest.mark.asyncio
async def test_end_node_requires_env_node_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(tmp_path / "h.json"))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.delenv("UNREST_NODE_ID", raising=False)
    server = create_worker_server()
    with pytest.raises(Exception):
        await server.call_tool(
            "end_node",
            {"done": True, "report": ""},
        )


@pytest.mark.asyncio
async def test_end_node_idempotent_overwrite(tmp_path: Path, monkeypatch) -> None:
    handoff_path = tmp_path / "handoff.json"
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(handoff_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.setenv("UNREST_NODE_ID", "w1")
    server = create_worker_server()
    await server.call_tool(
        "end_node", {"done": True, "report": "first"}
    )
    await server.call_tool(
        "end_node", {"done": True, "report": "second"}
    )
    assert json.loads(handoff_path.read_text())["report"] == "second"


@pytest.mark.asyncio
async def test_submit_terminal_review_writes_file(tmp_path: Path, monkeypatch) -> None:
    review_path = tmp_path / "terminal-review.json"
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(review_path))
    server = create_terminal_reviewer_server()
    await server.call_tool(
        "submit_terminal_review", {"done": True, "report": "all clean"}
    )
    data = json.loads(review_path.read_text())
    assert data == {"done": True, "report": "all clean"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "path_name"),
    (("worker", "handoff.json"), ("reviewer", "terminal-review.json")),
)
async def test_mcp_handoff_is_redacted_before_tool_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    path_name: str,
) -> None:
    secret = "plum"
    inventory = credential_source_values(
        {"DECLARED_AUTH": secret},
        declared_names=("DECLARED_AUTH",),
    )
    path = tmp_path / path_name
    if mode == "worker":
        monkeypatch.setenv("UNREST_HANDOFF_PATH", str(path))
        monkeypatch.setenv("UNREST_NODE_TYPE", "work")
        monkeypatch.setenv("UNREST_NODE_ID", "w-secret")
        server = create_worker_server(inventory)
        await server.call_tool(
            "end_node",
            {"done": True, "report": secret},
        )
    else:
        monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(path))
        server = create_terminal_reviewer_server(inventory)
        await server.call_tool(
            "submit_terminal_review",
            {"done": True, "report": secret},
        )

    persisted = path.read_text(encoding="utf-8")
    assert secret not in persisted
    assert "<redacted:DECLARED_AUTH>" in persisted


@pytest.mark.asyncio
async def test_redacted_mcp_handoffs_survive_restart_and_mirroring(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "plum"
    inventory = credential_source_values(
        {"DECLARED_AUTH": secret},
        declared_names=("DECLARED_AUTH",),
    )
    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id="p-secret")
    spawn_ts = "2026-08-03T00-00-00Z"

    attempt_path = store.attempt_path(
        "p-secret", "mission-001", spawn_ts, "w-secret"
    )
    monkeypatch.setenv("UNREST_HANDOFF_PATH", str(attempt_path))
    monkeypatch.setenv("UNREST_NODE_TYPE", "work")
    monkeypatch.setenv("UNREST_NODE_ID", "w-secret")
    await create_worker_server(inventory).call_tool(
        "end_node",
        {"done": True, "report": secret},
    )

    restarted = ProjectStore(config)
    handoff = restarted.read_attempt(
        "p-secret", "mission-001", spawn_ts, "w-secret"
    )
    assert isinstance(handoff, WorkHandoff)
    restarted.save_attempt(
        "p-secret", "mission-001", spawn_ts, "w-secret", handoff
    )

    review_path = restarted.terminal_review_path(
        "p-secret", "mission-001", spawn_ts
    )
    monkeypatch.setenv("UNREST_TERMINAL_REVIEW_PATH", str(review_path))
    await create_terminal_reviewer_server(inventory).call_tool(
        "submit_terminal_review",
        {"done": True, "report": secret},
    )
    restarted_again = ProjectStore(config)
    review = TerminalReviewHandoff.model_validate_json(
        review_path.read_text(encoding="utf-8")
    )
    restarted_again.save_terminal_review(
        "p-secret", "mission-001", spawn_ts, review
    )

    persisted_paths = (
        attempt_path,
        restarted.attempt_report_path(
            "p-secret", "mission-001", spawn_ts, "w-secret"
        ),
        review_path,
        restarted_again.terminal_review_report_path(
            "p-secret", "mission-001", spawn_ts
        ),
    )
    for path in persisted_paths:
        persisted = path.read_text(encoding="utf-8")
        assert secret not in persisted
        assert "<redacted:DECLARED_AUTH>" in persisted


# ---------------------------------------------------------------------------
# Integration: orchestrator tools in-process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_end_to_end_in_process(
    config: HarnessConfig, workspace: Path
) -> None:
    def responder(req):
        if req.task.type == "work":
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")
        return ValidateHandoff(
            node_id=req.task.id,
            done=True,
            report="audited",
            items=[ValidationItem(item_id="VAL-001", passed=True)],
            passed=True,
        )

    controller = ProjectController(
        config,
        MockDispatcher(responder),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)

    await server.call_tool(
        "start_project",
        {"brief": "Ship it.", "workspace_dir": str(workspace)},
    )
    pid = ProjectStore(config).list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n")
    task_list_dict = {
        "tasks": [
            {"id": "w1", "type": "work", "body": "do", "targets": ["VAL-001"], "skill": "s", "depends_on": []},
            {"id": "v1", "type": "validate", "body": "audit", "targets": ["VAL-001"], "skill": "aud", "depends_on": ["w1"]},
            {"id": "g1", "type": "gate", "body": "", "targets": ["VAL-001"], "skill": None, "depends_on": ["v1"]},
        ],
    }
    await server.call_tool("submit_plan", {"project_id": pid, "task_list": task_list_dict})
    await server.call_tool("advance_project", {"project_id": pid})
    items = controller.store.load_attention(pid)
    assert len(items) == 1
    await server.call_tool(
        "decide_attention",
        {
            "project_id": pid,
            "decisions": [{"item_id": items[0].id, "action": "continue"}],
        },
    )
    await server.call_tool("advance_project", {"project_id": pid})
    await server.call_tool("inspect_project", {"project_id": pid})
    report = (
        controller.store.mission_dir(pid, "mission-001")
        / "evidence"
        / "final"
        / "report.md"
    )
    report.parent.mkdir(parents=True)
    report.write_text("final report", encoding="utf-8")
    await server.call_tool(
        "end_mission",
        {"project_id": pid, "deliverable_roots": [str(report)]},
    )
    state = controller.store.load_state(pid)
    assert state is not None
    assert state.state == "done"
    review_config = controller.store.load_terminal_review_config(
        pid, "mission-001"
    )
    assert review_config.deliverable_roots == [str(report.resolve())]


# ---------------------------------------------------------------------------
# Regression: dispatcher that calls asyncio.run() must not crash the MCP
# event loop. Reproduces:
#   "asyncio.run() cannot be called from a running event loop"
# observed in the attempts/*.json report when a worker dispatch path
# inadvertently ran inside the FastMCP handler's loop.
# ---------------------------------------------------------------------------


class _AsyncioRunDispatcher:
    """Dispatcher whose dispatch() goes through asyncio.run(), mimicking
    ACPNodeDispatcher. If invoked from a running loop without thread
    isolation, raises the canonical RuntimeError.
    """

    def dispatch(self, request: DispatchRequest) -> WorkHandoff | ValidateHandoff:
        async def _do() -> WorkHandoff | ValidateHandoff:
            await asyncio.sleep(0)
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        return asyncio.run(_do())

    def dispatch_batch(
        self, requests: list[DispatchRequest]
    ) -> list[WorkHandoff | ValidateHandoff]:
        return [self.dispatch(r) for r in requests]


@pytest.mark.asyncio
async def test_advance_project_tolerates_asyncio_run_dispatcher(
    config: HarnessConfig, workspace: Path
) -> None:
    controller = ProjectController(
        config,
        _AsyncioRunDispatcher(),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    server = create_orchestrator_server(config, controller)
    await server.call_tool(
        "start_project",
        {"brief": "Ship it.", "workspace_dir": str(workspace)},
    )
    pid = ProjectStore(config).list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n")
    task_list_dict = {
        "tasks": [
            {"id": "w1", "type": "work", "body": "do", "targets": ["VAL-001"], "skill": "s", "depends_on": []},
            {"id": "v1", "type": "validate", "body": "audit", "targets": ["VAL-001"], "skill": "aud", "depends_on": ["w1"]},
            {"id": "g1", "type": "gate", "body": "", "targets": ["VAL-001"], "skill": None, "depends_on": ["v1"]},
        ],
    }
    await server.call_tool("submit_plan", {"project_id": pid, "task_list": task_list_dict})
    # Before the fix this raised:
    #   RuntimeError: asyncio.run() cannot be called from a running event loop
    await server.call_tool("advance_project", {"project_id": pid})
    items = controller.store.load_attention(pid)
    assert len(items) == 1


def test_run_coro_blocking_works_inside_running_loop() -> None:
    """The dispatcher defense: if asyncio.run() is reached while a loop is
    already running, _run_coro_blocking falls back to a worker thread.
    """
    from unrest_harness.acp_runner import _run_coro_blocking

    async def _outer() -> int:
        async def _inner() -> int:
            await asyncio.sleep(0)
            return 42

        return _run_coro_blocking(_inner())

    assert asyncio.run(_outer()) == 42
