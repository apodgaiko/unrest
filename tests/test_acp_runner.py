"""ACP runner adaptation tests — direct-to-PROJECT handoff path discipline.

Most tests use the bundled ``mock_acp_agent.py`` rather than a live provider.
The startup-channel regression runs the real worker/reviewer MCP subprocesses;
the other mock-agent tests bypass those subprocesses and write the handoff
directly.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from fastmcp import Client

from unrest_harness.acp_runner import (
    ACPClient,
    ACPNodeDispatcher,
    ACPTerminalReviewer,
    ACPNodeRunner,
    _acp_subprocess_env,
    _augment_acp_command,
    _ensure_claude_settings,
)
from unrest_harness.capability_policy import (
    SAFE_PROFILE,
    CapabilityPolicyError,
    credential_values,
    load_capability_policy,
    resolve_role_capability,
)
from unrest_harness.providers import PROVIDERS
from unrest_harness.assets import AssetLoader
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import DispatchRequest
from unrest_harness.models import (
    Task,
    TaskList,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore


def _safe_policy(provider_name: str):
    root = Path(__file__).resolve().parents[1]
    bundled = root / "src" / "unrest_harness" / "bundled"
    return resolve_role_capability(
        PROVIDERS[provider_name],  # type: ignore[index]
        role="worker",
        policy=load_capability_policy(bundled),
        profile=SAFE_PROFILE,
        workspace=root,
        project_record=root,
    )


@pytest.fixture
def mock_acp_command() -> str:
    """Wrap the mock agent script so it's invocable from a shell."""
    mock = Path(__file__).resolve().parent / "mock_acp_agent.py"
    return f"{sys.executable} {mock}"


@pytest.fixture
def config(harness_home: Path, mock_acp_command: str) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=mock_acp_command,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )


@pytest.fixture
def project_setup(config: HarnessConfig, workspace: Path):
    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id="p1")
    contract_dir = store.ensure_contract_dir("p1", "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nTest.\n")
    return store


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("worker", "terminal-reviewer"))
async def test_real_mcp_inventory_fd_redacts_before_crash_and_restart(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """The private startup FD protects the first durable write, before cleanup."""
    secret_name = "ANTHROPIC_API_KEY"
    secret = "plum"
    monkeypatch.setenv(secret_name, secret)

    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id=f"p-{mode}")
    project_id = f"p-{mode}"
    mission_id = "mission-001"
    spawn_ts = "2026-08-03T00-00-00Z"
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    role = "worker" if mode == "worker" else "terminal_reviewer"
    policy = resolve_role_capability(
        PROVIDERS["claude"],
        role=role,  # type: ignore[arg-type]
        policy=load_capability_policy(config.bundled_dir),
        profile=SAFE_PROFILE,
        workspace=workspace,
        project_record=store.unrest_dir(project_id),
    )
    inventory = credential_values(policy, {secret_name: os.environ[secret_name]})
    assert inventory == {secret_name: secret}

    mcp_port = runner._find_free_port()
    base_environment = {
        "LANG": "C",
        "PATH": os.environ["PATH"],
        "UNREST_HOME": str(config.harness_home),
        "UNREST_MISSION_ID": mission_id,
        "UNREST_PROJECT_ID": project_id,
    }
    if mode == "worker":
        artifact_path = store.attempt_path(
            project_id, mission_id, spawn_ts, "w-secret"
        )
        base_environment.update(
            {
                "UNREST_HANDOFF_PATH": str(artifact_path),
                "UNREST_NODE_ID": "w-secret",
                "UNREST_NODE_TYPE": "work",
            }
        )
        process = await runner._start_worker_mcp_server(
            task=Task(
                id="w-secret",
                type="work",
                body="persist",
                targets=["VAL-001"],
                skill="s",
            ),
            project_id=project_id,
            mission_id=mission_id,
            handoff_path=str(artifact_path),
            workspace_dir=str(workspace),
            mcp_port=mcp_port,
            sensitive_inventory=inventory,
            environment=base_environment,
        )
        tool_name = "end_node"
    else:
        artifact_path = store.terminal_review_path(
            project_id, mission_id, spawn_ts
        )
        base_environment["UNREST_TERMINAL_REVIEW_PATH"] = str(artifact_path)
        process = await runner._start_terminal_reviewer_mcp(
            project_id=project_id,
            mission_id=mission_id,
            report_path=str(artifact_path),
            workspace_dir=str(workspace),
            mcp_port=mcp_port,
            sensitive_inventory=inventory,
            environment=base_environment,
        )
        tool_name = "submit_terminal_review"

    child_output = ""
    try:
        await runner._wait_for_server_ready("127.0.0.1", mcp_port)
        async with Client(f"http://127.0.0.1:{mcp_port}/mcp") as client:
            await client.call_tool(
                tool_name,
                {"done": True, "report": secret},
            )

            # This is the vulnerable window: the tool has returned, while both
            # the MCP child and its parent-side runner cleanup are still live.
            persisted = artifact_path.read_text(encoding="utf-8")
            assert process.returncode is None
            assert secret not in persisted
            assert f"<redacted:{secret_name}>" in persisted
    finally:
        # Model a crash immediately after the successful handoff and prove the
        # inherited FD child is actually terminated before restart recovery.
        if process.returncode is None:
            process.terminate()
        child_output = await asyncio.wait_for(
            runner._close_mcp_process(process, inventory),
            timeout=10,
        )
    assert process.returncode is not None, child_output
    assert runner._mcp_drains == {}
    assert not any(
        task.get_name().startswith("unrest-mcp-")
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
    )

    restarted = ProjectStore(config)
    if mode == "worker":
        handoff = restarted.read_attempt(
            project_id, mission_id, spawn_ts, "w-secret"
        )
        assert isinstance(handoff, WorkHandoff)
        restarted.save_attempt(
            project_id, mission_id, spawn_ts, "w-secret", handoff
        )
        mirror_path = restarted.attempt_report_path(
            project_id, mission_id, spawn_ts, "w-secret"
        )
    else:
        review = TerminalReviewHandoff.model_validate_json(
            artifact_path.read_text(encoding="utf-8")
        )
        restarted.save_terminal_review(
            project_id, mission_id, spawn_ts, review
        )
        mirror_path = restarted.terminal_review_report_path(
            project_id, mission_id, spawn_ts
        )

    for path in (artifact_path, mirror_path):
        persisted = path.read_text(encoding="utf-8")
        assert secret not in persisted
        assert f"<redacted:{secret_name}>" in persisted


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("worker", "terminal-reviewer"))
async def test_mcp_role_child_oversized_streams_are_bounded_and_singly_drained(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    secret_name = "ANTHROPIC_API_KEY"
    secret = "oversized-child-secret"
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    original_spawn = asyncio.create_subprocess_exec
    spawned_argv: list[str] = []

    async def spawn_chatty(*args, **kwargs):
        spawned_argv.extend(str(arg) for arg in args)
        return await original_spawn(
            sys.executable,
            "-c",
            (
                "import sys; "
                f"sys.stdout.write('stdout-cause-{secret}-' + 'o'*524288); "
                "sys.stdout.flush(); "
                f"sys.stderr.write('stderr-cause-{secret}-' + 'e'*524288); "
                "sys.stderr.flush()"
            ),
            stdout=kwargs["stdout"],
            stderr=kwargs["stderr"],
            cwd=kwargs["cwd"],
            env=kwargs["env"],
            limit=kwargs["limit"],
            pass_fds=kwargs["pass_fds"],
        )

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn_chatty)
    common = {
        "project_id": "p-chatty",
        "mission_id": "mission-001",
        "workspace_dir": str(workspace),
        "mcp_port": 43210,
        "sensitive_inventory": {secret_name: secret},
        "environment": {"PATH": os.environ["PATH"]},
    }
    if mode == "worker":
        process = await runner._start_worker_mcp_server(
            task=Task(
                id="w-chatty",
                type="work",
                body="x",
                targets=["VAL-SEC-014"],
                skill="s",
            ),
            handoff_path=str(workspace / "attempt.json"),
            **common,
        )
        assert "worker" in spawned_argv
    else:
        process = await runner._start_terminal_reviewer_mcp(
            report_path=str(workspace / "terminal-review.json"),
            **common,
        )
        assert "terminal-reviewer" in spawned_argv

    output = await asyncio.wait_for(
        runner._close_mcp_process(process, {secret_name: secret}),
        timeout=5,
    )

    assert process.returncode == 0
    assert runner._mcp_drains == {}
    assert "stdout-cause-<redacted:ANTHROPIC_API_KEY>" in output
    assert "stderr-cause-<redacted:ANTHROPIC_API_KEY>" in output
    assert secret not in output
    assert len(output.encode("utf-8")) <= 2 * 64 * 1024
    assert not any(
        task.get_name().startswith("unrest-mcp-")
        for task in asyncio.all_tasks()
        if task is not asyncio.current_task()
    )


@pytest.mark.asyncio
async def test_adapter_stderr_and_log_sink_redact_before_emission(
    config: HarnessConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "adapter-stderr-secret-credential"
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.stderr.write('adapter failed: {secret}'); "
            "raise SystemExit(2)"
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    runner._start_mcp_drains(process)

    with caplog.at_level("WARNING", logger="unrest_harness.acp_runner"):
        output = await runner._close_mcp_process(
            process, {"OPENAI_API_KEY": secret}
        )

    assert secret not in output
    assert secret not in caplog.text
    assert "adapter failed: <redacted:OPENAI_API_KEY>" in output
    assert "adapter failed: <redacted:OPENAI_API_KEY>" in caplog.text


# ---------------------------------------------------------------------------
# Mock-agent integration: the agent writes directly to UNREST_HANDOFF_PATH
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not shutil.which("python3") and not Path(sys.executable).exists(),
    reason="Python interpreter unavailable",
)
def test_run_node_with_mock_agent(config: HarnessConfig, project_setup, workspace: Path):
    """End-to-end via the mock agent (NO real worker MCP server subprocess —
    we point at a free port that nothing binds to and rely on the mock to
    write the handoff file itself).
    """
    store = project_setup
    task = Task(id="w1", type="work", body="do it", targets=["VAL-001"], skill="s")
    spawn_ts = "2026-05-17T00-00-00Z"
    handoff_path = store.attempt_path("p1", "mission-001", spawn_ts, "w1")
    handoff_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["UNREST_HANDOFF_PATH"] = str(handoff_path)
    os.environ["UNREST_NODE_ID"] = task.id
    os.environ["UNREST_NODE_TYPE"] = task.type
    try:
        loader = AssetLoader(config)
        runner = ACPNodeRunner(config=config, loader=loader)

        async def _no_op_server(*args, **kwargs):
            return await asyncio.create_subprocess_exec(
                "sleep",
                "30",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

        async def _ready_immediately(*args, **kwargs):
            return None

        runner._find_free_port = lambda: 0  # type: ignore[method-assign]
        runner._start_worker_mcp_server = _no_op_server  # type: ignore[method-assign]
        runner._wait_for_server_ready = _ready_immediately  # type: ignore[method-assign]

        handoff = asyncio.run(
            runner.run_node(
                project_id="p1",
                mission_id="mission-001",
                task=task,
                spawn_ts=spawn_ts,
                store=store,
            )
        )
    finally:
        for k in ("UNREST_HANDOFF_PATH", "UNREST_NODE_ID", "UNREST_NODE_TYPE"):
            os.environ.pop(k, None)

    assert isinstance(handoff, WorkHandoff)
    assert handoff.done is True
    # The file should be at the durable audit path.
    assert handoff_path.exists()
    data = json.loads(handoff_path.read_text())
    assert data["node_id"] == "w1"


@pytest.mark.parametrize("provider_name", ("claude", "codex"))
@pytest.mark.parametrize(
    "task_type",
    ("work", "validate"),
    ids=("worker", "validator"),
)
def test_full_jobs_and_handoffs_preserve_complete_format_templates(
    config: HarnessConfig,
    project_setup,
    mock_acp_command: str,
    monkeypatch: pytest.MonkeyPatch,
    provider_name: str,
    task_type: str,
) -> None:
    template = (
        "UNREST_FORMAT_TEST_custom:/v22/"
        "{mapping[layout}mode]!s:^12}"
        ";layout={mapping[layout{mode]!s:{width}}"
        "?region={request.region!a}"
        "#database={database}"
    )
    host_path = f"{template}:relative-tools:local-bin"
    source_name = (
        f"PAYMENTS_{provider_name}_{task_type}_DSN_TEMPLATE_URI_V21"
    ).upper()
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("PATH", host_path)
    monkeypatch.setenv(source_name, template)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    role_config = replace(
        config,
        worker_provider_name=provider_name,
        worker_acp_command=mock_acp_command,
        validator_provider_name=provider_name,
        validator_acp_command=mock_acp_command,
    )
    runner = ACPNodeRunner(
        config=role_config,
        loader=AssetLoader(role_config),
    )
    mcp_environments: list[dict[str, str]] = []

    async def _no_op_server(*args, **kwargs):
        mcp_environments.append(kwargs["environment"])
        return await asyncio.create_subprocess_exec(
            "/bin/sleep",
            "30",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _ready_immediately(*args, **kwargs):
        return None

    runner._find_free_port = lambda: 0  # type: ignore[method-assign]
    runner._start_worker_mcp_server = _no_op_server  # type: ignore[method-assign]
    runner._wait_for_server_ready = _ready_immediately  # type: ignore[method-assign]
    task = Task(
        id=f"{provider_name}-{task_type}",
        type=task_type,  # type: ignore[arg-type]
        body="observe the environment",
        targets=["VAL-001"],
        skill="s",
    )
    spawn_ts = f"2026-07-29T05-00-00Z-{provider_name}-{task_type}"

    handoff = asyncio.run(
        runner.run_node(
            project_id="p1",
            mission_id="mission-001",
            task=task,
            spawn_ts=spawn_ts,
            store=project_setup,
        )
    )
    handoff_path = project_setup.attempt_path(
        "p1",
        "mission-001",
        spawn_ts,
        task.id,
    )

    assert handoff.done is True
    assert template in handoff.report
    assert template in handoff_path.read_text(encoding="utf-8")
    assert len(mcp_environments) == 1
    assert mcp_environments[0]["PATH"] == host_path


@pytest.mark.parametrize("provider_name", ("claude", "codex"))
@pytest.mark.parametrize(
    "task_type",
    ("work", "validate"),
    ids=("worker", "validator"),
)
def test_full_jobs_do_not_infer_credentials_inside_format_fields(
    config: HarnessConfig,
    project_setup,
    mock_acp_command: str,
    monkeypatch: pytest.MonkeyPatch,
    provider_name: str,
    task_type: str,
) -> None:
    secret = f"v22-{provider_name}-{task_type}-format-ast-credential"
    source_name = (
        f"PAYMENTS_{provider_name}_{task_type}_FORMAT_DSN_TEMPLATE_URI_V22"
    ).upper()
    source_value = (
        "custom:/v22"
        f";render={{value:password={secret}}}"
        f"?layout={{mapping[password={secret}]!s:^12}}"
        f"#meta={{value:token={secret};width={{width}}}}"
    )
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("PATH", f"{os.defpath}:{secret}")
    monkeypatch.setenv(source_name, source_value)
    monkeypatch.delenv("CODEX_PATH", raising=False)
    role_config = replace(
        config,
        worker_provider_name=provider_name,
        worker_acp_command=mock_acp_command,
        validator_provider_name=provider_name,
        validator_acp_command=mock_acp_command,
    )
    runner = ACPNodeRunner(
        config=role_config,
        loader=AssetLoader(role_config),
    )
    mcp_environments: list[dict[str, str]] = []

    async def _no_op_server(*args, **kwargs):
        mcp_environments.append(kwargs["environment"])
        return await asyncio.create_subprocess_exec(
            "/bin/sleep",
            "30",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _ready_immediately(*args, **kwargs):
        return None

    runner._find_free_port = lambda: 0  # type: ignore[method-assign]
    runner._start_worker_mcp_server = _no_op_server  # type: ignore[method-assign]
    runner._wait_for_server_ready = _ready_immediately  # type: ignore[method-assign]
    task = Task(
        id=f"{provider_name}-{task_type}-format-credential",
        type=task_type,  # type: ignore[arg-type]
        body="observe the filtered environment",
        targets=["VAL-001"],
        skill="s",
    )
    spawn_ts = f"2026-07-29T08-00-00Z-{provider_name}-{task_type}"

    handoff = asyncio.run(
        runner.run_node(
            project_id="p1",
            mission_id="mission-001",
            task=task,
            spawn_ts=spawn_ts,
            store=project_setup,
        )
    )
    handoff_path = project_setup.attempt_path(
        "p1",
        "mission-001",
        spawn_ts,
        task.id,
    )
    persisted = handoff_path.read_text(encoding="utf-8")

    assert handoff.done is True
    assert secret not in handoff.report
    assert secret not in persisted
    assert source_value not in persisted
    assert len(mcp_environments) == 1
    assert mcp_environments[0]["PATH"] == f"{os.defpath}:{secret}"
    assert source_name not in mcp_environments[0]


def test_synthesize_missing_handoff_records_failure(
    config: HarnessConfig, project_setup, workspace: Path
):
    """If the agent exits without writing, the runner synthesizes a failure
    handoff and persists it to the durable audit path.
    """
    store = project_setup
    task = Task(id="w1", type="work", body="b", targets=["VAL-001"], skill="s")
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    handoff_path = store.attempt_path("p1", "mission-001", "2026-05-17T00-00-00Z", "w1")
    handoff = runner._synthesize_and_persist_missing_handoff(
        handoff_path=handoff_path,
        task=task,
        stop_reason="cancelled",
        exit_code=1,
        stderr="boom",
        session_error=None,
    )
    assert handoff.done is False
    assert handoff.attempt_id == "2026-05-17T00-00-00Z"
    assert "stop_reason=cancelled" in handoff.report
    assert json.loads(handoff_path.read_text())["attempt_id"] == handoff.attempt_id


def test_missing_end_node_diagnostics_survive_production_dispatch_and_attention(
    config: HarnessConfig,
    workspace: Path,
    mock_acp_command: str,
) -> None:
    role_config = replace(
        config,
        worker_acp_command=f"{mock_acp_command} --missing-handoff-diagnostics",
    )
    store = ProjectStore(role_config)
    dispatcher = ACPNodeDispatcher(role_config, store)

    class UnusedReviewer:
        def review(
            self, project_id: str, mission_id: str, spawn_ts: str
        ) -> TerminalReviewHandoff:
            raise AssertionError("terminal review must not run for a failed work task")

    controller = ProjectController(
        role_config,
        dispatcher,
        UnusedReviewer(),
        store=store,
    )
    started = controller.start_project("missing handoff regression", str(workspace))
    project_id = started.projectId
    mission_id = "mission-001"
    contract_dir = store.ensure_contract_dir(project_id, mission_id)
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nTest.\n")
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(
                    id="w1",
                    type="work",
                    body="exit without end_node",
                    targets=["VAL-001"],
                    skill="s",
                )
            ]
        ),
    )

    envelope = controller.advance_project(project_id)

    assert envelope.state.state == "attention_needed"
    task_state = store.load_task_state(project_id, mission_id)
    generation = task_state.tasks["w1"].last_attempt
    assert generation is not None
    runtime_path = store.attempt_path(project_id, mission_id, generation, "w1")
    durable_path = store.attempt_report_path(project_id, mission_id, generation, "w1")
    runtime = json.loads(runtime_path.read_text())
    durable = durable_path.read_text()
    attention = store.load_attention(project_id)
    assert len(attention) == 1
    assert attention[0].kind == "node_failed"
    assert runtime["attempt_id"] == generation
    assert f"attempt_id: {generation}" in durable

    expected_diagnostics = (
        "stop_reason=refusal",
        "exit_code=7",
        "stderr=mock ACP stderr before missing handoff",
        "agent_output=agent diagnostic before missing handoff.",
    )
    for diagnostic in expected_diagnostics:
        assert diagnostic in runtime["report"]
        assert diagnostic in durable
        assert diagnostic in attention[0].report
    assert "null attempt identity" not in attention[0].report
    assert len(runtime["report"]) < 2200


@pytest.mark.parametrize("provider_name", ("claude", "codex"))
def test_dispatch_batch_serializes_mcp_startup_and_preserves_sibling_success(
    config: HarnessConfig,
    project_setup: ProjectStore,
    workspace: Path,
    mock_acp_command: str,
    provider_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only MCP startup serializes; the real ACP sessions still overlap."""
    role_config = replace(
        config,
        worker_provider_name=provider_name,
        worker_acp_command=mock_acp_command,
        validator_provider_name=provider_name,
        validator_acp_command=mock_acp_command,
    )
    dispatcher = ACPNodeDispatcher(role_config, project_setup)
    runner = dispatcher.runner
    active_starts = 0
    maximum_active_starts = 0
    active_sessions = 0
    maximum_active_sessions = 0
    both_sessions_started = asyncio.Event()
    next_port = 41000

    def _next_port() -> int:
        nonlocal next_port
        next_port += 1
        return next_port

    async def _start_fixture(**kwargs):
        nonlocal active_starts, maximum_active_starts
        active_starts += 1
        maximum_active_starts = max(maximum_active_starts, active_starts)
        process = await asyncio.create_subprocess_exec(
            "/bin/sleep",
            "30",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        runner._start_mcp_drains(process)
        return process

    async def _ready_fixture(*args, **kwargs):
        nonlocal active_starts
        await asyncio.sleep(0.05)
        active_starts -= 1

    original_send_request = ACPClient.send_request

    async def _send_request_fixture(self, method, params):
        nonlocal active_sessions, maximum_active_sessions
        if method != "session/prompt":
            return await original_send_request(self, method, params)
        active_sessions += 1
        maximum_active_sessions = max(maximum_active_sessions, active_sessions)
        if active_sessions == 2:
            both_sessions_started.set()
        try:
            await asyncio.wait_for(both_sessions_started.wait(), timeout=1)
            return await original_send_request(self, method, params)
        finally:
            active_sessions -= 1

    runner._find_free_port = _next_port  # type: ignore[method-assign]
    runner._start_worker_mcp_server = _start_fixture  # type: ignore[method-assign]
    runner._wait_for_server_ready = _ready_fixture  # type: ignore[method-assign]
    monkeypatch.setattr(ACPClient, "send_request", _send_request_fixture)
    requests = [
        DispatchRequest(
            project_id="p1",
            mission_id="mission-001",
            task=Task(
                id=f"v{index}",
                type="validate",
                body="validate",
                targets=["VAL-001"],
                skill="s",
            ),
            spawn_ts=f"2026-08-10T07-00-00Z-{index:04d}",
        )
        for index in range(2)
    ]

    handoffs = dispatcher.dispatch_batch(requests)

    assert maximum_active_starts == 1
    assert maximum_active_sessions == 2
    assert runner._mcp_drains == {}
    assert [handoff.node_id for handoff in handoffs] == ["v0", "v1"]
    assert all(isinstance(handoff, ValidateHandoff) for handoff in handoffs)
    assert all(handoff.done and handoff.passed for handoff in handoffs)


def test_reused_dispatcher_serializes_startup_in_each_fresh_event_loop(
    config: HarnessConfig,
    project_setup: ProjectStore,
) -> None:
    dispatcher = ACPNodeDispatcher(config, project_setup)
    runner = dispatcher.runner
    active_starts = 0
    maximum_active_starts: list[int] = []

    async def run_node(**kwargs):
        nonlocal active_starts
        async with runner._mcp_start_lock():
            active_starts += 1
            maximum_active_starts.append(active_starts)
            await asyncio.sleep(0.01)
            active_starts -= 1
        task = kwargs["task"]
        return WorkHandoff(node_id=task.id, done=True, report="complete")

    runner.run_node = run_node  # type: ignore[method-assign]

    for batch in range(2):
        requests = [
            DispatchRequest(
                project_id="p1",
                mission_id="mission-001",
                task=Task(
                    id=f"w{batch}-{index}",
                    type="work",
                    body="work",
                    targets=["VAL-BATCH-001"],
                    skill="s",
                ),
                spawn_ts=f"2026-08-12T12-00-0{batch}Z-{index:04d}",
            )
            for index in range(2)
        ]
        handoffs = dispatcher.dispatch_batch(requests)
        assert [handoff.node_id for handoff in handoffs] == [
            f"w{batch}-0",
            f"w{batch}-1",
        ]
        assert all(handoff.done for handoff in handoffs)

    assert maximum_active_starts == [1, 1, 1, 1]


def test_claude_settings_create_migrate_preserve_and_reject_symlink(
    tmp_path: Path,
) -> None:
    provider = PROVIDERS["claude"]

    missing_workspace = tmp_path / "missing"
    missing_workspace.mkdir()
    _ensure_claude_settings(
        missing_workspace,
        provider,
        SAFE_PROFILE,
        allowed_ancestor=missing_workspace,
    )
    assert json.loads(
        (missing_workspace / ".claude/settings.json").read_text(encoding="utf-8")
    ) == {"permissions": {"defaultMode": "default"}}

    legacy_workspace = tmp_path / "legacy"
    legacy_settings = legacy_workspace / ".claude/settings.json"
    legacy_settings.parent.mkdir(parents=True)
    legacy_settings.write_text(
        '{"permissions":{"defaultMode":"bypassPermissions"}}\n',
        encoding="utf-8",
    )
    _ensure_claude_settings(
        legacy_workspace,
        provider,
        SAFE_PROFILE,
        allowed_ancestor=legacy_workspace,
    )
    assert json.loads(legacy_settings.read_text(encoding="utf-8")) == {
        "permissions": {"defaultMode": "default"}
    }

    unmanaged_workspace = tmp_path / "unmanaged"
    unmanaged_settings = unmanaged_workspace / ".claude/settings.json"
    unmanaged_settings.parent.mkdir(parents=True)
    unmanaged_bytes = b'{"permissions":{"defaultMode":"default"},"theme":"dark"}\n'
    unmanaged_settings.write_bytes(unmanaged_bytes)
    _ensure_claude_settings(
        unmanaged_workspace,
        provider,
        SAFE_PROFILE,
        allowed_ancestor=unmanaged_workspace,
    )
    assert unmanaged_settings.read_bytes() == unmanaged_bytes
    assert not (unmanaged_settings.parent / ".unrest-managed-settings.json").exists()

    current_workspace = tmp_path / "current"
    current_root = current_workspace / ".claude"
    current_root.mkdir(parents=True)
    current_settings = current_root / "settings.json"
    current_marker = current_root / ".unrest-managed-settings.json"
    current_settings.write_text(
        '{\n  "permissions": {\n    "defaultMode": "default"\n  }\n}\n',
        encoding="utf-8",
    )
    current_marker.write_text(
        '{\n  "managed_fields": [\n    "permissions.defaultMode"\n  ],\n'
        '  "schema_version": 1\n}\n',
        encoding="utf-8",
    )
    current_bytes = (current_settings.read_bytes(), current_marker.read_bytes())
    _ensure_claude_settings(
        current_workspace,
        provider,
        SAFE_PROFILE,
        allowed_ancestor=current_workspace,
    )
    assert (current_settings.read_bytes(), current_marker.read_bytes()) == current_bytes

    unsafe_workspace = tmp_path / "unsafe"
    unsafe_settings = unsafe_workspace / ".claude/settings.json"
    unsafe_settings.parent.mkdir(parents=True)
    unsafe_bytes = b'{"permissions":{"defaultMode":"plan"}}\n'
    unsafe_settings.write_bytes(unsafe_bytes)
    with pytest.raises(CapabilityPolicyError, match="unmanaged ambient permission"):
        _ensure_claude_settings(
            unsafe_workspace,
            provider,
            SAFE_PROFILE,
            allowed_ancestor=unsafe_workspace,
        )
    assert unsafe_settings.read_bytes() == unsafe_bytes

    external = tmp_path / "external"
    external.mkdir()
    external_settings = external / "settings.json"
    external_settings.write_bytes(b'{"external":true}\n')
    symlink_workspace = tmp_path / "symlink"
    symlink_workspace.mkdir()
    (symlink_workspace / ".claude").symlink_to(external, target_is_directory=True)
    before = external_settings.read_bytes()
    with pytest.raises(CapabilityPolicyError, match="safe regular workspace path"):
        _ensure_claude_settings(
            symlink_workspace,
            provider,
            SAFE_PROFILE,
            allowed_ancestor=symlink_workspace,
        )
    assert external_settings.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    (
        {"command": "/usr/bin/true"},
        {
            "command": "/usr/bin/true",
            "args": None,
            "env": None,
            "outputByteLimit": None,
        },
    ),
)
async def test_terminal_create_optional_nulls_use_omission_defaults(
    params: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _safe_policy("claude")
    spawned: list[tuple[tuple[object, ...], dict[str, object]]] = []
    original_spawn = asyncio.create_subprocess_exec

    async def capture_spawn(*args, **kwargs):
        spawned.append((args, kwargs))
        return await original_spawn(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)
    client = ACPClient(
        None,  # type: ignore[arg-type]
        str(Path(__file__).resolve().parents[1]),
        policy=policy,
        terminal_environment={"PATH": os.environ["PATH"]},
    )

    response = await client._handle_terminal_create(params)  # type: ignore[arg-type]
    terminal = client._terminals[response["terminalId"]]
    await terminal.process.wait()

    assert spawned[0][0] == ("/usr/bin/true",)
    assert terminal.output_limit == 1024 * 1024


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("args", False),
        ("args", "bad"),
        ("env", False),
        ("env", {}),
        ("outputByteLimit", False),
        ("outputByteLimit", "1024"),
    ),
)
async def test_terminal_create_rejects_non_null_wrong_types(
    field: str,
    value: object,
) -> None:
    client = ACPClient(
        None,  # type: ignore[arg-type]
        str(Path(__file__).resolve().parents[1]),
        policy=_safe_policy("claude"),
        terminal_environment={"PATH": os.environ["PATH"]},
    )

    with pytest.raises(ValueError):
        await client._handle_terminal_create(
            {"command": "/usr/bin/true", field: value}
        )


@pytest.mark.parametrize("provider_name", ("claude", "codex"))
def test_dispatch_batch_persists_bounded_redacted_crash_without_harming_sibling(
    config: HarnessConfig,
    project_setup: ProjectStore,
    workspace: Path,
    mock_acp_command: str,
    monkeypatch: pytest.MonkeyPatch,
    provider_name: str,
) -> None:
    secret = "batch-crash-known-value"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    role_config = replace(
        config,
        validator_provider_name=provider_name,
        validator_acp_command=mock_acp_command,
    )
    dispatcher = ACPNodeDispatcher(role_config, project_setup)
    runner = dispatcher.runner
    mcp_processes: dict[str, asyncio.subprocess.Process] = {}

    async def _start_fixture(**kwargs):
        process = await asyncio.create_subprocess_exec(
            "/bin/sleep",
            "30",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        mcp_processes[kwargs["task"].id] = process
        runner._start_mcp_drains(process)
        return process

    async def _ready_fixture(*args, **kwargs):
        return None

    original_render_prompts = runner._render_prompts

    def _render_prompts_fixture(**kwargs):
        if kwargs["task"].id == "v-crash":
            raise RuntimeError(f"prompt-render-neighbor-{secret}")
        return original_render_prompts(**kwargs)

    runner._find_free_port = lambda: 41001  # type: ignore[method-assign]
    runner._start_worker_mcp_server = _start_fixture  # type: ignore[method-assign]
    runner._wait_for_server_ready = _ready_fixture  # type: ignore[method-assign]
    runner._render_prompts = _render_prompts_fixture  # type: ignore[method-assign]
    good = DispatchRequest(
        project_id="p1",
        mission_id="mission-001",
        task=Task(
            id="v-good",
            type="validate",
            body="validate",
            targets=["VAL-001"],
            skill="s",
        ),
        spawn_ts="2026-08-10T07-05-00Z-0000",
    )
    bad = DispatchRequest(
        project_id="p1",
        mission_id="mission-001",
        task=Task(
            id="v-crash",
            type="validate",
            body="validate",
            targets=["VAL-001"],
            skill="s",
        ),
        spawn_ts="2026-08-10T07-05-00Z-0001",
    )

    good_handoff, crash_handoff = dispatcher.dispatch_batch([good, bad])

    assert isinstance(good_handoff, ValidateHandoff)
    assert good_handoff.done is True
    assert good_handoff.passed is True
    assert isinstance(crash_handoff, ValidateHandoff)
    assert crash_handoff.done is False
    assert crash_handoff.passed is False
    assert "RuntimeError" in crash_handoff.report
    assert "prompt-render-neighbor-<redacted:ANTHROPIC_API_KEY>" in crash_handoff.report
    assert secret not in crash_handoff.report
    assert len(crash_handoff.report) < 2200
    assert set(mcp_processes) == {"v-good", "v-crash"}
    assert all(process.returncode is not None for process in mcp_processes.values())
    assert runner._mcp_drains == {}
    attempt = project_setup.attempt_path(
        "p1", "mission-001", bad.spawn_ts, bad.task.id
    )
    persisted = attempt.read_text(encoding="utf-8")
    assert "RuntimeError" in persisted
    assert "prompt-render-neighbor-<redacted:ANTHROPIC_API_KEY>" in persisted
    assert secret not in persisted


def test_augment_acp_command_codex_untouched():
    assert _augment_acp_command("codex-acp", PROVIDERS["codex"]) == "codex-acp"


def test_codex_acp_env_uses_documented_config_and_effort(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CODEX_CONFIG", '{"features":{"memories":true},"model":"kept"}')

    env = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=_safe_policy("codex"),
        reasoning_effort="medium",
    )

    assert env["INITIAL_AGENT_MODE"] == "agent"
    assert json.loads(env["CODEX_CONFIG"]) == {
        "features": {"memories": True},
        "model": "kept",
        "model_reasoning_effort": "medium",
        "sandbox_mode": "workspace-write",
        "approval_policy": "on-request",
    }


def test_codex_acp_env_defaults_to_medium(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CODEX_CONFIG", raising=False)
    config = json.loads(
        _acp_subprocess_env(
            PROVIDERS["codex"],
            policy=_safe_policy("codex"),
        )["CODEX_CONFIG"]
    )
    assert config["model_reasoning_effort"] == "medium"


def test_codex_acp_env_explicit_work_node_settings_win(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CODEX_CONFIG", '{"model":"inherited"}')
    config = json.loads(
        _acp_subprocess_env(
            PROVIDERS["codex"],
            policy=_safe_policy("codex"),
            reasoning_effort="high",
            model="project-model",
        )["CODEX_CONFIG"]
    )
    assert config["model"] == "project-model"
    assert config["model_reasoning_effort"] == "high"


def test_codex_acp_env_malformed_inherited_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CODEX_CONFIG", "not-json")
    with pytest.raises(ValueError, match="CODEX_CONFIG must be a valid JSON object"):
        _acp_subprocess_env(
            PROVIDERS["codex"],
            policy=_safe_policy("codex"),
        )


@pytest.mark.asyncio
async def test_malformed_codex_config_fails_before_any_runtime_process_starts(
    config: HarnessConfig,
    project_setup,
    monkeypatch: pytest.MonkeyPatch,
):
    config = replace(
        config,
        worker_provider_name="codex",
        worker_acp_command="codex-acp",
    )
    monkeypatch.setenv("CODEX_CONFIG", "not-json")
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    started = False

    async def forbidden_start(**kwargs):
        nonlocal started
        started = True
        raise AssertionError("worker MCP server must not start")

    monkeypatch.setattr(runner, "_start_worker_mcp_server", forbidden_start)
    task = Task(id="w1", type="work", body="b", targets=["VAL-001"], skill="s")

    with pytest.raises(ValueError, match="CODEX_CONFIG must be a valid JSON object"):
        await runner.run_node(
            "p1",
            "mission-001",
            task,
            "2026-05-17T00-00-02Z",
            project_setup,
        )
    assert started is False


def test_augment_acp_command_claude_untouched():
    assert _augment_acp_command("claude-agent-acp", PROVIDERS["claude"]) == "claude-agent-acp"
    assert (
        _augment_acp_command("claude-agent-acp", PROVIDERS["claude"], reasoning_effort="low")
        == "claude-agent-acp"
    )


def test_non_codex_env_removes_inherited_codex_controls(monkeypatch: pytest.MonkeyPatch):
    for key in (
        "CODEX_CONFIG",
        "CODEX_PATH",
        "CODEX_SANDBOX",
        "CODEX_DISABLE_SANDBOX",
        "INITIAL_AGENT_MODE",
    ):
        monkeypatch.setenv(key, "inherited")

    env = _acp_subprocess_env(
        PROVIDERS["claude"],
        policy=_safe_policy("claude"),
    )

    for key in (
        "CODEX_CONFIG",
        "CODEX_PATH",
        "CODEX_SANDBOX",
        "CODEX_DISABLE_SANDBOX",
        "INITIAL_AGENT_MODE",
    ):
        assert key not in env


def test_codex_acp_env_preserves_node_path_when_bwrap_is_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for executable in ("node", "bwrap"):
        path = bin_dir / executable
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    env = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=_safe_policy("codex"),
    )

    assert str(bin_dir) in env["PATH"].split(os.pathsep)
    assert env["INITIAL_AGENT_MODE"] == "agent"
    assert "CODEX_SANDBOX" not in env
    assert "CODEX_DISABLE_SANDBOX" not in env


def test_codex_acp_env_prefers_installed_codex_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\n", encoding="utf-8")
    codex.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("CODEX_PATH", raising=False)

    env = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=_safe_policy("codex"),
    )

    assert env["CODEX_PATH"] == str(codex)


def test_missing_handoff_includes_bounded_agent_diagnostics(config: HarnessConfig, project_setup):
    store = project_setup
    task = Task(id="w1", type="work", body="b", targets=["VAL-001"], skill="s")
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    path = store.attempt_path("p1", "mission-001", "2026-05-17T00-00-01Z", "w1")

    handoff = runner._synthesize_and_persist_missing_handoff(
        handoff_path=path,
        task=task,
        stop_reason="end_turn",
        exit_code=0,
        stderr="",
        session_error=None,
        agent_output="secret-prefix " + ("diagnostic " * 500),
    )

    assert "agent_output=" in handoff.report
    assert "secret-prefix" not in handoff.report
    assert len(handoff.report) < 2200


def test_attempt_path_naming(config: HarnessConfig, project_setup):
    store = project_setup
    p = store.attempt_path("p1", "mission-001", "2026-05-17T10-00-00Z", "w1")
    assert p.name == "2026-05-17T10-00-00Z__w1.json"
    assert "attempts" in p.parts
    # JSON handoff lives in the runtime cursor tree, not the durable .unrest record.
    assert ".unrest-runtime" in p.parts


def test_terminal_review_path_naming(config: HarnessConfig, project_setup):
    store = project_setup
    p = store.terminal_review_path("p1", "mission-001", "2026-05-17T10-00-00Z")
    assert p.name == "2026-05-17T10-00-00Z.json"
    assert "terminal-reviews" in p.parts
    # JSON handoff lives in the runtime cursor tree, not the durable .unrest record.
    assert ".unrest-runtime" in p.parts


@pytest.mark.asyncio
async def test_terminal_review_timeout_cleans_acp_and_mcp_children(
    config: HarnessConfig,
    project_setup,
    monkeypatch: pytest.MonkeyPatch,
):
    import unrest_harness.acp_runner as acp_runner_module

    config = replace(
        config,
        terminal_reviewer_acp_command="fake-acp",
        terminal_review_timeout_seconds=1,
    )
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))

    class FakeProcess:
        def __init__(self) -> None:
            self.returncode = None
            self.stdin = None
            self.stderr = asyncio.StreamReader()
            self.terminated = False
            self._exited = asyncio.Event()

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = -15
            self._exited.set()

        def kill(self) -> None:
            self.terminate()

        async def wait(self) -> int:
            await self._exited.wait()
            return -15

    mcp_process = FakeProcess()
    acp_process = FakeProcess()
    client_cleaned = False
    progress: list[str] = []

    class FakeClient:
        def __init__(
            self,
            process,
            working_dir,
            policy=None,
            terminal_environment=None,
            session_update_handler=None,
        ) -> None:
            self.session_update_handler = session_update_handler

        async def start(self) -> None:
            return None

        async def send_request(self, method: str, params: dict):
            if method == "session/new":
                return {"sessionId": "review-session"}
            if method == "session/prompt":
                assert self.session_update_handler is not None
                await self.session_update_handler(
                    {
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "messageId": "m1",
                            "content": [{"type": "text", "text": "still reviewing.\n"}],
                        }
                    }
                )
                await asyncio.Event().wait()
            return {}

        async def cleanup(self, *, close_main_process: bool = True) -> None:
            nonlocal client_cleaned
            client_cleaned = True

    async def fake_start_mcp(**kwargs):
        return mcp_process

    async def ready(*args, **kwargs) -> None:
        return None

    async def fake_spawn(*args, **kwargs):
        return acp_process

    monkeypatch.setattr(runner, "_start_terminal_reviewer_mcp", fake_start_mcp)
    monkeypatch.setattr(runner, "_wait_for_server_ready", ready)
    monkeypatch.setattr(runner, "_find_free_port", lambda: 54321)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setattr(acp_runner_module, "ACPClient", FakeClient)

    handoff = await runner.run_terminal_review(
        "p1",
        "mission-001",
        "2026-05-17T10-00-01Z",
        project_setup,
        progress_callback=progress.append,
    )

    assert handoff.done is False
    assert "timed out after 1 seconds" in handoff.report
    assert "closure was not sealed" in handoff.report
    assert progress == ["Agent: still reviewing."]
    assert acp_process.terminated is True
    assert mcp_process.terminated is True
    assert client_cleaned is True


def test_production_terminal_reviewer_emits_progress_to_stderr(
    config: HarnessConfig,
    project_setup,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reviewer = ACPTerminalReviewer(config, project_setup)

    async def fake_review(*args, progress_callback=None, **kwargs):
        assert progress_callback is not None
        progress_callback("Agent: checking release evidence")
        return TerminalReviewHandoff(done=False, report="gap")

    monkeypatch.setattr(reviewer.runner, "run_terminal_review", fake_review)

    handoff = reviewer.review("p1", "mission-001", "2026-05-17T10-00-02Z")

    assert handoff.done is False
    assert "[unrest terminal-review] Agent: checking release evidence" in capsys.readouterr().err
