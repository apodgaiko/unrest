"""ACP runner adaptation tests — direct-to-PROJECT handoff path discipline.

We don't run a real `claude-agent-acp` here; we use the bundled
`mock_acp_agent.py` to exercise the ACP client + the handoff polling
mechanic. The worker MCP server subprocess is bypassed: the mock agent
writes directly to UNREST_HANDOFF_PATH itself.
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

from unrest_harness.acp_runner import (
    ACPTerminalReviewer,
    ACPNodeRunner,
    _acp_subprocess_env,
    _augment_acp_command,
)
from unrest_harness.providers import PROVIDERS
from unrest_harness.assets import AssetLoader
from unrest_harness.config import HarnessConfig
from unrest_harness.models import Task, TerminalReviewHandoff, WorkHandoff
from unrest_harness.storage import ProjectStore


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
    assert "stop_reason=cancelled" in handoff.report
    assert handoff_path.exists()


def test_augment_acp_command_codex_untouched():
    assert _augment_acp_command("codex-acp", PROVIDERS["codex"]) == "codex-acp"


def test_codex_acp_env_uses_documented_config_and_effort(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CODEX_CONFIG", '{"features":{"memories":true},"model":"kept"}')

    env = _acp_subprocess_env(PROVIDERS["codex"], reasoning_effort="medium")

    assert env["INITIAL_AGENT_MODE"] == "agent-full-access"
    assert json.loads(env["CODEX_CONFIG"]) == {
        "features": {"memories": True},
        "model": "kept",
        "model_reasoning_effort": "medium",
        "sandbox_mode": "danger-full-access",
        "approval_policy": "never",
    }


def test_codex_acp_env_defaults_to_historical_xhigh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CODEX_CONFIG", raising=False)
    config = json.loads(_acp_subprocess_env(PROVIDERS["codex"])["CODEX_CONFIG"])
    assert config["model_reasoning_effort"] == "xhigh"


def test_codex_acp_env_explicit_work_node_settings_win(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CODEX_CONFIG", '{"model":"inherited"}')
    config = json.loads(
        _acp_subprocess_env(
            PROVIDERS["codex"],
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
        _acp_subprocess_env(PROVIDERS["codex"])


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

    env = _acp_subprocess_env(PROVIDERS["claude"])

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

    env = _acp_subprocess_env(PROVIDERS["codex"])

    assert str(bin_dir) in env["PATH"].split(os.pathsep)
    assert env["CODEX_SANDBOX"] == "danger-full-access"
    assert env["CODEX_DISABLE_SANDBOX"] == "1"


def test_codex_acp_env_prefers_installed_codex_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    codex = tmp_path / "codex"
    codex.write_text("#!/bin/sh\n", encoding="utf-8")
    codex.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("CODEX_PATH", raising=False)

    env = _acp_subprocess_env(PROVIDERS["codex"])

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
        def __init__(self, process, working_dir, session_update_handler=None) -> None:
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
    monkeypatch.setattr(asyncio, "create_subprocess_shell", fake_spawn)
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
