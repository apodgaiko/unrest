from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from unrest_harness.acp_runner import _acp_subprocess_env
from unrest_harness.capability_policy import (
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_PROFILE,
    CapabilityAccessError,
    load_capability_policy,
    resolve_role_capability,
)
from unrest_harness.config import HarnessConfig
from unrest_harness.provider_sessions import (
    ProviderSessionRequest,
    ProviderSessionRunner,
)
from unrest_harness.providers import PROVIDERS

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"
MOCK_ADAPTER = Path(__file__).with_name("mock_provider_session_acp.py")
SESSION_ROLES = (
    "inquiry_branch",
    "inquiry_synthesis",
    "candidate_author",
    "independent_evaluator",
    "independent_reviewer",
)


def _config(tmp_path: Path, command: str, *, profile: str = SAFE_PROFILE) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=BUNDLED,
        harness_home=tmp_path / "home",
        projects_dir=tmp_path / "home" / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=command,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        capability_profile=profile,
    )


def _request(tmp_path: Path, *, max_response_bytes: int = 1024) -> ProviderSessionRequest:
    workspace = tmp_path / "workspace"
    record = tmp_path / "record"
    private = record / "private"
    for path in (workspace, record, private):
        path.mkdir(exist_ok=True)
    return ProviderSessionRequest(
        role="inquiry_branch",
        prompt="Answer the bounded question.",
        workspace_path=workspace,
        project_record_path=record,
        private_artifact_path=private / "session.json",
        private_artifact_root=private,
        timeout_seconds=2,
        max_response_bytes=max_response_bytes,
    )


@pytest.mark.parametrize("profile", (SAFE_PROFILE, UNSAFE_DEVELOPMENT_PROFILE))
@pytest.mark.parametrize("role", SESSION_ROLES)
def test_structured_session_roles_are_read_only_even_in_unsafe_profile(
    tmp_path: Path,
    profile: str,
    role: str,
) -> None:
    workspace = tmp_path / "workspace"
    record = tmp_path / "record"
    workspace.mkdir()
    record.mkdir()
    policy = resolve_role_capability(
        PROVIDERS["codex"],
        role=role,  # type: ignore[arg-type]
        policy=load_capability_policy(BUNDLED),
        profile=profile,
        workspace=workspace,
        project_record=record,
    )

    assert policy.process.enabled is False
    assert policy.approvals.tool_kinds == ("fetch", "read", "search", "think")
    assert policy.roots
    assert all(root.read and not root.write for root in policy.roots)
    with pytest.raises(CapabilityAccessError, match="filesystem:write"):
        policy.authorize_path(
            workspace / "blocked.txt",
            access="write",
            working_dir=workspace,
        )
    with pytest.raises(CapabilityAccessError, match="process access is disabled"):
        policy.authorize_command(sys.executable)
    environment = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment={"HOME": str(tmp_path), "PATH": os.environ["PATH"]},
    )
    codex_config = json.loads(environment["CODEX_CONFIG"])
    assert codex_config["sandbox_mode"] == "read-only"
    assert codex_config["approval_policy"] == "on-request"
    assert "CODEX_DISABLE_SANDBOX" not in environment


def test_role_provider_mapping_preserves_separate_authorities(tmp_path: Path) -> None:
    config = replace(
        _config(tmp_path, "mock-worker"),
        validator_provider_name="codex",
        validator_acp_command="mock-evaluator",
        terminal_reviewer_provider_name="claude",
        terminal_reviewer_acp_command="mock-reviewer",
    )
    assert config.for_role("inquiry_branch").worker_provider.name == "claude"
    assert config.for_role("candidate_author").worker_provider.name == "claude"
    assert config.for_role("inquiry_synthesis").worker_provider.name == "codex"
    assert config.for_role("independent_evaluator").worker_provider.name == "codex"
    assert config.for_role("independent_reviewer").worker_provider.name == "claude"
    assert config.for_role("independent_evaluator").worker_acp_command == "mock-evaluator"
    assert config.for_role("independent_reviewer").worker_acp_command == "mock-reviewer"
    config.validate_capability_support()


@pytest.mark.parametrize("role", SESSION_ROLES)
def test_every_session_role_has_a_bundled_structured_prompt(role: str) -> None:
    prompt = (BUNDLED / "prompts" / role / "system_prompt.md").read_text(
        encoding="utf-8"
    )
    assert "Return exactly one JSON object" in prompt
    assert prompt.endswith("\n")


@pytest.mark.asyncio
async def test_success_keeps_content_private_redacted_and_mode_0600(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "provider-session-secret-7f21d9"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    command = f"{sys.executable} {MOCK_ADAPTER} --echo-credential ANTHROPIC_API_KEY"
    request = _request(tmp_path)
    result = await ProviderSessionRunner(_config(tmp_path, command)).run(request)

    assert result.status == "completed"
    assert result.structured_output is True
    assert result.error_code is None
    public = json.dumps(result.public_metadata(), sort_keys=True)
    assert secret not in public
    assert str(request.private_artifact_path) not in public
    assert "digest" not in public
    artifact_text = request.private_artifact_path.read_text(encoding="utf-8")
    artifact = json.loads(artifact_text)
    assert secret not in artifact_text
    assert artifact["output"]["parsed"] == {
        "answer": "<redacted:ANTHROPIC_API_KEY>"
    }
    assert artifact["input"]["prompt"].startswith("# Unrest Inquiry Branch")
    assert stat.S_IMODE(request.private_artifact_path.stat().st_mode) == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_args", "limit", "expected_error"),
    (
        ("--invalid", 1024, "invalid_structured_output"),
        ("--payload-size 4096", 128, "output_limit_exceeded"),
    ),
)
async def test_invalid_or_oversize_output_fails_closed(
    tmp_path: Path,
    adapter_args: str,
    limit: int,
    expected_error: str,
) -> None:
    command = f"{sys.executable} {MOCK_ADAPTER} {adapter_args}"
    request = _request(tmp_path, max_response_bytes=limit)
    result = await ProviderSessionRunner(_config(tmp_path, command)).run(request)

    assert result.status == "failed"
    assert result.error_code == expected_error
    assert result.structured_output is False
    artifact = json.loads(request.private_artifact_path.read_text(encoding="utf-8"))
    assert artifact["status"] == "failed"
    assert artifact["error_code"] == expected_error


@pytest.mark.asyncio
async def test_cancel_event_returns_typed_result_and_stops_adapter(tmp_path: Path) -> None:
    command = f"{sys.executable} {MOCK_ADAPTER} --sleep 30"
    request = _request(tmp_path)
    cancel = asyncio.Event()
    task = asyncio.create_task(
        ProviderSessionRunner(_config(tmp_path, command)).run(
            request,
            cancel_event=cancel,
        )
    )
    await asyncio.sleep(0.1)
    cancel.set()
    result = await asyncio.wait_for(task, timeout=4)

    assert result.status == "cancelled"
    assert result.error_code == "cancelled"
    assert json.loads(request.private_artifact_path.read_text())["status"] == "cancelled"


@pytest.mark.asyncio
async def test_timeout_kills_adapter_process_group(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    child_stop_path = tmp_path / "child.stopped"
    command = (
        f"{sys.executable} {MOCK_ADAPTER} --sleep 30 "
        f"--child-pid-path {child_pid_path} --child-stop-path {child_stop_path}"
    )
    request = _request(tmp_path)
    request = ProviderSessionRequest(
        **{**request.__dict__, "timeout_seconds": 0.3},
    )
    result = await ProviderSessionRunner(_config(tmp_path, command)).run(request)

    assert result.status == "timed_out"
    assert result.error_code == "timed_out"
    assert int(child_pid_path.read_text(encoding="utf-8")) > 0
    for _ in range(60):
        if child_stop_path.exists():
            break
        await asyncio.sleep(0.05)
    assert child_stop_path.read_text(encoding="utf-8") == "stopped"


@pytest.mark.asyncio
async def test_unknown_stop_reason_and_stderr_are_private_and_bounded(
    tmp_path: Path,
) -> None:
    command = (
        f"{sys.executable} {MOCK_ADAPTER} --stderr-size 100000 "
        "--stop-reason provider-private-detail"
    )
    request = _request(tmp_path)
    result = await ProviderSessionRunner(_config(tmp_path, command)).run(request)

    assert result.status == "completed"
    assert result.stop_reason == "unknown"
    assert "provider-private-detail" not in json.dumps(result.public_metadata())
    artifact = json.loads(request.private_artifact_path.read_text(encoding="utf-8"))
    assert len(artifact["output"]["stderr"].encode("utf-8")) <= 64 * 1024


@pytest.mark.asyncio
async def test_private_artifact_cannot_escape_caller_root(tmp_path: Path) -> None:
    request = _request(tmp_path)
    escaped = ProviderSessionRequest(
        **{
            **request.__dict__,
            "private_artifact_path": request.private_artifact_root.parent / "escaped.json",
        }
    )
    runner = ProviderSessionRunner(
        _config(tmp_path, f"{sys.executable} {MOCK_ADAPTER}")
    )
    with pytest.raises(OSError, match="must be beneath its trusted root"):
        await runner.run(escaped)
    assert not escaped.private_artifact_path.exists()
