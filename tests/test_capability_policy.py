"""Focused tests for the finite Lean Core authority boundary."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner

from unrest_harness.acp_runner import ACPClient, ACPProgressTracker, _acp_subprocess_env
from unrest_harness.capability_policy import (
    CAPABILITY_PROFILE_ENV,
    CAPABILITY_VERSION_ENV,
    FINITE_CREDENTIAL_NAMES,
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_PROFILE,
    CapabilityAccessError,
    CapabilityBoundaryError,
    CapabilityPolicyError,
    StreamingCredentialRedactor,
    build_role_environment,
    credential_source_values,
    credential_values,
    load_capability_policy,
    redact_credential_values,
    redact_sensitive_value,
    resolve_role_capability,
    validate_provider_support,
)
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.providers import PROVIDERS

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "src" / "unrest_harness" / "bundled"


def _resolved(
    tmp_path: Path,
    *,
    provider_name: str = "claude",
    role: str = "worker",
    profile: str = SAFE_PROFILE,
):
    workspace = tmp_path / "workspace"
    record = tmp_path / "record"
    workspace.mkdir(exist_ok=True)
    record.mkdir(exist_ok=True)
    return resolve_role_capability(
        PROVIDERS[provider_name],  # type: ignore[index]
        role=role,  # type: ignore[arg-type]
        policy=load_capability_policy(BUNDLED),
        profile=profile,
        workspace=workspace,
        project_record=record,
    )


def _client(tmp_path: Path, *, role: str = "worker") -> ACPClient:
    policy = _resolved(tmp_path, role=role)
    return ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=build_role_environment(
            policy,
            {"PATH": os.environ["PATH"], "LANG": "C"},
        ),
    )


@pytest.mark.parametrize("profile", ("unknown", "safe-ish"))
def test_unsupported_profile_has_stable_provider_role_version_error(profile: str) -> None:
    with pytest.raises(CapabilityPolicyError) as caught:
        validate_provider_support(
            PROVIDERS["claude"],
            role="worker",
            policy=load_capability_policy(BUNDLED),
            profile=profile,
        )
    assert profile not in str(caught.value)
    assert "provider=claude role=worker version=1 capability=opaque#" in str(
        caught.value
    )


def test_safe_codex_subprocess_settings_override_ambient_unrestricted(
    tmp_path: Path,
) -> None:
    policy = _resolved(tmp_path, provider_name="codex")
    environment = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment={
            "PATH": os.environ["PATH"],
            "HOME": str(tmp_path),
            "CODEX_CONFIG": json.dumps(
                {"sandbox_mode": "danger-full-access", "approval_policy": "never"}
            ),
            "CODEX_DISABLE_SANDBOX": "1",
            "DATABASE_URL": "ambient",
        },
    )
    config = json.loads(environment["CODEX_CONFIG"])
    assert config["sandbox_mode"] == "workspace-write"
    assert config["approval_policy"] == "on-request"
    assert environment["INITIAL_AGENT_MODE"] == "agent"
    assert "CODEX_DISABLE_SANDBOX" not in environment
    assert "DATABASE_URL" not in environment


def test_only_explicit_unsafe_profile_emits_unrestricted_provider_settings(
    tmp_path: Path,
) -> None:
    policy = _resolved(
        tmp_path,
        provider_name="codex",
        profile=UNSAFE_DEVELOPMENT_PROFILE,
    )
    environment = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment={"PATH": os.environ["PATH"]},
    )
    config = json.loads(environment["CODEX_CONFIG"])
    assert environment["INITIAL_AGENT_MODE"] == "agent-full-access"
    assert environment["CODEX_DISABLE_SANDBOX"] == "1"
    assert config["sandbox_mode"] == "danger-full-access"
    assert config["approval_policy"] == "never"


def test_role_environment_is_minimal_deterministic_and_credential_named(
    tmp_path: Path,
) -> None:
    policy = _resolved(tmp_path)
    host = {
        "ZAI_API_KEY": "known-value",
        "PATH": "/one:/two",
        "LANG": "C",
        "DATABASE_URL": "not-forwarded",
    }
    assert build_role_environment(policy, host) == build_role_environment(
        policy, dict(reversed(tuple(host.items())))
    ) == {"LANG": "C", "PATH": "/one:/two", "ZAI_API_KEY": "known-value"}


@pytest.mark.parametrize("reverse", (False, True), ids=("0", "1"))
def test_ambient_credential_inventory_is_provider_neutral_and_deterministic(
    reverse: bool,
) -> None:
    environment = {
        "OPENAI_API_KEY": "known-openai",
        "ANTHROPIC_API_KEY": "known-anthropic",
        "ARBITRARY_PASSWORD": "outside-finite-authority",
        "TOKENISH_PAYLOAD": "high-entropy-looking-but-ordinary",
    }
    if reverse:
        environment = dict(reversed(tuple(environment.items())))
    inventory = credential_source_values(
        environment,
        declared_names=FINITE_CREDENTIAL_NAMES,
    )
    assert inventory == {
        "ANTHROPIC_API_KEY": "known-anthropic",
        "OPENAI_API_KEY": "known-openai",
    }


def test_credential_redaction_is_boundary_aware_and_deterministic() -> None:
    inventory = {"OPENAI_API_KEY": "KEY-long", "ZAI_API_KEY": "KEY"}
    source = "KEY; MONKEY KEY-label .KEY xKEY-longy"
    expected = (
        "<redacted:ZAI_API_KEY>; MONKEY KEY-label .KEY "
        "x<redacted:OPENAI_API_KEY>y"
    )
    assert redact_credential_values(source, inventory) == expected
    for split in range(len(source) + 1):
        redactor = StreamingCredentialRedactor(inventory)
        assert redactor.feed(source[:split]) + redactor.feed(
            source[split:], final=True
        ) == expected


@pytest.mark.asyncio
async def test_progress_redaction_spans_chunks_callbacks_and_message_ids() -> None:
    secret = "PROGRESS_SECRET_8fd1"
    progress: list[str] = []
    inventory = {"ZAI_API_KEY": secret}
    tracker = ACPProgressTracker(
        callback=progress.append,
        redactor=lambda text: redact_credential_values(text, inventory),
        stream_redactor=StreamingCredentialRedactor(inventory),
    )
    for chunk in (secret[:10], secret[10:] + " ordinary=kept\n"):
        await tracker.handle_session_update(
            {
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "messageId": "same",
                    "content": [{"type": "text", "text": chunk}],
                }
            }
        )
    assert progress == ["Agent: <redacted:ZAI_API_KEY> ordinary=kept"]


@pytest.mark.parametrize("kind", ("list", "mapping"))
def test_cyclic_containers_have_stable_value_free_boundary_diagnostics(
    kind: str,
) -> None:
    value: Any = [] if kind == "list" else {}
    if kind == "list":
        value.append(value)
    else:
        value["child"] = value
    with pytest.raises(CapabilityBoundaryError) as caught:
        redact_sensitive_value(value, {})
    assert str(caught.value) == (
        "CAP-BOUNDARY-001 classification=cyclic-container: "
        "output blocked before serialization"
    )
    assert "child" not in str(caught.value)


def test_codex_structured_config_drops_exact_aliases_and_preserves_config(
    tmp_path: Path,
) -> None:
    secret = "long-known-codex-value"
    policy = _resolved(tmp_path, provider_name="codex")
    environment = _acp_subprocess_env(
        PROVIDERS["codex"],
        policy=policy,
        host_environment={
            "PATH": os.environ["PATH"],
            "OPENAI_API_KEY": secret,
            "CODEX_CONFIG": json.dumps(
                {
                    "features": {"memories": True, "alias": secret},
                    "model": secret,
                    "ordinary": "kept",
                }
            ),
        },
    )
    rendered = environment["CODEX_CONFIG"]
    assert secret not in rendered
    assert json.loads(rendered)["ordinary"] == "kept"
    assert json.loads(rendered)["features"] == {"memories": True}


def test_filesystem_callbacks_enforce_absolute_traversal_symlink_and_read_only(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "inside.txt").write_text("inside")
    (outside / "secret.txt").write_text("outside")
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    worker = _client(tmp_path)
    assert worker._handle_fs_read({"path": "inside.txt"}) == {"content": "inside"}
    for path in (str(outside / "secret.txt"), "../outside/secret.txt", "escape/secret.txt"):
        with pytest.raises(CapabilityAccessError):
            worker._handle_fs_read({"path": path})
    reviewer = _client(tmp_path, role="terminal_reviewer")
    with pytest.raises(CapabilityAccessError):
        reviewer._handle_fs_write({"path": "blocked.txt", "content": "blocked"})


@pytest.mark.asyncio
async def test_terminal_callbacks_enforce_process_cwd_and_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    worker = _client(tmp_path)
    with pytest.raises(CapabilityAccessError, match="terminal:environment"):
        await worker._handle_terminal_create(
            {"command": sys.executable, "env": [{"name": "DATABASE_URL", "value": "x"}]}
        )
    with pytest.raises(CapabilityAccessError, match="filesystem:cwd"):
        await worker._handle_terminal_create(
            {"command": sys.executable, "cwd": str(outside)}
        )
    orchestrator = _client(tmp_path, role="orchestrator")
    started = False

    async def forbidden_start(*args, **kwargs):
        nonlocal started
        started = True

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_start)
    with pytest.raises(CapabilityAccessError, match="process access is disabled"):
        await orchestrator._handle_terminal_create({"command": sys.executable})
    assert not started


@pytest.mark.asyncio
async def test_raw_acp_terminal_protocol_redacts_credential_values(
    tmp_path: Path,
) -> None:
    policy = _resolved(tmp_path)
    secret = "RAW_ACP_CREDENTIAL_79d0b1"
    terminal_environment = build_role_environment(
        policy,
        {"PATH": os.environ["PATH"], "ZAI_API_KEY": secret},
    )
    client = ACPClient(
        cast(Any, object()),
        str(tmp_path / "workspace"),
        policy=policy,
        terminal_environment=terminal_environment,
    )
    client.set_credential_inventory(credential_values(policy, terminal_environment))
    created = await client._handle_terminal_create(
        {
            "command": sys.executable,
            "args": ["-c", "import os; print(os.environ['ZAI_API_KEY'])"],
        }
    )
    terminal_id = created["terminalId"]
    await client._handle_terminal_wait({"terminalId": terminal_id})
    output = client._handle_terminal_output({"terminalId": terminal_id})["output"]
    await client.cleanup(close_main_process=False)
    assert secret not in output
    assert "<redacted:ZAI_API_KEY>" in output


def test_cli_safe_init_round_trips_policy_and_never_persists_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sentinel = "credential-value-must-not-persist"
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ZAI_API_KEY", sentinel)
    monkeypatch.setenv("DATABASE_URL", sentinel)
    result = CliRunner().invoke(
        cli,
        ["init", "--workspace-dir", str(workspace), "--agent", "claude"],
    )
    assert result.exit_code == 0, result.output
    generated = json.loads((workspace / ".mcp.json").read_text())
    environment = generated["mcpServers"]["unrest"]["env"]
    assert environment[CAPABILITY_PROFILE_ENV] == SAFE_PROFILE
    assert environment[CAPABILITY_VERSION_ENV] == "1"
    for path in workspace.rglob("*"):
        if path.is_file():
            assert sentinel not in path.read_text(encoding="utf-8", errors="ignore")
    runtime = HarnessConfig.discover()
    assert runtime.capability_profile == SAFE_PROFILE
