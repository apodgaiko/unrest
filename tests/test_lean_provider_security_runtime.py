from __future__ import annotations

import asyncio
import base64
import codecs
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from unrest_harness.acp_runner import ACPNodeRunner, _acp_subprocess_env
from unrest_harness.assets import AssetLoader
from unrest_harness.capability_policy import (
    FINITE_CREDENTIAL_NAMES,
    SAFE_PROFILE,
    UNSAFE_DEVELOPMENT_PROFILE,
    StreamingCredentialRedactor,
    build_role_environment,
    credential_values,
    enforce_environment_credential_provenance,
    finite_credential_values,
    load_capability_policy,
    redact_sensitive_value,
    resolve_role_capability,
)
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import Task, TaskList, TerminalReviewHandoff, WorkHandoff
from unrest_harness.providers import PROVIDERS, provider_names_for_role
from unrest_harness.storage import ProjectStore
from unrest_harness.server import _to_payload
from unrest_harness.task_validation import ValidationError


def test_supported_provider_set_is_claude_and_codex_only() -> None:
    assert tuple(sorted(PROVIDERS)) == ("claude", "codex")
    assert provider_names_for_role("orchestrator") == ("claude", "codex")
    assert provider_names_for_role("worker") == ("claude", "codex")


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
    )


@pytest.mark.parametrize("profile", (SAFE_PROFILE, UNSAFE_DEVELOPMENT_PROFILE))
@pytest.mark.parametrize("provider_name", provider_names_for_role("worker"))
@pytest.mark.parametrize(
    ("projection", "role", "include_credentials"),
    (
        ("adapter", "worker", True),
        ("worker-mcp", "worker", False),
        ("reviewer-mcp", "terminal_reviewer", False),
        ("terminal", "worker", False),
    ),
)
def test_projection_excludes_raw_wrappers_and_preserves_transformed_controls(
    config: HarnessConfig,
    workspace: Path,
    profile: str,
    provider_name: str,
    projection: str,
    role: str,
    include_credentials: bool,
) -> None:
    policy = resolve_role_capability(
        PROVIDERS[provider_name],
        role=role,  # type: ignore[arg-type]
        policy=load_capability_policy(config.bundled_dir),
        profile=profile,
        workspace=workspace,
        project_record=workspace,
    )
    credential_values_by_name = {
        name: (
            "KEY"
            if index == 0
            else f"sentinel-{index}-{name.lower()}"
        )
        for index, name in enumerate(FINITE_CREDENTIAL_NAMES)
    }
    wrapped_credential = credential_values_by_name[FINITE_CREDENTIAL_NAMES[1]]
    encoded_control = base64.urlsafe_b64encode(wrapped_credential.encode()).decode()
    hashed_control = hashlib.sha256(wrapped_credential.encode()).hexdigest()
    reordered_control = wrapped_credential[::-1]
    host = {
        "PATH": "/bin",
        **credential_values_by_name,
        "HOME": f"prefix::{wrapped_credential}::suffix",
        "TEMP": "KEY",
        "SSL_CERT_DIR": "MONKEY",
        "NO_PROXY": "ordinary-neighboring-text",
        "TMP": encoded_control,
        "UNDECLARED_SECRET": "unsafe-only-value",
        **{
            f"UNRELATED_ALIAS_{index}": credential_values_by_name[name]
            for index, name in enumerate(FINITE_CREDENTIAL_NAMES)
        },
        "WRAPPED_LONG": f"prefix::{wrapped_credential}::suffix",
        "HASHED_CONTROL": hashed_control,
        "REORDERED_CONTROL": reordered_control,
    }

    expected_names = PROVIDERS[provider_name].credential_names
    assert policy.environment.credentials == expected_names
    assert "*" not in policy.environment.credentials
    assert credential_values(policy, host) == {
        name: host[name] for name in expected_names
    }
    internal = None
    if projection in {"adapter", "worker-mcp", "reviewer-mcp"}:
        internal = {"UNREST_HOME": f"internal::{wrapped_credential}::wrapper"}
    if projection == "adapter":
        projected = _acp_subprocess_env(
            PROVIDERS[provider_name],
            policy=policy,
            host_environment=host,
            internal=internal,
        )
    else:
        projected = build_role_environment(
            policy,
            host,
            internal=internal,
            include_credentials=include_credentials,
        )

    for name in FINITE_CREDENTIAL_NAMES:
        if projection == "adapter" and name in expected_names:
            assert projected[name] == host[name]
        else:
            assert name not in projected
    assert "HOME" not in projected
    assert "TEMP" not in projected
    assert "UNREST_HOME" not in projected
    assert projected["SSL_CERT_DIR"] == "MONKEY"
    assert projected["NO_PROXY"] == "ordinary-neighboring-text"
    assert projected["TMP"] == encoded_control
    if profile == SAFE_PROFILE:
        assert "UNDECLARED_SECRET" not in projected
        assert "HASHED_CONTROL" not in projected
        assert "REORDERED_CONTROL" not in projected
    else:
        assert projected["UNDECLARED_SECRET"] == "unsafe-only-value"
        assert projected["HASHED_CONTROL"] == hashed_control
        assert projected["REORDERED_CONTROL"] == reordered_control
        assert "WRAPPED_LONG" not in projected
        for index in range(len(FINITE_CREDENTIAL_NAMES)):
            assert f"UNRELATED_ALIAS_{index}" not in projected

    assert finite_credential_values(host) == {
        name: host[name] for name in FINITE_CREDENTIAL_NAMES
    }


def test_exact_redaction_short_guard_structures_transforms_and_every_split() -> None:
    inventory = {
        "SHORT": "KEY",
        "LONG": "long-known-value",
        "PUNCT": "p@ss",
    }
    source = "KEY; MONKEY KEY-label .KEY xlong-known-valuey xp@ssy"
    expected = (
        "<redacted:SHORT>; MONKEY KEY-label .KEY "
        "x<redacted:LONG>y x<redacted:PUNCT>y"
    )
    for split in range(len(source) + 1):
        redactor = StreamingCredentialRedactor(inventory)
        assert redactor.feed(source[:split]) + redactor.feed(
            source[split:], final=True
        ) == expected

    structured = redact_sensitive_value(
        {"KEY": ["long-known-value", {"nested": "p@ss"}]}, inventory
    )
    assert structured == {
        "<redacted:SHORT>": [
            "<redacted:LONG>",
            {"nested": "<redacted:PUNCT>"},
        ]
    }
    transformed = base64.urlsafe_b64encode(b"long-known-value").decode()
    assert redact_sensitive_value(transformed, inventory) == transformed
    assert redact_sensitive_value("unknown-secret-like-value", {}) == (
        "unknown-secret-like-value"
    )
    assert enforce_environment_credential_provenance(
        {
            "ALIAS": "long-known-value",
            "WRAPPED_LONG": "prefix-long-known-value-suffix",
            "SHORT_BOUNDARY": "KEY",
            "SHORT_EMBEDDED": "MONKEY",
            "ORDINARY": "kept",
        },
        inventory,
    ) == {"ORDINARY": "kept", "SHORT_EMBEDDED": "MONKEY"}
    assert enforce_environment_credential_provenance(
        {
            "ALIAS": "long-known-value",
            "WRAPPED_LONG": "prefix-long-known-value-suffix",
            "SHORT_BOUNDARY": "KEY",
            "SHORT_EMBEDDED": "MONKEY",
            "ORDINARY": "kept",
        },
        inventory,
        inherit_all=True,
    ) == {"ORDINARY": "kept", "SHORT_EMBEDDED": "MONKEY"}


def test_streaming_redactor_handles_empty_flush_overlap_collisions_and_unicode_bytes(
) -> None:
    inventory = {
        "LONG": "credential-overlap",
        "SHORT": "credential",
        "TOKEN": "KEY",
        "UNICODE": "密钥-credential",
    }
    source = "KEY MONKEY credential-overlap 密钥-credential ordinary"
    expected = (
        "<redacted:TOKEN> MONKEY <redacted:LONG> "
        "<redacted:UNICODE> ordinary"
    )
    encoded = source.encode("utf-8")

    for split in range(len(encoded) + 1):
        decoder = codecs.getincrementaldecoder("utf-8")()
        redactor = StreamingCredentialRedactor(inventory)
        output = redactor.feed("")
        output += redactor.feed(decoder.decode(encoded[:split], final=False))
        output += redactor.feed("")
        output += redactor.feed(decoder.decode(encoded[split:], final=True))
        output += redactor.finish()
        assert output == expected

    assert redact_sensitive_value(
        {
            "credential": "kept",
            "prefix-credential-suffix": "credential-overlap",
        },
        inventory,
    ) == {
        "<redacted:SHORT>": "kept",
        "prefix-<redacted:SHORT>-suffix": "<redacted:LONG>",
    }
    assert redact_sensitive_value(source, {}) == source


def test_tool_error_message_and_details_use_explicit_inventory() -> None:
    message_secret = "diagnostic-message-credential-61b4"
    details_secret = "diagnostic-details-credential-90ce"
    payload = _to_payload(
        ToolError(
            code="invalid_request",
            message=f"left {message_secret} right",
            details=[
                ValidationError(
                    "invalid_target",
                    f"detail contains {details_secret}",
                )
            ],
        ),
        inventory={
            "OPENAI_API_KEY": message_secret,
            "ANTHROPIC_API_KEY": details_secret,
        },
    )
    response_bytes = json.dumps(payload, sort_keys=True).encode()
    assert message_secret.encode() not in response_bytes
    assert details_secret.encode() not in response_bytes
    assert payload == {
        "error": "invalid_request",
        "message": "left <redacted:OPENAI_API_KEY> right",
        "details": [
            "invalid_target: detail contains <redacted:ANTHROPIC_API_KEY>"
        ],
    }


def test_store_snapshot_redacts_attempt_cursor_and_mirror(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "coordinator-known-value")
    store = ProjectStore(config)
    store.create_project("brief", workspace, project_id="p1")
    path = store.save_attempt(
        "p1",
        "mission-001",
        "2026-08-10T00-00-00Z",
        "w1",
        WorkHandoff(
            node_id="w1", done=True, report="left coordinator-known-value right"
        ),
    )
    mirror = store.attempt_report_path(
        "p1", "mission-001", "2026-08-10T00-00-00Z", "w1"
    )
    for artifact in (path, mirror):
        text = artifact.read_text(encoding="utf-8")
        assert "coordinator-known-value" not in text
        assert "left <redacted:OPENAI_API_KEY> right" in text


def test_coordinator_refreshes_inventory_at_child_creation(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                done=True,
                report="left dispatch-known-value right",
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="clean")),
    )
    controller.start_project("brief", str(workspace))
    project_id = controller.store.list_projects()[0].id
    contract = controller.store.ensure_contract_dir(project_id, "mission-001")
    (contract / "VAL-001.md").write_text(
        "# VAL-001: probe\n\nSurface: other.\nNeeds: none.\n"
        "Behavior: probe.\nEvidence: probe.\n",
        encoding="utf-8",
    )
    controller.submit_plan(
        project_id,
        TaskList(
            tasks=[
                Task(id="w1", type="work", body="work", targets=["VAL-001"], skill="s"),
                Task(
                    id="v1",
                    type="validate",
                    body="validate",
                    targets=["VAL-001"],
                    skill="s",
                    depends_on=["w1"],
                ),
                Task(
                    id="g1",
                    type="gate",
                    body="",
                    targets=["VAL-001"],
                    depends_on=["v1"],
                ),
            ]
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "dispatch-known-value")
    controller.advance_project(project_id, max_steps=1)
    attempt = controller.store.list_attempts(project_id, "mission-001", "w1")[0]
    for artifact in (
        attempt.path,
        controller.store.attempt_report_path(
            project_id, "mission-001", attempt.spawn_ts, "w1"
        ),
    ):
        text = artifact.read_text(encoding="utf-8")
        assert "dispatch-known-value" not in text
        assert "left <redacted:OPENAI_API_KEY> right" in text


@pytest.mark.asyncio
async def test_chatty_child_pipes_are_continuously_drained_bounded_and_reaped(
    config: HarnessConfig,
    workspace: Path,
) -> None:
    runner = ACPNodeRunner(config=config, loader=AssetLoader(config))
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        (
            "import sys; "
            "sys.stdout.write('o'*262144); sys.stdout.flush(); "
            "sys.stderr.write('e'*262144); sys.stderr.flush()"
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=workspace,
        env={"PATH": os.environ["PATH"]},
    )
    runner._start_mcp_drains(process)
    await asyncio.wait_for(runner._close_mcp_process(process, {}), timeout=5)
    assert process.returncode == 0
    assert runner._mcp_drains == {}
