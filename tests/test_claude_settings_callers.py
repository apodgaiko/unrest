"""Public-caller matrix for Claude managed settings policy."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Callable

import pytest
from click.testing import CliRunner

import unrest_harness.acp_runner as acp_runner
import unrest_harness.cli as cli_module
from unrest_harness.acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
from unrest_harness.capability_policy import SAFE_PROFILE
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import Task, TaskList, TerminalReviewHandoff, WorkHandoff
from unrest_harness.storage import ProjectStore


STATES = (
    "missing",
    "symlinked",
    "legacy-managed",
    "current-managed",
    "safe-unmanaged",
    "malformed",
    "unsafe-unmanaged",
)
ALLOWED_STATES = {
    "missing",
    "legacy-managed",
    "current-managed",
    "safe-unmanaged",
}
MUTATED_STATES = {"missing", "legacy-managed"}
CURRENT_SETTINGS = b'{\n  "permissions": {\n    "defaultMode": "default"\n  }\n}\n'
CURRENT_MARKER = (
    b'{\n  "managed_fields": [\n    "permissions.defaultMode"\n  ],\n'
    b'  "schema_version": 1\n}\n'
)
CURRENT_HASHES = (
    "6f0bfdb7a445b4000beaf125c62e249b82698881d97b266d6939e75014388804",
    "c75fb753ed8157f6f98f865e98e07b1e5eb948e9b2f10e37f13490b0c4ca5c33",
)


class SpawnTrap(RuntimeError):
    pass


def _sha256(path: Path) -> str | None:
    if not path.exists() or path.is_symlink():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_secret_absent(root: Path, secret: str, *, skip: set[Path] | None = None) -> None:
    skipped = {path.absolute() for path in (skip or set())}
    secret_bytes = secret.encode()
    for path in root.rglob("*"):
        if path.absolute() in skipped or not path.is_file() or path.is_symlink():
            continue
        assert secret_bytes not in path.read_bytes(), path


def _settings_snapshot(workspace: Path, external: Path) -> dict[str, object]:
    settings = workspace / ".claude/settings.json"
    marker = workspace / ".claude/.unrest-managed-settings.json"
    return {
        "settings_hash": _sha256(settings),
        "settings_mode": (
            stat.S_IMODE(settings.stat().st_mode)
            if settings.exists() and not settings.is_symlink()
            else None
        ),
        "marker_hash": _sha256(marker),
        "marker_mode": (
            stat.S_IMODE(marker.stat().st_mode)
            if marker.exists() and not marker.is_symlink()
            else None
        ),
        "settings_link": (
            settings.readlink().as_posix() if settings.is_symlink() else None
        ),
        "external_hash": _sha256(external),
        "workspace_identity": str(workspace.resolve(strict=True)),
        "workspace_mode": stat.S_IMODE(workspace.stat().st_mode),
    }


def _prepare_state(workspace: Path, external: Path, state: str) -> str:
    secret = f"claude-{state}-value-sentinel"
    settings = workspace / ".claude/settings.json"
    marker = workspace / ".claude/.unrest-managed-settings.json"
    if state == "missing":
        return secret
    settings.parent.mkdir()
    if state == "symlinked":
        external.write_bytes(f'{{"external":"{secret}"}}\n'.encode())
        settings.symlink_to(external)
    elif state == "legacy-managed":
        settings.write_bytes(b'{"permissions":{"defaultMode":"bypassPermissions"}}\n')
    elif state == "current-managed":
        settings.write_bytes(CURRENT_SETTINGS)
        marker.write_bytes(CURRENT_MARKER)
    elif state == "safe-unmanaged":
        settings.write_bytes(
            b'{"permissions":{"defaultMode":"default"},"theme":"dark"}\n'
        )
    elif state == "malformed":
        settings.write_bytes(f'{{"value":"{secret}"'.encode())
    elif state == "unsafe-unmanaged":
        settings.write_bytes(
            json.dumps(
                {
                    "permissions": {"defaultMode": "plan"},
                    "value": secret,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
    else:  # pragma: no cover - guarded by parametrization
        raise AssertionError(state)
    return secret


def _config(home: Path) -> HarnessConfig:
    bundled = Path(__file__).parents[1] / "src/unrest_harness/bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command="spawn-trap",
        validator_provider_name="claude",
        validator_acp_command="spawn-trap",
        terminal_reviewer_provider_name="claude",
        terminal_reviewer_acp_command="spawn-trap",
        capability_profile=SAFE_PROFILE,
        max_parallel_nodes=1,
    )


def _instrument_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[tuple[Path, str, Path]], list[Path]]:
    calls: list[tuple[Path, str, Path]] = []
    writes: list[Path] = []
    original_ensure = acp_runner._ensure_claude_settings
    original_write = acp_runner.atomic_write_json

    def capture_ensure(
        workspace: Path,
        provider: object,
        profile: str,
        *,
        role: str = "orchestrator",
        settings_dir: Path | None = None,
        allowed_ancestor: Path | None = None,
    ) -> None:
        calls.append(
            (
                workspace.resolve(strict=True),
                role,
                (allowed_ancestor or workspace).resolve(strict=True),
            )
        )
        original_ensure(
            workspace,
            provider,
            profile,
            role=role,  # type: ignore[arg-type]
            settings_dir=settings_dir,
            allowed_ancestor=allowed_ancestor,
        )

    def capture_write(path: Path, payload: object, **kwargs: object) -> None:
        writes.append(Path(path))
        original_write(path, payload, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(acp_runner, "_ensure_claude_settings", capture_ensure)
    monkeypatch.setattr(acp_runner, "atomic_write_json", capture_write)
    return calls, writes


def _assert_settings_result(
    workspace: Path,
    external: Path,
    state: str,
    before: dict[str, object],
    writes: list[Path],
) -> None:
    after = _settings_snapshot(workspace, external)
    assert after["workspace_identity"] == before["workspace_identity"]
    assert after["workspace_mode"] == before["workspace_mode"]
    assert after["external_hash"] == before["external_hash"]
    assert not list((workspace / ".claude").glob(".*.tmp"))

    if state in MUTATED_STATES:
        assert (after["settings_hash"], after["marker_hash"]) == CURRENT_HASHES
        assert (after["settings_mode"], after["marker_mode"]) == (0o644, 0o644)
        assert {path.name for path in writes} == {
            "settings.json",
            ".unrest-managed-settings.json",
        }
    elif state == "current-managed":
        assert after == before
        assert {path.name for path in writes} == {
            "settings.json",
            ".unrest-managed-settings.json",
        }
    else:
        assert after == before
        assert writes == []


def _seed_controller(
    config: HarnessConfig,
    workspace: Path,
    dispatcher: object,
    reviewer: object,
    task: Task,
) -> tuple[ProjectController, str]:
    store = ProjectStore(config)
    controller = ProjectController(
        config,
        dispatcher,  # type: ignore[arg-type]
        reviewer,  # type: ignore[arg-type]
        store=store,
    )
    controller.start_project("caller matrix", str(workspace))
    project_id = store.list_projects()[0].id
    contract_dir = store.ensure_contract_dir(project_id, "mission-001")
    (contract_dir / "VAL-001.md").write_text(
        "# VAL-001\n\nSurface: other.\nNeeds: none.\n"
        "Behavior: caller matrix.\nEvidence: caller outcome.\n",
        encoding="utf-8",
    )
    if task.type == "validate":
        owner = Task(
            id="w-owner",
            type="work",
            body="contract owner",
            targets=task.targets,
            skill="engineering-mission-playbook",
        )
        task = task.model_copy(update={"depends_on": [owner.id]})
        controller.submit_plan(project_id, TaskList(tasks=[owner, task]))
        task_state = store.load_task_state(project_id, "mission-001")
        task_state.set_status(owner.id, "cleared")
        store.save_task_state(project_id, "mission-001", task_state)
    else:
        controller.submit_plan(project_id, TaskList(tasks=[task]))
    return controller, project_id


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("caller", ("worker", "validator"))
def test_worker_and_validator_settings_caller_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caller: str,
    state: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o750)
    external = tmp_path / "external-settings.json"
    secret = _prepare_state(workspace, external, state)
    before = _settings_snapshot(workspace, external)
    calls, writes = _instrument_settings(monkeypatch)
    config = _config(tmp_path / "home")
    store = ProjectStore(config)
    dispatcher = ACPNodeDispatcher(config, store)
    spawned = False

    async def trap_spawn(**_kwargs: object) -> None:
        nonlocal spawned
        spawned = True
        raise SpawnTrap(f"{caller} spawn intercepted")

    monkeypatch.setattr(dispatcher.runner, "_start_worker_mcp_server", trap_spawn)
    task = Task(
        id="w1" if caller == "worker" else "v1",
        type="work" if caller == "worker" else "validate",
        body="caller matrix",
        targets=["VAL-001"],
        skill="engineering-mission-playbook" if caller == "worker" else "scrutiny-validator",
    )
    controller, project_id = _seed_controller(
        config,
        workspace,
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        task,
    )

    result = controller.advance_project(project_id, max_steps=1)
    attention = controller.store.load_attention(project_id)
    attempt = next(
        controller.store.attempts_runtime_dir(project_id, "mission-001").glob("*.json")
    )
    attempt_data = json.loads(attempt.read_text(encoding="utf-8"))

    assert result.state.state == "attention_needed"
    assert [item.kind for item in attention] == [
        "node_failed" if caller == "worker" else "node_attention"
    ]
    assert attempt_data["done"] is False
    assert len(attempt_data["report"].encode()) <= 2000
    assert secret not in attempt_data["report"]
    _assert_secret_absent(config.harness_home, secret)
    assert spawned is (state in ALLOWED_STATES)
    assert calls == [(workspace.resolve(), caller, workspace.resolve())]
    _assert_settings_result(workspace, external, state, before, writes)


@pytest.mark.parametrize("state", STATES)
def test_terminal_reviewer_settings_caller_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o750)
    external = tmp_path / "external-settings.json"
    secret = _prepare_state(workspace, external, state)
    before = _settings_snapshot(workspace, external)
    calls, writes = _instrument_settings(monkeypatch)
    config = _config(tmp_path / "home")
    store = ProjectStore(config)
    reviewer = ACPTerminalReviewer(config, store)
    spawned = False

    async def trap_spawn(**_kwargs: object) -> None:
        nonlocal spawned
        spawned = True
        raise SpawnTrap("terminal reviewer spawn intercepted")

    monkeypatch.setattr(reviewer.runner, "_start_terminal_reviewer_mcp", trap_spawn)
    task = Task(
        id="w1",
        type="work",
        body="setup",
        targets=["VAL-001"],
        skill="engineering-mission-playbook",
    )
    controller, project_id = _seed_controller(
        config,
        workspace,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                done=True,
                report="setup complete",
            )
        ),
        reviewer,
        task,
    )
    assert controller.advance_project(project_id, max_steps=1).state.state == "mission_running"

    result = controller.end_mission(project_id)
    attention = controller.store.load_attention(project_id)
    review_path = next(
        controller.store.terminal_reviews_runtime_dir(project_id, "mission-001").glob("*.json")
    )
    review = json.loads(review_path.read_text(encoding="utf-8"))

    assert result.state.state == "attention_needed"
    assert [item.kind for item in attention] == ["terminal_review"]
    assert review["done"] is False
    assert review["report"].startswith("Terminal reviewer runtime failure")
    assert len(review["report"].encode()) < 4096
    assert secret not in review["report"]
    _assert_secret_absent(config.harness_home, secret)
    assert spawned is (state in ALLOWED_STATES)
    assert calls == [(workspace.resolve(), "terminal_reviewer", workspace.resolve())]
    _assert_settings_result(workspace, external, state, before, writes)


@pytest.mark.parametrize("state", STATES)
def test_cli_orchestrator_settings_caller_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o750)
    external = tmp_path / "external-settings.json"
    secret = _prepare_state(workspace, external, state)
    before = _settings_snapshot(workspace, external)
    calls, writes = _instrument_settings(monkeypatch)
    continued = False
    original_bootstrap: Callable[..., None] = cli_module._write_bootstrap_config

    def capture_bootstrap(*args: object, **kwargs: object) -> None:
        nonlocal continued
        continued = True
        original_bootstrap(*args, **kwargs)

    monkeypatch.setattr(cli_module, "_write_bootstrap_config", capture_bootstrap)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["init", "--workspace-dir", str(workspace), "--agent", "claude"],
        env={"UNREST_HOME": str(tmp_path / "home")},
    )

    assert result.exit_code == (0 if state in ALLOWED_STATES else 1)
    if state in ALLOWED_STATES:
        assert f"Initialized v5 project workspace at {workspace}" in result.output
    else:
        assert result.output == "Error: provider settings configuration rejected\n"
    assert secret not in result.output
    _assert_secret_absent(
        workspace,
        secret,
        skip={workspace / ".claude/settings.json"},
    )
    assert continued is (state in ALLOWED_STATES)
    assert calls == (
        []
        if state == "symlinked"
        else [(workspace.resolve(), "orchestrator", workspace.resolve())]
    )
    _assert_settings_result(workspace, external, state, before, writes)
