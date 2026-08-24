"""Public mutation authority, grant custody, and restart idempotency."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.foundation_tools import FoundationTools
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff
from unrest_harness.mutation_journal import MutationJournalError
from unrest_harness.run_control import EXECUTOR_FAILURE_KEY
from unrest_harness.runtime_executor import _payload
from unrest_harness.controller import ToolError


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(path: Path) -> Path:
    path.mkdir()
    _git(path, "init")
    _git(path, "config", "user.name", "Authority Test")
    _git(path, "config", "user.email", "authority@example.test")
    (path / ".gitignore").write_text(
        "/.agents\n/.claude\n/.codex\n/.unrest\n/.unrest-runtime\n/AGENTS.md\n"
    )
    (path / "artifact.txt").write_text("before\n")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "base")
    return path


def _config(harness_home: Path) -> HarnessConfig:
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


def _tools(config: HarnessConfig) -> tuple[FoundationTools, ProjectController]:
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id, done=True, report="unused"
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    return FoundationTools(config, controller), controller


def test_workspace_mutations_replay_exactly_and_collision_precedes_events(
    tmp_path: Path, harness_home: Path
) -> None:
    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    tools, controller = _tools(config)
    project_id = controller.start_project("authority", str(repository)).projectId
    base = _git(repository, "rev-parse", "HEAD")

    first = tools.lease_workspace(
        project_id, base, ["artifact.txt"], "lease-idempotency", lease_seconds=120
    )
    restarted, _ = _tools(config)
    assert restarted.lease_workspace(
        project_id, base, ["artifact.txt"], "lease-idempotency", lease_seconds=120
    ) == first
    lease_events = repository / ".unrest" / "workspaces" / "leases"
    before = tuple(sorted(lease_events.glob("*/*.json")))
    with pytest.raises(MutationJournalError) as conflict:
        restarted.lease_workspace(
            project_id, base, ["artifact.txt"], "lease-idempotency", lease_seconds=121
        )
    assert conflict.value.code == "conflict"
    assert tuple(sorted(lease_events.glob("*/*.json"))) == before


def test_integration_requires_retained_exact_grant_and_consumes_it_once(
    tmp_path: Path, harness_home: Path
) -> None:
    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    tools, controller = _tools(config)
    project_id = controller.start_project("authority", str(repository)).projectId
    base = _git(repository, "rev-parse", "HEAD")
    leased = tools.lease_workspace(
        project_id, base, ["artifact.txt"], "lease-for-integration"
    )
    manager = tools._find_workspace(leased["workspace_id"])
    lease = manager.inspect_workspace(leased["workspace_id"])
    (Path(lease.worktree_path) / "artifact.txt").write_text("after\n")
    tools.return_workspace(lease.lease_id, "return-for-integration")
    returned = manager.inspect_workspace(lease.lease_id)
    assert returned.patch_digest is not None

    grant_id = "human-grant:integration-one"
    with pytest.raises(MutationJournalError) as missing:
        tools.integrate_workspace(lease.lease_id, grant_id, "integrate-once")
    assert missing.value.code == "unauthorized"
    assert _git(repository, "rev-parse", "HEAD") == base

    scope = {
        "expected_parent_revision": base,
        "patch_digest": returned.patch_digest,
        "workspace_id": lease.lease_id,
    }
    tools.retain_human_grant(
        project_id=project_id,
        grant_id=grant_id,
        authorized_by="human:maintainer",
        operation="integrate_workspace",
        scope=scope,
    )
    integrated = tools.integrate_workspace(lease.lease_id, grant_id, "integrate-once")
    assert integrated["state"] == "integrated"
    assert (repository / "artifact.txt").read_text() == "after\n"
    accepted = _git(repository, "rev-parse", "HEAD")

    restarted, _ = _tools(config)
    assert restarted.integrate_workspace(lease.lease_id, grant_id, "integrate-once") == integrated
    assert _git(repository, "rev-parse", "HEAD") == accepted
    with pytest.raises(MutationJournalError) as collision:
        restarted.integrate_workspace(
            lease.lease_id, "human-grant:different", "integrate-once"
        )
    assert collision.value.code == "conflict"
    assert _git(repository, "rev-parse", "HEAD") == accepted


def test_scope_mismatched_retained_grant_fails_before_parent_effect(
    tmp_path: Path, harness_home: Path
) -> None:
    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    tools, controller = _tools(config)
    project_id = controller.start_project("authority", str(repository)).projectId
    base = _git(repository, "rev-parse", "HEAD")
    leased = tools.lease_workspace(project_id, base, ["artifact.txt"], "lease-wrong-scope")
    manager = tools._find_workspace(leased["workspace_id"])
    lease = manager.inspect_workspace(leased["workspace_id"])
    (Path(lease.worktree_path) / "artifact.txt").write_text("changed\n")
    tools.return_workspace(lease.lease_id, "return-wrong-scope")
    returned = manager.inspect_workspace(lease.lease_id)
    assert returned.patch_digest is not None
    grant_id = "human-grant:wrong-scope"
    tools.retain_human_grant(
        project_id=project_id,
        grant_id=grant_id,
        authorized_by="human:maintainer",
        operation="integrate_workspace",
        scope={
            "expected_parent_revision": base,
            "patch_digest": "sha256:" + "0" * 64,
            "workspace_id": lease.lease_id,
        },
    )

    with pytest.raises(MutationJournalError) as mismatch:
        tools.integrate_workspace(lease.lease_id, grant_id, "integrate-wrong-scope")
    assert mismatch.value.code == "unauthorized"
    assert _git(repository, "rev-parse", "HEAD") == base
    assert (repository / "artifact.txt").read_text() == "before\n"


def test_tool_error_mapping_is_closed_and_private_details_survive_async_run(
    tmp_path: Path, harness_home: Path
) -> None:
    mapped_argument = _payload(ToolError("invalid_brief", "brief is empty"))
    assert mapped_argument[EXECUTOR_FAILURE_KEY]["public_error"]["error"]["code"] == "invalid_argument"
    mapped_transition = _payload(
        ToolError("invalid_task_list", "task list validation failed")
    )
    assert mapped_transition[EXECUTOR_FAILURE_KEY]["public_error"]["error"]["code"] == "invalid_transition"
    assert _payload(ToolError("not_found", "missing"))[EXECUTOR_FAILURE_KEY]["public_error"]["error"]["code"] == "not_found"

    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    tools, controller = _tools(config)
    project_id = controller.start_project("authority", str(repository)).projectId
    controller.store.ensure_contract_dir(project_id, "mission-001")
    admitted = tools.submit_run(
        "submit_plan",
        {
            "project_id": project_id,
            "task_list": {
                "tasks": [
                    {
                        "body": "invalid target",
                        "id": "work",
                        "skill": "test",
                        "targets": ["VAL-MISSING"],
                        "type": "work",
                    }
                ]
            },
        },
        "async-invalid-task-list",
    )
    terminal = tools.attach_run(admitted["run_id"])
    assert terminal["state"] == "failed"
    assert terminal["error"] == {
        "error": {"code": "invalid_transition", "message": "invalid transition"}
    }
    token = admitted["run_id"].removeprefix("run:")
    private = json.loads(
        (harness_home / ".unrest" / "runs" / token / "private" / "tool-error.json").read_text()
    )
    assert private["code"] == "invalid_task_list"
    assert private["message"] == "task list validation failed"
    assert private["details"]
