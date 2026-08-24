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
from unrest_harness.mutation_journal import DurableMutationJournal, MutationJournalError
from unrest_harness.provider_sessions import ProviderSessionRequest, ProviderSessionResult
from unrest_harness.project_lock import ProjectMutationLock
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


class _FaultOnce:
    def __init__(self, boundary: str) -> None:
        self.boundary = boundary
        self.triggered = False

    def __call__(self, boundary: str) -> None:
        if boundary == self.boundary and not self.triggered:
            self.triggered = True
            raise RuntimeError("injected journal crash")


class _QueueProvider:
    def __init__(self, outputs: list[dict[str, object]]) -> None:
        self.outputs = outputs
        self.calls = 0

    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event=None,
    ) -> ProviderSessionResult:
        del cancel_event
        self.calls += 1
        output = self.outputs.pop(0)
        request.private_artifact_path.write_text(
            json.dumps(
                {
                    "output": {"parsed": output, "response_text": "private"},
                    "privacy": "private-provider-session",
                }
            )
        )
        return ProviderSessionResult(
            role=request.role,
            provider="codex",
            status="completed",
            stop_reason="end_turn",
            response_bytes=20,
            response_truncated=False,
            structured_output=True,
            adapter_exit_code=0,
            error_code=None,
        )


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
    assert not hasattr(tools, "retain_human_grant")
    assert not hasattr(tools, "controller")
    assert not hasattr(tools, "local_grant_custodian")
    custodian = controller.local_grant_custodian(project_id, "human:maintainer")
    custodian.admit(
        grant_id=grant_id,
        operation="integrate_workspace",
        scope=scope,
    )
    fault = _FaultOnce("effect_applied")
    crashing = FoundationTools(
        config,
        controller,
        mutation_journal_factory=lambda root: DurableMutationJournal(root, fault=fault),
    )
    with pytest.raises(RuntimeError, match="injected journal crash"):
        crashing.integrate_workspace(lease.lease_id, grant_id, "integrate-once")
    accepted = _git(repository, "rev-parse", "HEAD")
    integrated = tools.integrate_workspace(lease.lease_id, grant_id, "integrate-once")
    assert integrated["state"] == "integrated"
    assert (repository / "artifact.txt").read_text() == "after\n"
    assert _git(repository, "rev-parse", "HEAD") == accepted

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
    custodian = controller.local_grant_custodian(project_id, "human:maintainer")
    custodian.admit(
        grant_id=grant_id,
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


def test_async_project_lock_contention_is_public_busy_with_private_cause(
    tmp_path: Path, harness_home: Path
) -> None:
    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    tools, controller = _tools(config)
    project_id = controller.start_project("authority", str(repository)).projectId
    lock = ProjectMutationLock(controller.store.mutation_lock_path(project_id))
    assert lock.try_acquire()
    try:
        admitted = tools.submit_run(
            "end_mission",
            {"project_id": project_id},
            "async-project-busy",
        )
        terminal = tools.attach_run(admitted["run_id"])
    finally:
        lock.release()
    assert terminal["state"] == "failed"
    assert terminal["error"] == {"error": {"code": "busy", "message": "busy"}}
    token = admitted["run_id"].removeprefix("run:")
    private = json.loads(
        (harness_home / ".unrest" / "runs" / token / "private" / "tool-error.json").read_text()
    )
    assert private["code"] == "project_mutation_busy"


@pytest.mark.asyncio
async def test_evolution_provider_and_git_faults_reconcile_without_reexecution(
    tmp_path: Path, harness_home: Path
) -> None:
    repository = _repository(tmp_path / "repo")
    config = _config(harness_home)
    _, controller = _tools(config)
    project_id = controller.start_project("evolution authority", str(repository)).projectId
    provider = _QueueProvider(
        [
            {"outcome": "completed_pass", "suspected_reward_hack": False},
            {"outcome": "approve", "dissent_digests": []},
        ]
    )
    normal = FoundationTools(
        config,
        controller,
        evolution_provider_runner=provider,
    )
    base = _git(repository, "rev-parse", "HEAD")
    lease_summary = normal.lease_workspace(
        project_id, base, ["artifact.txt"], "evolution-lease"
    )
    workspace = normal._find_workspace(lease_summary["workspace_id"])
    lease = workspace.inspect_workspace(lease_summary["workspace_id"])
    (Path(lease.worktree_path) / "artifact.txt").write_text("candidate\n")
    normal.return_workspace(lease.lease_id, "evolution-return")
    campaign = normal.open_campaign(
        project_id,
        "sha256:" + "a" * 64,
        "workload:test",
        "evaluator:test",
        "reviewer:test",
        {"max_steps": 10, "timeout_seconds": 60},
        7,
        "campaign-open",
    )
    campaign_id = campaign["campaign_id"]
    candidate_summary = normal.add_candidate(
        campaign_id,
        lease.lease_id,
        "initial",
        "candidate-add",
    )
    candidate_id = candidate_summary["candidate_ids"][0]

    evaluation_fault = _FaultOnce("effect_applied")
    crashing_evaluation = FoundationTools(
        config,
        controller,
        evolution_provider_runner=provider,
        mutation_journal_factory=lambda root: DurableMutationJournal(
            root, fault=evaluation_fault
        ),
    )
    with pytest.raises(RuntimeError, match="injected journal crash"):
        await crashing_evaluation.evaluate_candidate(
            campaign_id, candidate_id, "evaluation-once"
        )
    assert provider.calls == 1
    await normal.evaluate_candidate(campaign_id, candidate_id, "evaluation-once")
    assert provider.calls == 1

    review_fault = _FaultOnce("effect_applied")
    crashing_review = FoundationTools(
        config,
        controller,
        evolution_provider_runner=provider,
        mutation_journal_factory=lambda root: DurableMutationJournal(
            root, fault=review_fault
        ),
    )
    with pytest.raises(RuntimeError, match="injected journal crash"):
        await crashing_review.review_candidate(campaign_id, candidate_id, "review-once")
    assert provider.calls == 2
    await normal.review_candidate(campaign_id, candidate_id, "review-once")
    assert provider.calls == 2

    manager = normal._find_campaign(campaign_id)
    snapshot = manager.inspect_campaign(campaign_id)
    candidate = next(item for item in snapshot.candidates if item.candidate_id == candidate_id)
    evaluation = next(item for item in snapshot.evaluations if item.candidate_id == candidate_id)
    review = next(item for item in snapshot.reviews if item.candidate_id == candidate_id)
    promotion_scope = {
        "campaign_id": campaign_id,
        "candidate_digest": candidate.candidate_digest,
        "candidate_id": candidate_id,
        "evaluation_receipt_digest": evaluation.receipt_digest,
        "expected_predecessor_revision": snapshot.freeze.accepted_revision,
        "lease_id": candidate.lease_id,
        "patch_digest": candidate.patch_digest,
        "review_receipt_digest": review.receipt_digest,
    }
    custodian = controller.local_grant_custodian(project_id, "human:maintainer")
    custodian.admit(
        grant_id="human-grant:promote-fault",
        operation="promote_candidate",
        scope=promotion_scope,
    )
    promotion_fault = _FaultOnce("effect_applied")
    crashing_promotion = FoundationTools(
        config,
        controller,
        evolution_provider_runner=provider,
        mutation_journal_factory=lambda root: DurableMutationJournal(
            root, fault=promotion_fault
        ),
    )
    with pytest.raises(RuntimeError, match="injected journal crash"):
        crashing_promotion.promote_candidate(
            campaign_id,
            candidate_id,
            "human-grant:promote-fault",
            "promotion-once",
        )
    accepted = _git(repository, "rev-parse", "HEAD")
    promoted = normal.promote_candidate(
        campaign_id,
        candidate_id,
        "human-grant:promote-fault",
        "promotion-once",
    )
    assert _git(repository, "rev-parse", "HEAD") == accepted

    promoted_snapshot = manager.inspect_campaign(campaign_id)
    promotion = promoted_snapshot.promotions[-1]
    assert promotion.promotion_receipt_digest == promoted["receipt_id"]
    rollback_scope = {
        "campaign_id": campaign_id,
        "expected_current_revision": promotion.accepted_revision,
        "promotion_id": promotion.promotion_id,
        "promotion_receipt_id": promotion.promotion_receipt_digest,
        "rollback_target_revision": promotion.predecessor_revision,
    }
    custodian.admit(
        grant_id="human-grant:rollback-fault",
        operation="rollback_promotion",
        scope=rollback_scope,
    )
    rollback_fault = _FaultOnce("effect_applied")
    crashing_rollback = FoundationTools(
        config,
        controller,
        evolution_provider_runner=provider,
        mutation_journal_factory=lambda root: DurableMutationJournal(
            root, fault=rollback_fault
        ),
    )
    with pytest.raises(RuntimeError, match="injected journal crash"):
        crashing_rollback.rollback_promotion(
            campaign_id,
            promotion.promotion_receipt_digest,
            "human-grant:rollback-fault",
            "rollback-once",
        )
    restored = _git(repository, "rev-parse", "HEAD")
    normal.rollback_promotion(
        campaign_id,
        promotion.promotion_receipt_digest,
        "human-grant:rollback-fault",
        "rollback-once",
    )
    assert restored == promotion.predecessor_revision
    assert _git(repository, "rev-parse", "HEAD") == restored
