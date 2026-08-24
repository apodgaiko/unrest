from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from unrest_harness.evolution import (
    CampaignFreeze,
    EvolutionError,
    EvolutionManager,
    HumanPromotionGrant,
    HumanRollbackGrant,
)
from unrest_harness.provider_sessions import ProviderSessionRequest, ProviderSessionResult
from unrest_harness.workspaces import ResourceBudget, WorkspaceManager


def _sha(character: str) -> str:
    return "sha256:" + character * 64


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Evolution Test")
    _git(root, "config", "user.email", "evolution@example.test")
    (root / "README.md").write_text("base\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-m", "base")
    return root


def _freeze(repository: Path) -> CampaignFreeze:
    return CampaignFreeze(
        accepted_revision=_git(repository, "rev-parse", "HEAD"),
        accepted_working_point_digest=_sha("a"),
        workload_digest=_sha("b"),
        oracle_digest=_sha("c"),
        author_policy_digest=_sha("d"),
        evaluator_policy_digest=_sha("e"),
        reviewer_policy_digest=_sha("f"),
        capability_policy_digest=_sha("1"),
        provider_configuration_digest=_sha("2"),
        route_profile_digest=_sha("3"),
        context_digest=_sha("4"),
        environment_digest=_sha("5"),
        secret_set_version_id="secret-set:test:v1",
        author_id="worker:evolution-author",
        evaluator_id="validator:independent-evaluator",
        reviewer_id="reviewer:independent-reviewer",
        budget_steps=20,
        seed=7,
        stopping_rule_digest=_sha("6"),
        promotion_rule_digest=_sha("7"),
        protected_paths=(".git", ".unrest", ".unrest-runtime"),
    )


class QueueProvider:
    def __init__(self, outputs: list[dict[str, Any]]) -> None:
        self.outputs = outputs
        self.requests: list[ProviderSessionRequest] = []

    async def run(self, request: ProviderSessionRequest, *, cancel_event=None):
        self.requests.append(request)
        output = self.outputs.pop(0)
        request.private_artifact_path.write_text(
            json.dumps(
                {
                    "output": {"parsed": output, "response_text": "private"},
                    "privacy": "private-provider-session",
                }
            ),
            encoding="utf-8",
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


def _candidate(
    repository: Path,
    manager: EvolutionManager,
    *,
    lease_id: str = "lease:candidate-one",
    filename: str = "candidate.txt",
    content: str = "candidate\n",
    action: str = "original",
    parent: str | None = None,
):
    workspace = manager.workspace_manager
    lease = workspace.lease_workspace(
        base_revision=_git(repository, "rev-parse", "HEAD"),
        owner_id="worker:evolution-author",
        declared_write_paths=(filename,),
        capability_policy_digest=_sha("1"),
        duration_seconds=600,
        lease_id=lease_id,
        resource_budget=ResourceBudget(max_patch_bytes=100_000),
    )
    Path(lease.worktree_path, filename).write_text(content, encoding="utf-8")
    returned = workspace.return_workspace(lease.lease_id)
    assert returned.patch_digest is not None
    return manager.add_candidate(
        campaign_id="campaign:test",
        lease_id=lease.lease_id,
        action=action,  # type: ignore[arg-type]
        parent_candidate_id=parent,
        author_id="worker:evolution-author",
    )


def _manager(
    repository: Path,
    *,
    provider: QueueProvider | None = None,
    validation=None,
) -> EvolutionManager:
    workspace = WorkspaceManager(repository, custody_root_id="evolution-test")
    manager = EvolutionManager(
        repository,
        provider_runner=provider,
        workspace_manager=workspace,
        validation=validation,
    )
    manager.open_campaign(campaign_id="campaign:test", freeze=_freeze(repository))
    return manager


def test_campaign_freeze_is_complete_immutable_and_restartable(repository: Path) -> None:
    manager = _manager(repository)
    opened = manager.inspect_campaign("campaign:test")
    restarted = EvolutionManager(
        repository,
        workspace_manager=WorkspaceManager(repository, custody_root_id="evolution-test"),
    )
    assert restarted.inspect_campaign("campaign:test") == opened
    assert opened.denominator == 0
    assert opened.campaign_identity_digest.startswith("sha256:")

    for field in CampaignFreeze.__dataclass_fields__:
        value = getattr(opened.freeze, field)
        if field == "budget_steps":
            changed = replace(opened.freeze, budget_steps=value + 1)
        elif field == "seed":
            changed = replace(opened.freeze, seed=value + 1)
        elif field == "protected_paths":
            changed = replace(opened.freeze, protected_paths=(*value, "secrets"))
        elif field == "accepted_revision":
            changed = replace(opened.freeze, accepted_revision="0" * 40)
        elif field in {"author_id", "evaluator_id", "reviewer_id", "secret_set_version_id"}:
            changed = replace(opened.freeze, **{field: value + "-changed"})  # type: ignore[arg-type]
        else:
            changed = replace(opened.freeze, **{field: _sha("8")})  # type: ignore[arg-type]
        with pytest.raises(EvolutionError):
            manager.open_campaign(campaign_id="campaign:test", freeze=changed)

    collision = replace(opened.freeze, reviewer_id=opened.freeze.evaluator_id)
    with pytest.raises(EvolutionError, match="authority_collision"):
        manager.open_campaign(campaign_id="campaign:collision", freeze=collision)


def test_genealogy_retains_failures_retries_and_rejections(repository: Path) -> None:
    manager = _manager(repository)
    parent = _candidate(repository, manager)
    retry = _candidate(
        repository,
        manager,
        lease_id="lease:candidate-retry",
        filename="retry.txt",
        content="retry\n",
        action="retry",
        parent=parent.candidate_id,
    )
    assert retry.parent_candidate_id == parent.candidate_id

    with pytest.raises(EvolutionError, match="candidate_parent_not_found"):
        manager.add_candidate(
            campaign_id="campaign:test",
            lease_id="lease:missing",
            action="edit",
            parent_candidate_id="candidate:missing",
            author_id="worker:evolution-author",
        )
    inspected = manager.inspect_campaign("campaign:test")
    assert inspected.denominator == 3
    assert [item.outcome for item in inspected.candidates] == ["admitted", "admitted", "rejected"]
    assert sum(item.cost_steps for item in inspected.candidates) == 0
    assert EvolutionManager(
        repository,
        workspace_manager=WorkspaceManager(repository, custody_root_id="evolution-test"),
    ).inspect_campaign("campaign:test").candidates == inspected.candidates


@pytest.mark.asyncio
async def test_independent_evaluation_review_and_reward_hack_fail_closed(repository: Path) -> None:
    provider = QueueProvider(
        [
            {"outcome": "completed_pass", "suspected_reward_hack": False},
            {"outcome": "approve", "dissent_digests": []},
            {"outcome": "completed_pass", "suspected_reward_hack": True},
            {"outcome": "approve", "dissent_digests": []},
        ]
    )
    manager = _manager(repository, provider=provider)
    first = _candidate(repository, manager)
    evaluation = await manager.evaluate_candidate(
        campaign_id="campaign:test",
        candidate_id=first.candidate_id,
        evaluation_id="evaluation:first",
        cost_steps=3,
    )
    review = await manager.review_candidate(
        campaign_id="campaign:test",
        candidate_id=first.candidate_id,
        evaluation_id=evaluation.evaluation_id,
        review_id="review:first",
    )
    assert evaluation.outcome == "completed_pass"
    assert review.outcome == "approve"
    assert review.complete_denominator == 1
    assert evaluation.receipt_digest.startswith("sha256:")
    assert review.receipt_digest.startswith("sha256:")

    second = _candidate(
        repository,
        manager,
        lease_id="lease:candidate-two",
        filename="two.txt",
        content="two\n",
        action="edit",
        parent=first.candidate_id,
    )
    hacked = await manager.evaluate_candidate(
        campaign_id="campaign:test",
        candidate_id=second.candidate_id,
        evaluation_id="evaluation:hacked",
    )
    hacked_review = await manager.review_candidate(
        campaign_id="campaign:test",
        candidate_id=second.candidate_id,
        evaluation_id=hacked.evaluation_id,
        review_id="review:hacked",
    )
    assert hacked.outcome == "suspected_reward_hack"
    assert hacked.non_improving is True
    assert hacked_review.outcome == "inconclusive"
    assert hacked_review.complete_denominator == 2

    public_events = b"".join(
        path.read_bytes()
        for path in (repository / ".unrest" / "evolution" / "campaigns" / "test").glob("*.json")
    )
    assert b'"response_text":"private"' not in public_events
    assert [request.role for request in provider.requests] == [
        "independent_evaluator",
        "independent_reviewer",
        "independent_evaluator",
        "independent_reviewer",
    ]


@pytest.mark.asyncio
async def test_missing_provider_is_non_improving_and_cannot_promote(repository: Path) -> None:
    manager = _manager(repository)
    candidate = _candidate(repository, manager)
    evaluation = await manager.evaluate_candidate(
        campaign_id="campaign:test",
        candidate_id=candidate.candidate_id,
        evaluation_id="evaluation:missing",
    )
    assert evaluation.outcome == "evaluator_error"
    assert evaluation.non_improving is True


async def _approved_candidate(repository: Path):
    provider = QueueProvider(
        [
            {"outcome": "completed_pass", "suspected_reward_hack": False},
            {"outcome": "approve", "dissent_digests": []},
        ]
    )
    manager = _manager(repository, provider=provider, validation=lambda _: True)
    candidate = _candidate(repository, manager)
    evaluation = await manager.evaluate_candidate(
        campaign_id="campaign:test",
        candidate_id=candidate.candidate_id,
        evaluation_id="evaluation:approved",
    )
    review = await manager.review_candidate(
        campaign_id="campaign:test",
        candidate_id=candidate.candidate_id,
        evaluation_id=evaluation.evaluation_id,
        review_id="review:approved",
    )
    grant = HumanPromotionGrant(
        grant_id="human-grant:promote-one",
        authorized_by="human:maintainer",
        campaign_id="campaign:test",
        candidate_id=candidate.candidate_id,
        candidate_digest=candidate.candidate_digest,
        expected_predecessor_revision=_freeze(repository).accepted_revision,
        lease_id=candidate.lease_id,
        patch_digest=candidate.patch_digest,
        evaluation_receipt_digest=evaluation.receipt_digest,
        review_receipt_digest=review.receipt_digest,
    )
    return manager, candidate, grant


@pytest.mark.asyncio
async def test_human_promotion_is_exact_atomic_and_idempotent(repository: Path) -> None:
    manager, candidate, grant = await _approved_candidate(repository)
    predecessor = grant.expected_predecessor_revision
    wrong = replace(grant, candidate_digest=_sha("9"), grant_id="human-grant:wrong")
    with pytest.raises(EvolutionError, match="promotion_candidate_mismatch"):
        manager.promote_candidate(wrong)
    assert _git(repository, "rev-parse", "HEAD") == predecessor

    promoted = manager.promote_candidate(grant)
    assert promoted.predecessor_revision == predecessor
    assert promoted.accepted_revision == _git(repository, "rev-parse", "HEAD")
    assert promoted.promotion_receipt_digest is not None
    assert promoted.effect_count == 1
    assert (repository / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"
    assert manager.promote_candidate(grant) == promoted
    assert manager.inspect_campaign("campaign:test").state == "promoted"

    stale = replace(grant, grant_id="human-grant:stale", candidate_id=candidate.candidate_id)
    with pytest.raises(EvolutionError, match="campaign_not_open"):
        manager.promote_candidate(stale)


@pytest.mark.asyncio
async def test_post_accept_receipt_failure_reconciles_without_reapply(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _, grant = await _approved_candidate(repository)
    original = manager._promotion_receipt
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise EvolutionError("injected_receipt_failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager, "_promotion_receipt", fail_once)
    with pytest.raises(EvolutionError, match="injected_receipt_failure"):
        manager.promote_candidate(grant)
    accepted = _git(repository, "rev-parse", "HEAD")
    partial = manager.inspect_campaign("campaign:test").promotions[0]
    assert partial.state == "effect_applied"
    assert partial.effect_count == 1

    completed = manager.promote_candidate(grant)
    assert completed.accepted_revision == accepted
    assert completed.effect_count == 1
    assert calls == 2


@pytest.mark.asyncio
async def test_exact_human_rollback_and_receipt_recovery(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _, promotion_grant = await _approved_candidate(repository)
    promotion = manager.promote_candidate(promotion_grant)
    wrong = HumanRollbackGrant(
        grant_id="human-grant:rollback-wrong",
        authorized_by="human:maintainer",
        campaign_id="campaign:test",
        promotion_id=promotion.promotion_id,
        expected_current_revision=promotion.accepted_revision,
        rollback_target_revision="0" * 40,
    )
    with pytest.raises(EvolutionError, match="rollback_target_mismatch"):
        manager.rollback_promotion(wrong)
    assert _git(repository, "rev-parse", "HEAD") == promotion.accepted_revision

    grant = replace(
        wrong,
        grant_id="human-grant:rollback-exact",
        rollback_target_revision=promotion.predecessor_revision,
    )
    original = manager._rollback_receipt
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise EvolutionError("injected_rollback_receipt_failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager, "_rollback_receipt", fail_once)
    with pytest.raises(EvolutionError, match="injected_rollback_receipt_failure"):
        manager.rollback_promotion(grant, validate=lambda _: True)
    partial = manager.inspect_campaign("campaign:test").rollbacks[0]
    assert partial.state == "effect_applied"
    assert _git(repository, "rev-parse", "HEAD") == promotion.predecessor_revision

    rolled_back = manager.rollback_promotion(grant, validate=lambda _: True)
    assert rolled_back.predecessor_revision == promotion.predecessor_revision
    assert _git(repository, "rev-parse", "HEAD") == promotion.predecessor_revision
    assert rolled_back.rollback_receipt_digest is not None
    assert rolled_back.effect_count == 1
    assert calls == 2
    assert manager.rollback_promotion(grant) == rolled_back
    assert manager.inspect_campaign("campaign:test").state == "rolled_back"


@pytest.mark.asyncio
async def test_rollback_validation_failure_preserves_current(repository: Path) -> None:
    manager, _, promotion_grant = await _approved_candidate(repository)
    promotion = manager.promote_candidate(promotion_grant)
    grant = HumanRollbackGrant(
        grant_id="human-grant:rollback-invalid",
        authorized_by="human:maintainer",
        campaign_id="campaign:test",
        promotion_id=promotion.promotion_id,
        expected_current_revision=promotion.accepted_revision,
        rollback_target_revision=promotion.predecessor_revision,
    )
    with pytest.raises(EvolutionError, match="rollback_validation_failed"):
        manager.rollback_promotion(grant, validate=lambda _: False)
    assert _git(repository, "rev-parse", "HEAD") == promotion.accepted_revision
