from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
from typing import Any

import pytest

from unrest_harness.evolution import CampaignFreeze, EvolutionManager
from unrest_harness.improve_adapter import (
    ImprovementAdapterError,
    ImprovementRequest,
    run_improvement,
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
    _git(root, "config", "user.name", "Improve Adapter Test")
    _git(root, "config", "user.email", "improve@example.test")
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
        secret_set_version_id="secret-set:improve:v1",
        author_id="worker:improve-author",
        evaluator_id="validator:improve-evaluator",
        reviewer_id="reviewer:improve-reviewer",
        budget_steps=20,
        seed=13,
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
        request.private_artifact_path.write_text(
            json.dumps(
                {
                    "output": {"parsed": self.outputs.pop(0), "response_text": "private"},
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


def _manager(
    repository: Path,
    *,
    provider: QueueProvider | None = None,
) -> EvolutionManager:
    workspace = WorkspaceManager(repository, custody_root_id="improve-adapter-test")
    return EvolutionManager(
        repository,
        provider_runner=provider,
        workspace_manager=workspace,
    )


def _request(
    repository: Path,
    manager: EvolutionManager,
    *,
    content: str = "private candidate source token\n",
) -> ImprovementRequest:
    lease = manager.workspace_manager.lease_workspace(
        base_revision=_git(repository, "rev-parse", "HEAD"),
        owner_id="worker:improve-author",
        declared_write_paths=("candidate.txt",),
        capability_policy_digest=_sha("1"),
        duration_seconds=600,
        lease_id="lease:improve-candidate",
        resource_budget=ResourceBudget(max_patch_bytes=100_000),
    )
    Path(lease.worktree_path, "candidate.txt").write_text(content, encoding="utf-8")
    manager.workspace_manager.return_workspace(lease.lease_id)
    return ImprovementRequest(
        campaign_id="campaign:improve",
        freeze=_freeze(repository),
        lease_id=lease.lease_id,
        candidate_id="candidate:improve",
        action="original",
        author_id="worker:improve-author",
        evaluation_id="evaluation:improve",
        review_id="review:improve",
        candidate_cost_steps=2,
        evaluation_cost_steps=3,
    )


def _event_kinds(repository: Path) -> list[str]:
    root = repository / ".unrest" / "evolution" / "campaigns" / "improve"
    return [json.loads(path.read_text(encoding="utf-8"))["event_kind"] for path in sorted(root.glob("*.json"))]


@pytest.mark.asyncio
async def test_nominal_provider_free_open_add_evaluate_review_inspect(repository: Path) -> None:
    manager = _manager(repository)
    request = _request(repository, manager)

    result = await run_improvement(manager, request)

    snapshot = manager.inspect_campaign(request.campaign_id)
    assert _event_kinds(repository) == [
        "campaign_opened",
        "candidate_added",
        "evaluation_started",
        "evaluation_completed",
        "review_started",
        "review_completed",
    ]
    assert len(snapshot.candidates) == len(snapshot.evaluations) == len(snapshot.reviews) == 1
    assert result.evaluation_outcome == "evaluator_error"
    assert result.review_outcome == "inconclusive"


@pytest.mark.asyncio
async def test_success_stops_at_reviewed_decision_needed(repository: Path) -> None:
    manager = _manager(repository)
    request = _request(repository, manager)

    result = await run_improvement(manager, request)

    assert result.stage == "reviewed"
    assert result.campaign_state == "decision_needed"
    assert result.operation_limit == 5
    assert result.later_decision_action_count == 0


@pytest.mark.asyncio
async def test_resume_from_persisted_candidate(repository: Path) -> None:
    manager = _manager(repository)
    request = _request(repository, manager)
    manager.open_campaign(campaign_id=request.campaign_id, freeze=request.freeze)
    candidate = manager.add_candidate(
        campaign_id=request.campaign_id,
        lease_id=request.lease_id,
        action=request.action,
        candidate_id=request.candidate_id,
        author_id=request.author_id,
        cost_steps=request.candidate_cost_steps,
    )

    restarted = _manager(repository)
    result = await run_improvement(restarted, request)

    snapshot = restarted.inspect_campaign(request.campaign_id)
    assert result.candidate_identity_digest == candidate.candidate_identity_digest
    assert [item.candidate_id for item in snapshot.candidates] == [request.candidate_id]
    assert [item.evaluation_id for item in snapshot.evaluations] == [request.evaluation_id]
    assert [item.review_id for item in snapshot.reviews] == [request.review_id]


@pytest.mark.asyncio
async def test_operation_failure_is_stable_and_bounded(repository: Path) -> None:
    manager = _manager(repository)
    request = ImprovementRequest(
        campaign_id="campaign:improve",
        freeze=_freeze(repository),
        lease_id="invalid",
        candidate_id="candidate:improve",
        action="original",
        author_id="worker:improve-author",
        evaluation_id="evaluation:improve",
        review_id="review:improve",
    )

    with pytest.raises(ImprovementAdapterError) as caught:
        await run_improvement(manager, request)

    assert caught.value.code == "operation_failed"
    assert caught.value.operation == "add_candidate"
    assert caught.value.cause_code == "invalid_lease_id"
    snapshot = manager.inspect_campaign(request.campaign_id)
    assert snapshot.candidates == ()
    assert snapshot.evaluations == ()
    assert snapshot.reviews == ()


@pytest.mark.asyncio
async def test_resume_preserves_existing_review_outcome(repository: Path) -> None:
    provider = QueueProvider(
        [
            {"outcome": "completed_pass", "suspected_reward_hack": False},
            {"outcome": "reject", "dissent_digests": []},
        ]
    )
    seeded = _manager(repository, provider=provider)
    request = _request(repository, seeded)
    seeded.open_campaign(campaign_id=request.campaign_id, freeze=request.freeze)
    seeded.add_candidate(
        campaign_id=request.campaign_id,
        lease_id=request.lease_id,
        action=request.action,
        candidate_id=request.candidate_id,
        author_id=request.author_id,
        cost_steps=request.candidate_cost_steps,
    )
    evaluation = await seeded.evaluate_candidate(
        campaign_id=request.campaign_id,
        candidate_id=request.candidate_id,
        evaluation_id=request.evaluation_id,
        cost_steps=request.evaluation_cost_steps,
    )
    review = await seeded.review_candidate(
        campaign_id=request.campaign_id,
        candidate_id=request.candidate_id,
        evaluation_id=evaluation.evaluation_id,
        review_id=request.review_id,
    )
    assert review.outcome == "reject"
    provider_calls_before_resume = len(provider.requests)

    result = await run_improvement(_manager(repository), request)

    assert result.review_outcome == "reject"
    assert len(provider.requests) == provider_calls_before_resume
    assert result.provider_effect_count == 0


@pytest.mark.asyncio
async def test_serialization_is_canonical_and_resume_stable(repository: Path) -> None:
    manager = _manager(repository)
    request = _request(repository, manager)

    first = await run_improvement(manager, request)
    sequence = manager.inspect_campaign(request.campaign_id).sequence
    second = await run_improvement(_manager(repository), request)

    assert second == first
    assert second.to_json_bytes() == first.to_json_bytes()
    assert json.loads(first.to_json_bytes()) == first.as_mapping()
    assert manager.inspect_campaign(request.campaign_id).sequence == sequence


@pytest.mark.asyncio
async def test_public_result_preserves_provenance_without_private_content(repository: Path) -> None:
    manager = _manager(repository)
    private_content = "private candidate source token\n"
    request = _request(repository, manager, content=private_content)

    result = await run_improvement(manager, request)

    snapshot = manager.inspect_campaign(request.campaign_id)
    candidate = snapshot.candidates[0]
    evaluation = snapshot.evaluations[0]
    review = snapshot.reviews[0]
    assert result.campaign_digest == snapshot.campaign_digest
    assert result.candidate_identity_digest == candidate.candidate_identity_digest
    assert result.evaluation_receipt_digest == evaluation.receipt_digest
    assert result.review_receipt_digest == review.receipt_digest
    assert private_content.strip().encode() not in result.to_json_bytes()
    public_events = b"".join(
        path.read_bytes()
        for path in sorted(
            (repository / ".unrest" / "evolution" / "campaigns" / "improve").glob("*.json")
        )
    )
    assert private_content.strip().encode() not in public_events


@pytest.mark.asyncio
async def test_no_later_decision_network_or_external_effect(repository: Path, monkeypatch) -> None:
    manager = _manager(repository)
    request = _request(repository, manager)
    original_head = _git(repository, "rev-parse", "HEAD")

    def unexpected_network(*_args, **_kwargs):
        raise AssertionError("network effect attempted")

    monkeypatch.setattr(socket.socket, "connect", unexpected_network)
    result = await run_improvement(manager, request)

    snapshot = manager.inspect_campaign(request.campaign_id)
    assert snapshot.state == "open"
    assert snapshot.promotions == ()
    assert snapshot.rollbacks == ()
    assert _git(repository, "rev-parse", "HEAD") == original_head
    assert result.provider_effect_count == 0
    assert result.network_effect_count == 0
    assert result.external_effect_count == 0
    assert result.later_decision_action_count == 0


@pytest.mark.asyncio
async def test_configured_provider_is_rejected_before_any_campaign_operation(repository: Path) -> None:
    provider = QueueProvider([])
    manager = _manager(repository, provider=provider)
    request = _request(repository, manager)

    with pytest.raises(ImprovementAdapterError, match="provider_runner_configured"):
        await run_improvement(manager, request)

    assert provider.requests == []
    campaign_root = repository / ".unrest" / "evolution" / "campaigns" / "improve"
    assert not campaign_root.exists()
