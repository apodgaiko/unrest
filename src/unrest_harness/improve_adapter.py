"""Provider-free composition of the accepted campaign improvement operations."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from .canonical_identity import canonical_json_bytes
from .evolution import (
    CampaignFreeze,
    CampaignSnapshot,
    CandidateAction,
    CandidateAttempt,
    EvaluationRecord,
    EvolutionError,
    EvolutionManager,
    ReviewOutcome,
    ReviewRecord,
)


ImprovementOperation = Literal["open", "add_candidate", "evaluate", "review", "inspect"]
_T = TypeVar("_T")


class ImprovementAdapterError(RuntimeError):
    """Stable, content-free failure from one bounded campaign operation."""

    def __init__(
        self,
        code: str,
        *,
        operation: ImprovementOperation,
        cause_code: str | None = None,
    ) -> None:
        self.code = code
        self.operation = operation
        self.cause_code = cause_code
        detail = f":{cause_code}" if cause_code is not None else ""
        super().__init__(f"{code}:{operation}{detail}")


@dataclass(frozen=True)
class ImprovementRequest:
    """Exact, restart-stable inputs for one campaign candidate."""

    campaign_id: str
    freeze: CampaignFreeze | Mapping[str, Any]
    lease_id: str
    candidate_id: str
    action: CandidateAction
    author_id: str
    evaluation_id: str
    review_id: str
    parent_candidate_id: str | None = None
    candidate_cost_steps: int = 0
    candidate_dissent_digests: Sequence[str] = ()
    evaluation_cost_steps: int = 0


@dataclass(frozen=True)
class ImprovementResult:
    """Public reviewed boundary; it intentionally carries no decision method."""

    campaign_id: str
    campaign_identity_digest: str
    campaign_digest: str
    candidate_id: str
    candidate_identity_digest: str
    candidate_digest: str
    patch_digest: str
    evaluation_id: str
    evaluation_outcome: str
    evaluation_evidence_digest: str
    evaluation_run_receipt_digest: str
    evaluation_receipt_digest: str
    review_id: str
    review_outcome: ReviewOutcome
    review_digest: str
    review_receipt_digest: str
    stage: Literal["reviewed"] = "reviewed"
    campaign_state: Literal["decision_needed"] = "decision_needed"
    operation_limit: Literal[5] = 5
    provider_effect_count: Literal[0] = 0
    network_effect_count: Literal[0] = 0
    external_effect_count: Literal[0] = 0
    later_decision_action_count: Literal[0] = 0
    schema_version: Literal[1] = 1

    def as_mapping(self) -> Mapping[str, object]:
        """Return the bounded public projection used for deterministic receipts."""

        return {
            "campaign_digest": self.campaign_digest,
            "campaign_id": self.campaign_id,
            "campaign_identity_digest": self.campaign_identity_digest,
            "campaign_state": self.campaign_state,
            "candidate_digest": self.candidate_digest,
            "candidate_id": self.candidate_id,
            "candidate_identity_digest": self.candidate_identity_digest,
            "effects": {
                "external": self.external_effect_count,
                "later_decision_action": self.later_decision_action_count,
                "network": self.network_effect_count,
                "provider": self.provider_effect_count,
            },
            "evaluation": {
                "evidence_digest": self.evaluation_evidence_digest,
                "evaluation_id": self.evaluation_id,
                "outcome": self.evaluation_outcome,
                "receipt_digest": self.evaluation_receipt_digest,
                "run_receipt_digest": self.evaluation_run_receipt_digest,
            },
            "operation_limit": self.operation_limit,
            "patch_digest": self.patch_digest,
            "review": {
                "outcome": self.review_outcome,
                "receipt_digest": self.review_receipt_digest,
                "review_digest": self.review_digest,
                "review_id": self.review_id,
            },
            "schema_version": self.schema_version,
            "stage": self.stage,
        }

    def to_json_bytes(self) -> bytes:
        """Serialize with the repository's canonical JSON encoder."""

        return canonical_json_bytes(self.as_mapping())


def _call(operation: ImprovementOperation, function: Callable[[], _T]) -> _T:
    try:
        return function()
    except EvolutionError as exc:
        raise ImprovementAdapterError(
            "operation_failed",
            operation=operation,
            cause_code=exc.code,
        ) from exc
    except Exception as exc:
        raise ImprovementAdapterError("operation_failed", operation=operation) from exc


async def _evaluate(
    manager: EvolutionManager,
    request: ImprovementRequest,
) -> EvaluationRecord:
    try:
        return await manager.evaluate_candidate(
            campaign_id=request.campaign_id,
            candidate_id=request.candidate_id,
            evaluation_id=request.evaluation_id,
            cost_steps=request.evaluation_cost_steps,
        )
    except EvolutionError as exc:
        raise ImprovementAdapterError(
            "operation_failed",
            operation="evaluate",
            cause_code=exc.code,
        ) from exc
    except Exception as exc:
        raise ImprovementAdapterError("operation_failed", operation="evaluate") from exc


async def _review(
    manager: EvolutionManager,
    request: ImprovementRequest,
) -> ReviewRecord:
    try:
        return await manager.review_candidate(
            campaign_id=request.campaign_id,
            candidate_id=request.candidate_id,
            evaluation_id=request.evaluation_id,
            review_id=request.review_id,
        )
    except EvolutionError as exc:
        raise ImprovementAdapterError(
            "operation_failed",
            operation="review",
            cause_code=exc.code,
        ) from exc
    except Exception as exc:
        raise ImprovementAdapterError("operation_failed", operation="review") from exc


def _assert_no_later_decision(snapshot: CampaignSnapshot, operation: ImprovementOperation) -> None:
    if snapshot.state != "open" or snapshot.promotions or snapshot.rollbacks:
        raise ImprovementAdapterError("later_decision_action_present", operation=operation)


def _candidate(snapshot: CampaignSnapshot, request: ImprovementRequest) -> CandidateAttempt | None:
    candidate = next(
        (item for item in snapshot.candidates if item.candidate_id == request.candidate_id),
        None,
    )
    if candidate is None:
        return None
    expected_dissent = tuple(sorted(request.candidate_dissent_digests))
    if (
        candidate.lease_id != request.lease_id
        or candidate.action != request.action
        or candidate.parent_candidate_id != request.parent_candidate_id
        or candidate.author_id != request.author_id
        or candidate.outcome != "admitted"
        or candidate.cost_steps != request.candidate_cost_steps
        or candidate.dissent_digests != expected_dissent
    ):
        raise ImprovementAdapterError("resume_mismatch", operation="add_candidate")
    return candidate


def _evaluation(snapshot: CampaignSnapshot, request: ImprovementRequest) -> EvaluationRecord | None:
    evaluation = next(
        (item for item in snapshot.evaluations if item.evaluation_id == request.evaluation_id),
        None,
    )
    if evaluation is not None and (
        evaluation.candidate_id != request.candidate_id
        or evaluation.cost_steps != request.evaluation_cost_steps
    ):
        raise ImprovementAdapterError("resume_mismatch", operation="evaluate")
    return evaluation


def _review_record(snapshot: CampaignSnapshot, request: ImprovementRequest) -> ReviewRecord | None:
    review = next(
        (item for item in snapshot.reviews if item.review_id == request.review_id),
        None,
    )
    if review is not None and (
        review.candidate_id != request.candidate_id
        or review.evaluation_id != request.evaluation_id
    ):
        raise ImprovementAdapterError("resume_mismatch", operation="review")
    return review


async def run_improvement(
    manager: EvolutionManager,
    request: ImprovementRequest,
) -> ImprovementResult:
    """Run or resume one candidate through review, then stop for a decision.

    The control flow is deliberately finite: it invokes each mutation operation
    at most once and performs one final inspection. Existing records are reused
    only when their stable identifiers and provenance match the request.
    """

    if manager.provider_runner is not None:
        raise ImprovementAdapterError("provider_runner_configured", operation="open")

    snapshot = _call(
        "open",
        lambda: manager.open_campaign(campaign_id=request.campaign_id, freeze=request.freeze),
    )
    _assert_no_later_decision(snapshot, "open")

    candidate = _candidate(snapshot, request)
    if candidate is None:
        candidate = _call(
            "add_candidate",
            lambda: manager.add_candidate(
                campaign_id=request.campaign_id,
                lease_id=request.lease_id,
                action=request.action,
                parent_candidate_id=request.parent_candidate_id,
                candidate_id=request.candidate_id,
                author_id=request.author_id,
                outcome="admitted",
                cost_steps=request.candidate_cost_steps,
                dissent_digests=request.candidate_dissent_digests,
            ),
        )

    evaluation = _evaluation(snapshot, request)
    if evaluation is None:
        evaluation = await _evaluate(manager, request)

    review = _review_record(snapshot, request)
    if review is None:
        review = await _review(manager, request)

    final = _call("inspect", lambda: manager.inspect_campaign(request.campaign_id))
    _assert_no_later_decision(final, "inspect")
    final_candidate = _candidate(final, request)
    final_evaluation = _evaluation(final, request)
    final_review = _review_record(final, request)
    if final_candidate is None or final_evaluation is None or final_review is None:
        raise ImprovementAdapterError("incomplete_reviewed_boundary", operation="inspect")
    if (
        final_candidate != candidate
        or final_evaluation != evaluation
        or final_review != review
    ):
        raise ImprovementAdapterError("resume_mismatch", operation="inspect")

    return ImprovementResult(
        campaign_id=final.campaign_id,
        campaign_identity_digest=final.campaign_identity_digest,
        campaign_digest=final.campaign_digest,
        candidate_id=final_candidate.candidate_id,
        candidate_identity_digest=final_candidate.candidate_identity_digest,
        candidate_digest=final_candidate.candidate_digest,
        patch_digest=final_candidate.patch_digest,
        evaluation_id=final_evaluation.evaluation_id,
        evaluation_outcome=final_evaluation.outcome,
        evaluation_evidence_digest=final_evaluation.evidence_digest,
        evaluation_run_receipt_digest=final_evaluation.run_receipt_digest,
        evaluation_receipt_digest=final_evaluation.receipt_digest,
        review_id=final_review.review_id,
        review_outcome=final_review.outcome,
        review_digest=final_review.review_digest,
        review_receipt_digest=final_review.receipt_digest,
    )
