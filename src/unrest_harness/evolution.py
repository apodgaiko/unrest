"""Offline evolution campaigns with human-only promotion and rollback.

Campaign inputs and candidate genealogy are immutable public records.  Provider
responses stay in a private artifact tree; only bounded outcome metadata and
identity digests cross into campaign events.  Git effects are delegated to the
workspace parent authority and are bracketed by durable transaction events so
restart reconciliation never applies an effect twice.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
from typing import Any, Iterator, Literal, Protocol, cast
import uuid

from .accepted_point_authority import (
    AcceptedPointAuthorityError,
    _AcceptedPointCapability,
    _require_accepted_point_capability,
)
from .canonical_identity import (
    IdentityRecord,
    canonical_json_bytes,
    construct_identity,
    verify_canonical_json_bytes,
)
from .foundation_store import CustodyActor, FoundationStore
from .provider_sessions import ProviderSessionRequest, ProviderSessionResult
from .receipts import ReceiptRecord, construct_receipt, load_receipt_catalog
from .workspaces import (
    HumanIntegrationGrant,
    IntegrationResult,
    WorkspaceError,
    WorkspaceManager,
)


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_PUBLIC_ID = re.compile(r"^[a-z][a-z0-9-]*:[a-z0-9][a-z0-9-]*$")
_LEASE_ID = re.compile(r"^lease:[a-z0-9-]+$")
_EVENT_PREFIX = b"unrest.evolution-event.v1\0"
_PROTECTED_PATHS = (".git", ".unrest", ".unrest-runtime")

CandidateAction = Literal["original", "edit", "rebase", "retry"]
CandidateOutcome = Literal[
    "admitted",
    "rejected",
    "rework",
    "failed",
    "cancelled",
    "inconclusive",
    "budget_exhausted",
]
EvaluationOutcome = Literal[
    "completed_pass",
    "completed_fail",
    "contaminated",
    "suspected_reward_hack",
    "evaluator_error",
    "infrastructure_error",
    "policy_rejected",
    "skipped",
    "stale_input",
    "timed_out",
    "cancelled",
]
ReviewOutcome = Literal["approve", "reject", "rework", "inconclusive", "dissent", "cancelled"]

_CANDIDATE_OUTCOMES = frozenset(
    {"admitted", "rejected", "rework", "failed", "cancelled", "inconclusive", "budget_exhausted"}
)
_EVALUATION_OUTCOMES = frozenset(
    {
        "completed_pass",
        "completed_fail",
        "contaminated",
        "suspected_reward_hack",
        "evaluator_error",
        "infrastructure_error",
        "policy_rejected",
        "skipped",
        "stale_input",
        "timed_out",
        "cancelled",
    }
)
_REVIEW_OUTCOMES = frozenset({"approve", "reject", "rework", "inconclusive", "dissent", "cancelled"})


class EvolutionError(RuntimeError):
    """Stable public failure that never embeds provider or source content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProviderRunner(Protocol):
    async def run(
        self,
        request: ProviderSessionRequest,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> ProviderSessionResult: ...


@dataclass(frozen=True)
class CampaignFreeze:
    accepted_revision: str
    accepted_working_point_digest: str
    workload_digest: str
    oracle_digest: str
    author_policy_digest: str
    evaluator_policy_digest: str
    reviewer_policy_digest: str
    capability_policy_digest: str
    provider_configuration_digest: str
    route_profile_digest: str
    context_digest: str
    environment_digest: str
    secret_set_version_id: str
    author_id: str
    evaluator_id: str
    reviewer_id: str
    budget_steps: int
    seed: int
    stopping_rule_digest: str
    promotion_rule_digest: str
    protected_paths: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CampaignFreeze:
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != expected:
            raise EvolutionError("invalid_campaign_freeze")
        paths = value.get("protected_paths")
        if not isinstance(paths, (list, tuple)) or not all(isinstance(item, str) for item in paths):
            raise EvolutionError("invalid_campaign_freeze")
        try:
            return cls(
                **{
                    **{key: value[key] for key in expected - {"protected_paths"}},
                    "protected_paths": tuple(paths),
                }
            )
        except TypeError as exc:
            raise EvolutionError("invalid_campaign_freeze") from exc

    def validate(self) -> None:
        string_fields = (
            self.accepted_revision,
            self.accepted_working_point_digest,
            self.workload_digest,
            self.oracle_digest,
            self.author_policy_digest,
            self.evaluator_policy_digest,
            self.reviewer_policy_digest,
            self.capability_policy_digest,
            self.provider_configuration_digest,
            self.route_profile_digest,
            self.context_digest,
            self.environment_digest,
            self.secret_set_version_id,
            self.author_id,
            self.evaluator_id,
            self.reviewer_id,
            self.stopping_rule_digest,
            self.promotion_rule_digest,
        )
        if not all(isinstance(item, str) for item in string_fields):
            raise EvolutionError("invalid_campaign_freeze")
        digest_fields = (
            self.accepted_working_point_digest,
            self.workload_digest,
            self.oracle_digest,
            self.author_policy_digest,
            self.evaluator_policy_digest,
            self.reviewer_policy_digest,
            self.capability_policy_digest,
            self.provider_configuration_digest,
            self.route_profile_digest,
            self.context_digest,
            self.environment_digest,
            self.stopping_rule_digest,
            self.promotion_rule_digest,
        )
        if _REVISION.fullmatch(self.accepted_revision) is None or any(
            _DIGEST.fullmatch(item) is None for item in digest_fields
        ):
            raise EvolutionError("invalid_campaign_freeze")
        if not re.fullmatch(r"^secret-set:[a-z0-9-]+:v[1-9][0-9]*$", self.secret_set_version_id):
            raise EvolutionError("invalid_campaign_freeze")
        if (
            not self.author_id
            or not self.evaluator_id
            or not self.reviewer_id
            or len({self.author_id, self.evaluator_id, self.reviewer_id}) != 3
        ):
            raise EvolutionError("authority_collision")
        if (
            isinstance(self.budget_steps, bool)
            or not isinstance(self.budget_steps, int)
            or not 0 < self.budget_steps <= 9_007_199_254_740_991
            or isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or not -9_007_199_254_740_991 <= self.seed <= 9_007_199_254_740_991
        ):
            raise EvolutionError("invalid_campaign_freeze")
        if not isinstance(self.protected_paths, tuple) or not all(
            isinstance(item, str) for item in self.protected_paths
        ):
            raise EvolutionError("invalid_campaign_freeze")
        normalized = tuple(sorted(_normalize_path(item) for item in self.protected_paths))
        if normalized != self.protected_paths or len(set(normalized)) != len(normalized):
            raise EvolutionError("invalid_campaign_freeze")
        if not set(_PROTECTED_PATHS).issubset(normalized):
            raise EvolutionError("incomplete_protected_paths")


@dataclass(frozen=True)
class CandidateAttempt:
    attempt_id: str
    candidate_id: str
    candidate_identity_digest: str
    candidate_digest: str
    patch_digest: str
    lease_id: str
    parent_candidate_id: str | None
    action: CandidateAction
    author_id: str
    outcome: CandidateOutcome
    cost_steps: int
    dissent_digests: tuple[str, ...]
    sequence: int


@dataclass(frozen=True)
class EvaluationRecord:
    evaluation_id: str
    candidate_id: str
    outcome: EvaluationOutcome
    non_improving: bool
    suspected_reward_hack: bool
    evidence_digest: str
    run_receipt_digest: str
    receipt_digest: str
    cost_steps: int
    public_provider_metadata: Mapping[str, object]
    sequence: int


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    candidate_id: str
    evaluation_id: str
    outcome: ReviewOutcome
    complete_denominator: int
    denominator_digest: str
    dissent_digests: tuple[str, ...]
    review_digest: str
    receipt_digest: str
    public_provider_metadata: Mapping[str, object]
    sequence: int


@dataclass(frozen=True)
class PromotionRecord:
    promotion_id: str
    grant_id: str
    candidate_id: str
    predecessor_revision: str
    accepted_revision: str
    integration_receipt_digest: str
    promotion_receipt_digest: str | None
    effect_count: int
    state: Literal["effect_applied", "promoted"]
    sequence: int


@dataclass(frozen=True)
class RollbackRecord:
    rollback_id: str
    grant_id: str
    promotion_id: str
    predecessor_revision: str
    replaced_revision: str
    rollback_receipt_digest: str | None
    effect_count: int
    state: Literal["effect_applied", "restored"]
    sequence: int


@dataclass(frozen=True)
class CampaignSnapshot:
    campaign_id: str
    campaign_identity_digest: str
    campaign_digest: str
    freeze: CampaignFreeze
    state: Literal["open", "promoted", "rolled_back"]
    sequence: int
    candidates: tuple[CandidateAttempt, ...]
    evaluations: tuple[EvaluationRecord, ...]
    reviews: tuple[ReviewRecord, ...]
    promotions: tuple[PromotionRecord, ...]
    rollbacks: tuple[RollbackRecord, ...]

    @property
    def denominator(self) -> int:
        return len(self.candidates)


@dataclass(frozen=True)
class HumanPromotionGrant:
    grant_id: str
    authorized_by: str
    campaign_id: str
    candidate_id: str
    candidate_digest: str
    expected_predecessor_revision: str
    lease_id: str
    patch_digest: str
    evaluation_receipt_digest: str
    review_receipt_digest: str


@dataclass(frozen=True)
class HumanRollbackGrant:
    grant_id: str
    authorized_by: str
    campaign_id: str
    promotion_id: str
    expected_current_revision: str
    rollback_target_revision: str


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalize_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise EvolutionError("invalid_protected_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvolutionError("invalid_protected_path")
    return path.as_posix()


class EvolutionManager:
    """Manage one repository's bounded, offline evolution campaigns."""

    def __init__(
        self,
        repository: str | Path,
        *,
        provider_runner: ProviderRunner | None = None,
        workspace_manager: WorkspaceManager | None = None,
        validation: Callable[[Path], bool] | None = None,
        custody_root_id: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = Path(repository).resolve(strict=True)
        self.provider_runner = provider_runner
        self.workspace_manager = workspace_manager or WorkspaceManager(self.repository)
        self.validation = validation
        resolved_custody = custody_root_id or self.workspace_manager.store.custody_root_id
        self.store = FoundationStore(self.repository, custody_root_id=resolved_custody)
        self._now = now or (lambda: datetime.now(UTC))
        self.durable_root = self.repository / ".unrest" / "evolution"
        self.campaign_root = self.durable_root / "campaigns"
        self.private_root = self.durable_root / "private"
        self.runtime_root = self.repository / ".unrest-runtime" / "evolution"
        for directory in (self.campaign_root, self.private_root, self.runtime_root):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock_path = self.runtime_root / "manager.lock"
        self._assert_repository()

    def open_campaign(
        self,
        *,
        campaign_id: str,
        freeze: CampaignFreeze | Mapping[str, Any],
    ) -> CampaignSnapshot:
        """Freeze a complete campaign generation before admitting candidates."""

        checked = freeze if isinstance(freeze, CampaignFreeze) else CampaignFreeze.from_mapping(freeze)
        checked.validate()
        self._validate_public_id(campaign_id, "campaign")
        campaign_digest = _sha(canonical_json_bytes(asdict(checked)))
        campaign_identity = construct_identity(
            "campaign",
            {
                "accepted_working_point_digest": checked.accepted_working_point_digest,
                "budget_envelope": {"amount": checked.budget_steps, "unit": "steps"},
                "campaign_digest": campaign_digest,
                "evaluator_digest": self._evaluator_dimension(checked),
                "public_id": campaign_id,
                "schema_version": 1,
                "workload_digest": checked.workload_digest,
            },
        )
        with self._locked():
            if self._campaign_directory(campaign_id).exists():
                existing = self._inspect_unlocked(campaign_id)
                if existing.campaign_digest != campaign_digest:
                    raise EvolutionError("immutable_campaign")
                return existing
            if self._head_revision() != checked.accepted_revision:
                raise EvolutionError("stale_accepted_working_point")
            self.store.append_identity(campaign_identity)
            self._append_event(
                campaign_id,
                "campaign_opened",
                {
                    "campaign_digest": campaign_digest,
                    "campaign_identity_digest": campaign_identity.digest,
                    "freeze": asdict(checked),
                },
            )
            return self._inspect_unlocked(campaign_id)

    def inspect_campaign(self, campaign_id: str) -> CampaignSnapshot:
        self._validate_public_id(campaign_id, "campaign")
        with self._locked():
            return self._inspect_unlocked(campaign_id)

    def retain_frozen_oracle_result(
        self,
        *,
        campaign_id: str,
        candidate_id: str,
        outcome: Literal["pass", "fail", "reward_hack"],
        evidence_digest: str,
    ) -> str:
        """Retain a post-author, immutable oracle result for read-only evaluation.

        This is an internal measurement seam, not a promotion or campaign-state
        transition. The result is identity-bound and created only after the
        candidate patch has been returned and admitted.
        """
        if outcome not in {"pass", "fail", "reward_hack"} or _DIGEST.fullmatch(evidence_digest) is None:
            raise EvolutionError("invalid_oracle_result")
        self._validate_public_id(campaign_id, "campaign")
        self._validate_public_id(candidate_id, "candidate")
        with self._locked():
            snapshot = self._inspect_unlocked(campaign_id)
            candidate = self._candidate(snapshot, candidate_id)
            record: dict[str, Any] = {
                "campaign_digest": snapshot.campaign_digest,
                "candidate_digest": candidate.candidate_digest,
                "candidate_id": candidate_id,
                "evidence_digest": evidence_digest,
                "oracle_digest": snapshot.freeze.oracle_digest,
                "outcome": outcome,
                "schema_version": 1,
                "workload_digest": snapshot.freeze.workload_digest,
            }
            record["oracle_result_digest"] = _sha(canonical_json_bytes(record))
            path = self._oracle_result_path(campaign_id, candidate_id)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            encoded = canonical_json_bytes(record)
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                existing = verify_canonical_json_bytes(path.read_bytes())
                if existing != record:
                    raise EvolutionError("immutable_oracle_result")
                return str(record["oracle_result_digest"])
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written == 0:
                        raise OSError("short write")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return str(record["oracle_result_digest"])

    def add_candidate(
        self,
        *,
        campaign_id: str,
        lease_id: str,
        action: CandidateAction,
        parent_candidate_id: str | None = None,
        candidate_id: str | None = None,
        author_id: str,
        outcome: CandidateOutcome = "admitted",
        cost_steps: int = 0,
        dissent_digests: Sequence[str] = (),
    ) -> CandidateAttempt:
        """Append one identity-bound genealogy node; never accept candidate bytes."""

        self._validate_public_id(campaign_id, "campaign")
        if _LEASE_ID.fullmatch(lease_id) is None:
            raise EvolutionError("invalid_lease_id")
        if parent_candidate_id is not None:
            self._validate_public_id(parent_candidate_id, "candidate")
        with self._locked():
            snapshot = self._inspect_unlocked(campaign_id)
            attempt_id = "attempt:" + uuid.uuid4().hex
            try:
                if snapshot.state != "open":
                    raise EvolutionError("campaign_not_open")
                if action not in {"original", "edit", "rebase", "retry"}:
                    raise EvolutionError("invalid_candidate_action")
                if outcome not in _CANDIDATE_OUTCOMES:
                    raise EvolutionError("invalid_candidate_outcome")
                if author_id != snapshot.freeze.author_id:
                    raise EvolutionError("candidate_author_mismatch")
                if author_id in {snapshot.freeze.evaluator_id, snapshot.freeze.reviewer_id}:
                    raise EvolutionError("authority_collision")
                if isinstance(cost_steps, bool) or not isinstance(cost_steps, int) or cost_steps < 0:
                    raise EvolutionError("invalid_cost")
                dissent = tuple(sorted(dissent_digests))
                if len(set(dissent)) != len(dissent) or any(_DIGEST.fullmatch(item) is None for item in dissent):
                    raise EvolutionError("invalid_dissent")
                parents = {item.candidate_id: item for item in snapshot.candidates if item.outcome != "rejected"}
                if action == "original" and parent_candidate_id is not None:
                    raise EvolutionError("unexpected_candidate_parent")
                if action != "original" and parent_candidate_id not in parents:
                    raise EvolutionError("candidate_parent_not_found")
                lease = self.workspace_manager.inspect_workspace(lease_id)
                if lease.state != "returned" or lease.patch_digest is None or lease.candidate_identity_digest is None:
                    raise EvolutionError("candidate_patch_not_returned")
                if lease.base_revision != snapshot.freeze.accepted_revision:
                    raise EvolutionError("candidate_base_mismatch")
                if lease.owner_id != author_id:
                    raise EvolutionError("candidate_lease_owner_mismatch")
                generated_id = "candidate:" + lease.patch_digest[-24:]
                resolved_id = candidate_id or generated_id
                self._validate_public_id(resolved_id, "candidate")
                if any(item.candidate_id == resolved_id for item in snapshot.candidates):
                    raise EvolutionError("duplicate_candidate")
                payload = {
                    "action": action,
                    "attempt_id": attempt_id,
                    "author_id": author_id,
                    "candidate_digest": lease.patch_digest,
                    "candidate_id": resolved_id,
                    "candidate_identity_digest": lease.candidate_identity_digest,
                    "cost_steps": cost_steps,
                    "dissent_digests": list(dissent),
                    "lease_id": lease_id,
                    "outcome": outcome,
                    "parent": (
                        {"state": "present", "value": parent_candidate_id}
                        if parent_candidate_id is not None
                        else {"state": "absent"}
                    ),
                    "patch_digest": lease.patch_digest,
                }
                event = self._append_event(campaign_id, "candidate_added", payload)
                return self._candidate_from_event(event)
            except EvolutionError as exc:
                self._append_event(
                    campaign_id,
                    "candidate_rejected",
                    {
                        "attempt_id": attempt_id,
                        "author_id_digest": _sha(author_id.encode("utf-8")),
                        "cost_steps": max(cost_steps, 0) if isinstance(cost_steps, int) and not isinstance(cost_steps, bool) else 0,
                        "outcome": "rejected",
                        "reason": exc.code,
                    },
                )
                raise

    async def evaluate_candidate(
        self,
        *,
        campaign_id: str,
        candidate_id: str,
        evaluation_id: str | None = None,
        cancel_event: asyncio.Event | None = None,
        cost_steps: int = 0,
    ) -> EvaluationRecord:
        """Run the configured independent evaluator on exact frozen inputs."""

        self._validate_public_id(campaign_id, "campaign")
        self._validate_public_id(candidate_id, "candidate")
        if isinstance(cost_steps, bool) or not isinstance(cost_steps, int) or cost_steps < 0:
            raise EvolutionError("invalid_cost")
        resolved_id = evaluation_id or "evaluation:" + uuid.uuid4().hex
        self._validate_public_id(resolved_id, "evaluation")
        with self._locked():
            snapshot = self._inspect_unlocked(campaign_id)
            candidate = self._candidate(snapshot, candidate_id)
            if snapshot.state != "open":
                raise EvolutionError("campaign_not_open")
            if candidate.outcome != "admitted":
                raise EvolutionError("candidate_not_admitted")
            if any(item.evaluation_id == resolved_id for item in snapshot.evaluations):
                return next(item for item in snapshot.evaluations if item.evaluation_id == resolved_id)
            self._append_event(
                campaign_id,
                "evaluation_started",
                {
                    "candidate_id": candidate_id,
                    "evaluation_id": resolved_id,
                    "frozen_input_digest": self._evaluation_input_digest(snapshot, candidate),
                },
            )

        private_directory = self._private_campaign_directory(campaign_id)
        private_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        artifact_path = private_directory / (resolved_id.replace(":", "-") + ".json")
        provider_metadata: Mapping[str, object] = {
            "error_code": "adapter_not_configured",
            "role": "independent_evaluator",
            "status": "failed",
        }
        parsed: Mapping[str, Any] | None = None
        if self.provider_runner is not None:
            oracle_record = self._load_oracle_result(campaign_id, candidate_id)
            project_record = (
                self._oracle_result_path(campaign_id, candidate_id)
                if oracle_record is not None
                else self._provider_project_record()
            )
            request = ProviderSessionRequest(
                role="independent_evaluator",
                prompt=self._evaluator_assignment(snapshot, candidate, oracle_record),
                workspace_path=Path(self.workspace_manager.inspect_workspace(candidate.lease_id).worktree_path),
                project_record_path=project_record,
                private_artifact_path=artifact_path,
                private_artifact_root=private_directory,
            )
            result = await self.provider_runner.run(request, cancel_event=cancel_event)
            provider_metadata = {
                key: value
                for key, value in result.public_metadata().items()
                if value is not None
            }
            parsed = self._private_parsed_output(artifact_path)

        outcome, reward_hack = self._evaluation_outcome(provider_metadata, parsed)
        non_improving = outcome != "completed_pass" or reward_hack
        evidence_digest = _sha(
            canonical_json_bytes(
                {
                    "evaluation_id": resolved_id,
                    "frozen_input_digest": self._evaluation_input_digest(snapshot, candidate),
                    "outcome": outcome,
                    "provider_metadata": dict(provider_metadata),
                    "suspected_reward_hack": reward_hack,
                }
            )
        )
        with self._locked():
            current = self._inspect_unlocked(campaign_id)
            self._assert_frozen_candidate(current, snapshot, candidate)
            existing = next((item for item in current.evaluations if item.evaluation_id == resolved_id), None)
            if existing is not None:
                return existing
            identities = self._identity_bundle(current, candidate, evidence_digest=evidence_digest)
            run_receipt = self._run_receipt(
                current,
                candidate,
                identities,
                succeeded=outcome in {"completed_pass", "completed_fail", "suspected_reward_hack", "contaminated"},
                cost_steps=cost_steps,
            )
            dependencies = dict(identities)
            dependencies["run_receipt.v1"] = run_receipt.digest
            receipt = self._issue_receipt(
                "evaluation_receipt.v1",
                subject_id=candidate.candidate_id,
                subject_digest=candidate.candidate_identity_digest,
                outcome=outcome,
                terminal="retained_result" if outcome in {"completed_pass", "completed_fail"} else "retained_failure",
                dependency_digests=dependencies,
                sequence=current.sequence + 1,
                cost_steps=cost_steps,
            )
            event = self._append_event(
                campaign_id,
                "evaluation_completed",
                {
                    "candidate_id": candidate_id,
                    "cost_steps": cost_steps,
                    "evaluation_id": resolved_id,
                    "evidence_digest": evidence_digest,
                    "non_improving": non_improving,
                    "outcome": outcome,
                    "provider_metadata": dict(provider_metadata),
                    "receipt_digest": receipt.digest,
                    "run_receipt_digest": run_receipt.digest,
                    "suspected_reward_hack": reward_hack,
                },
            )
            return self._evaluation_from_event(event)

    async def review_candidate(
        self,
        *,
        campaign_id: str,
        candidate_id: str,
        evaluation_id: str,
        review_id: str | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> ReviewRecord:
        """Review the complete retained denominator with an independent role."""

        self._validate_public_id(campaign_id, "campaign")
        self._validate_public_id(candidate_id, "candidate")
        self._validate_public_id(evaluation_id, "evaluation")
        resolved_id = review_id or "review:" + uuid.uuid4().hex
        self._validate_public_id(resolved_id, "review")
        with self._locked():
            snapshot = self._inspect_unlocked(campaign_id)
            if snapshot.state != "open":
                raise EvolutionError("campaign_not_open")
            candidate = self._candidate(snapshot, candidate_id)
            evaluation = self._evaluation(snapshot, evaluation_id)
            if evaluation.candidate_id != candidate_id:
                raise EvolutionError("review_candidate_mismatch")
            if any(item.review_id == resolved_id for item in snapshot.reviews):
                return next(item for item in snapshot.reviews if item.review_id == resolved_id)
            self._append_event(
                campaign_id,
                "review_started",
                {
                    "candidate_id": candidate_id,
                    "complete_denominator": snapshot.denominator,
                    "denominator_digest": self._denominator_digest(snapshot),
                    "evaluation_id": evaluation_id,
                    "review_id": resolved_id,
                },
            )

        private_directory = self._private_campaign_directory(campaign_id)
        private_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        artifact_path = private_directory / (resolved_id.replace(":", "-") + ".json")
        provider_metadata: Mapping[str, object] = {
            "error_code": "adapter_not_configured",
            "role": "independent_reviewer",
            "status": "failed",
        }
        parsed: Mapping[str, Any] | None = None
        if self.provider_runner is not None:
            oracle_record = self._load_oracle_result(campaign_id, candidate_id)
            project_record = (
                self._oracle_result_path(campaign_id, candidate_id)
                if oracle_record is not None
                else self._provider_project_record()
            )
            request = ProviderSessionRequest(
                role="independent_reviewer",
                prompt=self._reviewer_assignment(
                    snapshot,
                    candidate,
                    evaluation,
                    oracle_record,
                ),
                workspace_path=Path(self.workspace_manager.inspect_workspace(candidate.lease_id).worktree_path),
                project_record_path=project_record,
                private_artifact_path=artifact_path,
                private_artifact_root=private_directory,
            )
            result = await self.provider_runner.run(request, cancel_event=cancel_event)
            provider_metadata = {
                key: value
                for key, value in result.public_metadata().items()
                if value is not None
            }
            parsed = self._private_parsed_output(artifact_path)
        outcome, dissent = self._review_outcome(provider_metadata, parsed, evaluation)
        with self._locked():
            current = self._inspect_unlocked(campaign_id)
            self._assert_frozen_candidate(current, snapshot, candidate)
            if current.denominator != snapshot.denominator:
                outcome = "inconclusive"
            existing = next((item for item in current.reviews if item.review_id == resolved_id), None)
            if existing is not None:
                return existing
            review_digest = _sha(
                canonical_json_bytes(
                    {
                        "candidate_id": candidate_id,
                        "complete_denominator": snapshot.denominator,
                        "denominator_digest": self._denominator_digest(snapshot),
                        "dissent_digests": list(dissent),
                        "evaluation_id": evaluation_id,
                        "outcome": outcome,
                        "provider_metadata": dict(provider_metadata),
                        "review_id": resolved_id,
                    }
                )
            )
            identities = self._identity_bundle(current, candidate, evidence_digest=evaluation.evidence_digest)
            review_identity = construct_identity(
                "review",
                {
                    "candidate_digest": candidate.candidate_digest,
                    "evidence_digest": evaluation.evidence_digest,
                    "public_id": resolved_id,
                    "review_digest": review_digest,
                    "schema_version": 1,
                },
            )
            self.store.append_identity(review_identity)
            identities["review"] = review_identity.digest
            identities["evaluation_receipt.v1"] = evaluation.receipt_digest
            receipt = self._issue_receipt(
                "review_receipt.v1",
                subject_id=candidate.candidate_id,
                subject_digest=candidate.candidate_identity_digest,
                outcome=outcome,
                terminal={
                    "approve": "approved",
                    "reject": "rejected",
                    "rework": "rework",
                    "inconclusive": "inconclusive",
                    "dissent": "inconclusive",
                    "cancelled": "inconclusive",
                }[outcome],
                dependency_digests=identities,
                sequence=current.sequence + 1,
                cost_steps=0,
            )
            event = self._append_event(
                campaign_id,
                "review_completed",
                {
                    "candidate_id": candidate_id,
                    "complete_denominator": snapshot.denominator,
                    "denominator_digest": self._denominator_digest(snapshot),
                    "dissent_digests": list(dissent),
                    "evaluation_id": evaluation_id,
                    "outcome": outcome,
                    "provider_metadata": dict(provider_metadata),
                    "receipt_digest": receipt.digest,
                    "review_digest": review_digest,
                    "review_id": resolved_id,
                },
            )
            return self._review_from_event(event)

    def promote_candidate(
        self,
        grant: HumanPromotionGrant,
        *,
        validate: Callable[[Path], bool] | None = None,
        request_fingerprint: str = "",
        _accepted_point_capability: _AcceptedPointCapability | None = None,
    ) -> PromotionRecord:
        """Apply one externally granted exact candidate through parent authority."""

        try:
            _require_accepted_point_capability(
                _accepted_point_capability, self.repository
            )
        except AcceptedPointAuthorityError as exc:
            raise EvolutionError(exc.code) from exc
        self._validate_human_grant(grant.grant_id, grant.authorized_by)
        if _DIGEST.fullmatch(request_fingerprint) is None:
            raise EvolutionError("invalid_request_fingerprint")
        self._validate_public_id(grant.campaign_id, "campaign")
        self._validate_public_id(grant.candidate_id, "candidate")
        if _LEASE_ID.fullmatch(grant.lease_id) is None:
            raise EvolutionError("invalid_lease_id")
        with self._locked():
            snapshot = self._inspect_unlocked(grant.campaign_id)
            existing = next((item for item in snapshot.promotions if item.grant_id == grant.grant_id), None)
            if existing is not None and existing.promotion_receipt_digest is not None:
                return existing
            candidate, evaluation, review = self._promotion_inputs(snapshot, grant)
            promotion_id = existing.promotion_id if existing else "promotion:" + uuid.uuid4().hex
            if existing is None:
                self._append_event(
                    grant.campaign_id,
                    "promotion_prepared",
                    {
                        "candidate_id": candidate.candidate_id,
                        "grant_id": grant.grant_id,
                        "promotion_id": promotion_id,
                        "predecessor_revision": grant.expected_predecessor_revision,
                    },
                )

        integration = self._reconcile_or_integrate(
            grant,
            candidate,
            validate or self.validation,
            _accepted_point_capability,
            request_fingerprint,
        )
        with self._locked():
            snapshot = self._inspect_unlocked(grant.campaign_id)
            candidate, evaluation, review = self._promotion_inputs(snapshot, grant, allow_promoted=True)
            current = next((item for item in snapshot.promotions if item.grant_id == grant.grant_id), None)
            if current is None or current.accepted_revision != integration.accepted_revision:
                event = self._append_event(
                    grant.campaign_id,
                    "promotion_effect_applied",
                    {
                        "accepted_revision": integration.accepted_revision,
                        "candidate_id": candidate.candidate_id,
                        "grant_id": grant.grant_id,
                        "integration_receipt_digest": integration.receipt_digests[0],
                        "predecessor_revision": integration.predecessor,
                        "promotion_id": promotion_id,
                    },
                )
                current = self._promotion_from_event(event)
            if current.promotion_receipt_digest is not None:
                return current
            receipt = self._promotion_receipt(snapshot, candidate, evaluation, review, current)
            event = self._append_event(
                grant.campaign_id,
                "promotion_completed",
                {
                    "accepted_revision": current.accepted_revision,
                    "candidate_id": candidate.candidate_id,
                    "grant_id": grant.grant_id,
                    "integration_receipt_digest": current.integration_receipt_digest,
                    "predecessor_revision": current.predecessor_revision,
                    "promotion_id": current.promotion_id,
                    "promotion_receipt_digest": receipt.digest,
                },
            )
            return self._promotion_from_event(event)

    def rollback_promotion(
        self,
        grant: HumanRollbackGrant,
        *,
        validate: Callable[[Path], bool] | None = None,
        request_fingerprint: str = "",
        _accepted_point_capability: _AcceptedPointCapability | None = None,
    ) -> RollbackRecord:
        """Restore only the exact predecessor selected by a human grant."""

        try:
            _require_accepted_point_capability(
                _accepted_point_capability, self.repository
            )
        except AcceptedPointAuthorityError as exc:
            raise EvolutionError(exc.code) from exc
        self._validate_human_grant(grant.grant_id, grant.authorized_by)
        if _DIGEST.fullmatch(request_fingerprint) is None:
            raise EvolutionError("invalid_request_fingerprint")
        self._validate_public_id(grant.campaign_id, "campaign")
        self._validate_public_id(grant.promotion_id, "promotion")
        with self._locked():
            snapshot = self._inspect_unlocked(grant.campaign_id)
            existing = next((item for item in snapshot.rollbacks if item.grant_id == grant.grant_id), None)
            if existing is not None and existing.rollback_receipt_digest is not None:
                transaction = self._load_rollback_transaction(request_fingerprint)
                if (
                    transaction is None
                    or transaction.get("grant_id") != grant.grant_id
                    or transaction.get("request_fingerprint") != request_fingerprint
                ):
                    raise EvolutionError("rollback_transaction_mismatch")
                if transaction.get("state") != "completed":
                    self._append_rollback_transaction(
                        request_fingerprint,
                        {**transaction, "state": "completed"},
                    )
                return existing
            promotion = next((item for item in snapshot.promotions if item.promotion_id == grant.promotion_id), None)
            if promotion is None or promotion.promotion_receipt_digest is None:
                raise EvolutionError("promotion_not_complete")
            if (
                grant.expected_current_revision != promotion.accepted_revision
                or grant.rollback_target_revision != promotion.predecessor_revision
            ):
                raise EvolutionError("rollback_target_mismatch")
            rollback_id = existing.rollback_id if existing else "rollback:" + uuid.uuid4().hex
            if existing is None:
                self._append_event(
                    grant.campaign_id,
                    "rollback_prepared",
                    {
                        "grant_id": grant.grant_id,
                        "promotion_id": promotion.promotion_id,
                        "replaced_revision": promotion.accepted_revision,
                        "rollback_id": rollback_id,
                        "rollback_target_revision": promotion.predecessor_revision,
                    },
                )

        self._restore_exact_predecessor(
            promotion,
            validate or self.validation,
            grant.grant_id,
            request_fingerprint,
        )
        with self._locked():
            snapshot = self._inspect_unlocked(grant.campaign_id)
            promotion = next(item for item in snapshot.promotions if item.promotion_id == grant.promotion_id)
            current = next((item for item in snapshot.rollbacks if item.grant_id == grant.grant_id), None)
            if current is None or current.predecessor_revision != promotion.predecessor_revision:
                event = self._append_event(
                    grant.campaign_id,
                    "rollback_effect_applied",
                    {
                        "grant_id": grant.grant_id,
                        "predecessor_revision": promotion.predecessor_revision,
                        "promotion_id": promotion.promotion_id,
                        "replaced_revision": promotion.accepted_revision,
                        "rollback_id": rollback_id,
                    },
                )
                current = self._rollback_from_event(event)
            if current.rollback_receipt_digest is not None:
                return current
            receipt = self._rollback_receipt(snapshot, promotion)
            event = self._append_event(
                grant.campaign_id,
                "rollback_completed",
                {
                    "grant_id": grant.grant_id,
                    "predecessor_revision": promotion.predecessor_revision,
                    "promotion_id": promotion.promotion_id,
                    "replaced_revision": promotion.accepted_revision,
                    "rollback_id": current.rollback_id,
                    "rollback_receipt_digest": receipt.digest,
                },
            )
            self._accepted_point_fault("post_receipt")
            self._append_rollback_transaction(
                request_fingerprint,
                {
                    "expected_new_revision": promotion.predecessor_revision,
                    "expected_old_revision": promotion.accepted_revision,
                    "grant_id": grant.grant_id,
                    "request_fingerprint": request_fingerprint,
                    "state": "completed",
                },
            )
            return self._rollback_from_event(event)

    def _assert_repository(self) -> None:
        result = self._git("rev-parse", "--show-toplevel")
        if Path(result).resolve() != self.repository:
            raise EvolutionError("repository_root_required")

    def _git(self, *arguments: str, cwd: Path | None = None) -> str:
        try:
            return subprocess.run(
                ["git", *arguments],
                cwd=cwd or self.repository,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
            raise EvolutionError("git_operation_failed") from exc

    def _head_revision(self) -> str:
        return self._git("rev-parse", "HEAD")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _validate_public_id(value: str, prefix: str) -> None:
        if _PUBLIC_ID.fullmatch(value) is None or not value.startswith(prefix + ":"):
            raise EvolutionError("invalid_public_id")

    @staticmethod
    def _validate_human_grant(grant_id: str, authorized_by: str) -> None:
        if not grant_id.startswith("human-grant:") or not authorized_by.startswith("human:"):
            raise EvolutionError("human_grant_required")

    @staticmethod
    def _evaluator_dimension(freeze: CampaignFreeze) -> str:
        return _sha(
            canonical_json_bytes(
                {
                    "evaluator_id": freeze.evaluator_id,
                    "evaluator_policy_digest": freeze.evaluator_policy_digest,
                }
            )
        )

    def _campaign_directory(self, campaign_id: str) -> Path:
        return self.campaign_root / campaign_id.removeprefix("campaign:")

    def _private_campaign_directory(self, campaign_id: str) -> Path:
        return self.private_root / campaign_id.removeprefix("campaign:")

    def _oracle_result_path(self, campaign_id: str, candidate_id: str) -> Path:
        token = candidate_id.removeprefix("candidate:")
        return self._private_campaign_directory(campaign_id) / f"oracle-{token}.json"

    def _load_oracle_result(
        self,
        campaign_id: str,
        candidate_id: str,
    ) -> Mapping[str, Any] | None:
        path = self._oracle_result_path(campaign_id, candidate_id)
        if not path.is_file():
            return None
        try:
            record = verify_canonical_json_bytes(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise EvolutionError("invalid_oracle_result") from exc
        expected = record.get("oracle_result_digest")
        unsigned = dict(record)
        unsigned.pop("oracle_result_digest", None)
        if expected != _sha(canonical_json_bytes(unsigned)):
            raise EvolutionError("invalid_oracle_result")
        return record

    def _event_files(self, campaign_id: str) -> tuple[Path, ...]:
        directory = self._campaign_directory(campaign_id)
        return tuple(sorted(directory.glob("*.json"))) if directory.exists() else ()

    def _append_event(self, campaign_id: str, kind: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        directory = self._campaign_directory(campaign_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        events = self._load_events(campaign_id)
        sequence = len(events) + 1
        previous: Mapping[str, Any] = (
            {"state": "present", "value": events[-1]["event_digest"]}
            if events
            else {"state": "absent"}
        )
        record: dict[str, Any] = {
            "campaign_id": campaign_id,
            "event_kind": kind,
            "observed_at": _format_time(self._now()),
            "payload": dict(payload),
            "previous_event_digest": previous,
            "schema_version": 1,
            "sequence": sequence,
        }
        record["event_digest"] = _sha(_EVENT_PREFIX + canonical_json_bytes(record))
        encoded = canonical_json_bytes(record)
        path = directory / f"{sequence:020d}.json"
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise EvolutionError("concurrent_campaign_update") from exc
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written == 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return record

    def _load_events(self, campaign_id: str) -> tuple[Mapping[str, Any], ...]:
        events: list[Mapping[str, Any]] = []
        predecessor: str | None = None
        for expected, path in enumerate(self._event_files(campaign_id), start=1):
            if path.name != f"{expected:020d}.json":
                raise EvolutionError("campaign_integrity_error")
            try:
                parsed = verify_canonical_json_bytes(path.read_bytes())
            except (OSError, ValueError) as exc:
                raise EvolutionError("campaign_integrity_error") from exc
            if not isinstance(parsed, Mapping):
                raise EvolutionError("campaign_integrity_error")
            stored_digest = parsed.get("event_digest")
            unsigned = {key: value for key, value in parsed.items() if key != "event_digest"}
            expected_digest = _sha(_EVENT_PREFIX + canonical_json_bytes(unsigned))
            previous = parsed.get("previous_event_digest")
            expected_previous: Mapping[str, Any] = (
                {"state": "present", "value": predecessor}
                if predecessor is not None
                else {"state": "absent"}
            )
            if (
                parsed.get("campaign_id") != campaign_id
                or parsed.get("sequence") != expected
                or previous != expected_previous
                or stored_digest != expected_digest
            ):
                raise EvolutionError("campaign_integrity_error")
            predecessor = cast(str, stored_digest)
            events.append(parsed)
        return tuple(events)

    def _inspect_unlocked(self, campaign_id: str) -> CampaignSnapshot:
        events = self._load_events(campaign_id)
        if not events or events[0].get("event_kind") != "campaign_opened":
            raise EvolutionError("campaign_not_found")
        first = cast(Mapping[str, Any], events[0]["payload"])
        freeze = CampaignFreeze.from_mapping(cast(Mapping[str, Any], first["freeze"]))
        candidates: list[CandidateAttempt] = []
        evaluations: list[EvaluationRecord] = []
        reviews: list[ReviewRecord] = []
        promotions: dict[str, PromotionRecord] = {}
        rollbacks: dict[str, RollbackRecord] = {}
        for event in events[1:]:
            kind = event["event_kind"]
            if kind == "candidate_added":
                candidates.append(self._candidate_from_event(event))
            elif kind == "candidate_rejected":
                payload = cast(Mapping[str, Any], event["payload"])
                synthetic = _sha(canonical_json_bytes(payload))
                candidates.append(
                    CandidateAttempt(
                        attempt_id=cast(str, payload["attempt_id"]),
                        candidate_id="candidate:rejected-" + synthetic[-16:],
                        candidate_identity_digest=synthetic,
                        candidate_digest=synthetic,
                        patch_digest=synthetic,
                        lease_id="lease:rejected",
                        parent_candidate_id=None,
                        action="original",
                        author_id="redacted:" + cast(str, payload["author_id_digest"])[-16:],
                        outcome="rejected",
                        cost_steps=cast(int, payload["cost_steps"]),
                        dissent_digests=(),
                        sequence=cast(int, event["sequence"]),
                    )
                )
            elif kind == "evaluation_completed":
                evaluations.append(self._evaluation_from_event(event))
            elif kind == "review_completed":
                reviews.append(self._review_from_event(event))
            elif kind in {"promotion_effect_applied", "promotion_completed"}:
                promotion_item = self._promotion_from_event(event)
                promotions[promotion_item.grant_id] = promotion_item
            elif kind in {"rollback_effect_applied", "rollback_completed"}:
                rollback_item = self._rollback_from_event(event)
                rollbacks[rollback_item.grant_id] = rollback_item
        state: Literal["open", "promoted", "rolled_back"] = "open"
        if any(item.state == "promoted" for item in promotions.values()):
            state = "promoted"
        if any(item.state == "restored" for item in rollbacks.values()):
            state = "rolled_back"
        return CampaignSnapshot(
            campaign_id,
            cast(str, first["campaign_identity_digest"]),
            cast(str, first["campaign_digest"]),
            freeze,
            state,
            len(events),
            tuple(candidates),
            tuple(evaluations),
            tuple(reviews),
            tuple(promotions.values()),
            tuple(rollbacks.values()),
        )

    @staticmethod
    def _candidate_from_event(event: Mapping[str, Any]) -> CandidateAttempt:
        payload = cast(Mapping[str, Any], event["payload"])
        parent = cast(Mapping[str, Any], payload["parent"])
        return CandidateAttempt(
            cast(str, payload["attempt_id"]),
            cast(str, payload["candidate_id"]),
            cast(str, payload["candidate_identity_digest"]),
            cast(str, payload["candidate_digest"]),
            cast(str, payload["patch_digest"]),
            cast(str, payload["lease_id"]),
            cast(str, parent["value"]) if parent["state"] == "present" else None,
            cast(CandidateAction, payload["action"]),
            cast(str, payload["author_id"]),
            cast(CandidateOutcome, payload["outcome"]),
            cast(int, payload["cost_steps"]),
            tuple(cast(Sequence[str], payload["dissent_digests"])),
            cast(int, event["sequence"]),
        )

    @staticmethod
    def _evaluation_from_event(event: Mapping[str, Any]) -> EvaluationRecord:
        payload = cast(Mapping[str, Any], event["payload"])
        return EvaluationRecord(
            cast(str, payload["evaluation_id"]),
            cast(str, payload["candidate_id"]),
            cast(EvaluationOutcome, payload["outcome"]),
            cast(bool, payload["non_improving"]),
            cast(bool, payload["suspected_reward_hack"]),
            cast(str, payload["evidence_digest"]),
            cast(str, payload["run_receipt_digest"]),
            cast(str, payload["receipt_digest"]),
            cast(int, payload["cost_steps"]),
            cast(Mapping[str, object], payload["provider_metadata"]),
            cast(int, event["sequence"]),
        )

    @staticmethod
    def _review_from_event(event: Mapping[str, Any]) -> ReviewRecord:
        payload = cast(Mapping[str, Any], event["payload"])
        return ReviewRecord(
            cast(str, payload["review_id"]),
            cast(str, payload["candidate_id"]),
            cast(str, payload["evaluation_id"]),
            cast(ReviewOutcome, payload["outcome"]),
            cast(int, payload["complete_denominator"]),
            cast(str, payload["denominator_digest"]),
            tuple(cast(Sequence[str], payload["dissent_digests"])),
            cast(str, payload["review_digest"]),
            cast(str, payload["receipt_digest"]),
            cast(Mapping[str, object], payload["provider_metadata"]),
            cast(int, event["sequence"]),
        )

    @staticmethod
    def _promotion_from_event(event: Mapping[str, Any]) -> PromotionRecord:
        payload = cast(Mapping[str, Any], event["payload"])
        completed = event["event_kind"] == "promotion_completed"
        return PromotionRecord(
            cast(str, payload["promotion_id"]),
            cast(str, payload["grant_id"]),
            cast(str, payload["candidate_id"]),
            cast(str, payload["predecessor_revision"]),
            cast(str, payload["accepted_revision"]),
            cast(str, payload["integration_receipt_digest"]),
            cast(str, payload["promotion_receipt_digest"]) if completed else None,
            1,
            "promoted" if completed else "effect_applied",
            cast(int, event["sequence"]),
        )

    @staticmethod
    def _rollback_from_event(event: Mapping[str, Any]) -> RollbackRecord:
        payload = cast(Mapping[str, Any], event["payload"])
        completed = event["event_kind"] == "rollback_completed"
        return RollbackRecord(
            cast(str, payload["rollback_id"]),
            cast(str, payload["grant_id"]),
            cast(str, payload["promotion_id"]),
            cast(str, payload["predecessor_revision"]),
            cast(str, payload["replaced_revision"]),
            cast(str, payload["rollback_receipt_digest"]) if completed else None,
            1,
            "restored" if completed else "effect_applied",
            cast(int, event["sequence"]),
        )

    @staticmethod
    def _candidate(snapshot: CampaignSnapshot, candidate_id: str) -> CandidateAttempt:
        item = next((candidate for candidate in snapshot.candidates if candidate.candidate_id == candidate_id), None)
        if item is None:
            raise EvolutionError("candidate_not_found")
        return item

    @staticmethod
    def _evaluation(snapshot: CampaignSnapshot, evaluation_id: str) -> EvaluationRecord:
        item = next((evaluation for evaluation in snapshot.evaluations if evaluation.evaluation_id == evaluation_id), None)
        if item is None:
            raise EvolutionError("evaluation_not_found")
        return item

    @staticmethod
    def _assert_frozen_candidate(current: CampaignSnapshot, previous: CampaignSnapshot, candidate: CandidateAttempt) -> None:
        if current.campaign_digest != previous.campaign_digest:
            raise EvolutionError("stale_campaign")
        fresh = EvolutionManager._candidate(current, candidate.candidate_id)
        if fresh != candidate:
            raise EvolutionError("stale_candidate")

    @staticmethod
    def _evaluation_input_digest(snapshot: CampaignSnapshot, candidate: CandidateAttempt) -> str:
        return _sha(
            canonical_json_bytes(
                {
                    "campaign_digest": snapshot.campaign_digest,
                    "candidate_digest": candidate.candidate_digest,
                    "evaluator_id": snapshot.freeze.evaluator_id,
                    "evaluator_policy_digest": snapshot.freeze.evaluator_policy_digest,
                    "oracle_digest": snapshot.freeze.oracle_digest,
                    "workload_digest": snapshot.freeze.workload_digest,
                }
            )
        )

    @staticmethod
    def _denominator_digest(snapshot: CampaignSnapshot) -> str:
        return _sha(
            canonical_json_bytes(
                [
                    {
                        "attempt_id": item.attempt_id,
                        "candidate_digest": item.candidate_digest,
                        "cost_steps": item.cost_steps,
                        "dissent_digests": list(item.dissent_digests),
                        "outcome": item.outcome,
                    }
                    for item in snapshot.candidates
                ]
            )
        )

    @staticmethod
    def _evaluator_assignment(
        snapshot: CampaignSnapshot,
        candidate: CandidateAttempt,
        oracle_record: Mapping[str, Any] | None = None,
    ) -> str:
        assignment = {
            "campaign_digest": snapshot.campaign_digest,
            "candidate_digest": candidate.candidate_digest,
            "evaluation_input_digest": EvolutionManager._evaluation_input_digest(snapshot, candidate),
            "oracle_digest": snapshot.freeze.oracle_digest,
            "required_output": {
                "outcome": "completed_pass|completed_fail|contaminated|suspected_reward_hack|policy_rejected|skipped",
                "suspected_reward_hack": "boolean",
            },
            "workload_digest": snapshot.freeze.workload_digest,
        }
        if oracle_record is not None:
            assignment["frozen_oracle_result"] = {
                "digest": oracle_record["oracle_result_digest"],
                "path": "project_record_path",
            }
        return "Evaluate the exact frozen candidate. Return only one JSON object.\n" + json.dumps(assignment, sort_keys=True)

    @staticmethod
    def _reviewer_assignment(
        snapshot: CampaignSnapshot,
        candidate: CandidateAttempt,
        evaluation: EvaluationRecord,
        oracle_record: Mapping[str, Any] | None = None,
    ) -> str:
        assignment = {
            "campaign_digest": snapshot.campaign_digest,
            "candidate_digest": candidate.candidate_digest,
            "complete_denominator": snapshot.denominator,
            "denominator_digest": EvolutionManager._denominator_digest(snapshot),
            "evaluation_evidence_digest": evaluation.evidence_digest,
            "evaluation_non_improving": evaluation.non_improving,
            "required_output": {
                "dissent_digests": "sorted array of sha256 digests",
                "outcome": "approve|reject|rework|inconclusive|dissent",
            },
        }
        if oracle_record is not None:
            assignment["frozen_oracle_result"] = {
                "digest": oracle_record["oracle_result_digest"],
                "path": "project_record_path",
            }
        return "Review the complete frozen evidence set. Return only one JSON object.\n" + json.dumps(assignment, sort_keys=True)

    def _provider_project_record(self) -> Path:
        path = self.durable_root / "provider-project.json"
        if not path.exists():
            encoded = canonical_json_bytes({"project_id": "evolution:local", "schema_version": 1})
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                return path
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written == 0:
                        raise OSError("short write")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return path

    @staticmethod
    def _private_parsed_output(path: Path) -> Mapping[str, Any] | None:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return None
        if not isinstance(document, Mapping):
            return None
        output = document.get("output")
        parsed = output.get("parsed") if isinstance(output, Mapping) else None
        return cast(Mapping[str, Any], parsed) if isinstance(parsed, Mapping) else None

    @staticmethod
    def _evaluation_outcome(
        metadata: Mapping[str, object], parsed: Mapping[str, Any] | None
    ) -> tuple[EvaluationOutcome, bool]:
        status = metadata.get("status")
        if status == "timed_out":
            return "timed_out", False
        if status == "cancelled":
            return "cancelled", False
        if status != "completed" or parsed is None:
            return "evaluator_error", False
        raw = parsed.get("outcome")
        outcome: EvaluationOutcome = (
            cast(EvaluationOutcome, raw)
            if isinstance(raw, str) and raw in _EVALUATION_OUTCOMES
            else "evaluator_error"
        )
        reward_hack = parsed.get("suspected_reward_hack") is True or outcome == "suspected_reward_hack"
        if reward_hack:
            outcome = "suspected_reward_hack"
        return outcome, reward_hack

    @staticmethod
    def _review_outcome(
        metadata: Mapping[str, object],
        parsed: Mapping[str, Any] | None,
        evaluation: EvaluationRecord,
    ) -> tuple[ReviewOutcome, tuple[str, ...]]:
        if metadata.get("status") == "cancelled":
            return "cancelled", ()
        if metadata.get("status") != "completed" or parsed is None:
            return "inconclusive", ()
        raw = parsed.get("outcome")
        outcome: ReviewOutcome = (
            cast(ReviewOutcome, raw)
            if isinstance(raw, str) and raw in _REVIEW_OUTCOMES
            else "inconclusive"
        )
        raw_dissent = parsed.get("dissent_digests", [])
        dissent = (
            tuple(
                sorted(
                    {
                        item
                        for item in raw_dissent
                        if isinstance(item, str) and _DIGEST.fullmatch(item)
                    }
                )
            )
            if isinstance(raw_dissent, list)
            else ()
        )
        if evaluation.non_improving and outcome == "approve":
            outcome = "inconclusive"
        if dissent and outcome == "approve":
            outcome = "dissent"
        return outcome, dissent

    def _identity_bundle(
        self,
        snapshot: CampaignSnapshot,
        candidate: CandidateAttempt,
        *,
        evidence_digest: str,
    ) -> dict[str, str]:
        freeze = snapshot.freeze
        identities: dict[str, IdentityRecord] = {
            "accepted_working_point": construct_identity(
                "accepted_working_point",
                {
                    "accepted_working_point_digest": freeze.accepted_working_point_digest,
                    "base_revision": freeze.accepted_revision,
                    "public_id": "accepted_working_point:" + freeze.accepted_revision[:20],
                    "schema_version": 1,
                },
            ),
            "artifact": construct_identity(
                "artifact",
                {"artifact_digest": candidate.patch_digest, "public_id": "artifact:" + candidate.patch_digest[-24:], "schema_version": 1},
            ),
            "base": construct_identity("base", {"base_revision": freeze.accepted_revision, "public_id": "base:" + freeze.accepted_revision[:20], "schema_version": 1}),
            "budget": construct_identity("budget", {"budget_envelope": {"amount": freeze.budget_steps, "unit": "steps"}, "public_id": "budget:" + snapshot.campaign_digest[-24:], "schema_version": 1}),
            "context": construct_identity("context", {"context_digest": freeze.context_digest, "public_id": "context:" + freeze.context_digest[-24:], "schema_version": 1}),
            "environment": construct_identity("environment", {"environment_digest": freeze.environment_digest, "public_id": "environment:" + freeze.environment_digest[-24:], "schema_version": 1}),
            "policy": construct_identity("policy", {"capability_policy_digest": freeze.capability_policy_digest, "public_id": "policy:" + freeze.capability_policy_digest[-24:], "schema_version": 1}),
            "provider_configuration": construct_identity("provider_configuration", {"provider_configuration_digest": freeze.provider_configuration_digest, "public_id": "provider_configuration:" + freeze.provider_configuration_digest[-24:], "schema_version": 1, "secret_set_version_id": freeze.secret_set_version_id}),
            "route_profile": construct_identity("route_profile", {"provider_configuration_digest": freeze.provider_configuration_digest, "public_id": "route_profile:" + freeze.route_profile_digest[-24:], "route_profile_digest": freeze.route_profile_digest, "schema_version": 1}),
            "secret_set_version": construct_identity("secret_set_version", {"public_id": "secret_set_version:" + freeze.secret_set_version_id.removeprefix("secret-set:"), "schema_version": 1, "secret_set_version_id": freeze.secret_set_version_id}),
            "seed": construct_identity("seed", {"public_id": "seed:" + str(abs(freeze.seed)), "schema_version": 1, "seed": freeze.seed}),
            "workload": construct_identity("workload", {"environment_digest": freeze.environment_digest, "public_id": "workload:" + freeze.workload_digest[-24:], "schema_version": 1, "seed": freeze.seed, "workload_digest": freeze.workload_digest}),
        }
        evaluator_dimension = self._evaluator_dimension(freeze)
        identities["evaluator"] = construct_identity(
            "evaluator",
            {"environment_digest": freeze.environment_digest, "evaluator_digest": evaluator_dimension, "public_id": "evaluator:" + evaluator_dimension[-24:], "schema_version": 1, "workload_digest": freeze.workload_digest},
        )
        identities["evidence"] = construct_identity(
            "evidence",
            {"artifact_digest": candidate.patch_digest, "candidate_digest": candidate.candidate_digest, "evaluator_digest": evaluator_dimension, "evidence_digest": evidence_digest, "public_id": "evidence:" + evidence_digest[-24:], "schema_version": 1},
        )
        for identity in identities.values():
            self.store.append_identity(identity)
        self.store.load_identity("candidate", candidate.candidate_identity_digest)
        lease = self.workspace_manager.inspect_workspace(candidate.lease_id)
        return {
            **{kind: identity.digest for kind, identity in identities.items()},
            "candidate": candidate.candidate_identity_digest,
            "workspace_lease": lease.lease_identity_digest,
        }

    def _run_receipt(
        self,
        snapshot: CampaignSnapshot,
        candidate: CandidateAttempt,
        identities: Mapping[str, str],
        *,
        succeeded: bool,
        cost_steps: int,
    ) -> ReceiptRecord:
        freeze = snapshot.freeze
        run_identity = construct_identity(
            "run",
            {
                "accepted_working_point_digest": freeze.accepted_working_point_digest,
                "base_revision": freeze.accepted_revision,
                "budget_envelope": {"amount": freeze.budget_steps, "unit": "steps"},
                "candidate_digest": candidate.candidate_digest,
                "capability_policy_digest": freeze.capability_policy_digest,
                "context_digest": freeze.context_digest,
                "environment_digest": freeze.environment_digest,
                "evaluator_digest": self._evaluator_dimension(freeze),
                "provider_configuration_digest": freeze.provider_configuration_digest,
                "public_id": "run:" + uuid.uuid4().hex,
                "route_profile_digest": freeze.route_profile_digest,
                "schema_version": 1,
                "secret_set_version_id": freeze.secret_set_version_id,
                "seed": freeze.seed,
                "workload_digest": freeze.workload_digest,
                "workspace_lease_id": candidate.lease_id,
            },
        )
        self.store.append_identity(run_identity)
        return self._issue_receipt(
            "run_receipt.v1",
            subject_id=cast(str, run_identity.payload["public_id"]),
            subject_digest=run_identity.digest,
            outcome="succeeded" if succeeded else "failed",
            terminal="succeeded" if succeeded else "failed",
            dependency_digests=identities,
            sequence=snapshot.sequence + 1,
            cost_steps=cost_steps,
        )

    def _issue_receipt(
        self,
        family_id: str,
        *,
        subject_id: str,
        subject_digest: str,
        outcome: str,
        terminal: str,
        dependency_digests: Mapping[str, str],
        sequence: int,
        cost_steps: int,
    ) -> ReceiptRecord:
        family = load_receipt_catalog().families[family_id]
        dependencies: list[dict[str, Any]] = []
        for spec in family.dependencies:
            kind = str(spec["dependency_kind"])
            digest = dependency_digests.get(kind)
            if digest is None:
                raise EvolutionError("missing_receipt_dependency")
            dependencies.append(
                {
                    "dependency_digest": digest,
                    "dependency_id": kind + ":" + digest[-16:],
                    "dependency_kind": kind,
                    "dependency_type": spec["dependency_type"],
                    "must_be_fresh": spec["must_be_fresh"],
                    "role": spec["role"],
                }
            )
        dependencies.sort(key=lambda item: (item["dependency_type"], item["dependency_kind"], item["dependency_id"], item["role"]))
        authority = family.issuer_authority
        issuer_id = "component:" + authority
        decision_ref = "decision:issue:" + family_id
        receipt = construct_receipt(
            {
                "append_only_disposition": "immutable",
                "artifact_refs": [],
                "chronology_is_authority": False,
                "consumers": list(family.consumers),
                "cost": {"accounting_boundary": "campaign:" + family_id, "completeness": "complete", "quantities": [{"amount": cost_steps, "unit": "steps"}]},
                "dependencies": dependencies,
                "deviations": [],
                "freshness_policy": {
                    "dependency_mode": "exact_typed_set",
                    "expiry": {"state": "absent"},
                    "policy_id": "freshness:" + family_id,
                    "revocation_authority": family.revocation_authority,
                    "revocation_view": {"state": "present", "value": {"authority_decision_ref": "decision:revocation:" + family_id, "watermark": "evolution-local-v1"}},
                    "unavailable_dependency": "unverifiable",
                },
                "integrity": {"canonicalization": "canonical-json-v1", "detached_signature": {"state": "absent"}, "digest_algorithm": "sha256", "domain": "unrest.receipt.v1"},
                "issuer": {"identity_digest": _sha(issuer_id.encode()), "issuer_id": issuer_id, "issuer_kind": "provider_configuration"},
                "issuer_authority": {"authority_class": authority, "decision_ref": decision_ref},
                "observed_at": _format_time(self._now()),
                "outcome": outcome,
                "receipt_id": "receipt:" + family_id + ":" + uuid.uuid4().hex,
                "receipt_kind": family_id,
                "schema_version": 1,
                "sequence": sequence,
                "subject": {"subject_digest": subject_digest, "subject_id": subject_id, "subject_kind": family.subject_kind},
                "terminal_disposition": terminal,
            }
        )
        self.store.append_receipt(receipt, custodian=CustodyActor(issuer_id, authority, decision_ref))
        return receipt

    def _promotion_inputs(
        self,
        snapshot: CampaignSnapshot,
        grant: HumanPromotionGrant,
        *,
        allow_promoted: bool = False,
    ) -> tuple[CandidateAttempt, EvaluationRecord, ReviewRecord]:
        if snapshot.state != "open" and not (allow_promoted and snapshot.state == "promoted"):
            raise EvolutionError("campaign_not_open")
        candidate = self._candidate(snapshot, grant.candidate_id)
        evaluation = next((item for item in snapshot.evaluations if item.candidate_id == candidate.candidate_id and item.receipt_digest == grant.evaluation_receipt_digest), None)
        review = next((item for item in snapshot.reviews if item.candidate_id == candidate.candidate_id and item.receipt_digest == grant.review_receipt_digest), None)
        if evaluation is None or review is None:
            raise EvolutionError("promotion_evidence_mismatch")
        if review.evaluation_id != evaluation.evaluation_id:
            raise EvolutionError("promotion_evidence_mismatch")
        if (
            grant.candidate_digest != candidate.candidate_digest
            or grant.lease_id != candidate.lease_id
            or grant.patch_digest != candidate.patch_digest
            or grant.expected_predecessor_revision != snapshot.freeze.accepted_revision
        ):
            raise EvolutionError("promotion_candidate_mismatch")
        if (
            evaluation.non_improving
            or evaluation.suspected_reward_hack
            or review.outcome != "approve"
            or review.dissent_digests
            or review.complete_denominator != snapshot.denominator
            or review.denominator_digest != self._denominator_digest(snapshot)
        ):
            raise EvolutionError("promotion_evidence_not_approved")
        try:
            self.store.load_receipt("evaluation_receipt.v1", evaluation.receipt_digest)
            self.store.load_receipt("review_receipt.v1", review.receipt_digest)
        except ValueError as exc:
            raise EvolutionError("promotion_evidence_unverifiable") from exc
        return candidate, evaluation, review

    def _reconcile_or_integrate(
        self,
        grant: HumanPromotionGrant,
        candidate: CandidateAttempt,
        validate: Callable[[Path], bool] | None,
        accepted_point_capability: _AcceptedPointCapability | None,
        request_fingerprint: str,
    ) -> IntegrationResult:
        lease = self.workspace_manager.inspect_workspace(candidate.lease_id)
        if lease.state == "integrated" and lease.integration_receipt_digest is not None:
            if (
                lease.integration_grant_id != grant.grant_id
                or lease.integration_request_fingerprint != request_fingerprint
            ):
                raise EvolutionError("integration_state_mismatch")
            try:
                integration_receipt = self.store.load_receipt(
                    "integration_receipt.v1", lease.integration_receipt_digest
                )
                subject = cast(Mapping[str, Any], integration_receipt.record["subject"])
                accepted_identity = self.store.load_identity(
                    "accepted_working_point", cast(str, subject["subject_digest"])
                )
                accepted = cast(str, accepted_identity.payload["base_revision"])
            except (KeyError, TypeError, ValueError) as exc:
                raise EvolutionError("integration_evidence_unverifiable") from exc
            if accepted == grant.expected_predecessor_revision or self._head_revision() != accepted:
                raise EvolutionError("integration_state_mismatch")
            return IntegrationResult(
                grant.expected_predecessor_revision,
                accepted,
                ((candidate.lease_id, candidate.patch_digest),),
                (lease.integration_receipt_digest,),
            )
        if self._head_revision() != grant.expected_predecessor_revision:
            raise EvolutionError("stale_promotion_predecessor")
        try:
            return self.workspace_manager.integrate_workspaces(
                [
                    HumanIntegrationGrant(
                        grant_id=grant.grant_id,
                        authorized_by=grant.authorized_by,
                        lease_id=grant.lease_id,
                        patch_digest=grant.patch_digest,
                        expected_parent_revision=grant.expected_predecessor_revision,
                    )
                ],
                validate=validate,
                request_fingerprint=request_fingerprint,
                _accepted_point_capability=accepted_point_capability,
            )
        except WorkspaceError as exc:
            raise EvolutionError("workspace_" + exc.code) from exc

    def _promotion_receipt(
        self,
        snapshot: CampaignSnapshot,
        candidate: CandidateAttempt,
        evaluation: EvaluationRecord,
        review: ReviewRecord,
        promotion: PromotionRecord,
    ) -> ReceiptRecord:
        accepted_dimension = _sha((promotion.accepted_revision + "\0" + promotion.predecessor_revision).encode())
        accepted = construct_identity(
            "accepted_working_point",
            {"accepted_working_point_digest": accepted_dimension, "base_revision": promotion.accepted_revision, "public_id": "accepted_working_point:" + promotion.accepted_revision[:20], "schema_version": 1},
        )
        self.store.append_identity(accepted)
        return self._issue_receipt(
            "promotion_receipt.v1",
            subject_id=candidate.candidate_id,
            subject_digest=candidate.candidate_identity_digest,
            outcome="promoted",
            terminal="promoted",
            dependency_digests={
                "accepted_working_point": accepted.digest,
                "candidate": candidate.candidate_identity_digest,
                "evaluation_receipt.v1": evaluation.receipt_digest,
                "integration_receipt.v1": promotion.integration_receipt_digest,
                "review_receipt.v1": review.receipt_digest,
            },
            sequence=snapshot.sequence + 1,
            cost_steps=0,
        )

    def _restore_exact_predecessor(
        self,
        promotion: PromotionRecord,
        validate: Callable[[Path], bool] | None,
        grant_id: str,
        request_fingerprint: str,
    ) -> None:
        transaction = self._load_rollback_transaction(request_fingerprint)
        if transaction is not None and (
            transaction.get("expected_new_revision") != promotion.predecessor_revision
            or transaction.get("expected_old_revision") != promotion.accepted_revision
            or transaction.get("grant_id") != grant_id
            or transaction.get("request_fingerprint") != request_fingerprint
        ):
            raise EvolutionError("rollback_transaction_mismatch")
        current = self._head_revision()
        if current == promotion.predecessor_revision:
            self._append_rollback_transaction(
                request_fingerprint,
                {
                    "expected_new_revision": promotion.predecessor_revision,
                    "expected_old_revision": promotion.accepted_revision,
                    "grant_id": grant_id,
                    "request_fingerprint": request_fingerprint,
                    "state": "post_ref",
                },
            )
            return
        if current != promotion.accepted_revision:
            raise EvolutionError("stale_rollback_current")
        if validate is not None:
            tree = Path(tempfile.mkdtemp(prefix="rollback-", dir=self.runtime_root))
            try:
                self._git("worktree", "add", "--detach", str(tree), promotion.predecessor_revision)
                try:
                    valid = validate(tree)
                except Exception as exc:
                    raise EvolutionError("rollback_validation_failed") from exc
                if not valid:
                    raise EvolutionError("rollback_validation_failed")
            finally:
                subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=self.repository, capture_output=True)
                shutil.rmtree(tree, ignore_errors=True)
        if transaction is None:
            self._append_rollback_transaction(
                request_fingerprint,
                {
                    "expected_new_revision": promotion.predecessor_revision,
                    "expected_old_revision": promotion.accepted_revision,
                    "grant_id": grant_id,
                    "request_fingerprint": request_fingerprint,
                    "state": "pre_ref",
                },
            )
            self._accepted_point_fault("pre_ref")
        parent_ref = self._git("symbolic-ref", "--quiet", "HEAD")
        self._git("update-ref", parent_ref, promotion.predecessor_revision, promotion.accepted_revision)
        self._git("reset", "--hard", promotion.predecessor_revision)
        self._append_rollback_transaction(
            request_fingerprint,
            {
                "expected_new_revision": promotion.predecessor_revision,
                "expected_old_revision": promotion.accepted_revision,
                "grant_id": grant_id,
                "request_fingerprint": request_fingerprint,
                "state": "post_ref",
            },
        )
        self._accepted_point_fault("post_ref")

    def _rollback_transaction_directory(self, fingerprint: str) -> Path:
        token = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        return self.durable_root / "transactions" / "rollback" / token

    def _load_rollback_transaction(
        self, fingerprint: str
    ) -> Mapping[str, Any] | None:
        events = sorted(self._rollback_transaction_directory(fingerprint).glob("*.json"))
        if not events:
            return None
        try:
            value = verify_canonical_json_bytes(events[-1].read_bytes())
        except (OSError, ValueError) as exc:
            raise EvolutionError("rollback_transaction_corrupt") from exc
        if not isinstance(value, Mapping):
            raise EvolutionError("rollback_transaction_corrupt")
        return value

    def _append_rollback_transaction(
        self,
        fingerprint: str,
        record: Mapping[str, Any],
    ) -> None:
        directory = self._rollback_transaction_directory(fingerprint)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sequence = len(tuple(directory.glob("*.json"))) + 1
        path = directory / f"{sequence:08d}.json"
        encoded = canonical_json_bytes(record)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _accepted_point_fault(self, _boundary: str) -> None:
        return None

    def _rollback_receipt(self, snapshot: CampaignSnapshot, promotion: PromotionRecord) -> ReceiptRecord:
        candidate = self._candidate(snapshot, promotion.candidate_id)
        freeze = snapshot.freeze
        accepted = construct_identity(
            "accepted_working_point",
            {"accepted_working_point_digest": freeze.accepted_working_point_digest, "base_revision": promotion.predecessor_revision, "public_id": "accepted_working_point:" + promotion.predecessor_revision[:20], "schema_version": 1},
        )
        artifact = construct_identity(
            "artifact",
            {"artifact_digest": candidate.patch_digest, "public_id": "artifact:" + candidate.patch_digest[-24:], "schema_version": 1},
        )
        policy = construct_identity(
            "policy",
            {"capability_policy_digest": freeze.capability_policy_digest, "public_id": "policy:" + freeze.capability_policy_digest[-24:], "schema_version": 1},
        )
        for identity in (accepted, artifact, policy):
            self.store.append_identity(identity)
        if promotion.promotion_receipt_digest is None:
            raise EvolutionError("promotion_receipt_missing")
        return self._issue_receipt(
            "rollback_receipt.v1",
            subject_id=cast(str, accepted.payload["public_id"]),
            subject_digest=accepted.digest,
            outcome="restored_and_validated",
            terminal="restored",
            dependency_digests={
                "accepted_working_point": accepted.digest,
                "artifact": artifact.digest,
                "integration_receipt.v1": promotion.integration_receipt_digest,
                "policy": policy.digest,
                "promotion_receipt.v1": promotion.promotion_receipt_digest,
            },
            sequence=snapshot.sequence + 1,
            cost_steps=0,
        )
