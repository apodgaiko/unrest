"""Controller/store-owned authority for accepted working-point mutations.

Workspace and evolution managers prepare and reconcile bounded transactions,
but their Git-effect methods require the opaque capability minted here.  The
capability proves call-path custody only; public effects must separately
present an exact retained human grant.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess
from typing import Literal, Protocol

from .canonical_identity import verify_canonical_json_bytes
from .mutation_journal import (
    _require_consumed_grant,
    _retain_external_grant,
    request_fingerprint_for_scope,
)
from .project_lock import (
    ProjectLockError,
    ProjectMutationLock,
    project_mutation_lock_held,
)


class AcceptedPointAuthorityError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _AcceptedPointStore(Protocol):
    def workspace_dir(self, project_id: str) -> Path: ...

    def mutation_lock_path(self, project_id: str) -> Path: ...

    def mission_dir(self, project_id: str, mission_id: str) -> Path: ...


_CAPABILITY_GUARD = object()
_ACTOR_GUARD = object()


class _AcceptedPointCapability:
    """Opaque identity capability accepted only by manager effect methods."""

    __slots__ = ("_guard", "project_id", "repository")

    def __init__(
        self,
        guard: object,
        *,
        project_id: str,
        repository: Path,
    ) -> None:
        if guard is not _CAPABILITY_GUARD:
            raise TypeError("accepted-point capability is controller-owned")
        self._guard = guard
        self.project_id = project_id
        self.repository = repository


def _require_accepted_point_capability(
    capability: _AcceptedPointCapability | None,
    repository: Path,
) -> None:
    if (
        not isinstance(capability, _AcceptedPointCapability)
        or capability._guard is not _CAPABILITY_GUARD
        or capability.repository != repository.resolve()
    ):
        raise AcceptedPointAuthorityError("parent_authority_required")


@dataclass(frozen=True)
class WorkspaceIntegrationPlan:
    lease_ids: tuple[str, ...]
    grant_ids: tuple[str, ...]
    request_fingerprint: str
    validation_policy: Literal["none", "git_index_check"] = "none"


@dataclass(frozen=True)
class CandidatePromotionPlan:
    campaign_id: str
    candidate_id: str
    grant_id: str
    request_fingerprint: str
    validation_policy: Literal["none", "git_index_check"] = "none"


@dataclass(frozen=True)
class PromotionRollbackPlan:
    campaign_id: str
    promotion_receipt_id: str
    grant_id: str
    request_fingerprint: str
    validation_policy: Literal["none", "git_index_check"] = "none"


AcceptedPointPlan = WorkspaceIntegrationPlan | CandidatePromotionPlan | PromotionRollbackPlan


_MISSION_PROOF_GUARD = object()


class _MissionGrantProof:
    __slots__ = (
        "_guard",
        "mission_id",
        "project_id",
        "request_fingerprint",
        "scope_digest",
    )

    def __init__(
        self,
        guard: object,
        *,
        mission_id: str,
        project_id: str,
        request_fingerprint: str,
        scope_digest: str,
    ) -> None:
        if guard is not _MISSION_PROOF_GUARD:
            raise TypeError("mission proofs are store-owned")
        self._guard = guard
        self.mission_id = mission_id
        self.project_id = project_id
        self.request_fingerprint = request_fingerprint
        self.scope_digest = scope_digest


def _mint_mission_grant_proof(
    store: _AcceptedPointStore,
    project_id: str,
    mission_id: str,
    plan: WorkspaceIntegrationPlan,
) -> _MissionGrantProof:
    if not store.mission_dir(project_id, mission_id).is_dir():
        raise AcceptedPointAuthorityError("unauthorized")
    scope = _workspace_plan_scope(plan)
    return _MissionGrantProof(
        _MISSION_PROOF_GUARD,
        mission_id=mission_id,
        project_id=project_id,
        request_fingerprint=plan.request_fingerprint,
        scope_digest=request_fingerprint_for_scope(scope),
    )


def _apply_accepted_point_plan(
    store: _AcceptedPointStore,
    project_id: str,
    plan: AcceptedPointPlan,
    issuer_proof: object,
) -> object:
    """Apply one typed plan under the store-owned project authority."""

    repository = store.workspace_dir(project_id).resolve(strict=True)
    if not plan.request_fingerprint.startswith("sha256:"):
        raise AcceptedPointAuthorityError("invalid_argument")
    lock_path = store.mutation_lock_path(project_id)
    nested = project_mutation_lock_held(lock_path)
    lock = ProjectMutationLock(lock_path)
    try:
        if not nested and not lock.try_acquire():
            raise AcceptedPointAuthorityError("busy")
        capability = _AcceptedPointCapability(
            _CAPABILITY_GUARD,
            project_id=project_id,
            repository=repository,
        )
        if isinstance(plan, WorkspaceIntegrationPlan):
            from .workspaces import HumanIntegrationGrant, WorkspaceManager

            if (
                not plan.lease_ids
                or len(plan.lease_ids) != len(plan.grant_ids)
                or tuple(sorted(plan.lease_ids)) != plan.lease_ids
            ):
                raise AcceptedPointAuthorityError("invalid_argument")
            workspace_manager = WorkspaceManager(
                repository, custody_root_id=_local_custody_root_id(repository)
            )
            leases = tuple(
                workspace_manager.inspect_workspace(item) for item in plan.lease_ids
            )
            scope = _workspace_plan_scope(plan)
            human = all(item.startswith("human-grant:") for item in plan.grant_ids)
            mission = all(item.startswith("mission-grant:") for item in plan.grant_ids)
            if human and len(plan.grant_ids) == 1:
                human_proof = _require_consumed_grant(
                    issuer_proof,
                    grant_id=plan.grant_ids[0],
                    operation="integrate_workspace",
                    project_id=project_id,
                    request_fingerprint=plan.request_fingerprint,
                    scope={
                        "expected_parent_revision": leases[0].base_revision,
                        "patch_digest": leases[0].patch_digest,
                        "validation_policy": plan.validation_policy,
                        "workspace_id": leases[0].lease_id,
                    },
                )
                authorized_by = human_proof.authorized_by
            elif mission:
                _require_mission_proof(issuer_proof, project_id, plan, scope)
                authorized_by = "mission-plan-parent-authority"
            else:
                raise AcceptedPointAuthorityError("unauthorized")
            grants = tuple(
                HumanIntegrationGrant(
                    grant_id=grant_id,
                    authorized_by=authorized_by,
                    lease_id=lease.lease_id,
                    patch_digest=lease.patch_digest or "",
                    expected_parent_revision=lease.base_revision,
                )
                for grant_id, lease in zip(plan.grant_ids, leases, strict=True)
            )
            return workspace_manager.integrate_workspaces(
                grants,
                validate=_validation(plan.validation_policy),
                request_fingerprint=plan.request_fingerprint,
                _accepted_point_capability=capability,
            )
        if isinstance(plan, CandidatePromotionPlan):
            from .evolution import EvolutionManager, HumanPromotionGrant
            from .workspaces import WorkspaceManager

            custody_root_id = _local_custody_root_id(repository)
            promotion_manager = EvolutionManager(
                repository,
                custody_root_id=custody_root_id,
                workspace_manager=WorkspaceManager(
                    repository, custody_root_id=custody_root_id
                ),
            )
            snapshot = promotion_manager.inspect_campaign(plan.campaign_id)
            candidate = next(
                (item for item in snapshot.candidates if item.candidate_id == plan.candidate_id),
                None,
            )
            evaluation = next(
                (item for item in reversed(snapshot.evaluations) if item.candidate_id == plan.candidate_id),
                None,
            )
            review = next(
                (item for item in reversed(snapshot.reviews) if item.candidate_id == plan.candidate_id),
                None,
            )
            if candidate is None or evaluation is None or review is None:
                raise AcceptedPointAuthorityError("invalid_transition")
            scope = {
                "campaign_id": plan.campaign_id,
                "candidate_digest": candidate.candidate_digest,
                "candidate_id": plan.candidate_id,
                "evaluation_receipt_digest": evaluation.receipt_digest,
                "expected_predecessor_revision": snapshot.freeze.accepted_revision,
                "lease_id": candidate.lease_id,
                "patch_digest": candidate.patch_digest,
                "review_receipt_digest": review.receipt_digest,
                "validation_policy": plan.validation_policy,
            }
            human_proof = _require_consumed_grant(
                issuer_proof,
                grant_id=plan.grant_id,
                operation="promote_candidate",
                project_id=project_id,
                request_fingerprint=plan.request_fingerprint,
                scope=scope,
            )
            promotion_grant = HumanPromotionGrant(
                plan.grant_id,
                human_proof.authorized_by,
                plan.campaign_id,
                plan.candidate_id,
                candidate.candidate_digest,
                snapshot.freeze.accepted_revision,
                candidate.lease_id,
                candidate.patch_digest,
                evaluation.receipt_digest,
                review.receipt_digest,
            )
            return promotion_manager.promote_candidate(
                promotion_grant,
                validate=_validation(plan.validation_policy),
                request_fingerprint=plan.request_fingerprint,
                _accepted_point_capability=capability,
            )
        if isinstance(plan, PromotionRollbackPlan):
            from .evolution import EvolutionManager, HumanRollbackGrant
            from .workspaces import WorkspaceManager

            custody_root_id = _local_custody_root_id(repository)
            rollback_manager = EvolutionManager(
                repository,
                custody_root_id=custody_root_id,
                workspace_manager=WorkspaceManager(
                    repository, custody_root_id=custody_root_id
                ),
            )
            snapshot = rollback_manager.inspect_campaign(plan.campaign_id)
            promotion = next(
                (item for item in snapshot.promotions if item.promotion_receipt_digest == plan.promotion_receipt_id),
                None,
            )
            if promotion is None:
                raise AcceptedPointAuthorityError("invalid_transition")
            scope = {
                "campaign_id": plan.campaign_id,
                "expected_current_revision": promotion.accepted_revision,
                "promotion_id": promotion.promotion_id,
                "promotion_receipt_id": plan.promotion_receipt_id,
                "rollback_target_revision": promotion.predecessor_revision,
                "validation_policy": plan.validation_policy,
            }
            human_proof = _require_consumed_grant(
                issuer_proof,
                grant_id=plan.grant_id,
                operation="rollback_promotion",
                project_id=project_id,
                request_fingerprint=plan.request_fingerprint,
                scope=scope,
            )
            rollback_grant = HumanRollbackGrant(
                plan.grant_id,
                human_proof.authorized_by,
                plan.campaign_id,
                promotion.promotion_id,
                promotion.accepted_revision,
                promotion.predecessor_revision,
            )
            return rollback_manager.rollback_promotion(
                rollback_grant,
                validate=_validation(plan.validation_policy),
                request_fingerprint=plan.request_fingerprint,
                _accepted_point_capability=capability,
            )
        raise AcceptedPointAuthorityError("invalid_argument")
    except ProjectLockError as exc:
        raise AcceptedPointAuthorityError("internal_error") from exc
    finally:
        if not nested:
            lock.release()


def _workspace_plan_scope(plan: WorkspaceIntegrationPlan) -> Mapping[str, object]:
    return {
        "grant_ids": list(plan.grant_ids),
        "lease_ids": list(plan.lease_ids),
        "validation_policy": plan.validation_policy,
    }


def _require_mission_proof(
    proof: object,
    project_id: str,
    plan: WorkspaceIntegrationPlan,
    scope: Mapping[str, object],
) -> None:
    if (
        not isinstance(proof, _MissionGrantProof)
        or proof._guard is not _MISSION_PROOF_GUARD
        or proof.project_id != project_id
        or proof.request_fingerprint != plan.request_fingerprint
        or proof.scope_digest != request_fingerprint_for_scope(scope)
    ):
        raise AcceptedPointAuthorityError("unauthorized")


def _validation(policy: str):
    if policy == "none":
        return None
    if policy == "git_index_check":
        return _validate_git_index
    raise AcceptedPointAuthorityError("invalid_argument")


def _validate_git_index(worktree: Path) -> bool:
    return subprocess.run(
        ["git", "diff", "--cached", "--check"],
        cwd=worktree,
        check=False,
        capture_output=True,
    ).returncode == 0


class _LocalHostActor:
    """Identity object minted by the controller for a local operator session."""

    __slots__ = ("_guard", "actor_id", "custody_root_id", "identity_digest")

    def __init__(
        self,
        guard: object,
        *,
        actor_id: str,
        custody_root_id: str,
        identity_digest: str,
    ) -> None:
        if guard is not _ACTOR_GUARD:
            raise TypeError("local host actor must be controller-authenticated")
        self._guard = guard
        self.actor_id = actor_id
        self.custody_root_id = custody_root_id
        self.identity_digest = identity_digest


def _mint_local_host_actor(repository: Path, actor_id: str) -> _LocalHostActor:
    """Controller-only factory binding an injected actor to local custody."""

    if not actor_id or any(character.isspace() for character in actor_id):
        raise AcceptedPointAuthorityError("invalid_argument")
    custody_root_id = _local_custody_root_id(repository)
    digest = "sha256:" + hashlib.sha256(
        (
            "unrest.local-host-actor.v1\0"
            + custody_root_id
            + "\0"
            + actor_id
        ).encode("utf-8")
    ).hexdigest()
    return _LocalHostActor(
        _ACTOR_GUARD,
        actor_id=actor_id,
        custody_root_id=custody_root_id,
        identity_digest=digest,
    )


class HostGrantCustodian:
    """Supported non-MCP local operator seam for immutable grant admission."""

    def __init__(self, repository: Path, project_id: str, actor: _LocalHostActor) -> None:
        resolved = repository.resolve(strict=True)
        if (
            actor._guard is not _ACTOR_GUARD
            or actor.custody_root_id != _local_custody_root_id(resolved)
        ):
            raise AcceptedPointAuthorityError("unauthorized")
        self.repository = resolved
        self.project_id = project_id
        self.actor = actor

    def admit(
        self,
        *,
        grant_id: str,
        operation: str,
        scope: Mapping[str, object],
    ) -> None:
        _retain_external_grant(
            self.repository,
            custody_root_id=self.actor.custody_root_id,
            grant_id=grant_id,
            authorized_by=self.actor.actor_id,
            issuer_custody_root_id=self.actor.custody_root_id,
            issuer_identity_digest=self.actor.identity_digest,
            operation=operation,
            project_id=self.project_id,
            scope=scope,
        )


def _local_custody_root_id(repository: Path) -> str:
    try:
        record = verify_canonical_json_bytes(
            (repository / ".unrest" / "foundation" / "custody-root.json").read_bytes()
        )
    except (OSError, ValueError) as exc:
        raise AcceptedPointAuthorityError("unauthorized") from exc
    value = record.get("custody_root_id") if isinstance(record, Mapping) else None
    if not isinstance(value, str) or not value:
        raise AcceptedPointAuthorityError("unauthorized")
    return value


__all__ = [
    "AcceptedPointAuthorityError",
    "CandidatePromotionPlan",
    "HostGrantCustodian",
    "PromotionRollbackPlan",
    "WorkspaceIntegrationPlan",
]
