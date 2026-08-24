"""Controller/store-owned authority for accepted working-point mutations.

Workspace and evolution managers prepare and reconcile bounded transactions,
but their Git-effect methods require the opaque capability minted here.  The
capability proves call-path custody only; public effects must separately
present an exact retained human grant.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Protocol

from .canonical_identity import verify_canonical_json_bytes
from .mutation_journal import (
    _require_consumed_grant,
    _retain_external_grant,
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
    manager: Any
    grants: Sequence[Any]
    validate: Callable[[Path], bool] | None = None
    retained_grant_proof: object | None = None


@dataclass(frozen=True)
class CandidatePromotionPlan:
    manager: Any
    grant: Any
    validate: Callable[[Path], bool] | None = None
    retained_grant_proof: object | None = None


@dataclass(frozen=True)
class PromotionRollbackPlan:
    manager: Any
    grant: Any
    validate: Callable[[Path], bool] | None = None
    retained_grant_proof: object | None = None


AcceptedPointPlan = WorkspaceIntegrationPlan | CandidatePromotionPlan | PromotionRollbackPlan


def _apply_accepted_point_plan(
    store: _AcceptedPointStore,
    project_id: str,
    plan: AcceptedPointPlan,
) -> Any:
    """Apply one typed plan under the store-owned project authority."""

    repository = store.workspace_dir(project_id).resolve(strict=True)
    manager_repository = Path(plan.manager.repository).resolve(strict=True)
    if manager_repository != repository:
        raise AcceptedPointAuthorityError("unauthorized")
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
            human_grants = [
                grant for grant in plan.grants
                if str(getattr(grant, "grant_id", "")).startswith("human-grant:")
            ]
            if human_grants:
                if len(human_grants) != 1:
                    raise AcceptedPointAuthorityError("unauthorized")
                _require_consumed_grant(
                    plan.retained_grant_proof,
                    grant_id=human_grants[0].grant_id,
                    operation="integrate_workspace",
                    project_id=project_id,
                )
            return plan.manager.integrate_workspaces(
                plan.grants,
                validate=plan.validate,
                _accepted_point_capability=capability,
            )
        if isinstance(plan, CandidatePromotionPlan):
            _require_consumed_grant(
                plan.retained_grant_proof,
                grant_id=plan.grant.grant_id,
                operation="promote_candidate",
                project_id=project_id,
            )
            return plan.manager.promote_candidate(
                plan.grant,
                validate=plan.validate,
                _accepted_point_capability=capability,
            )
        if isinstance(plan, PromotionRollbackPlan):
            _require_consumed_grant(
                plan.retained_grant_proof,
                grant_id=plan.grant.grant_id,
                operation="rollback_promotion",
                project_id=project_id,
            )
            return plan.manager.rollback_promotion(
                plan.grant,
                validate=plan.validate,
                _accepted_point_capability=capability,
            )
        raise AcceptedPointAuthorityError("invalid_argument")
    except ProjectLockError as exc:
        raise AcceptedPointAuthorityError("internal_error") from exc
    finally:
        if not nested:
            lock.release()


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
        scope: Mapping[str, Any],
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
