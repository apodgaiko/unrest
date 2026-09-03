"""Integration facade for the accepted v0.3.1 foundation families."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping, cast

from .accepted_point_authority import (
    CandidatePromotionPlan,
    PromotionRollbackPlan,
    WorkspaceIntegrationPlan,
)
from .capability_policy import FINITE_CREDENTIAL_NAMES
from .canonical_identity import canonical_json_bytes
from .config import HARNESS_CONFIG_ENV_VARS, HarnessConfig
from .controller import ProjectController
from .evolution import (
    CampaignFreeze,
    CampaignSnapshot,
    CandidateAction,
    EvolutionError,
    EvolutionManager,
    HumanPromotionGrant,
    HumanRollbackGrant,
)
from .inquiry import InquiryBudget, InquiryManager
from .mutation_journal import (
    DurableMutationJournal,
    ExternalGrantVerifier,
)
from .provider_sessions import ProviderSessionRunner
from .run_control import RunControl
from .workspaces import (
    HumanIntegrationGrant,
    ResourceBudget,
    WorkspaceError,
    WorkspaceLease,
    WorkspaceManager,
)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _token(value: str, length: int = 24) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


class FoundationToolError(RuntimeError):
    """Stable error envelope for every additive public method."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.public_message = message
        super().__init__(message)

    def as_envelope(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.public_message}}


_ERROR_MAP = {
    "duplicate_lease": "conflict",
    "immutable_campaign": "conflict",
    "lease_not_active": "invalid_transition",
    "campaign_not_open": "invalid_transition",
    "workspace_not_returned": "invalid_transition",
    "write_scope_escape": "unauthorized",
    "protected_path_changed": "protected_path_changed",
    "protected_write_path": "protected_path_changed",
    "stale_base": "stale",
    "stale_parent": "stale",
    "stale_accepted_working_point": "stale",
}


def public_error(exc: Exception) -> FoundationToolError:
    code = getattr(exc, "code", "internal_error")
    stable = _ERROR_MAP.get(str(code), str(code))
    allowed = {
        "budget_exhausted", "busy", "cancelled", "conflict", "integrity_error",
        "internal_error", "invalid_argument", "invalid_transition", "not_found",
        "protected_path_changed", "provider_unavailable",
        "signature_suite_unsupported", "stale", "timeout", "unauthorized",
    }
    if stable not in allowed:
        stable = "invalid_argument"
    return FoundationToolError(stable, f"{stable.replace('_', ' ')}")


class FoundationTools:
    """One authority-aware adapter shared by MCP and library surfaces."""

    def __init__(
        self,
        config: HarnessConfig,
        controller: ProjectController,
        *,
        evolution_provider_runner: Any | None = None,
        mutation_journal_factory: Callable[[Path], DurableMutationJournal] | None = None,
    ) -> None:
        self.config = config
        # The public effect facade receives only the store authority surface.
        # Host grant admission remains structurally unreachable from this object.
        self.store = controller.store
        self._evolution_provider_runner = (
            evolution_provider_runner or ProviderSessionRunner(self.config)
        )
        self._mutation_journal_factory = (
            mutation_journal_factory or DurableMutationJournal
        )
        self.config.harness_home.mkdir(parents=True, exist_ok=True)
        worker_environment = {
            name: os.environ[name]
            for name in sorted(HARNESS_CONFIG_ENV_VARS | frozenset(FINITE_CREDENTIAL_NAMES))
            if os.environ.get(name)
        }
        worker_environment["UNREST_HOME"] = str(config.harness_home)
        worker_environment["UNREST_PROJECTS_DIR"] = str(config.projects_dir)
        self.runs = RunControl(
            config.harness_home,
            executor_ref="unrest_harness.runtime_executor:execute",
            worker_environment=worker_environment,
        )

    def _project_repository(self, project_id: str) -> Path:
        try:
            return self.store.workspace_dir(project_id).resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise FoundationToolError("not_found", "project was not found") from exc

    def _inquiry_root(self, project_id: str | None) -> Path:
        if project_id is not None:
            root = self.store.bucket_root(project_id)
            if not (root / ".unrest-runtime" / "project.json").is_file():
                raise FoundationToolError("not_found", "project was not found")
            return root
        root = self.config.harness_home / "foundation"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _project_roots(self) -> tuple[Path, ...]:
        return tuple(
            Path(record.workspace_dir).resolve()
            for record in self.store.list_projects()
        )

    def _project_id_for_repository(self, repository: Path) -> str:
        resolved = repository.resolve()
        for record in self.store.list_projects():
            if Path(record.workspace_dir).resolve() == resolved:
                return record.id
        raise FoundationToolError("not_found", "project was not found")

    def _journal(self, repository: Path) -> DurableMutationJournal:
        return self._mutation_journal_factory(repository)

    def _find_inquiry(self, inquiry_id: str) -> InquiryManager:
        foundation_root = self.config.harness_home / "foundation"
        if (
            foundation_root
            / ".unrest"
            / "inquiries"
            / inquiry_id.removeprefix("inquiry:")
        ).is_dir():
            return InquiryManager(foundation_root, self.config)
        for item in self.store.list_projects():
            root = self.store.bucket_root(item.id)
            if (
                root / ".unrest" / "inquiries" / inquiry_id.removeprefix("inquiry:")
            ).is_dir():
                return InquiryManager(
                    root,
                    self.config,
                    workspace_root=Path(item.workspace_dir),
                )
        raise FoundationToolError("not_found", "Inquiry was not found")

    def _find_workspace(self, workspace_id: str) -> WorkspaceManager:
        for root in self._project_roots():
            events = root / ".unrest" / "workspaces" / "leases" / workspace_id.removeprefix("lease:")
            if events.is_dir():
                return WorkspaceManager(root)
        raise FoundationToolError("not_found", "workspace was not found")

    def _find_campaign(self, campaign_id: str) -> EvolutionManager:
        for root in self._project_roots():
            events = root / ".unrest" / "evolution" / "campaigns" / campaign_id.removeprefix("campaign:")
            if events.is_dir():
                return EvolutionManager(
                    root,
                    provider_runner=self._evolution_provider_runner,
                )
        raise FoundationToolError("not_found", "campaign was not found")

    @staticmethod
    def _workspace_summary(lease: WorkspaceLease) -> dict[str, Any]:
        state = {"active": "leased"}.get(lease.state, lease.state)
        return {
            "workspace_id": lease.lease_id,
            "state": state,
            "base_revision": lease.base_revision,
            "lease_expires_at": lease.expires_at,
            "patch_id": lease.patch_digest,
            "receipt_id": (
                lease.integration_receipt_digest
                or lease.cleanup_receipt_digest
                or lease.patch_receipt_digest
                or lease.workspace_receipt_digest
            ),
        }

    @staticmethod
    def _campaign_summary(snapshot: CampaignSnapshot) -> dict[str, Any]:
        state: str = snapshot.state
        receipt: str | None = None
        if snapshot.rollbacks:
            receipt = snapshot.rollbacks[-1].rollback_receipt_digest
        elif snapshot.promotions:
            receipt = snapshot.promotions[-1].promotion_receipt_digest
        elif snapshot.reviews:
            receipt = snapshot.reviews[-1].receipt_digest
            state = "decision_needed"
        elif snapshot.evaluations:
            receipt = snapshot.evaluations[-1].receipt_digest
            state = "reviewing"
        return {
            "campaign_id": snapshot.campaign_id,
            "state": state,
            "candidate_ids": [item.candidate_id for item in snapshot.candidates],
            "receipt_id": receipt,
        }

    def submit_run(self, operation: str, arguments: Mapping[str, Any], idempotency_key: str) -> dict[str, Any]:
        return self.runs.submit_run(operation, arguments, idempotency_key).as_dict()

    def inspect_run(self, run_id: str) -> dict[str, Any]:
        return self.runs.inspect_run(run_id).as_dict()

    def attach_run(self, run_id: str) -> dict[str, Any]:
        return self.runs.attach_run(run_id).as_dict()

    def cancel_run(self, run_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
        return self.runs.cancel_run(run_id, reason, idempotency_key).as_dict()

    def open_inquiry(self, question: str, budget: Mapping[str, object], idempotency_key: str, project_id: str | None = None) -> dict[str, Any]:
        checked = InquiryBudget.from_mapping(budget)
        root = self._inquiry_root(project_id)
        manager = InquiryManager(
            root,
            self.config,
            workspace_root=(
                self._project_repository(project_id)
                if project_id is not None
                else root
            ),
        )
        return manager.open_inquiry(question=question, budget=checked, idempotency_key=idempotency_key, project_id=project_id).public_record()

    def inspect_inquiry(self, inquiry_id: str) -> dict[str, Any]:
        return self._find_inquiry(inquiry_id).inspect_inquiry(inquiry_id).public_record()

    async def advance_inquiry(self, inquiry_id: str, idempotency_key: str) -> dict[str, Any]:
        return (await self._find_inquiry(inquiry_id).advance_inquiry(inquiry_id, idempotency_key=idempotency_key)).public_record()

    def pause_inquiry(self, inquiry_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
        return self._find_inquiry(inquiry_id).pause_inquiry(inquiry_id, reason=reason, idempotency_key=idempotency_key).public_record()

    def resume_inquiry(self, inquiry_id: str, idempotency_key: str) -> dict[str, Any]:
        return self._find_inquiry(inquiry_id).resume_inquiry(inquiry_id, idempotency_key=idempotency_key).public_record()

    def cancel_inquiry(self, inquiry_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
        return self._find_inquiry(inquiry_id).cancel_inquiry(inquiry_id, reason=reason, idempotency_key=idempotency_key).public_record()

    def handoff_inquiry(self, inquiry_id: str, consumer_id: str, idempotency_key: str) -> dict[str, Any]:
        return self._find_inquiry(inquiry_id).handoff_inquiry(inquiry_id, consumer_id=consumer_id, idempotency_key=idempotency_key).public_record()

    def lease_workspace(self, project_id: str, base_revision: str, write_paths: list[str], idempotency_key: str, lease_seconds: int = 3600) -> dict[str, Any]:
        repository = self._project_repository(project_id)
        request = {
            "base_revision": base_revision,
            "idempotency_key": idempotency_key,
            "lease_seconds": lease_seconds,
            "project_id": project_id,
            "write_paths": list(write_paths),
        }
        lease_id = "lease:" + _token("workspace\0" + idempotency_key)

        def effect(_: str) -> Mapping[str, Any]:
            manager = WorkspaceManager(repository)
            try:
                lease = manager.lease_workspace(
                    base_revision=base_revision,
                    owner_id="public-workspace:" + project_id,
                    declared_write_paths=write_paths,
                    capability_policy_digest=_sha((self.config.bundled_dir / "policies" / "role-capabilities.v1.json").read_bytes()),
                    duration_seconds=lease_seconds,
                    lease_id=lease_id,
                    resource_budget=ResourceBudget(),
                )
            except WorkspaceError as exc:
                if exc.code != "duplicate_lease":
                    raise
                lease = manager.inspect_workspace(lease_id)
            return self._workspace_summary(lease)

        def reconcile(_: str) -> Mapping[str, Any] | None:
            try:
                return self._workspace_summary(
                    WorkspaceManager(repository).inspect_workspace(lease_id)
                )
            except WorkspaceError:
                return None

        return self._journal(repository).execute(
            operation="lease_workspace",
            resource_key=f"{project_id}\0{base_revision}\0{','.join(sorted(write_paths))}",
            idempotency_key=idempotency_key,
            request=request,
            effect=effect,
            reconcile=reconcile,
        )

    def inspect_workspace(self, workspace_id: str) -> dict[str, Any]:
        return self._workspace_summary(self._find_workspace(workspace_id).inspect_workspace(workspace_id))

    def return_workspace(self, workspace_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_workspace(workspace_id)
        repository = manager.repository
        request = {"idempotency_key": idempotency_key, "workspace_id": workspace_id}

        def effect(_: str) -> Mapping[str, Any]:
            lease = manager.inspect_workspace(workspace_id)
            if lease.state == "active":
                manager.return_workspace(workspace_id)
            elif lease.state != "returned":
                raise WorkspaceError("lease_not_active")
            return self._workspace_summary(manager.inspect_workspace(workspace_id))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            lease = manager.inspect_workspace(workspace_id)
            if lease.patch_digest is None or lease.patch_receipt_digest is None:
                return None
            return {
                **self._workspace_summary(lease),
                "state": "returned",
                "receipt_id": lease.patch_receipt_digest,
            }

        return self._journal(repository).execute(
            operation="return_workspace", resource_key=workspace_id,
            idempotency_key=idempotency_key, request=request, effect=effect,
            reconcile=reconcile,
        )

    def integrate_workspace(self, workspace_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_workspace(workspace_id)
        repository = manager.repository
        project_id = self._project_id_for_repository(repository)
        request = {
            "human_grant_id": human_grant_id,
            "idempotency_key": idempotency_key,
            "workspace_id": workspace_id,
        }

        def retained_grant(fingerprint: str) -> tuple[HumanIntegrationGrant, object]:
            lease = manager.inspect_workspace(workspace_id)
            if lease.patch_digest is None:
                raise WorkspaceError("workspace_not_returned")
            scope = {
                "expected_parent_revision": lease.base_revision,
                "patch_digest": lease.patch_digest,
                "validation_policy": "none",
                "workspace_id": workspace_id,
            }
            proof = ExternalGrantVerifier(
                repository,
                custody_root_id=manager.store.custody_root_id,
            ).consume(
                grant_id=human_grant_id,
                operation="integrate_workspace",
                project_id=project_id,
                scope=scope,
                request_fingerprint=fingerprint,
            )
            return HumanIntegrationGrant(
                human_grant_id,
                proof.authorized_by,
                workspace_id,
                lease.patch_digest,
                lease.base_revision,
            ), proof

        def effect(fingerprint: str) -> Mapping[str, Any]:
            grant, proof = retained_grant(fingerprint)
            self.store.apply_accepted_point_plan(
                project_id,
                WorkspaceIntegrationPlan(
                    (grant.lease_id,),
                    (grant.grant_id,),
                    fingerprint,
                ),
                proof,
            )
            return self._workspace_summary(manager.inspect_workspace(workspace_id))

        def reconcile(fingerprint: str) -> Mapping[str, Any] | None:
            lease = manager.inspect_workspace(workspace_id)
            if lease.state != "integrated":
                grant, proof = retained_grant(fingerprint)
                self.store.apply_accepted_point_plan(
                    project_id,
                    WorkspaceIntegrationPlan(
                        (grant.lease_id,),
                        (grant.grant_id,),
                        fingerprint,
                    ),
                    proof,
                )
                lease = manager.inspect_workspace(workspace_id)
            if (
                lease.state != "integrated"
                or lease.integration_receipt_digest is None
                or lease.integration_grant_id != human_grant_id
                or lease.integration_request_fingerprint != fingerprint
            ):
                return None
            return self._workspace_summary(lease)

        def stage(fingerprint: str) -> None:
            retained_grant(fingerprint)

        return self._journal(repository).execute(
            operation="integrate_workspace", resource_key=workspace_id,
            idempotency_key=idempotency_key, request=request, effect=effect,
            stage=stage,
            reconcile=reconcile,
        )

    def cleanup_workspace(self, workspace_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_workspace(workspace_id)
        repository = manager.repository
        request = {"idempotency_key": idempotency_key, "workspace_id": workspace_id}

        def effect(_: str) -> Mapping[str, Any]:
            manager.cleanup_workspace(workspace_id)
            return self._workspace_summary(manager.inspect_workspace(workspace_id))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            lease = manager.inspect_workspace(workspace_id)
            if lease.cleanup_receipt_digest is None:
                return None
            return self._workspace_summary(lease)

        return self._journal(repository).execute(
            operation="cleanup_workspace", resource_key=workspace_id,
            idempotency_key=idempotency_key, request=request, effect=effect,
            reconcile=reconcile,
        )

    def open_campaign(self, project_id: str, accepted_point_digest: str, workload_id: str, evaluator_id: str, reviewer_id: str, budget: Mapping[str, int], seed: int, idempotency_key: str) -> dict[str, Any]:
        repository = self._project_repository(project_id)
        request = {
            "accepted_point_digest": accepted_point_digest,
            "budget": dict(budget),
            "evaluator_id": evaluator_id,
            "idempotency_key": idempotency_key,
            "project_id": project_id,
            "reviewer_id": reviewer_id,
            "seed": seed,
            "workload_id": workload_id,
        }
        campaign_id = "campaign:" + _token("campaign\0" + idempotency_key)

        def effect(_: str) -> Mapping[str, Any]:
            revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
            policy = _sha((self.config.bundled_dir / "policies" / "role-capabilities.v1.json").read_bytes())

            def digest(label: str) -> str:
                return _sha(
                    canonical_json_bytes(
                        {
                            "label": label,
                            "project_id": project_id,
                            "workload_id": workload_id,
                        }
                    )
                )

            freeze = CampaignFreeze(
                accepted_revision=revision, accepted_working_point_digest=accepted_point_digest,
                workload_digest=digest("workload"), oracle_digest=digest("oracle"),
                author_policy_digest=digest("author-policy"), evaluator_policy_digest=digest("evaluator-policy"),
                reviewer_policy_digest=digest("reviewer-policy"), capability_policy_digest=policy,
                provider_configuration_digest=digest("provider"), route_profile_digest=digest("route"),
                context_digest=digest("context"), environment_digest=digest("environment"),
                secret_set_version_id="secret-set:local:v1", author_id="public-workspace:" + project_id,
                evaluator_id=evaluator_id, reviewer_id=reviewer_id,
                budget_steps=int(budget["max_steps"]), seed=seed,
                stopping_rule_digest=digest("stopping"), promotion_rule_digest=digest("promotion"),
                protected_paths=(".git", ".unrest", ".unrest-runtime"),
            )
            manager = EvolutionManager(
                repository,
                provider_runner=self._evolution_provider_runner,
            )
            return self._campaign_summary(manager.open_campaign(campaign_id=campaign_id, freeze=freeze))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            try:
                return self._campaign_summary(
                    EvolutionManager(
                        repository,
                        provider_runner=self._evolution_provider_runner,
                    ).inspect_campaign(campaign_id)
                )
            except EvolutionError:
                return None

        return self._journal(repository).execute(
            operation="open_campaign",
            resource_key=f"{project_id}\0{accepted_point_digest}\0{workload_id}",
            idempotency_key=idempotency_key,
            request=request,
            effect=effect,
            reconcile=reconcile,
        )

    def inspect_campaign(self, campaign_id: str) -> dict[str, Any]:
        return self._campaign_summary(self._find_campaign(campaign_id).inspect_campaign(campaign_id))

    def add_candidate(self, campaign_id: str, artifact_id: str, action: str, idempotency_key: str, parent_candidate_id: str | None = None) -> dict[str, Any]:
        manager = self._find_campaign(campaign_id)
        repository = manager.repository
        request = {
            "action": action,
            "artifact_id": artifact_id,
            "campaign_id": campaign_id,
            "idempotency_key": idempotency_key,
            "parent_candidate_id": parent_candidate_id,
        }
        candidate_id = "candidate:" + _token("candidate\0" + idempotency_key)

        def effect(_: str) -> Mapping[str, Any]:
            snapshot = manager.inspect_campaign(campaign_id)
            translated = "original" if action == "initial" else action
            if not any(item.candidate_id == candidate_id for item in snapshot.candidates):
                manager.add_candidate(
                    campaign_id=campaign_id,
                    lease_id=artifact_id,
                    action=cast(CandidateAction, translated),
                    parent_candidate_id=parent_candidate_id,
                    candidate_id=candidate_id,
                    author_id=snapshot.freeze.author_id,
                )
            return self._campaign_summary(manager.inspect_campaign(campaign_id))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            snapshot = manager.inspect_campaign(campaign_id)
            if not any(item.candidate_id == candidate_id for item in snapshot.candidates):
                return None
            return self._campaign_summary(snapshot)

        return self._journal(repository).execute(
            operation="add_candidate", resource_key=campaign_id,
            idempotency_key=idempotency_key, request=request, effect=effect,
            reconcile=reconcile,
        )

    async def evaluate_candidate(self, campaign_id: str, candidate_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_campaign(campaign_id)
        request = {
            "campaign_id": campaign_id,
            "candidate_id": candidate_id,
            "idempotency_key": idempotency_key,
        }
        evaluation_id = "evaluation:" + _token("evaluation\0" + idempotency_key)

        async def effect(_: str) -> Mapping[str, Any]:
            await manager.evaluate_candidate(campaign_id=campaign_id, candidate_id=candidate_id, evaluation_id=evaluation_id)
            return self._campaign_summary(manager.inspect_campaign(campaign_id))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            snapshot = manager.inspect_campaign(campaign_id)
            if not any(item.evaluation_id == evaluation_id for item in snapshot.evaluations):
                return None
            return self._campaign_summary(snapshot)

        return await self._journal(manager.repository).execute_async(
            operation="evaluate_candidate", resource_key=f"{campaign_id}\0{candidate_id}",
            idempotency_key=idempotency_key, request=request, effect=effect,
            reconcile=reconcile,
        )

    async def review_candidate(self, campaign_id: str, candidate_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_campaign(campaign_id)
        request = {
            "campaign_id": campaign_id,
            "candidate_id": candidate_id,
            "idempotency_key": idempotency_key,
        }
        review_id = "review:" + _token("review\0" + idempotency_key)

        async def effect(_: str) -> Mapping[str, Any]:
            snapshot = manager.inspect_campaign(campaign_id)
            evaluations = [item for item in snapshot.evaluations if item.candidate_id == candidate_id]
            if not evaluations:
                raise EvolutionError("evaluation_not_found")
            await manager.review_candidate(campaign_id=campaign_id, candidate_id=candidate_id, evaluation_id=evaluations[-1].evaluation_id, review_id=review_id)
            return self._campaign_summary(manager.inspect_campaign(campaign_id))

        def reconcile(_: str) -> Mapping[str, Any] | None:
            snapshot = manager.inspect_campaign(campaign_id)
            if not any(item.review_id == review_id for item in snapshot.reviews):
                return None
            return self._campaign_summary(snapshot)

        return await self._journal(manager.repository).execute_async(
            operation="review_candidate", resource_key=f"{campaign_id}\0{candidate_id}",
            idempotency_key=idempotency_key, request=request, effect=effect,
            reconcile=reconcile,
        )

    def promote_candidate(self, campaign_id: str, candidate_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_campaign(campaign_id)
        repository = manager.repository
        project_id = self._project_id_for_repository(repository)
        request = {
            "campaign_id": campaign_id,
            "candidate_id": candidate_id,
            "human_grant_id": human_grant_id,
            "idempotency_key": idempotency_key,
        }

        def retained_grant(fingerprint: str) -> tuple[HumanPromotionGrant, object]:
            snapshot = manager.inspect_campaign(campaign_id)
            candidate = next((item for item in snapshot.candidates if item.candidate_id == candidate_id), None)
            evaluation = next((item for item in reversed(snapshot.evaluations) if item.candidate_id == candidate_id), None)
            review = next((item for item in reversed(snapshot.reviews) if item.candidate_id == candidate_id), None)
            if candidate is None or evaluation is None or review is None:
                raise EvolutionError("promotion_evidence_mismatch")
            scope = {
                "campaign_id": campaign_id,
                "candidate_digest": candidate.candidate_digest,
                "candidate_id": candidate_id,
                "evaluation_receipt_digest": evaluation.receipt_digest,
                "expected_predecessor_revision": snapshot.freeze.accepted_revision,
                "lease_id": candidate.lease_id,
                "patch_digest": candidate.patch_digest,
                "review_receipt_digest": review.receipt_digest,
                "validation_policy": "none",
            }
            proof = ExternalGrantVerifier(
                repository,
                custody_root_id=manager.store.custody_root_id,
            ).consume(
                grant_id=human_grant_id,
                operation="promote_candidate",
                project_id=project_id,
                scope=scope,
                request_fingerprint=fingerprint,
            )
            return HumanPromotionGrant(
                human_grant_id, proof.authorized_by, campaign_id, candidate_id,
                candidate.candidate_digest, snapshot.freeze.accepted_revision, candidate.lease_id,
                candidate.patch_digest, evaluation.receipt_digest, review.receipt_digest,
            ), proof

        def effect(fingerprint: str) -> Mapping[str, Any]:
            grant, proof = retained_grant(fingerprint)
            self.store.apply_accepted_point_plan(
                project_id,
                CandidatePromotionPlan(
                    grant.campaign_id,
                    grant.candidate_id,
                    grant.grant_id,
                    fingerprint,
                ),
                proof,
            )
            return self._campaign_summary(manager.inspect_campaign(campaign_id))

        def reconcile(fingerprint: str) -> Mapping[str, Any] | None:
            snapshot = manager.inspect_campaign(campaign_id)
            if not any(
                item.grant_id == human_grant_id
                and item.promotion_receipt_digest is not None
                for item in snapshot.promotions
            ):
                grant, proof = retained_grant(fingerprint)
                self.store.apply_accepted_point_plan(
                    project_id,
                    CandidatePromotionPlan(
                        grant.campaign_id,
                        grant.candidate_id,
                        grant.grant_id,
                        fingerprint,
                    ),
                    proof,
                )
                snapshot = manager.inspect_campaign(campaign_id)
            return self._campaign_summary(snapshot)

        def stage(fingerprint: str) -> None:
            retained_grant(fingerprint)

        return self._journal(repository).execute(
            operation="promote_candidate", resource_key=f"{campaign_id}\0{candidate_id}",
            idempotency_key=idempotency_key, request=request, effect=effect,
            stage=stage,
            reconcile=reconcile,
        )

    def rollback_promotion(self, campaign_id: str, promotion_receipt_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
        manager = self._find_campaign(campaign_id)
        repository = manager.repository
        project_id = self._project_id_for_repository(repository)
        request = {
            "campaign_id": campaign_id,
            "human_grant_id": human_grant_id,
            "idempotency_key": idempotency_key,
            "promotion_receipt_id": promotion_receipt_id,
        }

        def retained_grant(fingerprint: str) -> tuple[HumanRollbackGrant, object]:
            snapshot = manager.inspect_campaign(campaign_id)
            promotion = next((item for item in snapshot.promotions if item.promotion_receipt_digest == promotion_receipt_id), None)
            if promotion is None:
                raise EvolutionError("promotion_not_complete")
            scope = {
                "campaign_id": campaign_id,
                "expected_current_revision": promotion.accepted_revision,
                "promotion_id": promotion.promotion_id,
                "promotion_receipt_id": promotion_receipt_id,
                "rollback_target_revision": promotion.predecessor_revision,
                "validation_policy": "none",
            }
            proof = ExternalGrantVerifier(
                repository,
                custody_root_id=manager.store.custody_root_id,
            ).consume(
                grant_id=human_grant_id,
                operation="rollback_promotion",
                project_id=project_id,
                scope=scope,
                request_fingerprint=fingerprint,
            )
            return HumanRollbackGrant(
                human_grant_id,
                proof.authorized_by,
                campaign_id,
                promotion.promotion_id,
                promotion.accepted_revision,
                promotion.predecessor_revision,
            ), proof

        def effect(fingerprint: str) -> Mapping[str, Any]:
            grant, proof = retained_grant(fingerprint)
            self.store.apply_accepted_point_plan(
                project_id,
                PromotionRollbackPlan(
                    grant.campaign_id,
                    promotion_receipt_id,
                    grant.grant_id,
                    fingerprint,
                ),
                proof,
            )
            return self._campaign_summary(manager.inspect_campaign(campaign_id))

        def reconcile(fingerprint: str) -> Mapping[str, Any] | None:
            snapshot = manager.inspect_campaign(campaign_id)
            if not any(
                item.grant_id == human_grant_id
                and item.rollback_receipt_digest is not None
                for item in snapshot.rollbacks
            ):
                grant, proof = retained_grant(fingerprint)
                self.store.apply_accepted_point_plan(
                    project_id,
                    PromotionRollbackPlan(
                        grant.campaign_id,
                        promotion_receipt_id,
                        grant.grant_id,
                        fingerprint,
                    ),
                    proof,
                )
                snapshot = manager.inspect_campaign(campaign_id)
            return self._campaign_summary(snapshot)

        def stage(fingerprint: str) -> None:
            retained_grant(fingerprint)

        return self._journal(repository).execute(
            operation="rollback_promotion",
            resource_key=f"{campaign_id}\0{promotion_receipt_id}",
            idempotency_key=idempotency_key,
            request=request,
            effect=effect,
            stage=stage,
            reconcile=reconcile,
        )


__all__ = ["FoundationToolError", "FoundationTools", "public_error"]
