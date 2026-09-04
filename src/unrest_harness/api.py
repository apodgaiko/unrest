"""Installed-library surface for the v0.3.1 foundation runtime.

The function names and signatures are frozen by
``docs/v03/v0.3.1/public-surface.v1.json``.  MCP delegates to the same
``FoundationTools`` methods; this module adds no second execution path.
"""
from __future__ import annotations

from collections.abc import Mapping
import inspect
import re
from typing import Any

from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
from .config import HarnessConfig
from .controller import ProjectController
from .coordinator import MissionCoordinator
from .foundation_tools import FoundationToolError, FoundationTools, public_error
from .measurement import MeasurementError, measure_baseline as _measure_baseline
from .evolution import CampaignFreeze, EvolutionError, EvolutionManager
from .improve_adapter import (
    ImprovementAdapterError,
    ImprovementRequest,
    ImprovementResult,
    run_improvement as _run_improvement,
)
from .project_adapter import (
    CancellationSignal,
    ProjectDag,
    ProjectRunResult,
    run_project as _run_project,
)
from .public_schema import (
    PublicSchemaValidationError,
    validate_public_request,
    validate_public_result,
)
from .task_adapter import (
    InquiryLifecycle,
    TaskRequest,
    TaskResult,
    run_task as _run_task,
)
from .models import SteeringRequest
from .run_control import RunControlError
from .supervision import steer_attempt as apply_steering


_PUBLIC_ID = re.compile(r"^[a-z][a-z0-9-]*:[a-z0-9][a-z0-9-]*$")
_LEASE_ID = re.compile(r"^lease:[a-z0-9-]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class _IntegratedFoundationTools:
    """Compose supervision without changing the authenticated foundation slice."""

    def __init__(self, tools: Any, controller: ProjectController) -> None:
        self._tools = tools
        runs = getattr(tools, "runs", None)
        if runs is not None:
            def inspect_active_attempts(project_id: str) -> dict[str, Any]:
                return {
                    "active_attempts": [
                        snapshot.model_dump(mode="json")
                        for snapshot in controller.inspect_project_live(
                            project_id
                        ).active_attempts
                    ]
                }

            runs.project_inspector = inspect_active_attempts
            runs.steering_handler = lambda request: apply_steering(
                controller.store,
                SteeringRequest.model_validate(request),
                project_guard=False,
            ).model_dump(mode="json")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tools, name)

    def steer_attempt(
        self, run_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            checked = SteeringRequest.model_validate(request)
            return dict(
                self._tools.runs.steer_attempt(
                    run_id, checked.model_dump(mode="json")
                )
            )
        except RunControlError as exc:
            raise FoundationToolError(exc.code, exc.public_message) from exc
        except Exception as exc:
            raise FoundationToolError("invalid_argument", "invalid argument") from exc


def _integrated_tools(
    config: HarnessConfig,
    controller: ProjectController,
    *,
    tools: Any | None = None,
) -> _IntegratedFoundationTools:
    return _IntegratedFoundationTools(
        FoundationTools(config, controller) if tools is None else tools,
        controller,
    )


def _tools() -> _IntegratedFoundationTools:
    config = HarnessConfig.discover()
    controller = ProjectController(
        config, ACPNodeDispatcher(config), ACPTerminalReviewer(config)
    )
    return _integrated_tools(config, controller)


def _call(name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    tools = _tools()
    method = getattr(tools, name)
    try:
        request = inspect.signature(method).bind(*args, **kwargs)
        request.apply_defaults()
        validate_public_request(name, dict(request.arguments))
    except (PublicSchemaValidationError, TypeError, ValueError):
        raise FoundationToolError("invalid_argument", "invalid argument") from None
    except RuntimeError:
        raise FoundationToolError("internal_error", "internal error") from None
    try:
        result = method(*args, **kwargs)
    except Exception as exc:
        raise public_error(exc) from None
    try:
        validate_public_result(name, result)
    except (PublicSchemaValidationError, RuntimeError):
        raise FoundationToolError("internal_error", "internal error") from None
    return result


async def _call_async(name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    tools = _tools()
    method = getattr(tools, name)
    try:
        request = inspect.signature(method).bind(*args, **kwargs)
        request.apply_defaults()
        validate_public_request(name, dict(request.arguments))
    except (PublicSchemaValidationError, TypeError, ValueError):
        raise FoundationToolError("invalid_argument", "invalid argument") from None
    except RuntimeError:
        raise FoundationToolError("internal_error", "internal error") from None
    try:
        result = await method(*args, **kwargs)
    except Exception as exc:
        raise public_error(exc) from None
    try:
        validate_public_result(name, result)
    except (PublicSchemaValidationError, RuntimeError):
        raise FoundationToolError("internal_error", "internal error") from None
    return result


def submit_run(operation: str, arguments: Mapping[str, Any], idempotency_key: str) -> dict[str, Any]:
    return _call("submit_run", operation, arguments, idempotency_key)


def inspect_run(run_id: str) -> dict[str, Any]:
    return _call("inspect_run", run_id)


def attach_run(run_id: str) -> dict[str, Any]:
    return _call("attach_run", run_id)


def cancel_run(run_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
    return _call("cancel_run", run_id, reason, idempotency_key)


def steer_attempt(run_id: str, request: Mapping[str, Any]) -> dict[str, Any]:
    return _call("steer_attempt", run_id, request)


def open_inquiry(question: str, budget: Mapping[str, int], idempotency_key: str, project_id: str | None = None) -> dict[str, Any]:
    return _call("open_inquiry", question, budget, idempotency_key, project_id)


def inspect_inquiry(inquiry_id: str) -> dict[str, Any]:
    return _call("inspect_inquiry", inquiry_id)


async def advance_inquiry(inquiry_id: str, idempotency_key: str) -> dict[str, Any]:
    return await _call_async("advance_inquiry", inquiry_id, idempotency_key)


def pause_inquiry(inquiry_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
    return _call("pause_inquiry", inquiry_id, reason, idempotency_key)


def resume_inquiry(inquiry_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("resume_inquiry", inquiry_id, idempotency_key)


def cancel_inquiry(inquiry_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
    return _call("cancel_inquiry", inquiry_id, reason, idempotency_key)


def handoff_inquiry(inquiry_id: str, consumer_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("handoff_inquiry", inquiry_id, consumer_id, idempotency_key)


def lease_workspace(project_id: str, base_revision: str, write_paths: list[str], idempotency_key: str, lease_seconds: int = 3600) -> dict[str, Any]:
    return _call("lease_workspace", project_id, base_revision, write_paths, idempotency_key, lease_seconds)


def inspect_workspace(workspace_id: str) -> dict[str, Any]:
    return _call("inspect_workspace", workspace_id)


def return_workspace(workspace_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("return_workspace", workspace_id, idempotency_key)


def integrate_workspace(workspace_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("integrate_workspace", workspace_id, human_grant_id, idempotency_key)


def cleanup_workspace(workspace_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("cleanup_workspace", workspace_id, idempotency_key)


def open_campaign(project_id: str, accepted_point_digest: str, workload_id: str, evaluator_id: str, reviewer_id: str, budget: Mapping[str, int], seed: int, idempotency_key: str) -> dict[str, Any]:
    return _call("open_campaign", project_id, accepted_point_digest, workload_id, evaluator_id, reviewer_id, budget, seed, idempotency_key)


def inspect_campaign(campaign_id: str) -> dict[str, Any]:
    return _call("inspect_campaign", campaign_id)


def add_candidate(campaign_id: str, artifact_id: str, action: str, idempotency_key: str, parent_candidate_id: str | None = None) -> dict[str, Any]:
    return _call("add_candidate", campaign_id, artifact_id, action, idempotency_key, parent_candidate_id)


async def evaluate_candidate(campaign_id: str, candidate_id: str, idempotency_key: str) -> dict[str, Any]:
    return await _call_async("evaluate_candidate", campaign_id, candidate_id, idempotency_key)


async def review_candidate(campaign_id: str, candidate_id: str, idempotency_key: str) -> dict[str, Any]:
    return await _call_async("review_candidate", campaign_id, candidate_id, idempotency_key)


def promote_candidate(campaign_id: str, candidate_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("promote_candidate", campaign_id, candidate_id, human_grant_id, idempotency_key)


def rollback_promotion(campaign_id: str, promotion_receipt_id: str, human_grant_id: str, idempotency_key: str) -> dict[str, Any]:
    return _call("rollback_promotion", campaign_id, promotion_receipt_id, human_grant_id, idempotency_key)


def measure_baseline(
    protocol: str,
    destination: str,
    confirm_provider_work: bool,
) -> dict[str, Any]:
    request = {
        "protocol": protocol,
        "destination": destination,
        "confirm_provider_work": confirm_provider_work,
    }
    try:
        validate_public_request("measure-baseline", request)
    except PublicSchemaValidationError:
        raise FoundationToolError("invalid_argument", "invalid argument") from None
    except RuntimeError:
        raise FoundationToolError("internal_error", "internal error") from None
    try:
        result = _measure_baseline(protocol, destination, confirm_provider_work)
    except MeasurementError:
        raise FoundationToolError("invalid_argument", "invalid argument") from None
    try:
        validate_public_result("measure-baseline", result)
    except (PublicSchemaValidationError, RuntimeError):
        raise FoundationToolError("internal_error", "internal error") from None
    return result


async def run_task(
    request: TaskRequest,
    *,
    lifecycle: InquiryLifecycle | None = None,
) -> TaskResult:
    """Execute the bounded task adapter through the installed Python carrier."""

    checked_lifecycle = lifecycle if lifecycle is not None else _tools()
    return await _run_task(checked_lifecycle, request)


def run_project(
    coordinator: MissionCoordinator,
    mission_id: str,
    project: ProjectDag,
    *,
    max_steps: int,
    cancel: CancellationSignal | None = None,
) -> ProjectRunResult:
    """Execute an exact, already-submitted project DAG through the Python carrier."""

    return _run_project(
        coordinator,
        mission_id,
        project,
        max_steps=max_steps,
        cancel=cancel,
    )


def _invalid_improvement_request() -> ImprovementAdapterError:
    return ImprovementAdapterError("invalid_argument", operation="open")


def _validate_improvement_request(request: ImprovementRequest) -> None:
    try:
        freeze = (
            request.freeze
            if isinstance(request.freeze, CampaignFreeze)
            else CampaignFreeze.from_mapping(request.freeze)
        )
        freeze.validate()
    except (EvolutionError, TypeError, ValueError):
        raise _invalid_improvement_request() from None

    public_ids = (
        (request.campaign_id, "campaign"),
        (request.candidate_id, "candidate"),
        (request.evaluation_id, "evaluation"),
        (request.review_id, "review"),
    )
    if any(
        not isinstance(value, str)
        or _PUBLIC_ID.fullmatch(value) is None
        or not value.startswith(prefix + ":")
        for value, prefix in public_ids
    ):
        raise _invalid_improvement_request()
    if not isinstance(request.lease_id, str) or _LEASE_ID.fullmatch(request.lease_id) is None:
        raise _invalid_improvement_request()
    if request.parent_candidate_id is not None and (
        not isinstance(request.parent_candidate_id, str)
        or _PUBLIC_ID.fullmatch(request.parent_candidate_id) is None
        or not request.parent_candidate_id.startswith("candidate:")
    ):
        raise _invalid_improvement_request()
    if request.action not in {"original", "edit", "rebase", "retry"}:
        raise _invalid_improvement_request()
    if (request.action == "original") != (request.parent_candidate_id is None):
        raise _invalid_improvement_request()
    if request.author_id != freeze.author_id:
        raise _invalid_improvement_request()
    costs = (request.candidate_cost_steps, request.evaluation_cost_steps)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in costs):
        raise _invalid_improvement_request()
    dissent = tuple(request.candidate_dissent_digests)
    if (
        dissent != tuple(sorted(dissent))
        or len(dissent) != len(set(dissent))
        or any(not isinstance(value, str) or _DIGEST.fullmatch(value) is None for value in dissent)
    ):
        raise _invalid_improvement_request()


async def run_improvement(
    manager: EvolutionManager,
    request: ImprovementRequest,
) -> ImprovementResult:
    """Execute the provider-free improvement adapter through the Python carrier."""

    _validate_improvement_request(request)
    return await _run_improvement(manager, request)


__all__ = [
    "add_candidate", "advance_inquiry", "attach_run", "cancel_inquiry",
    "cancel_run", "cleanup_workspace", "evaluate_candidate", "handoff_inquiry",
    "inspect_campaign", "inspect_inquiry", "inspect_run", "inspect_workspace",
    "integrate_workspace", "lease_workspace", "open_campaign", "open_inquiry",
    "pause_inquiry", "promote_candidate", "resume_inquiry", "return_workspace",
    "measure_baseline", "review_candidate", "rollback_promotion", "submit_run",
    "run_task", "run_project", "run_improvement",
]
