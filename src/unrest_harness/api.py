"""Installed-library surface for the v0.3.1 foundation runtime.

The function names and signatures are frozen by
``docs/v03/v0.3.1/public-surface.v1.json``.  MCP delegates to the same
``FoundationTools`` methods; this module adds no second execution path.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer
from .config import HarnessConfig
from .controller import ProjectController
from .foundation_tools import FoundationTools, public_error


def _tools() -> FoundationTools:
    config = HarnessConfig.discover()
    return FoundationTools(
        config,
        ProjectController(config, ACPNodeDispatcher(config), ACPTerminalReviewer(config)),
    )


def _call(name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return getattr(_tools(), name)(*args, **kwargs)
    except Exception as exc:
        raise public_error(exc) from None


async def _call_async(name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await getattr(_tools(), name)(*args, **kwargs)
    except Exception as exc:
        raise public_error(exc) from None


def submit_run(operation: str, arguments: Mapping[str, Any], idempotency_key: str) -> dict[str, Any]:
    return _call("submit_run", operation, arguments, idempotency_key)


def inspect_run(run_id: str) -> dict[str, Any]:
    return _call("inspect_run", run_id)


def attach_run(run_id: str) -> dict[str, Any]:
    return _call("attach_run", run_id)


def cancel_run(run_id: str, reason: str, idempotency_key: str) -> dict[str, Any]:
    return _call("cancel_run", run_id, reason, idempotency_key)


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


__all__ = [
    "add_candidate", "advance_inquiry", "attach_run", "cancel_inquiry",
    "cancel_run", "cleanup_workspace", "evaluate_candidate", "handoff_inquiry",
    "inspect_campaign", "inspect_inquiry", "inspect_run", "inspect_workspace",
    "integrate_workspace", "lease_workspace", "open_campaign", "open_inquiry",
    "pause_inquiry", "promote_candidate", "resume_inquiry", "return_workspace",
    "review_candidate", "rollback_promotion", "submit_run",
]
