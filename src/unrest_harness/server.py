"""v5 MCP server. 4 modes: orchestrator / worker / validator / terminal-reviewer.

See docs/v5/08-mcp-surface.md. Tool-surface isolation is structural:
each mode constructs its own MCP server. Worker and validator modes share the
strict ``end_node`` completion protocol, but retain role-specific identities
and instructions.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping

from fastmcp import Context, FastMCP
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .capability_policy import (
    CapabilityPolicy,
    CapabilityPolicyError,
    SensitiveValueInventory,
    deserialize_sensitive_value_inventory,
    redact_sensitive_value,
)
from .config import HarnessConfig
from .controller import ProjectController, ToolError
from .dispatcher import NodeDispatcher, TerminalReviewer
from .foundation_tools import FoundationToolError, FoundationTools, public_error
from .models import (
    ActiveAttemptSnapshot,
    Decision,
    TaskList,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from .public_schema import catalog_tool
from .storage import ProjectStore, atomic_write_json, trusted_persistence_root
from .supervision import (
    SupervisionSnapshotError,
    SupervisionSteeringError,
    load_snapshot,
    report_supervision_checkpoint,
    wait_for_steering_action,
)

logger = logging.getLogger(__name__)
_SENSITIVE_INVENTORY_MAX_BYTES = 4 * 1024 * 1024
_NonEmpty = Annotated[str, Field(min_length=1)]
_Revision = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
_Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class _RoleSteeringResult(BaseModel):
    """Private role-only checkpoint response; public receipts remain body-free."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["continue", "nudge", "stop_for_attention"]
    body: str | None
    code: str


class _CompletionTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    status: Literal["completed", "blocked", "passed", "failed"]
    return_ref: Annotated[str, Field(min_length=1, max_length=128)]
    evidence_refs: Annotated[list[str], Field(min_length=1)]


class _NodeCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["unrest.v045.node-completion.v1"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    attempt_id: str
    task_type: Literal["work", "validate"]
    targets: Annotated[list[_CompletionTarget], Field(min_length=1)]
    scope_status: Literal["in_scope", "uncertain", "violation"]
    blocker_code: Literal[
        "dependency_unavailable",
        "scope_ambiguous",
        "scope_violation",
        "integrity_refusal",
        "authority_required",
        "delivery_blocked",
    ] | None


_COMPLETION_SCHEMA = "unrest.v045.node-completion.v1"
_REFUSAL_SCHEMA = "unrest.v045.completion-refusal.v1"
_COMPLETION_FIELD_NAMES = frozenset(
    {
        "attempt_id",
        "blocker_code",
        "evidence_refs",
        "return_ref",
        "schema",
        "scope_status",
        "status",
        "target_id",
        "targets",
        "task_type",
    }
)


_WORK_RETURN_REF = re.compile(r"git:[0-9a-f]{40}\Z")
_VALIDATION_RETURN_REF = re.compile(r"verdict:sha256:[0-9a-f]{64}\Z")
_EVIDENCE_REF = re.compile(r"evidence:sha256:[0-9a-f]{64}\Z")
_RUNTIME_ASSIGNMENT_ENV = "UNREST_NODE_ASSIGNMENT"


def _completion_return_ref_valid(value: str, *, task_type: str) -> bool:
    pattern = _WORK_RETURN_REF if task_type == "work" else _VALIDATION_RETURN_REF
    return pattern.fullmatch(value) is not None


def _completion_evidence_ref_valid(value: str) -> bool:
    return _EVIDENCE_REF.fullmatch(value) is not None


def _completion_validation_fields(exc: Exception) -> list[str]:
    """Reduce parser diagnostics to closed, body-free field names."""
    rows: list[dict[str, Any]] = getattr(exc, "errors", lambda: [])()
    if not rows:
        return ["completion"]
    fields: list[str] = []
    for row in rows:
        location = row.get("loc") or ()
        if row.get("type") == "extra_forbidden":
            fields.append("targets" if "targets" in location[:-1] else "completion")
            continue
        known = [
            part
            for part in location
            if isinstance(part, str) and part in _COMPLETION_FIELD_NAMES
        ]
        fields.append(known[-1] if known else "completion")
    return fields


def _completion_evidence_ref(
    *, attempt_id: str, target_id: str, status: str, return_ref: str
) -> str:
    payload = {
        "attempt_id": attempt_id,
        "return_ref": return_ref,
        "status": status,
        "target_id": target_id,
    }
    digest = hashlib.sha256(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
    ).hexdigest()
    return f"evidence:sha256:{digest}"


def _completion_bound_store(
    *, node_id: str, attempt_id: str, handoff_path: str
) -> tuple[ProjectStore, str, str] | None:
    project_id = os.environ.get("UNREST_PROJECT_ID")
    mission_id = os.environ.get("UNREST_MISSION_ID")
    if not project_id or not mission_id:
        return None
    store = ProjectStore(HarnessConfig.discover())
    canonical_path = store.attempt_path(
        project_id, mission_id, attempt_id, node_id
    ).resolve(strict=False)
    if Path(handoff_path).resolve(strict=False) != canonical_path:
        return None
    return store, project_id, mission_id


def _runtime_assignment(node_type: str) -> tuple[str, list[str]] | None:
    encoded = os.environ.get(_RUNTIME_ASSIGNMENT_ENV)
    if encoded is None:
        return None
    try:
        payload = json.loads(encoded)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("targets") from exc
    if not isinstance(payload, dict) or set(payload) != {"task_type", "targets"}:
        raise ValueError("targets")
    task_type = payload["task_type"]
    if (
        not isinstance(task_type, str)
        or task_type not in {"work", "validate"}
        or task_type != node_type
    ):
        raise ValueError("task_type")
    targets = payload["targets"]
    if (
        not isinstance(targets, list)
        or not all(isinstance(target, str) and target for target in targets)
        or targets != sorted(set(targets))
    ):
        raise ValueError("targets")
    return task_type, targets


def _completion_context(
    *,
    node_id: str,
    node_type: str,
    attempt_id: str,
    handoff_path: str,
    items: list[ValidationItem],
    done: bool,
) -> tuple[_NodeCompletion | None, ProjectStore | None]:
    bound = _completion_bound_store(
        node_id=node_id, attempt_id=attempt_id, handoff_path=handoff_path
    )
    if bound is None:
        return None, None
    store, project_id, mission_id = bound
    try:
        task_list = store.load_task_list(project_id, mission_id)
    except FileNotFoundError:
        runtime_assignment = _runtime_assignment(node_type)
        if runtime_assignment is None:
            raise
        task_type, targets = runtime_assignment
    else:
        task = next(
            (candidate for candidate in task_list.tasks if candidate.id == node_id),
            None,
        )
        if task is None or task.type != node_type or node_type not in {"work", "validate"}:
            raise ValueError("task_type")
        task_type = task.type
        targets = sorted(set(task.targets))
    workspace = store.workspace_dir(project_id)
    if task_type == "work":
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return_ref = f"git:{revision}"
        statuses = {target: "completed" if done else "blocked" for target in targets}
    else:
        if sorted(item.item_id for item in items) != targets or len(
            {item.item_id for item in items}
        ) != len(items):
            raise ValueError("items")
        rows = sorted((item.item_id, item.passed) for item in items)
        digest = hashlib.sha256(
            (json.dumps(rows, separators=(",", ":")) + "\n").encode("ascii")
        ).hexdigest()
        return_ref = f"verdict:sha256:{digest}"
        statuses = {
            target: "passed" if verdict else "failed" for target, verdict in rows
        }
    completion = _NodeCompletion.model_validate(
        {
            "schema": "unrest.v045.node-completion.v1",
            "attempt_id": attempt_id,
            "task_type": task_type,
            "targets": [
                {
                    "target_id": target,
                    "status": statuses.get(target, "failed"),
                    "return_ref": return_ref,
                    "evidence_refs": [
                        _completion_evidence_ref(
                            attempt_id=attempt_id,
                            target_id=target,
                            status=statuses.get(target, "failed"),
                            return_ref=return_ref,
                        )
                    ],
                }
                for target in targets
            ],
            "scope_status": "in_scope",
            "blocker_code": None,
        }
    )
    return completion, store


def _completion_errors(
    supplied: _NodeCompletion,
    expected: _NodeCompletion,
    *,
    done: bool,
    request_attention: bool,
    passed: bool | None,
) -> list[str]:
    errors: set[str] = set()
    if supplied.attempt_id != expected.attempt_id:
        errors.add("attempt_id")
    if supplied.task_type != expected.task_type:
        errors.add("task_type")
    supplied_ids = [target.target_id for target in supplied.targets]
    expected_ids = [target.target_id for target in expected.targets]
    if supplied_ids != sorted(set(supplied_ids)) or supplied_ids != expected_ids:
        errors.add("targets")
    by_id = {target.target_id: target for target in expected.targets}
    for target in supplied.targets:
        reference = by_id.get(target.target_id)
        if reference is None:
            continue
        if target.status != reference.status:
            errors.add("status")
        if target.return_ref != reference.return_ref or not _completion_return_ref_valid(
            target.return_ref, task_type=supplied.task_type
        ):
            errors.add("return_ref")
        if (
            target.evidence_refs != reference.evidence_refs
            or len(target.evidence_refs) != 1
            or not _completion_evidence_ref_valid(target.evidence_refs[0])
        ):
            errors.add("evidence_refs")
    if supplied.task_type == "work" and any(
        target.status == "completed" for target in supplied.targets
    ) and not done:
        errors.add("done")
    if supplied.task_type == "validate":
        all_passed = all(target.status == "passed" for target in supplied.targets)
        if passed is None or passed != all_passed:
            errors.add("passed")
    if (
        supplied.scope_status != "in_scope" or supplied.blocker_code is not None
    ) and not request_attention:
        errors.add("request_attention")
    return sorted(errors)


def _completion_refusal_path(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    attempt_id: str,
    node_id: str,
) -> Path:
    token = hashlib.sha256(
        f"{project_id}\0{mission_id}\0{node_id}\0{attempt_id}\0{_COMPLETION_SCHEMA}".encode(
            "utf-8"
        )
    ).hexdigest()
    return (
        store.mission_runtime_dir(project_id, mission_id)
        / "completion-refusals"
        / f"{token}.json"
    )


def _consume_completion_refusal(
    path: Path,
    *,
    project_id: str,
    mission_id: str,
    node_id: str,
    attempt_id: str,
) -> bool:
    """Atomically consume the one warm refusal for an exact attempt."""
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = {
        "attempt_id": attempt_id,
        "carrier_schema": _COMPLETION_SCHEMA,
        "consumed": True,
        "mission_id": mission_id,
        "node_id": node_id,
        "project_id": project_id,
        "schema": _REFUSAL_SCHEMA,
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # A process may die after creating its private temporary but before linking
    # the marker. Such a temporary has no effect on the quota and is safe to
    # remove on the next exact-attempt call.
    prefix = f".{path.name}."
    for orphan in sorted(path.parent.iterdir()):
        if orphan.name.startswith(prefix) and orphan.name.endswith(".tmp"):
            try:
                orphan.unlink()
            except FileNotFoundError:
                pass

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    quota_already_claimed = metadata is not None
    if metadata is not None:
        valid_marker = (
            stat.S_ISREG(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and path.read_bytes() == encoded
        )
        if valid_marker:
            return False
        # A malformed, wrong-mode, or non-regular final cannot be trusted as a
        # marker, but its final-name claim must not mint a second warm refusal.
        # Canonicalize it below while keeping the quota consumed.
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or path.read_bytes() != encoded
            ):
                raise RuntimeError("completion refusal marker collision")
            return False
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return not quota_already_claimed
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _clear_completion_refusal(path: Path) -> None:
    """Remove a terminal attempt's private refusal cursor."""
    try:
        path.unlink()
    except OSError:
        return
    try:
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        # The terminal handoff is already durable. A stale cursor is private,
        # task-truth neutral, and remains exact-attempt bound.
        pass


class _FoundationBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_steps: StrictInt = Field(ge=1)
    timeout_seconds: StrictInt = Field(ge=1)
    max_branches: StrictInt = Field(default=4, ge=1, le=4)


def _read_sensitive_inventory_fd(fd: int | None) -> SensitiveValueInventory:
    if fd is None:
        return SensitiveValueInventory()
    chunks: list[bytes] = []
    size = 0
    try:
        while chunk := os.read(fd, min(65536, _SENSITIVE_INVENTORY_MAX_BYTES + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > _SENSITIVE_INVENTORY_MAX_BYTES:
                raise RuntimeError("sensitive inventory exceeds startup channel limit")
    finally:
        os.close(fd)
    return deserialize_sensitive_value_inventory(b"".join(chunks))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_orchestrator_server(
    config: HarnessConfig,
    controller: ProjectController | None = None,
) -> FastMCP:
    """Seven compatible Mission tools plus 23 additive foundation tools."""
    config.validate_capability_support()
    if controller is None:
        from .dispatcher import MockDispatcher, MockTerminalReviewer

        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=False, report="no ACP wired")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )

    mcp = FastMCP(
        name="unrest",
        instructions=(
            "Mission orchestration harness. Mode: orchestrator. "
            "Mission tools: start_project, submit_plan, advance_project, "
            "end_mission, decide_attention, inspect_project, abort_project. "
            "Additive run, Inquiry, workspace, and evolution tools follow the "
            "frozen v0.3.1 public catalog. "
            "Lifecycle: plan with submit_plan, run with advance_project, "
            "request closure with end_mission, resolve attention with decide_attention, "
            "then call advance_project again."
        ),
    )
    from .api import _integrated_tools

    _register_orchestrator_tools(mcp, controller)
    _register_foundation_tools(
        mcp,
        _integrated_tools(
            config,
            controller,
            tools=FoundationTools(config, controller),
        ),
    )
    return mcp


def create_worker_server(
    sensitive_inventory: Mapping[str, str] | None = None,
) -> FastMCP:
    """Two worker tools. Configured at runtime via env: UNREST_NODE_TYPE,
    UNREST_NODE_ID, UNREST_HANDOFF_PATH.
    """
    mcp = FastMCP(
        name="unrest-worker",
        instructions=(
            "Worker MCP server. Mode: worker. Tools: "
            "report_supervision_checkpoint and end_node. "
            "Call exactly once before exiting."
        ),
    )
    _register_worker_tools(mcp, sensitive_inventory=sensitive_inventory)
    _register_role_supervision_tool(mcp, expected_role="worker")
    return mcp


def create_validator_server(
    sensitive_inventory: Mapping[str, str] | None = None,
) -> FastMCP:
    """Validator completion plus the shared strict checkpoint protocol."""
    mcp = FastMCP(
        name="unrest-validator",
        instructions=(
            "Validator MCP server. Mode: validator. Tools: "
            "report_supervision_checkpoint and end_node. "
            "Call exactly once before exiting. Include `items` (one per assigned "
            "contract target) and the aggregate `passed`."
        ),
    )
    _register_worker_tools(mcp, sensitive_inventory=sensitive_inventory)
    _register_role_supervision_tool(mcp, expected_role="validator")
    return mcp


def create_terminal_reviewer_server(
    sensitive_inventory: Mapping[str, str] | None = None,
) -> FastMCP:
    """Reviewer completion plus the shared strict checkpoint protocol."""
    mcp = FastMCP(
        name="unrest-terminal-reviewer",
        instructions=(
            "Runtime closure-check MCP server. Tools: "
            "report_supervision_checkpoint and submit_terminal_review. "
            "Call exactly once with the structured gap list."
        ),
    )
    _register_terminal_reviewer_tools(
        mcp,
        sensitive_inventory=sensitive_inventory,
    )
    _register_role_supervision_tool(mcp, expected_role="terminal_reviewer")
    return mcp


def _register_role_supervision_tool(
    mcp: FastMCP,
    *,
    expected_role: Literal["worker", "validator", "terminal_reviewer"],
) -> None:
    """Expose the same exact-attempt semantic boundary to every ACP role."""

    @mcp.tool(
        name="report_supervision_checkpoint",
        description=(
            "Report one body-free exact-attempt semantic checkpoint and wait at "
            "most 60 seconds for bounded orchestrator steering. A timeout or "
            "blocked delivery returns continue."
        ),
    )
    async def report_checkpoint(
        snapshot: ActiveAttemptSnapshot,
    ) -> dict[str, Any]:
        def error_result(code: str) -> dict[str, Any]:
            return {"error": {"code": code, "message": code.replace("_", " ")}}

        project_id = os.environ.get("UNREST_PROJECT_ID")
        mission_id = os.environ.get("UNREST_MISSION_ID")
        identity_path = os.environ.get(
            "UNREST_TERMINAL_REVIEW_PATH"
            if expected_role == "terminal_reviewer"
            else "UNREST_HANDOFF_PATH"
        )
        attempt_id = (
            Path(identity_path).stem.split("__", 1)[0] if identity_path else None
        )
        node_id = (
            None
            if expected_role == "terminal_reviewer"
            else os.environ.get("UNREST_NODE_ID")
        )
        terminal_review_id = (
            attempt_id
            if expected_role == "terminal_reviewer"
            else None
        )
        if (
            not project_id
            or not mission_id
            or not attempt_id
            or snapshot.project_id != project_id
            or snapshot.mission_id != mission_id
            or snapshot.attempt_id != attempt_id
            or snapshot.role != expected_role
            or snapshot.node_id != node_id
            or snapshot.terminal_review_id != terminal_review_id
        ):
            return error_result("steering_binding_mismatch")

        config = HarnessConfig.discover()
        store = ProjectStore(config)
        task_list = store.load_task_list(project_id, mission_id)
        if node_id is None:
            assigned = list(
                dict.fromkeys(
                    target for task in task_list.tasks for target in task.targets
                )
            )
        else:
            task = next((item for item in task_list.tasks if item.id == node_id), None)
            if task is None:
                return error_result("steering_binding_mismatch")
            assigned = task.targets
        current = load_snapshot(store, project_id, mission_id, attempt_id)
        if current is None:
            return error_result("attempt_not_started")
        if snapshot.elapsed_nanoseconds != 0 or snapshot.checkpoint_requests != 0:
            return error_result("child_policy_state_forbidden")
        if snapshot.checkpoint_sequence != current.checkpoint_sequence + 1:
            return error_result("stale_checkpoint_binding")
        snapshot = snapshot.model_copy(
            update={
                "checkpoint_requests": current.checkpoint_requests,
                "elapsed_nanoseconds": current.elapsed_nanoseconds,
            },
            deep=True,
        )
        try:
            binding = await asyncio.to_thread(
                report_supervision_checkpoint,
                store,
                snapshot,
                assigned_target_ids=assigned,
                project_guard=False,
            )
            outcome = await asyncio.to_thread(
                wait_for_steering_action,
                store,
                binding,
                project_guard=False,
            )
        except (SupervisionSnapshotError, SupervisionSteeringError) as exc:
            code = exc.code if isinstance(exc, SupervisionSteeringError) else "invalid_checkpoint"
            return error_result(code)
        return _RoleSteeringResult(
            action=outcome.action,
            body=outcome.body,
            code=outcome.code,
        ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Orchestrator tools
# ---------------------------------------------------------------------------


def _register_orchestrator_tools(mcp: FastMCP, controller: ProjectController) -> None:
    def safe_payload(value: Any) -> dict[str, Any]:
        return _to_payload(value, inventory=controller.store.inventory)

    # SECURITY[SEC-MCP-001]: Lifecycle tools are registered only on the
    # orchestrator server; worker, validator, and reviewer modes construct
    # authority-limited servers.
    detached_mutations: set[asyncio.Task[dict[str, Any]]] = set()

    async def call_project_mutation(
        call: Callable[[], Any],
    ) -> dict[str, Any]:
        def invoke() -> Any:
            try:
                return call()
            except ToolError as exc:
                return exc

        async def run_mutation() -> dict[str, Any]:
            return safe_payload(await asyncio.to_thread(invoke))

        mutation_task = asyncio.create_task(
            run_mutation(), name="unrest-project-mutation"
        )
        try:
            return await asyncio.shield(mutation_task)
        except asyncio.CancelledError:
            # asyncio only keeps weak task references. Retain detached mutations
            # until their worker completes, then observe the result exactly once.
            detached_mutations.add(mutation_task)

            def observe_detached(completed: asyncio.Task[dict[str, Any]]) -> None:
                detached_mutations.discard(completed)
                try:
                    completed.result()
                except asyncio.CancelledError:
                    logger.error("Detached project mutation did not complete")
                except Exception:  # noqa: BLE001
                    # Exception text can contain provider or project data.
                    logger.error("Detached project mutation failed")

            mutation_task.add_done_callback(observe_detached)
            raise

    @mcp.tool(
        name="start_project",
        description=(
            "Create a new long-running project rooted at the workspace. "
            "Use when the user describes a goal that needs planning and decomposition. "
            "Writes brief.md, creates harness state, returns the envelope with "
            "state=mission_planning."
        ),
    )
    async def start_project(
        brief: Annotated[str, Field(description="The user's ask in prose; goes to brief.md")],
        workspace_dir: Annotated[
            str, Field(description="Absolute path to the user's workspace.")
        ],
        worker_model: Annotated[
            str | None,
            Field(description="Optional Codex model override for work nodes in this project."),
        ] = None,
        worker_reasoning_effort: Annotated[
            str | None,
            Field(
                description=(
                    "Optional Codex reasoning-effort override for work nodes in this "
                    "project; validators and terminal review keep their configured roles."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        # No per-project lock: project_id does not exist until the call returns.
        try:
            return safe_payload(
                await asyncio.to_thread(
                    controller.start_project,
                    brief,
                    workspace_dir,
                    worker_model,
                    worker_reasoning_effort,
                )
            )
        except ToolError as exc:
            return safe_payload(exc)

    @mcp.tool(
        name="submit_plan",
        description=(
            "Submit the current mission's contract-backed task list. Before calling, "
            "write every targeted contract/<id>.md file under the mission contract "
            "directory. Runtime validates a non-empty contract, task shape, "
            "depends_on resolution, acyclicity, coverage (each assertion has exactly "
            "one non-superseded work task). On success state becomes "
            "mission_running; call advance_project to dispatch work."
        ),
    )
    async def submit_plan(
        project_id: Annotated[str, Field(description="Project id from start_project.")],
        task_list: Annotated[
            TaskList,
            Field(
                description=(
                    "Mission task list (tasks: list[Task] with depends_on)."
                )
            ),
        ],
    ) -> dict[str, Any]:
        return await call_project_mutation(
            lambda: controller.submit_plan(project_id, task_list)
        )

    @mcp.tool(
        name="advance_project",
        description=(
            "Drive the runtime forward. BLOCKING — may run for many minutes while "
            "workers dispatch according to runtime scheduling. "
            "Call whenever state is mission_running. "
            "Returns when attention is needed, no runnable task work remains, or "
            "`max_steps` exhausts. It does not request mission closure; call "
            "end_mission when you intend to close after task work is quiescent. "
            "If it returns still mission_running with runnable work, call it again."
        ),
    )
    async def advance_project(
        project_id: Annotated[str, Field(description="Project id.")],
        max_steps: Annotated[
            int | None, Field(default=None, description="Optional cap on step() calls.")
        ] = None,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        return await call_project_mutation(
            lambda: controller.advance_project(project_id, max_steps)
        )

    @mcp.tool(
        name="end_mission",
        description=(
            "Request runtime mission closure. Call only when state is mission_running "
            "and you believe task work is complete/quiescent. This tool does not "
            "dispatch workers. If work or gates are still runnable, returns "
            "mission_not_ready_to_close; call advance_project first. If closure "
            "passes, state becomes done. If closure finds gaps, state becomes "
            "attention_needed with a closure report."
        ),
    )
    async def end_mission(
        project_id: Annotated[str, Field(description="Project id.")],
        deliverable_roots: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    "Final-artifact roots authorized by terminal-review policy in "
                    "addition to the normal workspace product surface. None keeps the "
                    "persisted declaration (default empty), [] clears it, and a "
                    "non-empty list replaces it after canonical preflight. This is a "
                    "preflight plus prompt policy for a trusted reviewer, not an "
                    "OS filesystem sandbox."
                ),
            ),
        ] = None,
    ) -> dict[str, Any]:
        return await call_project_mutation(
            lambda: controller.end_mission(project_id, deliverable_roots),
        )

    @mcp.tool(
        name="decide_attention",
        description=(
            "Resolve all open AttentionItem(s). Every open item must be covered by "
            "exactly one Decision. Use retry only for transient node_failed attempts; "
            "use patch for changed work, missing assertions, failed validation, "
            "over-broad scope, or task-list adaptation. Patches must pass structural "
            "validation. After a valid decide, state usually returns to "
            "mission_running; call advance_project to dispatch more work."
        ),
    )
    async def decide_attention(
        project_id: Annotated[str, Field(description="Project id.")],
        decisions: Annotated[
            list[Decision], Field(description="One Decision per open attention item.")
        ],
    ) -> dict[str, Any]:
        return await call_project_mutation(
            lambda: controller.decide_attention(project_id, decisions)
        )

    @mcp.tool(
        name="inspect_project",
        description=(
            "Pure read of current state, full task-list view, and open attention. "
            "No state change. Use when waking with no specific tool call in mind."
        ),
    )
    async def inspect_project(
        project_id: Annotated[str, Field(description="Project id.")],
    ) -> dict[str, Any]:
        try:
            return safe_payload(
                await asyncio.to_thread(
                    controller.inspect_project_live,
                    project_id,
                )
            )
        except SupervisionSnapshotError as exc:
            return safe_payload(ToolError("integrity_error", str(exc)))
        except ToolError as exc:
            return safe_payload(exc)

    @mcp.tool(
        name="abort_project",
        description=(
            "Cancel the current mission and project. Marks state=Aborted with the "
            "supplied reason. Preserves tasks.json + attempts/ + decisions/ for forensics."
        ),
    )
    async def abort_project(
        project_id: Annotated[str, Field(description="Project id.")],
        reason: Annotated[str, Field(description="Why we are aborting.")],
    ) -> dict[str, Any]:
        return await call_project_mutation(
            lambda: controller.abort_project(project_id, reason)
        )


def _register_foundation_tools(mcp: FastMCP, tools: Any) -> None:
    """Register the exact additive catalog on the orchestrator authority."""

    def failure(exc: Exception) -> dict[str, Any]:
        error = exc if isinstance(exc, FoundationToolError) else public_error(exc)
        return error.as_envelope()

    @catalog_tool(mcp, "submit_run")
    async def submit_run(
        operation: Literal[
            "abort_project",
            "advance_project",
            "decide_attention",
            "end_mission",
            "start_project",
            "submit_plan",
        ],
        arguments: Mapping[str, Any],
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.submit_run,
                operation,
                arguments,
                idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "inspect_run")
    async def inspect_run(run_id: _NonEmpty) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(tools.inspect_run, run_id)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "attach_run")
    async def attach_run(run_id: _NonEmpty) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(tools.attach_run, run_id)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "cancel_run")
    async def cancel_run(
        run_id: _NonEmpty, reason: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.cancel_run, run_id, reason, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "steer_attempt")
    async def steer_attempt(
        run_id: _NonEmpty,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                getattr(tools, "steer_attempt"), run_id, request
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "open_inquiry")
    async def open_inquiry(
        question: _NonEmpty,
        budget: _FoundationBudget,
        idempotency_key: _NonEmpty,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.open_inquiry,
                question,
                budget.model_dump(),
                idempotency_key,
                project_id,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "inspect_inquiry")
    async def inspect_inquiry(inquiry_id: _NonEmpty) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(tools.inspect_inquiry, inquiry_id)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "advance_inquiry")
    async def advance_inquiry(
        inquiry_id: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await tools.advance_inquiry(inquiry_id, idempotency_key)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "pause_inquiry")
    async def pause_inquiry(
        inquiry_id: _NonEmpty, reason: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.pause_inquiry, inquiry_id, reason, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "resume_inquiry")
    async def resume_inquiry(
        inquiry_id: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.resume_inquiry, inquiry_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "cancel_inquiry")
    async def cancel_inquiry(
        inquiry_id: _NonEmpty, reason: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.cancel_inquiry, inquiry_id, reason, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "handoff_inquiry")
    async def handoff_inquiry(
        inquiry_id: _NonEmpty, consumer_id: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.handoff_inquiry, inquiry_id, consumer_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "lease_workspace")
    async def lease_workspace(
        project_id: _NonEmpty,
        base_revision: _Revision,
        write_paths: Annotated[list[_NonEmpty], Field(min_length=1)],
        idempotency_key: _NonEmpty,
        lease_seconds: Annotated[int, Field(ge=1)] = 3600,
    ) -> dict[str, Any]:
        try:
            if len(write_paths) != len(set(write_paths)):
                raise FoundationToolError(
                    "invalid_argument", "write_paths must contain unique values"
                )
            return await asyncio.to_thread(
                tools.lease_workspace,
                project_id,
                base_revision,
                write_paths,
                idempotency_key,
                lease_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "inspect_workspace")
    async def inspect_workspace(workspace_id: _NonEmpty) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(tools.inspect_workspace, workspace_id)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "return_workspace")
    async def return_workspace(
        workspace_id: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.return_workspace, workspace_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "integrate_workspace")
    async def integrate_workspace(
        workspace_id: _NonEmpty,
        human_grant_id: _NonEmpty,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.integrate_workspace,
                workspace_id,
                human_grant_id,
                idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "cleanup_workspace")
    async def cleanup_workspace(
        workspace_id: _NonEmpty, idempotency_key: _NonEmpty
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.cleanup_workspace, workspace_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "open_campaign")
    async def open_campaign(
        project_id: _NonEmpty,
        accepted_point_digest: _Digest,
        workload_id: _NonEmpty,
        evaluator_id: _NonEmpty,
        reviewer_id: _NonEmpty,
        budget: _FoundationBudget,
        seed: int,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.open_campaign,
                project_id,
                accepted_point_digest,
                workload_id,
                evaluator_id,
                reviewer_id,
                budget.model_dump(),
                seed,
                idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "inspect_campaign")
    async def inspect_campaign(campaign_id: _NonEmpty) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(tools.inspect_campaign, campaign_id)
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "add_candidate")
    async def add_candidate(
        campaign_id: _NonEmpty,
        artifact_id: _NonEmpty,
        action: Literal["edit", "initial", "rebase", "retry"],
        idempotency_key: _NonEmpty,
        parent_candidate_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.add_candidate,
                campaign_id,
                artifact_id,
                action,
                idempotency_key,
                parent_candidate_id,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "evaluate_candidate")
    async def evaluate_candidate(
        campaign_id: _NonEmpty,
        candidate_id: _NonEmpty,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await tools.evaluate_candidate(
                campaign_id, candidate_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "review_candidate")
    async def review_candidate(
        campaign_id: _NonEmpty,
        candidate_id: _NonEmpty,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await tools.review_candidate(
                campaign_id, candidate_id, idempotency_key
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "promote_candidate")
    async def promote_candidate(
        campaign_id: _NonEmpty,
        candidate_id: _NonEmpty,
        human_grant_id: _NonEmpty,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.promote_candidate,
                campaign_id,
                candidate_id,
                human_grant_id,
                idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)

    @catalog_tool(mcp, "rollback_promotion")
    async def rollback_promotion(
        campaign_id: _NonEmpty,
        promotion_receipt_id: _NonEmpty,
        human_grant_id: _NonEmpty,
        idempotency_key: _NonEmpty,
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                tools.rollback_promotion,
                campaign_id,
                promotion_receipt_id,
                human_grant_id,
                idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            return failure(exc)


# ---------------------------------------------------------------------------
# Worker tool
# ---------------------------------------------------------------------------


def _register_worker_tools(
    mcp: FastMCP,
    *,
    sensitive_inventory: Mapping[str, str] | None = None,
) -> None:
    @mcp.tool(
        name="end_node",
        description=(
            "Assigned-session runtime handoff. Report completion for the assigned "
            "work or validation task. Call exactly "
            "once before exiting, except that completion_refused permits one repaired "
            "same-attempt call. After a recorded call, do not invoke other tools — the "
            "session is finished. For validation tasks, include `items` (one per "
            "assigned contract target) and the aggregate `passed`."
        ),
    )
    async def end_node(
        done: Annotated[
            bool,
            Field(description="True if the assigned work or validation audit completed."),
        ],
        report: Annotated[str, Field(description="Free-form handoff report. Severity tags are authoring discipline, not runtime triggers.")],
        request_attention: Annotated[
            bool,
            Field(
                default=False,
                description="Set True to return this completed task's raw report to the orchestrator before the task list continues.",
            ),
        ] = False,
        items: Annotated[
            list[ValidationItem] | None,
            Field(
                default=None,
                description="Validation task only: one entry per assigned contract target with per-item passed verdict.",
            ),
        ] = None,
        passed: Annotated[
            bool | None,
            Field(
                default=None,
                description="Validation task only: aggregate True iff every items[].passed.",
            ),
        ] = None,
        completion: Annotated[
            Any | None,
            Field(
                default=None,
                description="Optional closed unrest.v045.node-completion.v1 carrier.",
            ),
        ] = None,
    ) -> dict[str, Any]:
        node_type = os.environ.get("UNREST_NODE_TYPE", "work")
        handoff_path = os.environ.get("UNREST_HANDOFF_PATH")
        if not handoff_path:
            raise RuntimeError("UNREST_HANDOFF_PATH not set in worker env")
        node_id = os.environ.get("UNREST_NODE_ID")
        if not node_id:
            raise RuntimeError("UNREST_NODE_ID not set in worker env")
        attempt_id = Path(handoff_path).stem.split("__", 1)[0]

        structural_errors: list[str] = []
        expected_completion: _NodeCompletion | None = None
        bound = _completion_bound_store(
            node_id=node_id,
            attempt_id=attempt_id,
            handoff_path=handoff_path,
        )
        completion_store = bound[0] if bound is not None else None
        try:
            expected_completion, completion_store = _completion_context(
                node_id=node_id,
                node_type=node_type,
                attempt_id=attempt_id,
                handoff_path=handoff_path,
                items=items or [],
                done=done,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            structural_errors.append(
                str(exc)
                if str(exc) in {"items", "targets", "task_type"}
                else "return_ref"
            )
        supplied_completion: _NodeCompletion | None = None
        if completion is not None:
            try:
                supplied_completion = _NodeCompletion.model_validate(completion)
            except Exception as exc:
                structural_errors.extend(_completion_validation_fields(exc))
        elif expected_completion is not None:
            supplied_completion = expected_completion
        if supplied_completion is not None and expected_completion is not None:
            structural_errors.extend(
                _completion_errors(
                    supplied_completion,
                    expected_completion,
                    done=done,
                    request_attention=request_attention,
                    passed=passed,
                )
            )

        if structural_errors and completion_store is not None:
            project_id = os.environ["UNREST_PROJECT_ID"]
            mission_id = os.environ["UNREST_MISSION_ID"]
            fields = sorted(set(structural_errors))
            refusal_path = _completion_refusal_path(
                completion_store,
                project_id,
                mission_id,
                attempt_id,
                node_id,
            )
            if _consume_completion_refusal(
                refusal_path,
                project_id=project_id,
                mission_id=mission_id,
                node_id=node_id,
                attempt_id=attempt_id,
            ):
                return {
                    "recorded": False,
                    "code": "completion_refused",
                    "fields": fields,
                }
            done = False
            request_attention = True
            report = "Structural completion refused: " + ", ".join(fields)

        handoff: WorkHandoff | ValidateHandoff
        if node_type == "validate":
            handoff = ValidateHandoff(
                node_id=node_id,
                attempt_id=attempt_id,
                done=done,
                report=report,
                items=items or [],
                passed=bool(passed) if passed is not None else all(i.passed for i in (items or [])),
                request_attention=request_attention,
            )
        else:
            handoff = WorkHandoff(
                node_id=node_id,
                attempt_id=attempt_id,
                done=done,
                report=report,
                request_attention=request_attention,
            )
        atomic_write_json(
            handoff_path,
            handoff.model_dump(mode="json"),
            trusted_root=trusted_persistence_root(handoff_path),
            inventory=sensitive_inventory,
        )
        if completion_store is not None:
            project_id = os.environ["UNREST_PROJECT_ID"]
            mission_id = os.environ["UNREST_MISSION_ID"]
            _clear_completion_refusal(
                _completion_refusal_path(
                    completion_store,
                    project_id,
                    mission_id,
                    attempt_id,
                    node_id,
                )
            )
        return {
            "recorded": True,
            "message": "Session complete, your job is done now; do not call further tools and just end your job now.",
        }


# ---------------------------------------------------------------------------
# Terminal-reviewer tool
# ---------------------------------------------------------------------------


def _register_terminal_reviewer_tools(
    mcp: FastMCP,
    *,
    sensitive_inventory: Mapping[str, str] | None = None,
) -> None:
    @mcp.tool(
        name="submit_terminal_review",
        description=(
            "Runtime-closure-check-only. Submit the mission closure result. "
            "`done=true` means clean enough to close; `done=false` returns the raw "
            "closure report to the orchestrator. Call exactly once."
        ),
    )
    async def submit_terminal_review(
        done: Annotated[
            bool,
            Field(description="True only when the mission should close as done."),
        ],
        report: Annotated[
            str,
            Field(description="Raw closure report for the orchestrator."),
        ] = "",
    ) -> dict[str, Any]:
        path = os.environ.get("UNREST_TERMINAL_REVIEW_PATH")
        if not path:
            raise RuntimeError(
                "UNREST_TERMINAL_REVIEW_PATH not set in terminal-reviewer env"
            )
        review = TerminalReviewHandoff(done=done, report=report)
        atomic_write_json(
            path,
            review.model_dump(mode="json"),
            trusted_root=trusted_persistence_root(path),
            inventory=sensitive_inventory,
        )
        return {
            "recorded": True,
            "message": "Terminal review submitted; do not call further tools.",
        }


# ---------------------------------------------------------------------------
# Envelope payload helper
# ---------------------------------------------------------------------------


def _to_payload(
    env_or_err: Any,
    *,
    inventory: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if isinstance(env_or_err, ToolError):
        payload = {
            "error": env_or_err.code,
            "message": env_or_err.message,
            "details": [str(d) for d in (env_or_err.details or [])],
        }
    else:
        payload = env_or_err.model_dump(mode="json", by_alias=True)
    redacted = redact_sensitive_value(payload, inventory or {})
    if not isinstance(redacted, dict):
        raise TypeError("MCP payload redaction returned a non-object")
    return redacted


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(
    *,
    bundled_dir: Path | None = None,
    policy_loader: Callable[[Path], CapabilityPolicy] | None = None,
) -> None:
    parser = argparse.ArgumentParser(description="Unrest MCP Server (v5)")
    parser.add_argument(
        "--mode",
        choices=["orchestrator", "worker", "validator", "terminal-reviewer"],
        default="orchestrator",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)  # 0 → ephemeral
    parser.add_argument("--sensitive-inventory-fd", type=int, default=None)
    args = parser.parse_args()

    config: HarnessConfig | None = None
    startup_rejected = False
    try:
        config = HarnessConfig.discover(
            bundled_dir=bundled_dir,
            policy_loader=policy_loader,
        )
        config.validate_capability_support()
    except (CapabilityPolicyError, ValueError):
        startup_rejected = True

    if startup_rejected:
        parser.exit(2, "unrest-server: startup configuration rejected\n")
    assert config is not None

    if args.mode == "orchestrator":
        from .acp_runner import ACPNodeDispatcher, ACPTerminalReviewer  # noqa: PLC0415

        dispatcher: NodeDispatcher = ACPNodeDispatcher(config)
        reviewer: TerminalReviewer = ACPTerminalReviewer(config)
        controller = ProjectController(config, dispatcher, reviewer)
        server = create_orchestrator_server(config, controller)
    elif args.mode == "worker":
        server = create_worker_server(
            _read_sensitive_inventory_fd(args.sensitive_inventory_fd)
        )
    elif args.mode == "validator":
        server = create_validator_server(
            _read_sensitive_inventory_fd(args.sensitive_inventory_fd)
        )
    else:
        server = create_terminal_reviewer_server(
            _read_sensitive_inventory_fd(args.sensitive_inventory_fd)
        )

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport=args.transport, host=args.host, port=args.port)


__all__ = [
    "create_orchestrator_server",
    "create_worker_server",
    "create_terminal_reviewer_server",
    "create_validator_server",
    "main",
]
