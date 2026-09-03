"""v5 schemas — task-list shape (see `specs/task_list/PRODUCT.md`).

The authoring vocabulary is intentionally small:
- `Task` + `TaskList` (orchestrator authors at `submit_plan`)
- `TaskListPatch` (orchestrator nests inside `Decision`)
- `Decision`, `AttentionItem` (decide_attention surface)
- `ProjectState`, `Envelope` (runtime surface)
- worker-side handoff types (`WorkHandoff`, `ValidateHandoff`, `TerminalReviewHandoff`)

Attempt filenames keep the `<ts>__<node_id>.json` token for on-disk continuity
— `node_id` reads as task id. WorkHandoff/ValidateHandoff retain the
`node_id` field for the same reason; an eventual rename is deferred.
"""
from __future__ import annotations

import hashlib
import re
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Identifier conventions
# ---------------------------------------------------------------------------

ASSERTION_ID_REGEX = re.compile(r"^[A-Z][A-Z0-9-]+$")
TASK_ID_REGEX = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
SKILL_NAME_REGEX = re.compile(r"^[a-z][a-z0-9_-]*$")


TaskType = Literal["work", "validate", "gate"]
TaskStatus = Literal["pending", "running", "cleared", "failed", "superseded"]
AssertionStatus = Literal["pending", "passed", "failed"]


# ---------------------------------------------------------------------------
# Task / TaskList (orchestrator authors at submit_plan + via TaskListPatch)
# ---------------------------------------------------------------------------


class Task(BaseModel):
    """A single mission task.

    Dependencies live inline as `depends_on: list[task_id]`. The runtime
    computes "runnable" by checking that every id in `depends_on` is in a
    terminal status (`cleared` or `superseded`).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Mission-unique task id.")
    type: TaskType = Field(description='"work" | "validate" | "gate"')
    body: str = Field(
        description=(
            "Markdown task body. Work/validate tasks need a specific outcome, "
            "scope, targets, evidence, setup, non-goals, and split rationale "
            "when broad. Gate bodies must be empty — they exist only to seal."
        )
    )
    targets: list[str] = Field(
        description=(
            "Contract assertion ids this task addresses. Work nodes may own one "
            "or multiple related atomic assertions when the implementation boundary "
            "is coherent; every assertion must still have exactly one active work "
            "owner. Validators / gates may bundle several."
        ),
    )
    skill: str | None = Field(
        default=None,
        description=(
            "Skill procedure to load. Required for work/validate; must be null for "
            "gate."
        ),
    )
    auto_merge: bool = Field(
        default=True,
        description=(
            "Legacy no-op. Work tasks always run directly in the project workspace."
        ),
    )
    depends_on: list[str] = Field(
        default_factory=list,
        description=(
            "Upstream task ids that must reach a terminal status before this task "
            "becomes runnable. Dependencies are untyped — gate semantics come from "
            "`type == 'gate'`, not from the dep itself."
        ),
    )


class TaskList(BaseModel):
    """What `submit_plan` accepts. List order is a topological tie-break hint."""

    model_config = ConfigDict(extra="forbid")

    tasks: list[Task] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# TaskListPatch (orchestrator nests inside Decision when action == "patch")
# ---------------------------------------------------------------------------


class TaskListPatch(BaseModel):
    """Four ops. See `specs/task_list/PRODUCT.md` §Patching.

    - `add_items`: new assertion ids (contract files must exist on disk).
    - `add`: new tasks appended to the task list.
    - `supersede`: dict mapping old_id → new_id. Old task marked
      `superseded`; **every `depends_on` reference to old_id in the task
      list is rewritten to new_id in-place**. No runtime chain resolver.
    - `cancel`: list of task ids to remove. Each cancelled task is marked
      `superseded`; **every `depends_on` list is rewritten to drop the
      cancelled id**. Use when a planned task is no longer needed (wrong
      authoring, scope retraction, dead-end discovered).
    """

    model_config = ConfigDict(extra="forbid")

    add_items: list[str] = Field(
        default_factory=list,
        description=(
            "New assertion ids to declare. Matching contract/<id>.md files must "
            "already exist on disk before decide_attention is called."
        ),
    )
    add: list[Task] = Field(
        default_factory=list,
        description="New tasks; appended to the task list. Ids must be globally new.",
    )
    supersede: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Old task id → new task id. The new id must appear in `add` (this patch) "
            "or be an existing non-superseded task. Cleared/running tasks cannot be "
            "superseded. Downstream `depends_on` references are rewritten in-place."
        ),
    )
    cancel: list[str] = Field(
        default_factory=list,
        description=(
            "Task ids to remove without replacement. Cancelled tasks are marked "
            "superseded and dropped from every downstream `depends_on` list. "
            "Cleared/running tasks cannot be cancelled."
        ),
    )

    @property
    def is_empty(self) -> bool:
        return not (self.add_items or self.add or self.supersede or self.cancel)


# ---------------------------------------------------------------------------
# Decision (orchestrator authors in decide_attention)
# ---------------------------------------------------------------------------

ActionName = Literal[
    "continue",
    "patch",
    "retry",
    "next_mission",
    "abort",
]


class Decision(BaseModel):
    """4 fields. See `specs/task_list/PRODUCT.md` §Patching."""

    model_config = ConfigDict(extra="forbid")

    item_id: str
    action: ActionName = Field(
        description=(
            "continue | patch | retry | next_mission | abort. retry is for "
            "transient node_failed attempts only; use patch for changed work, "
            "failed validation, missing assertions, over-broad scope, or task-list "
            "adaptation. next_mission is only for runtime closure-report gaps that "
            "cannot be patched inside the current mission."
        )
    )
    patch: TaskListPatch | None = Field(
        default=None,
        description="Required iff action == patch; must satisfy task-list structural validation.",
    )
    justification: str = Field(
        default="",
        description="Decision rationale, especially for accepted risk, scope change, or why patch/retry/next_mission is appropriate.",
    )


# ---------------------------------------------------------------------------
# Attention (runtime writes, orchestrator reads)
# ---------------------------------------------------------------------------

AttentionKind = Literal[
    "node_failed",
    "node_attention",
    "gate_failed",
    "gate_checkpoint",
    "terminal_review",
]
NextAction = Literal[
    "abort_project",
    "submit_plan",
    "advance_project",
    "decide_attention",
    "end_mission",
    "none",
]

SupervisionRole = Literal["worker", "validator", "terminal_reviewer"]
SupervisionPhase = Literal[
    "active", "waiting_at_checkpoint", "stopping", "terminal"
]
ScopeStatus = Literal["in_scope", "uncertain", "violation"]
SupervisionStatus = Literal[
    "running",
    "checkpoint_due",
    "waiting",
    "nudge_pending",
    "stop_requested",
    "terminal",
]
SupervisionBlockerCode = Literal[
    "dependency_unavailable",
    "scope_ambiguous",
    "scope_violation",
    "integrity_refusal",
    "authority_required",
    "delivery_blocked",
]
SteeringAction = Literal["continue", "nudge", "stop_for_attention"]
SteeringActor = Literal["orchestrator", "maintainer", "timeout_policy"]
SteeringDeliveryStatus = Literal[
    "not_applicable", "pending", "delivered", "consumed", "delivery_blocked"
]


class ActiveAttemptSnapshot(BaseModel):
    """Closed, body-free runtime projection for one active ACP attempt."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str
    blocker_code: SupervisionBlockerCode | None
    checkpoint_requests: int = Field(strict=True, ge=0)
    checkpoint_sequence: int = Field(strict=True, ge=0)
    completed_target_ids: list[str]
    elapsed_nanoseconds: int = Field(strict=True, ge=0)
    last_effect_sequence: int = Field(strict=True, ge=0)
    mission_id: str
    node_id: str | None
    phase: SupervisionPhase
    project_id: str
    remaining_target_ids: list[str]
    role: SupervisionRole
    scope_status: ScopeStatus
    supervision_status: SupervisionStatus
    terminal_review_id: str | None

    @model_validator(mode="after")
    def _closed_identity_and_terminal_state(self) -> ActiveAttemptSnapshot:
        identifiers = (
            self.attempt_id,
            self.mission_id,
            self.project_id,
            self.node_id,
            self.terminal_review_id,
        )
        for value in identifiers:
            if value is not None and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]*", value
            ):
                raise ValueError("supervision identity must be a non-empty ASCII identifier")
        if (self.node_id is None) == (self.terminal_review_id is None):
            raise ValueError("exactly one node or terminal-review identity is required")
        if self.role == "terminal_reviewer" and self.terminal_review_id is None:
            raise ValueError("terminal reviewer requires terminal_review_id")
        if self.role != "terminal_reviewer" and self.node_id is None:
            raise ValueError("worker and validator require node_id")
        for target_id in (*self.completed_target_ids, *self.remaining_target_ids):
            if ASSERTION_ID_REGEX.fullmatch(target_id) is None:
                raise ValueError("invalid assigned contract target id")
        if len(set(self.completed_target_ids)) != len(self.completed_target_ids):
            raise ValueError("completed target ids must be unique")
        if len(set(self.remaining_target_ids)) != len(self.remaining_target_ids):
            raise ValueError("remaining target ids must be unique")
        if set(self.completed_target_ids) & set(self.remaining_target_ids):
            raise ValueError("completed and remaining target ids must be disjoint")
        terminal = self.phase == "terminal" or self.supervision_status == "terminal"
        if terminal and not (
            self.phase == "terminal" and self.supervision_status == "terminal"
        ):
            raise ValueError("terminal phase and supervision status must agree")
        return self


class SteeringBinding(BaseModel):
    """Exact attempt-generation and semantic-checkpoint identity."""

    model_config = ConfigDict(extra="forbid")

    project_id: str
    mission_id: str
    node_id: str | None
    terminal_review_id: str | None
    attempt_id: str
    checkpoint_sequence: int = Field(strict=True, ge=0)

    @model_validator(mode="after")
    def _closed_identity(self) -> SteeringBinding:
        for value in (
            self.project_id,
            self.mission_id,
            self.node_id,
            self.terminal_review_id,
            self.attempt_id,
        ):
            if value is not None and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]*", value
            ):
                raise ValueError("steering identity must be a non-empty ASCII identifier")
        if (self.node_id is None) == (self.terminal_review_id is None):
            raise ValueError("exactly one node or terminal-review identity is required")
        return self


class SteeringRequest(SteeringBinding):
    """Closed local seam for the INT-owned orchestrator transport."""

    model_config = ConfigDict(extra="forbid")

    action: SteeringAction
    actor: SteeringActor
    body: str | None = None

    @model_validator(mode="after")
    def _body_matches_action(self) -> SteeringRequest:
        if self.actor == "timeout_policy":
            raise ValueError("timeout policy is internal and cannot steer directly")
        if self.action == "nudge":
            if self.body is None or not self.body:
                raise ValueError("nudge requires a non-empty body")
        elif self.body is not None:
            raise ValueError("only nudge accepts a body")
        return self


class SupervisionReceipt(BaseModel):
    """One body-free append-only steering transition."""

    model_config = ConfigDict(extra="forbid")

    project_id: str
    mission_id: str
    node_id: str | None
    terminal_review_id: str | None
    attempt_id: str
    receipt_sequence: int = Field(strict=True, ge=1)
    checkpoint_sequence: int = Field(strict=True, ge=0)
    action: SteeringAction
    actor: SteeringActor
    body_byte_count: int = Field(strict=True, ge=0, le=2048)
    body_sha256: str | None
    delivery_status: SteeringDeliveryStatus
    code: Literal[
        "continued",
        "timeout_continue",
        "nudge_pending",
        "nudge_delivered",
        "nudge_consumed",
        "stop_requested",
        "delivery_blocked",
    ]

    @model_validator(mode="after")
    def _closed_tuple(self) -> SupervisionReceipt:
        SteeringBinding.model_validate(
            {
                "project_id": self.project_id,
                "mission_id": self.mission_id,
                "node_id": self.node_id,
                "terminal_review_id": self.terminal_review_id,
                "attempt_id": self.attempt_id,
                "checkpoint_sequence": self.checkpoint_sequence,
            }
        )
        digest_valid = self.body_sha256 is not None and re.fullmatch(
            r"[0-9a-f]{64}", self.body_sha256
        )
        nudge_identity = 1 <= self.body_byte_count <= 2048 and digest_valid
        if self.action == "continue":
            valid = (
                self.body_byte_count == 0
                and self.body_sha256 is None
                and self.delivery_status == "not_applicable"
                and (
                    (self.actor in {"orchestrator", "maintainer"} and self.code == "continued")
                    or (self.actor == "timeout_policy" and self.code == "timeout_continue")
                )
            )
        elif self.action == "stop_for_attention":
            valid = (
                self.actor in {"orchestrator", "maintainer"}
                and self.body_byte_count == 0
                and self.body_sha256 is None
                and (
                    (self.delivery_status == "not_applicable" and self.code == "stop_requested")
                    or (
                        self.delivery_status == "delivery_blocked"
                        and self.code == "delivery_blocked"
                    )
                )
            )
        else:
            valid = (
                self.actor in {"orchestrator", "maintainer"}
                and bool(nudge_identity)
                and (
                    (self.delivery_status == "pending" and self.code == "nudge_pending")
                    or (
                        self.delivery_status == "delivered"
                        and self.code == "nudge_delivered"
                    )
                    or (
                        self.delivery_status == "consumed"
                        and self.code == "nudge_consumed"
                    )
                    or (
                        self.delivery_status == "delivery_blocked"
                        and self.code == "delivery_blocked"
                    )
                )
            )
        if not valid:
            raise ValueError("invalid supervision receipt tuple")
        return self


class SupervisionReceiptFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["unrest.v045.supervision-receipts.v1"] = Field(
        default="unrest.v045.supervision-receipts.v1",
        alias="schema",
        serialization_alias="schema",
    )
    receipts: list[SupervisionReceipt] = Field(default_factory=list)


class NudgeInbox(BaseModel):
    """Private runtime-only body carrier; never projected or durable."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["unrest.v045.nudge-inbox.v1"] = Field(
        default="unrest.v045.nudge-inbox.v1",
        alias="schema",
        serialization_alias="schema",
    )
    project_id: str
    mission_id: str
    node_id: str | None
    terminal_review_id: str | None
    attempt_id: str
    checkpoint_sequence: int = Field(strict=True, ge=0)
    action: Literal["nudge"] = "nudge"
    actor: Literal["orchestrator", "maintainer"]
    body: str
    body_byte_count: int = Field(strict=True, ge=1, le=2048)
    body_sha256: str
    state: Literal["pending", "consumed"]

    @model_validator(mode="after")
    def _binding_and_body(self) -> NudgeInbox:
        SteeringBinding.model_validate(
            self.model_dump(
                include={
                    "project_id",
                    "mission_id",
                    "node_id",
                    "terminal_review_id",
                    "attempt_id",
                    "checkpoint_sequence",
                }
            )
        )
        encoded = self.body.encode("utf-8")
        if len(encoded) != self.body_byte_count:
            raise ValueError("nudge byte count mismatch")
        if hashlib.sha256(encoded).hexdigest() != self.body_sha256:
            raise ValueError("nudge digest mismatch")
        return self


class AttentionItem(BaseModel):
    """Public, body-free routing identity for one open attention item."""

    model_config = ConfigDict(extra="forbid")

    id: str
    report: str
    kind: AttentionKind
    mission_id: str
    node_id: str | None
    attempt_id: str | None
    terminal_review_id: str | None

    @model_validator(mode="after")
    def _closed_kind_identity(self) -> AttentionItem:
        def present(value: str | None) -> bool:
            return value is not None and bool(value.strip())

        if self.kind in {"node_failed", "node_attention"}:
            if not present(self.node_id) or self.terminal_review_id is not None:
                raise ValueError("invalid node attention identity")
            # Null remains readable only for compatible pre-v0.4.5 records;
            # current authoring factories require the immutable attempt id.
            if self.attempt_id is not None and not present(self.attempt_id):
                raise ValueError("invalid node attention identity")
        elif self.kind in {"gate_failed", "gate_checkpoint"}:
            if (
                not present(self.node_id)
                or self.attempt_id is not None
                or self.terminal_review_id is not None
            ):
                raise ValueError("invalid gate attention identity")
        elif (
            not present(self.terminal_review_id)
            or self.node_id is not None
            or self.attempt_id is not None
        ):
            raise ValueError("invalid terminal-review attention identity")
        return self


class AttentionItemInternal(AttentionItem):
    """Runtime-only attention record retaining authorized private report text."""

    model_config = ConfigDict(extra="forbid")

    node_id: str | None = None
    # Optional only for decoding compatible records authored before v0.4.5.
    attempt_id: str | None = None
    terminal_review_id: str | None = None

# ---------------------------------------------------------------------------
# ProjectState (discriminated union)
# ---------------------------------------------------------------------------


class _StateBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Draft(_StateBase):
    state: Literal["draft"] = "draft"


class MissionPlanning(_StateBase):
    state: Literal["mission_planning"] = "mission_planning"
    mission_id: str


class MissionRunning(_StateBase):
    state: Literal["mission_running"] = "mission_running"
    mission_id: str


class AttentionNeeded(_StateBase):
    state: Literal["attention_needed"] = "attention_needed"
    items: list[AttentionItem] = Field(default_factory=list)


class Done(_StateBase):
    state: Literal["done"] = "done"


class Failed(_StateBase):
    state: Literal["failed"] = "failed"
    reason: str


class Aborted(_StateBase):
    state: Literal["aborted"] = "aborted"
    reason: str


ProjectState = Annotated[
    Union[
        Draft,
        MissionPlanning,
        MissionRunning,
        AttentionNeeded,
        Done,
        Failed,
        Aborted,
    ],
    Field(discriminator="state"),
]


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


class LineageIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mission_id: str
    node_id: str


class SupersessionLineageEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current: LineageIdentity
    superseded: list[LineageIdentity]


class Envelope(BaseModel):
    """Returned by every MCP tool.

    `dag` is a text view of the task list (kept named `dag` for
    envelope-surface stability).
    """

    model_config = ConfigDict(extra="forbid")

    projectId: str
    state: ProjectState
    projectRoot: str
    harnessRoot: str
    dag: str | None = None
    frontier: str | None = None
    next_action: NextAction
    supersession_lineage: list[SupersessionLineageEntry] = Field(default_factory=list)
    active_attempts: list[ActiveAttemptSnapshot] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Worker-side handoff schemas (written by spawned sessions, read off disk)
# ---------------------------------------------------------------------------


class WorkHandoff(BaseModel):
    """Written by work tasks via `end_node`.

    Field `node_id` is retained as the on-disk attempt filename token —
    interpreted as task id. Rename deferred.
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str
    # Optional only for decoding base-era JSON where the member is absent.
    # Storage distinguishes raw absence from an explicit JSON null.
    attempt_id: str | None = None
    done: bool
    report: str
    request_attention: bool = False


class ValidationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str
    passed: bool


class ValidateHandoff(BaseModel):
    """Written by validate tasks via `end_node`."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    # Optional only for decoding base-era JSON where the member is absent.
    # Storage distinguishes raw absence from an explicit JSON null.
    attempt_id: str | None = None
    done: bool = True
    report: str = ""
    items: list[ValidationItem] = Field(default_factory=list)
    passed: bool = False
    request_attention: bool = False


class TerminalReviewHandoff(BaseModel):
    """Written by the terminal reviewer via `submit_terminal_review`."""

    model_config = ConfigDict(extra="forbid")

    done: bool
    report: str = ""


class TerminalReviewConfig(BaseModel):
    """Canonical roots authorized by closure-review policy after preflight.

    This is preflight plus prompt policy for trusted reviewers, reducing
    accidental process-history exposure. It is not an OS filesystem sandbox
    or hard read-isolation boundary.
    """

    model_config = ConfigDict(extra="forbid")

    deliverable_roots: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# On-disk runtime cursors (HARNESS bucket; orchestrator-internal)
# ---------------------------------------------------------------------------


class TaskStateEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: TaskStatus = "pending"
    last_attempt: str | None = None  # spawn_ts of most recent dispatch


class TaskStateFile(BaseModel):
    """Live cursor: per-task status. HARNESS bucket.

    `supersede` and `cancel` patch ops rewrite downstream `depends_on`
    references in `tasks.json` directly — runtime dep-satisfaction is the
    simple `status == cleared` check. The chain mapping lives implicitly in
    the post-patch task list shape; the audit trail of "why" lives in
    `decisions/NNN.md`.
    """

    model_config = ConfigDict(extra="forbid")

    tasks: dict[str, TaskStateEntry] = Field(default_factory=dict)

    def status_of(self, task_id: str) -> TaskStatus:
        entry = self.tasks.get(task_id)
        return entry.status if entry else "pending"

    def set_status(self, task_id: str, status: TaskStatus) -> None:
        entry = self.tasks.setdefault(task_id, TaskStateEntry())
        entry.status = status

    def set_last_attempt(self, task_id: str, spawn_ts: str) -> None:
        entry = self.tasks.setdefault(task_id, TaskStateEntry())
        entry.last_attempt = spawn_ts


class ContractStateEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AssertionStatus = "pending"


class ContractStateFile(BaseModel):
    """Live cursor: per-assertion verdict. HARNESS bucket."""

    model_config = ConfigDict(extra="forbid")

    items: dict[str, ContractStateEntry] = Field(default_factory=dict)


class ProjectRecord(BaseModel):
    """Project identity and optional work-node runtime overrides."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_dir: str
    created_at: str
    current_mission_id: str | None = None
    worker_model: str | None = None
    worker_reasoning_effort: str | None = None


class AttentionFile(BaseModel):
    """List of open AttentionItemInternal entries. HARNESS bucket."""

    model_config = ConfigDict(extra="forbid")

    items: list[AttentionItemInternal] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Asset loader return type
# ---------------------------------------------------------------------------


class LoadedMarkdownAsset(BaseModel):
    name: str
    description: str | None = None
    source: Literal["project", "personal", "bundled"]
    path: str
    rawText: str
    body: str
    frontmatter: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "ASSERTION_ID_REGEX",
    "TASK_ID_REGEX",
    "SKILL_NAME_REGEX",
    "TaskType",
    "TaskStatus",
    "AssertionStatus",
    "ActionName",
    "AttentionKind",
    "NextAction",
    "SupervisionRole",
    "SupervisionPhase",
    "ScopeStatus",
    "SupervisionStatus",
    "SupervisionBlockerCode",
    "SteeringAction",
    "SteeringActor",
    "SteeringDeliveryStatus",
    "ActiveAttemptSnapshot",
    "SteeringBinding",
    "SteeringRequest",
    "SupervisionReceipt",
    "SupervisionReceiptFile",
    "NudgeInbox",
    "Task",
    "TaskList",
    "TaskListPatch",
    "Decision",
    "AttentionItem",
    "AttentionItemInternal",
    "Draft",
    "MissionPlanning",
    "MissionRunning",
    "AttentionNeeded",
    "Done",
    "Failed",
    "Aborted",
    "ProjectState",
    "LineageIdentity",
    "SupersessionLineageEntry",
    "Envelope",
    "WorkHandoff",
    "ValidationItem",
    "ValidateHandoff",
    "TerminalReviewHandoff",
    "TerminalReviewConfig",
    "TaskStateEntry",
    "TaskStateFile",
    "ContractStateEntry",
    "ContractStateFile",
    "ProjectRecord",
    "AttentionFile",
    "LoadedMarkdownAsset",
]
