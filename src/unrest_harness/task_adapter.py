"""Finite task composition over the accepted public Inquiry lifecycle.

The adapter deliberately receives its Inquiry operations from the caller.  It
does not construct a provider, manager, state store, or persistence surface of
its own; the accepted Inquiry implementation remains the sole lifecycle owner.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from typing import Literal, Protocol, cast


InquiryState = Literal[
    "open",
    "exploring",
    "synthesizing",
    "paused",
    "answered",
    "failed",
    "cancelled",
    "budget_exhausted",
]
BranchOutcome = Literal[
    "pending",
    "running",
    "paused",
    "answered",
    "failed",
    "cancelled",
    "budget_exhausted",
]
TaskTerminal = Literal[
    "completed",
    "paused",
    "failed",
    "cancelled",
    "budget_exhausted",
    "incomplete",
]
TaskOperationName = Literal[
    "open_inquiry",
    "pause_inquiry",
    "resume_inquiry",
    "advance_inquiry",
    "handoff_inquiry",
    "inspect_inquiry",
]

_INQUIRY_STATES = frozenset(
    {
        "open",
        "exploring",
        "synthesizing",
        "paused",
        "answered",
        "failed",
        "cancelled",
        "budget_exhausted",
    }
)
_BRANCH_OUTCOMES = frozenset(
    {
        "pending",
        "running",
        "paused",
        "answered",
        "failed",
        "cancelled",
        "budget_exhausted",
    }
)
_ACTIVE_STATES = frozenset({"open", "exploring", "synthesizing"})


class TaskAdapterError(RuntimeError):
    """Stable, value-free adapter validation failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class InquiryLifecycle(Protocol):
    """Accepted Inquiry public operations required by :func:`run_task`."""

    def open_inquiry(
        self,
        question: str,
        budget: Mapping[str, int],
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Mapping[str, object]: ...

    async def advance_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...

    def pause_inquiry(
        self,
        inquiry_id: str,
        reason: str,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...

    def resume_inquiry(
        self,
        inquiry_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...

    def handoff_inquiry(
        self,
        inquiry_id: str,
        consumer_id: str,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...

    def inspect_inquiry(self, inquiry_id: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class TaskBounds:
    """Finite budget passed unchanged to Inquiry."""

    max_steps: int
    timeout_seconds: int
    max_branches: int = 4

    def __post_init__(self) -> None:
        values = (self.max_steps, self.timeout_seconds, self.max_branches)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TaskAdapterError("invalid_argument", "Task bounds are invalid")
        if self.max_steps < 1 or self.timeout_seconds < 1 or not 1 <= self.max_branches <= 4:
            raise TaskAdapterError("invalid_argument", "Task bounds are invalid")

    def inquiry_budget(self) -> dict[str, int]:
        return {
            "max_branches": self.max_branches,
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class TaskRequest:
    """Private task input and deterministic lifecycle controls."""

    brief: str
    bounds: TaskBounds
    idempotency_key: str
    consumer_id: str = "task-adapter"
    project_id: str | None = None
    pause_reason: str | None = None
    resume_after_pause: bool = False

    def __post_init__(self) -> None:
        for value in (self.brief, self.idempotency_key, self.consumer_id):
            if not isinstance(value, str) or not value.strip():
                raise TaskAdapterError("invalid_argument", "Task request is invalid")
        if self.project_id is not None and (
            not isinstance(self.project_id, str) or not self.project_id.strip()
        ):
            raise TaskAdapterError("invalid_argument", "Task request is invalid")
        if self.pause_reason is not None and (
            not isinstance(self.pause_reason, str) or not self.pause_reason.strip()
        ):
            raise TaskAdapterError("invalid_argument", "Task request is invalid")
        if not isinstance(self.resume_after_pause, bool):
            raise TaskAdapterError("invalid_argument", "Task request is invalid")
        if self.resume_after_pause and self.pause_reason is None:
            raise TaskAdapterError("invalid_argument", "Task request is invalid")


@dataclass(frozen=True)
class InquiryRecord:
    inquiry_id: str
    state: InquiryState
    branch_outcomes: Mapping[str, BranchOutcome]
    receipt_id: str | None

    @classmethod
    def from_public(cls, value: Mapping[str, object]) -> InquiryRecord:
        inquiry_id = value.get("inquiry_id")
        state = value.get("state")
        outcomes = value.get("branch_outcomes")
        receipt_id = value.get("receipt_id")
        if not isinstance(inquiry_id, str) or not inquiry_id:
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        if not isinstance(state, str) or state not in _INQUIRY_STATES:
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        if not isinstance(outcomes, Mapping):
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        checked_outcomes: dict[str, BranchOutcome] = {}
        for role, outcome in outcomes.items():
            if (
                not isinstance(role, str)
                or not isinstance(outcome, str)
                or outcome not in _BRANCH_OUTCOMES
            ):
                raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
            checked_outcomes[role] = cast(BranchOutcome, outcome)
        if receipt_id is not None and not isinstance(receipt_id, str):
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        return cls(
            inquiry_id=inquiry_id,
            state=cast(InquiryState, state),
            branch_outcomes=dict(sorted(checked_outcomes.items())),
            receipt_id=receipt_id,
        )

    def public_record(self) -> dict[str, object]:
        return {
            "branch_outcomes": dict(sorted(self.branch_outcomes.items())),
            "inquiry_id": self.inquiry_id,
            "receipt_id": self.receipt_id,
            "state": self.state,
        }


@dataclass(frozen=True)
class HandoffRecord:
    consumer_id: str
    handoff_id: str
    inquiry_id: str
    receipt_id: str

    @classmethod
    def from_public(cls, value: Mapping[str, object]) -> HandoffRecord:
        fields = ("consumer_id", "handoff_id", "inquiry_id", "receipt_id")
        if any(not isinstance(value.get(field), str) or not value.get(field) for field in fields):
            raise TaskAdapterError("invalid_result", "Inquiry handoff result is invalid")
        return cls(
            consumer_id=cast(str, value["consumer_id"]),
            handoff_id=cast(str, value["handoff_id"]),
            inquiry_id=cast(str, value["inquiry_id"]),
            receipt_id=cast(str, value["receipt_id"]),
        )

    def public_record(self) -> dict[str, str]:
        return {
            "consumer_id": self.consumer_id,
            "handoff_id": self.handoff_id,
            "inquiry_id": self.inquiry_id,
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True)
class TaskOperation:
    operation: TaskOperationName
    inquiry: InquiryRecord | None = None
    handoff: HandoffRecord | None = None

    def __post_init__(self) -> None:
        if (self.inquiry is None) == (self.handoff is None):
            raise TaskAdapterError("invalid_result", "Task operation result is invalid")

    def public_record(self) -> dict[str, object]:
        result = (
            self.inquiry.public_record()
            if self.inquiry is not None
            else cast(HandoffRecord, self.handoff).public_record()
        )
        return {"operation": self.operation, "result": result}


@dataclass(frozen=True)
class TaskResult:
    terminal: TaskTerminal
    inquiry: InquiryRecord
    handoff: HandoffRecord | None
    operations: tuple[TaskOperation, ...]
    schema_version: int = 1

    def public_record(self) -> dict[str, object]:
        return {
            "handoff": self.handoff.public_record() if self.handoff is not None else None,
            "inquiry": self.inquiry.public_record(),
            "operations": [operation.public_record() for operation in self.operations],
            "schema_version": self.schema_version,
            "terminal": self.terminal,
        }

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 JSON bytes for the public result."""

        return json.dumps(
            self.public_record(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


def _operation_key(base: str, operation: TaskOperationName) -> str:
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return f"task-adapter:{digest}:{operation}"


def _terminal(state: InquiryState) -> TaskTerminal:
    terminal = {
        "answered": "completed",
        "paused": "paused",
        "failed": "failed",
        "cancelled": "cancelled",
        "budget_exhausted": "budget_exhausted",
    }.get(state, "incomplete")
    return cast(TaskTerminal, terminal)


async def run_task(lifecycle: InquiryLifecycle, request: TaskRequest) -> TaskResult:
    """Run one finite task pass using only accepted Inquiry operations.

    Active Inquiry states are advanced at most once.  A caller may request an
    explicit pause checkpoint and either return it or resume before that one
    advance.  Answered inquiries are handed off exactly once (idempotently),
    and every path ends with the accepted inspect operation.
    """

    operations: list[TaskOperation] = []
    current = InquiryRecord.from_public(
        lifecycle.open_inquiry(
            request.brief,
            request.bounds.inquiry_budget(),
            _operation_key(request.idempotency_key, "open_inquiry"),
            request.project_id,
        )
    )
    operations.append(TaskOperation("open_inquiry", inquiry=current))

    if request.pause_reason is not None and current.state in _ACTIVE_STATES:
        current = InquiryRecord.from_public(
            lifecycle.pause_inquiry(
                current.inquiry_id,
                request.pause_reason,
                _operation_key(request.idempotency_key, "pause_inquiry"),
            )
        )
        operations.append(TaskOperation("pause_inquiry", inquiry=current))

    if request.resume_after_pause and current.state == "paused":
        current = InquiryRecord.from_public(
            lifecycle.resume_inquiry(
                current.inquiry_id,
                _operation_key(request.idempotency_key, "resume_inquiry"),
            )
        )
        operations.append(TaskOperation("resume_inquiry", inquiry=current))

    if current.state in _ACTIVE_STATES:
        current = InquiryRecord.from_public(
            await lifecycle.advance_inquiry(
                current.inquiry_id,
                _operation_key(request.idempotency_key, "advance_inquiry"),
            )
        )
        operations.append(TaskOperation("advance_inquiry", inquiry=current))

    handoff: HandoffRecord | None = None
    if current.state == "answered":
        handoff = HandoffRecord.from_public(
            lifecycle.handoff_inquiry(
                current.inquiry_id,
                request.consumer_id,
                _operation_key(request.idempotency_key, "handoff_inquiry"),
            )
        )
        if handoff.inquiry_id != current.inquiry_id:
            raise TaskAdapterError("invalid_result", "Inquiry handoff result is invalid")
        operations.append(TaskOperation("handoff_inquiry", handoff=handoff))

    inspected = InquiryRecord.from_public(lifecycle.inspect_inquiry(current.inquiry_id))
    if inspected.inquiry_id != current.inquiry_id:
        raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
    operations.append(TaskOperation("inspect_inquiry", inquiry=inspected))
    return TaskResult(
        terminal=_terminal(inspected.state),
        inquiry=inspected,
        handoff=handoff,
        operations=tuple(operations),
    )


__all__ = [
    "HandoffRecord",
    "InquiryLifecycle",
    "InquiryRecord",
    "TaskAdapterError",
    "TaskBounds",
    "TaskOperation",
    "TaskRequest",
    "TaskResult",
    "run_task",
]
