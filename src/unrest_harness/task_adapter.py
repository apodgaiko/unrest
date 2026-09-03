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
_INQUIRY_RESULT_FIELDS = frozenset(
    {"answer", "branch_outcomes", "diagnostics", "inquiry_id", "receipt_id", "state"}
)
_LEGACY_INQUIRY_RESULT_FIELDS = frozenset(
    {"branch_outcomes", "inquiry_id", "receipt_id", "state"}
)
_DIAGNOSTIC_FIELDS = frozenset(
    {
        "aggregate_known_steps",
        "branch_attempts",
        "branch_steps_used",
        "error_codes",
        "synthesis_attempts",
        "synthesis_steps_used",
        "unknown_step_attempts",
    }
)
_HANDOFF_RESULT_FIELDS = frozenset(
    {"consumer_id", "handoff_id", "inquiry_id", "receipt_id"}
)
_TASK_OPERATION_ORDER = {
    "open_inquiry": 0,
    "pause_inquiry": 1,
    "resume_inquiry": 2,
    "advance_inquiry": 3,
    "handoff_inquiry": 4,
    "inspect_inquiry": 5,
}
_MAX_ANSWER_BYTES = 65_536


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


def _non_negative_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


@dataclass(frozen=True)
class InquiryDiagnostics:
    """Closed, value-free accounting projected by the Inquiry owner."""

    branch_attempts: int
    branch_steps_used: Mapping[str, int | None]
    synthesis_attempts: int
    synthesis_steps_used: int | None
    aggregate_known_steps: int
    unknown_step_attempts: int
    error_codes: Mapping[str, str | None]

    @classmethod
    def from_public(cls, value: object) -> InquiryDiagnostics:
        if not isinstance(value, Mapping) or set(value) != _DIAGNOSTIC_FIELDS:
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        branch_steps = value["branch_steps_used"]
        error_codes = value["error_codes"]
        integer_fields = (
            value["branch_attempts"],
            value["synthesis_attempts"],
            value["aggregate_known_steps"],
            value["unknown_step_attempts"],
        )
        synthesis_steps = value["synthesis_steps_used"]
        if (
            not all(_non_negative_integer(item) for item in integer_fields)
            or (
                synthesis_steps is not None
                and not _non_negative_integer(synthesis_steps)
            )
            or not isinstance(branch_steps, Mapping)
            or not isinstance(error_codes, Mapping)
        ):
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        checked_steps: dict[str, int | None] = {}
        for role, steps in branch_steps.items():
            if (
                not isinstance(role, str)
                or not role
                or (steps is not None and not _non_negative_integer(steps))
            ):
                raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
            checked_steps[role] = cast(int | None, steps)
        checked_codes: dict[str, str | None] = {}
        for role, code in error_codes.items():
            if (
                not isinstance(role, str)
                or not role
                or (code is not None and (not isinstance(code, str) or not code))
            ):
                raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
            checked_codes[role] = code
        if set(checked_steps) - set(checked_codes) or "synthesis" not in checked_codes:
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        return cls(
            branch_attempts=cast(int, value["branch_attempts"]),
            branch_steps_used=dict(sorted(checked_steps.items())),
            synthesis_attempts=cast(int, value["synthesis_attempts"]),
            synthesis_steps_used=cast(int | None, synthesis_steps),
            aggregate_known_steps=cast(int, value["aggregate_known_steps"]),
            unknown_step_attempts=cast(int, value["unknown_step_attempts"]),
            error_codes=dict(sorted(checked_codes.items())),
        )

    def public_record(self) -> dict[str, object]:
        return {
            "aggregate_known_steps": self.aggregate_known_steps,
            "branch_attempts": self.branch_attempts,
            "branch_steps_used": dict(sorted(self.branch_steps_used.items())),
            "error_codes": dict(sorted(self.error_codes.items())),
            "synthesis_attempts": self.synthesis_attempts,
            "synthesis_steps_used": self.synthesis_steps_used,
            "unknown_step_attempts": self.unknown_step_attempts,
        }


@dataclass(frozen=True)
class InquiryRecord:
    inquiry_id: str
    state: InquiryState
    branch_outcomes: Mapping[str, BranchOutcome]
    receipt_id: str | None
    answer: str | None = None
    diagnostics: InquiryDiagnostics | None = None

    @classmethod
    def from_public(cls, value: Mapping[str, object]) -> InquiryRecord:
        fields = frozenset(value)
        if fields not in {_LEGACY_INQUIRY_RESULT_FIELDS, _INQUIRY_RESULT_FIELDS}:
            raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
        inquiry_id = value.get("inquiry_id")
        state = value.get("state")
        outcomes = value.get("branch_outcomes")
        receipt_id = value.get("receipt_id")
        answer = value.get("answer")
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
        diagnostics: InquiryDiagnostics | None = None
        if fields == _INQUIRY_RESULT_FIELDS:
            if answer is not None and (
                not isinstance(answer, str)
                or len(answer.encode("utf-8")) > _MAX_ANSWER_BYTES
                or state != "answered"
            ):
                raise TaskAdapterError("invalid_result", "Inquiry result is invalid")
            diagnostics = InquiryDiagnostics.from_public(value["diagnostics"])
        return cls(
            inquiry_id=inquiry_id,
            state=cast(InquiryState, state),
            branch_outcomes=dict(sorted(checked_outcomes.items())),
            receipt_id=receipt_id,
            answer=cast(str | None, answer),
            diagnostics=diagnostics,
        )

    def public_record(self) -> dict[str, object]:
        return {
            "answer": self.answer,
            "branch_outcomes": dict(sorted(self.branch_outcomes.items())),
            "diagnostics": (
                self.diagnostics.public_record() if self.diagnostics is not None else None
            ),
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
        if set(value) != _HANDOFF_RESULT_FIELDS or any(
            not isinstance(value[field], str) or not value[field]
            for field in _HANDOFF_RESULT_FIELDS
        ):
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
        if (
            self.operation not in _TASK_OPERATION_ORDER
            or (self.inquiry is None) == (self.handoff is None)
        ):
            raise TaskAdapterError("invalid_result", "Task operation result is invalid")
        if (self.operation == "handoff_inquiry") != (self.handoff is not None):
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
    expected_consumer_id: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.terminal != _terminal(self.inquiry.state)
            or (
                self.expected_consumer_id is not None
                and (
                    not isinstance(self.expected_consumer_id, str)
                    or not self.expected_consumer_id.strip()
                )
            )
        ):
            raise TaskAdapterError("invalid_result", "Task result is invalid")
        if self.handoff is not None and (
            self.inquiry.state != "answered"
            or self.handoff.inquiry_id != self.inquiry.inquiry_id
            or (
                self.expected_consumer_id is not None
                and self.handoff.consumer_id != self.expected_consumer_id
            )
        ):
            raise TaskAdapterError("invalid_result", "Task result is invalid")
        inquiry_operations = tuple(
            operation.inquiry
            for operation in self.operations
            if operation.inquiry is not None
        )
        handoff_operations = tuple(
            operation.handoff
            for operation in self.operations
            if operation.handoff is not None
        )
        operation_names = tuple(operation.operation for operation in self.operations)
        if (
            not self.operations
            or operation_names[0] != "open_inquiry"
            or any(
                record.inquiry_id != self.inquiry.inquiry_id
                for record in inquiry_operations
            )
            or operation_names[-1] != "inspect_inquiry"
            or len(set(operation_names)) != len(operation_names)
            or tuple(_TASK_OPERATION_ORDER[name] for name in operation_names)
            != tuple(sorted(_TASK_OPERATION_ORDER[name] for name in operation_names))
            or (
                "resume_inquiry" in operation_names
                and "pause_inquiry" not in operation_names
            )
            or self.operations[-1].inquiry != self.inquiry
            or handoff_operations != (() if self.handoff is None else (self.handoff,))
        ):
            raise TaskAdapterError("invalid_result", "Task result is invalid")

    @property
    def answer(self) -> str | None:
        return self.inquiry.answer

    @property
    def diagnostics(self) -> InquiryDiagnostics | None:
        return self.inquiry.diagnostics

    @property
    def useful(self) -> bool:
        """Only a consumable Inquiry answer constitutes useful task output."""

        return (
            self.answer is not None
            and self.terminal == "completed"
            and self.inquiry.state == "answered"
            and self.handoff is not None
            and self.handoff.inquiry_id == self.inquiry.inquiry_id
            and self.expected_consumer_id is not None
            and self.handoff.consumer_id == self.expected_consumer_id
        )

    def public_record(self) -> dict[str, object]:
        return {
            "answer": self.answer,
            "diagnostics": (
                self.diagnostics.public_record() if self.diagnostics is not None else None
            ),
            "expected_consumer_id": self.expected_consumer_id,
            "handoff": self.handoff.public_record() if self.handoff is not None else None,
            "inquiry": self.inquiry.public_record(),
            "operations": [operation.public_record() for operation in self.operations],
            "schema_version": self.schema_version,
            "terminal": self.terminal,
            "useful": self.useful,
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
        if (
            handoff.inquiry_id != current.inquiry_id
            or handoff.consumer_id != request.consumer_id
        ):
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
        expected_consumer_id=request.consumer_id,
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
