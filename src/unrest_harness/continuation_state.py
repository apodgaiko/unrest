"""Inert classifier of one exact-bound work unit and its acceptance frontier.

The module is a pure function core: it reads no clock, file, environment or
process, has no importers, and grants no dispatch, retry, recovery or
completion authority.  ``assess_unit`` returns conditional advice over caller
supplied facts; ``advance_progress`` returns a new immutable frontier.  Basis
references and source kinds constrain form only and never authenticate origin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Callable, Final

from .continuation_types import (
    DURATION_MS_MAX,
    ClockReadingMs,
    DurationMs,
    elapsed_between,
)


LOCAL_TUPLE_CAP: Final[int] = 64
AGGREGATE_BASIS_CAP: Final[int] = 64
MAX_FRONTIER_SEEN: Final[int] = 1024
INT64_MAX: Final[int] = DURATION_MS_MAX

STATE_CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_type",
        "out_of_range",
        "invalid_token",
        "invalid_enum",
        "detail_mismatch",
        "source_kind_not_allowed",
        "duplicate_entry",
        "conflicting_entry",
        "too_many_refs",
        "binding_mismatch",
        "epoch_mismatch",
        "future_observation",
        "clock_regression",
        "sequence_regression",
        "evidence_identity_conflict",
        "frontier_capacity_exhausted",
        "frontier_invalid",
        "profile_invalid",
        "phase_invalid",
        "wait_invalid",
    }
)

SOURCE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "control_record",
        "integrity_check",
        "run_record",
        "stop_record",
        "admission_record",
        "attempt_observation",
        "policy_record",
        "authority_record",
        "user_decision_record",
        "external_predicate",
        "phase_observation",
        "obligation_record",
        "validator_verdict",
        "gate_verdict",
        "readiness_predicate",
        "dependency_assertion",
        "failure_record",
        "constraint_analysis",
        "agent_claim",
    }
)

CONTROL_VALUES: Final = frozenset({"requested", "absent", "unknown"})
INTEGRITY_VALUES: Final = frozenset({"passed", "refused", "unknown"})
COHERENCE_VALUES: Final = frozenset({"coherent", "inconsistent", "unknown"})
POLICY_VALUES: Final = frozenset({"none", "held", "unknown"})
ATTEMPT_VALUES: Final = frozenset({"none", "admitted", "unknown"})
APPLICABILITY_VALUES: Final = frozenset({"applies", "not_applicable", "unknown"})
SETTLEMENT_VALUES: Final = frozenset(
    {
        "not_applicable",
        "pending",
        "never_dispatched",
        "owner_completed",
        "owner_failed",
        "owner_reported",
        "owner_unproven",
        "unrequested_owner_cancel",
        "legacy_unclassified",
        "unknown",
    }
)
REPLAY_VALUES: Final = frozenset({"clear", "unresolved", "unknown"})
OUTCOME_VALUES: Final = frozenset({"settled", "unresolved", "unknown"})
COVERAGE_VALUES: Final = frozenset({"complete", "unknown"})
USER_DECISION_VALUES: Final = frozenset({"none_pending", "pending", "unknown"})
DECISION_KINDS: Final = frozenset(
    {"authority_decision_required", "scope_decision_required", "access_decision_required"}
)
WAIT_VALUES: Final = frozenset({"none", "waiting", "unknown"})
OBLIGATION_VALUES: Final = frozenset({"pending", "all_satisfied", "none_declared", "unknown"})
ELIGIBILITY_VALUES: Final = frozenset({"admissible", "not_admissible", "unknown"})
TRANSITION_KINDS: Final = frozenset({"planned_task", "verification_check", "closure_step"})
OWNER_VALUES: Final = frozenset({"absent", "present", "unknown"})
AUTHORITY_VALUES: Final = frozenset({"within_existing", "denied", "unknown"})
RELATION_VALUES: Final = frozenset({"independent", "dependent", "unknown"})
FAILURE_VALUES: Final = frozenset({"none", "recoverable_classified", "unknown"})
CONFLICT_VALUES: Final = frozenset({"none", "asserted", "unknown"})
CLAIM_CODES: Final = frozenset(
    {
        "contradiction_claimed",
        "done_claimed",
        "blocker_claimed",
        "dependency_unavailable_claimed",
        "scope_ambiguous_claimed",
        "authority_required_claimed",
    }
)
CLAIM_KEY_KINDS: Final = frozenset(
    {"assertion_satisfied", "gate_satisfied", "blocker_cleared", "diagnostic_finding"}
)
ACCEPTANCE_KINDS: Final = frozenset({"assertion_satisfied", "gate_satisfied", "blocker_cleared"})
PROGRESS_KINDS: Final = CLAIM_KEY_KINDS | {"activity"}
ACTIVITY_KINDS: Final = frozenset(
    {"token", "mtime", "poll", "report_rewrite", "status_repeat", "effect_sequence"}
)

STATES: Final = frozenset(
    {
        "working",
        "ready",
        "verifying",
        "waiting_external",
        "needs_user",
        "stalled",
        "paused_policy",
    }
)
PRIMARY_REASONS: Final[dict[str, frozenset[str]]] = {
    "paused_policy": frozenset(
        {
            "cancel_requested",
            "pause_requested",
            "drain_requested",
            "integrity_refused",
            "inconsistent_observations",
            "outcome_unresolved",
            "clearance_unresolved",
            "policy_hold",
            "dependency_on_held_unit",
            "authority_denied",
            "other_owner_present",
        }
    ),
    "needs_user": DECISION_KINDS,
    "stalled": frozenset(
        {"hard_deadline_elapsed", "wait_deadline_elapsed", "progress_deadline_elapsed"}
    ),
    "waiting_external": frozenset({"external_dependency"}),
    "working": frozenset({"attempt_admitted"}),
    "verifying": frozenset({"verification_pending"}),
    "ready": frozenset({"transition_admissible"}),
}
INDETERMINATE_CODES: Final = frozenset(
    {
        "stale_observation",
        "control_unknown",
        "integrity_unknown",
        "coherence_unknown",
        "policy_unknown",
        "attempt_unknown",
        "applicability_unknown",
        "clearance_unknown",
        "user_decision_unknown",
        "wait_unknown",
        "obligations_unknown",
        "conflict_unknown",
        "failure_unknown",
        "readiness_unknown",
        "authority_unknown",
        "owner_unknown",
        "related_holds_coverage_unknown",
        "independence_unknown",
        "clearance_coverage_unknown",
        "no_classifiable_condition",
    }
)
DIAGNOSTIC_CODES: Final = frozenset(
    {
        "obligations_satisfied_during_attempt",
        "transition_admissible_during_attempt",
        "obligations_pending_during_attempt",
        "attempt_admitted_during_wait",
        "proposed_transition_outcome_unresolved",
        "proposed_transition_clearance_unresolved",
        "phase_exemption_active",
        "phase_not_applicable",
        "recoverable_failure_known",
        "constraint_conflict_asserted",
        "external_observation_due",
    }
)
REASON_CODES: Final = (
    frozenset().union(*PRIMARY_REASONS.values())
    | (INDETERMINATE_CODES - {"no_classifiable_condition"})
    | DIAGNOSTIC_CODES
)
HINTS: Final = frozenset(
    {
        "none",
        "observe",
        "external_observation_due",
        "user_decision_required",
        "verification_required",
        "consider_existing_transition",
        "review_integrity",
        "review_unresolved_outcome",
        "review_clearance",
        "review_policy",
        "facts_required",
        "evaluation_deferred",
    }
)
LIVENESS_VALUES: Final = frozenset({"fresh", "stale", "unobserved", "not_applicable"})
DEFERRED_PAIRS: Final[dict[str, str]] = {
    "impossibility_evaluation": "constraint_conflict_requires_dossier",
    "recovery_evaluation": "recovery_not_in_slice",
    "completion_evaluation": "terminal_predicate_not_in_slice",
}
DISPOSITIONS: Final = frozenset(
    {
        "acceptance_advanced",
        "diagnostic_advanced",
        "semantic_repeat",
        "exact_duplicate",
        "activity_ignored",
    }
)

_TOKEN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_MISSING: Final = object()

# Allowed source kinds per basis role (contract V3 §4.2a-§4.5).
_K_CONTROL: Final = frozenset({"control_record"})
_K_INTEGRITY: Final = frozenset({"integrity_check", "run_record"})
_K_COHERENCE: Final = frozenset(
    {"run_record", "stop_record", "admission_record", "attempt_observation"}
)
_K_POLICY: Final = frozenset({"policy_record"})
_K_ATTEMPT_NONE: Final = frozenset({"run_record", "admission_record", "attempt_observation"})
_K_ATTEMPT_ADMITTED: Final = frozenset({"run_record", "attempt_observation"})
_K_LIVENESS: Final = frozenset({"attempt_observation"})
_K_USER: Final = frozenset({"user_decision_record"})
_K_EXTERNAL: Final = frozenset({"external_predicate"})
_K_OBLIGATION: Final = frozenset({"obligation_record"})
_K_VERDICT: Final = frozenset({"validator_verdict", "gate_verdict"})
_K_READINESS: Final = frozenset({"readiness_predicate"})
_K_OWNER: Final = frozenset({"run_record", "admission_record", "attempt_observation"})
_K_AUTHORITY: Final = frozenset({"authority_record"})
_K_DEPENDENCY: Final = frozenset({"dependency_assertion"})
_K_APPLICABILITY: Final = frozenset({"dependency_assertion", "stop_record", "admission_record"})
_K_CELL_STATE: Final = frozenset({"stop_record", "admission_record"})
_K_FAILURE: Final = frozenset({"failure_record"})
_K_CONFLICT: Final = frozenset({"constraint_analysis"})
_K_PHASE: Final = frozenset({"phase_observation"})
_K_CLAIM: Final = frozenset({"agent_claim"})
_K_PROGRESS: Final[dict[str, frozenset[str]]] = {
    "assertion_satisfied": frozenset({"validator_verdict"}),
    "gate_satisfied": frozenset({"gate_verdict"}),
    "blocker_cleared": frozenset({"readiness_predicate"}),
    "diagnostic_finding": frozenset(
        {"validator_verdict", "gate_verdict", "failure_record", "agent_claim"}
    ),
    "activity": frozenset({"attempt_observation", "agent_claim"}),
}


class ContinuationStateError(ValueError):
    """A closed, input-free state failure; ``str(error) == code``."""

    code: str

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in STATE_CODES:
            # Programmer misuse: a constant message, never the rejected value.
            raise ValueError("invalid_error_code")
        super().__init__(code)
        self.code = code


# Field checks return a closed code instead of raising, so every public error
# is raised outside any handler and never chains internal context.  Public
# operations revalidate the exact class and every field: frozen dataclasses can
# be bypassed with ``object.__setattr__``, ``object.__new__`` or subclasses, and
# ``getattr`` with a sentinel reads an empty slot without an exception.

Code = str | None


def _get(value: object, name: str) -> object:
    return getattr(value, name, _MISSING)


def _token_code(value: object) -> Code:
    if type(value) is not str:
        return "invalid_type"
    if _TOKEN.fullmatch(value) is None:
        return "invalid_token"
    return None


def _int_code(value: object, minimum: int) -> Code:
    if type(value) is not int:
        return "invalid_type"
    if value < minimum or value > INT64_MAX:
        return "out_of_range"
    return None


def _enum_code(value: object, allowed: frozenset[str]) -> Code:
    if type(value) is not str:
        return "invalid_type"
    if value not in allowed:
        return "invalid_enum"
    return None


def _clock_code(value: object) -> Code:
    if type(value) is not ClockReadingMs:
        return "invalid_type"
    return _token_code(_get(value, "epoch_id")) or _int_code(_get(value, "elapsed_ms"), 0)


def _optional_clock_code(value: object) -> Code:
    return None if value is None else _clock_code(value)


def _duration_code(value: object) -> Code:
    """Shape of a positive duration; ``0`` is reported by the caller's own code."""
    if type(value) is not DurationMs:
        return "invalid_type"
    return _int_code(_get(value, "value"), 0)


def _ref_class_code(value: object) -> Code:
    """Structural slot check: exactly ``BasisRef`` or ``None``; payload is not read."""
    if value is None or type(value) is BasisRef:
        return None
    return "invalid_type"


def _ref_payload_code(value: object) -> Code:
    if type(value) is not BasisRef:
        return "invalid_type"
    return _enum_code(_get(value, "source_kind"), SOURCE_KINDS) or _token_code(_get(value, "ref"))


def _role_code(value: object, required: bool, kinds: frozenset[str]) -> Code:
    """One singular basis role: exactly one ``BasisRef`` when required, else ``None``."""
    if required:
        if value is None:
            return "detail_mismatch"
        code = _ref_payload_code(value)
        if code is not None:
            return code
        if _get(value, "source_kind") not in kinds:
            return "source_kind_not_allowed"
        return None
    if value is not None:
        return "detail_mismatch" if type(value) is BasisRef else "invalid_type"
    return None


def _basis_code(value: object, kinds: frozenset[str]) -> Code:
    """An unconditional role typed ``BasisRef`` (never ``| None``): ``None`` is a wrong type."""
    if value is None:
        return "invalid_type"
    return _role_code(value, True, kinds)


def _tuple_shape_code(value: object) -> Code:
    if type(value) is not tuple:
        return "invalid_type"
    if len(value) > LOCAL_TUPLE_CAP:
        return "too_many_refs"
    return None


def _ref_key(ref: BasisRef) -> tuple[str, str]:
    return (ref.source_kind, ref.ref)


def _ref_tuple_code(value: object, kinds: frozenset[str], minimum: int, maximum: int) -> Code:
    """A tuple basis role; shape (class, local cap) before any element is read."""
    code = _tuple_shape_code(value)
    if code is not None:
        return code
    assert type(value) is tuple
    if len(value) < minimum or len(value) > maximum:
        return "detail_mismatch"
    for item in value:
        code = _ref_payload_code(item)
        if code is not None:
            return code
        if item.source_kind not in kinds:
            return "source_kind_not_allowed"
    keys = sorted(_ref_key(item) for item in value)
    if len(set(keys)) != len(keys):
        return "duplicate_entry"
    return None


def _sorted_refs(items: tuple[BasisRef, ...]) -> tuple[BasisRef, ...]:
    return tuple(sorted(items, key=_ref_key))


def _raise_if(code: Code) -> None:
    if code is not None:
        raise ContinuationStateError(code)


# --------------------------------------------------------------------------- values


@dataclass(frozen=True, slots=True)
class Binding:
    """Exact seven-component identity of one bound work unit."""

    mission_id: str
    continuation_id: str
    origin_id: str
    generation: int
    candidate_id: str
    scope_id: str
    unit_id: str

    def __post_init__(self) -> None:
        _raise_if(_binding_code(self))


def _binding_code(value: object) -> Code:
    if type(value) is not Binding:
        return "invalid_type"
    for name in ("mission_id", "continuation_id", "origin_id"):
        code = _token_code(_get(value, name))
        if code is not None:
            return code
    code = _int_code(_get(value, "generation"), 1)
    if code is not None:
        return code
    for name in ("candidate_id", "scope_id", "unit_id"):
        code = _token_code(_get(value, name))
        if code is not None:
            return code
    return None


@dataclass(frozen=True, slots=True)
class BasisRef:
    """A reference to a caller assertion; a label, not an authenticated source."""

    source_kind: str
    ref: str

    def __post_init__(self) -> None:
        _raise_if(_ref_payload_code(self))


@dataclass(frozen=True, slots=True)
class Controls:
    cancel: str
    pause: str
    drain: str
    basis: tuple[BasisRef, ...]

    def __post_init__(self) -> None:
        _raise_if(_controls_shape(self) or _controls_code(self))
        object.__setattr__(self, "basis", _sorted_refs(self.basis))


def _controls_shape(value: object) -> Code:
    return _tuple_shape_code(_get(value, "basis"))


def _controls_code(value: object) -> Code:
    states = [_get(value, name) for name in ("cancel", "pause", "drain")]
    for state in states:
        code = _enum_code(state, CONTROL_VALUES)
        if code is not None:
            return code
    known = any(state != "unknown" for state in states)
    return _ref_tuple_code(_get(value, "basis"), _K_CONTROL, 1 if known else 0, 64 if known else 0)


def _status_role_code(
    value: object, values: frozenset[str], kinds: frozenset[str]
) -> Code:
    """A holder ``(status, basis)`` whose known statuses all carry one basis."""
    status = _get(value, "status")
    code = _enum_code(status, values)
    if code is not None:
        return code
    return _role_code(_get(value, "basis"), status != "unknown", kinds)


@dataclass(frozen=True, slots=True)
class IntegrityFact:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, INTEGRITY_VALUES, _K_INTEGRITY))


@dataclass(frozen=True, slots=True)
class CoherenceFact:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, COHERENCE_VALUES, _K_COHERENCE))


@dataclass(frozen=True, slots=True)
class PolicyHoldFact:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, POLICY_VALUES, _K_POLICY))


@dataclass(frozen=True, slots=True)
class FailureFact:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, FAILURE_VALUES, _K_FAILURE))


@dataclass(frozen=True, slots=True)
class ConflictFact:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, CONFLICT_VALUES, _K_CONFLICT))


@dataclass(frozen=True, slots=True)
class Coverage:
    status: str
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_status_role_code(self, COVERAGE_VALUES, _K_DEPENDENCY))


@dataclass(frozen=True, slots=True)
class AttemptFact:
    status: str
    attempt_ref: str | None
    started_at: ClockReadingMs | None
    last_liveness_at: ClockReadingMs | None
    liveness_basis: BasisRef | None
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_attempt_code(self))


def _attempt_code(value: object) -> Code:
    status = _get(value, "status")
    code = _enum_code(status, ATTEMPT_VALUES)
    if code is not None:
        return code
    attempt_ref = _get(value, "attempt_ref")
    started_at = _get(value, "started_at")
    liveness_at = _get(value, "last_liveness_at")
    liveness_basis = _get(value, "liveness_basis")
    basis = _get(value, "basis")
    if status == "admitted":
        code = (
            _token_code(attempt_ref)
            if attempt_ref is not None
            else "detail_mismatch"
        )
        code = code or (_clock_code(started_at) if started_at is not None else "detail_mismatch")
        code = code or _optional_clock_code(liveness_at)
        code = code or _role_code(liveness_basis, liveness_at is not None, _K_LIVENESS)
        return code or _role_code(basis, True, _K_ATTEMPT_ADMITTED)
    for detail in (attempt_ref, started_at, liveness_at):
        if detail is not None:
            return "detail_mismatch"
    code = _role_code(liveness_basis, False, _K_LIVENESS)
    return code or _role_code(basis, status == "none", _K_ATTEMPT_NONE)


@dataclass(frozen=True, slots=True)
class ClearanceCell:
    """Clearance of the next proposed effect against one predecessor/resource."""

    predecessor_ref: str
    resource_ref: str
    applicability: str
    applicability_basis: BasisRef | None
    settlement: str
    replay_clearance: str
    outcome: str
    state_basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_cell_shape(self) or _cell_code(self))


def _cell_shape(value: object) -> Code:
    if type(value) is not ClearanceCell:
        return "invalid_type"
    return _ref_class_code(_get(value, "applicability_basis")) or _ref_class_code(
        _get(value, "state_basis")
    )


def _cell_code(value: object) -> Code:
    code = _token_code(_get(value, "predecessor_ref")) or _token_code(
        _get(value, "resource_ref")
    )
    if code is not None:
        return code
    applicability = _get(value, "applicability")
    code = _enum_code(applicability, APPLICABILITY_VALUES)
    code = code or _role_code(
        _get(value, "applicability_basis"), applicability != "unknown", _K_APPLICABILITY
    )
    code = code or _enum_code(_get(value, "settlement"), SETTLEMENT_VALUES)
    replay = _get(value, "replay_clearance")
    outcome = _get(value, "outcome")
    code = code or _enum_code(replay, REPLAY_VALUES) or _enum_code(outcome, OUTCOME_VALUES)
    if code is not None:
        return code
    known = replay != "unknown" or outcome != "unknown"
    return _role_code(_get(value, "state_basis"), known, _K_CELL_STATE)


def _cell_key(cell: ClearanceCell) -> tuple[str, str]:
    return (cell.predecessor_ref, cell.resource_ref)


@dataclass(frozen=True, slots=True)
class UserDecisionFact:
    status: str
    kind: str | None
    basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_user_decision_code(self))


def _user_decision_code(value: object) -> Code:
    status = _get(value, "status")
    code = _enum_code(status, USER_DECISION_VALUES)
    if code is not None:
        return code
    kind = _get(value, "kind")
    if status == "pending":
        code = _enum_code(kind, DECISION_KINDS) if kind is not None else "detail_mismatch"
    elif kind is not None:
        code = "detail_mismatch"
    return code or _role_code(_get(value, "basis"), status != "unknown", _K_USER)


@dataclass(frozen=True, slots=True)
class WaitSpec:
    predicate_ref: str
    source: BasisRef
    established_at: ClockReadingMs
    next_check_at: ClockReadingMs
    overall_timeout: DurationMs

    def __post_init__(self) -> None:
        _raise_if(_wait_spec_code(self))


def _wait_spec_code(value: object) -> Code:
    if type(value) is not WaitSpec:
        return "invalid_type"
    established = _get(value, "established_at")
    next_check = _get(value, "next_check_at")
    timeout = _get(value, "overall_timeout")
    code = _token_code(_get(value, "predicate_ref"))
    code = code or _basis_code(_get(value, "source"), _K_EXTERNAL)
    code = code or _clock_code(established) or _clock_code(next_check) or _duration_code(timeout)
    if code is not None:
        return code
    assert type(established) is ClockReadingMs and type(next_check) is ClockReadingMs
    assert type(timeout) is DurationMs
    if (
        timeout.value == 0
        or established.epoch_id != next_check.epoch_id
        or next_check.elapsed_ms < established.elapsed_ms
        or elapsed_between(established, next_check).value > timeout.value
    ):
        return "wait_invalid"
    return None


@dataclass(frozen=True, slots=True)
class WaitFact:
    status: str
    spec: WaitSpec | None
    absence_basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_wait_code(self))


def _wait_code(value: object) -> Code:
    status = _get(value, "status")
    code = _enum_code(status, WAIT_VALUES)
    if code is not None:
        return code
    spec = _get(value, "spec")
    if status == "waiting":
        code = _wait_spec_code(spec) if spec is not None else "detail_mismatch"
    elif spec is not None:
        code = "detail_mismatch"
    return code or _role_code(_get(value, "absence_basis"), status == "none", _K_EXTERNAL)


@dataclass(frozen=True, slots=True)
class ObligationFact:
    status: str
    refs: tuple[BasisRef, ...]
    declaration_basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_tuple_shape_code(self.refs) or _obligation_code(self))
        object.__setattr__(self, "refs", _sorted_refs(self.refs))


def _obligation_code(value: object) -> Code:
    status = _get(value, "status")
    code = _enum_code(status, OBLIGATION_VALUES)
    if code is not None:
        return code
    refs = _get(value, "refs")
    if status == "pending":
        code = _ref_tuple_code(refs, _K_OBLIGATION, 1, LOCAL_TUPLE_CAP)
    elif status == "all_satisfied":
        code = _ref_tuple_code(refs, _K_VERDICT, 1, LOCAL_TUPLE_CAP)
    else:
        code = _ref_tuple_code(refs, _K_OBLIGATION, 0, 0)
    return code or _role_code(
        _get(value, "declaration_basis"), status != "unknown", _K_OBLIGATION
    )


@dataclass(frozen=True, slots=True)
class ReadinessFact:
    eligibility: str
    transition_kind: str | None
    eligibility_basis: BasisRef | None
    other_owner: str
    owner_basis: BasisRef | None
    authority: str
    authority_basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_readiness_code(self))


def _readiness_code(value: object) -> Code:
    eligibility = _get(value, "eligibility")
    code = _enum_code(eligibility, ELIGIBILITY_VALUES)
    if code is not None:
        return code
    kind = _get(value, "transition_kind")
    if eligibility == "admissible":
        code = _enum_code(kind, TRANSITION_KINDS) if kind is not None else "detail_mismatch"
    elif kind is not None:
        code = "detail_mismatch"
    code = code or _role_code(
        _get(value, "eligibility_basis"), eligibility != "unknown", _K_READINESS
    )
    owner = _get(value, "other_owner")
    code = code or _enum_code(owner, OWNER_VALUES)
    code = code or _role_code(_get(value, "owner_basis"), owner != "unknown", _K_OWNER)
    authority = _get(value, "authority")
    code = code or _enum_code(authority, AUTHORITY_VALUES)
    return code or _role_code(
        _get(value, "authority_basis"), authority != "unknown", _K_AUTHORITY
    )


@dataclass(frozen=True, slots=True)
class RelatedHold:
    hold_ref: str
    relation: str
    relation_basis: BasisRef | None

    def __post_init__(self) -> None:
        _raise_if(_hold_shape(self) or _hold_code(self))


def _hold_shape(value: object) -> Code:
    if type(value) is not RelatedHold:
        return "invalid_type"
    return _ref_class_code(_get(value, "relation_basis"))


def _hold_code(value: object) -> Code:
    relation = _get(value, "relation")
    code = _token_code(_get(value, "hold_ref")) or _enum_code(relation, RELATION_VALUES)
    return code or _role_code(_get(value, "relation_basis"), relation != "unknown", _K_DEPENDENCY)


@dataclass(frozen=True, slots=True)
class PhaseObservation:
    phase_id: str
    last_observed_at: ClockReadingMs
    basis: BasisRef

    def __post_init__(self) -> None:
        _raise_if(_phase_observation_code(self))


def _phase_observation_code(value: object) -> Code:
    if type(value) is not PhaseObservation:
        return "invalid_type"
    code = _token_code(_get(value, "phase_id")) or _clock_code(_get(value, "last_observed_at"))
    return code or _basis_code(_get(value, "basis"), _K_PHASE)


@dataclass(frozen=True, slots=True)
class ClaimFact:
    """An agent claim: diagnostic only, never part of a decision."""

    code: str
    basis: BasisRef

    def __post_init__(self) -> None:
        _raise_if(_claim_shape(self) or _claim_code(self))


def _claim_shape(value: object) -> Code:
    if type(value) is not ClaimFact:
        return "invalid_type"
    return None if type(_get(value, "basis")) is BasisRef else "invalid_type"


def _claim_code(value: object) -> Code:
    code = _enum_code(_get(value, "code"), CLAIM_CODES)
    return code or _basis_code(_get(value, "basis"), _K_CLAIM)


_FACT_FIELDS: Final = (
    ("controls", Controls),
    ("integrity", IntegrityFact),
    ("coherence", CoherenceFact),
    ("policy_hold", PolicyHoldFact),
    ("attempt", AttemptFact),
    ("clearance", tuple),
    ("clearance_coverage", Coverage),
    ("user_decision", UserDecisionFact),
    ("wait", WaitFact),
    ("obligations", ObligationFact),
    ("readiness", ReadinessFact),
    ("related_holds", tuple),
    ("related_holds_coverage", Coverage),
    ("failure", FailureFact),
    ("constraint_conflict", ConflictFact),
)

# Singular top-level basis slots counted by occurrence (contract V3 §4.6a).
_SINGULAR_SLOTS: Final = (
    ("integrity", "basis"),
    ("coherence", "basis"),
    ("policy_hold", "basis"),
    ("attempt", "basis"),
    ("attempt", "liveness_basis"),
    ("user_decision", "basis"),
    ("wait", "absence_basis"),
    ("obligations", "declaration_basis"),
    ("readiness", "eligibility_basis"),
    ("readiness", "owner_basis"),
    ("readiness", "authority_basis"),
    ("clearance_coverage", "basis"),
    ("related_holds_coverage", "basis"),
    ("failure", "basis"),
    ("constraint_conflict", "basis"),
)


@dataclass(frozen=True, slots=True)
class UnitFacts:
    """Caller-supplied snapshot of one exact-bound unit; no field has a default."""

    binding: Binding
    observed_at: ClockReadingMs
    controls: Controls
    integrity: IntegrityFact
    coherence: CoherenceFact
    policy_hold: PolicyHoldFact
    attempt: AttemptFact
    clearance: tuple[ClearanceCell, ...]
    clearance_coverage: Coverage
    user_decision: UserDecisionFact
    wait: WaitFact
    obligations: ObligationFact
    readiness: ReadinessFact
    related_holds: tuple[RelatedHold, ...]
    related_holds_coverage: Coverage
    failure: FailureFact
    constraint_conflict: ConflictFact
    phase: PhaseObservation | None
    claims: tuple[ClaimFact, ...]

    def __post_init__(self) -> None:
        _raise_if(_facts_code(self))
        object.__setattr__(self, "clearance", tuple(sorted(self.clearance, key=_cell_key)))
        object.__setattr__(
            self, "related_holds", tuple(sorted(self.related_holds, key=lambda h: h.hold_ref))
        )
        object.__setattr__(self, "claims", tuple(sorted(self.claims, key=lambda c: c.code)))


def _facts_v1a(value: object) -> Code:
    """V1a: exact classes of holders, singular basis slots and tuple containers."""
    if type(value) is not UnitFacts:
        return "invalid_type"
    if type(_get(value, "binding")) is not Binding:
        return "invalid_type"
    if type(_get(value, "observed_at")) is not ClockReadingMs:
        return "invalid_type"
    for name, cls in _FACT_FIELDS:
        if type(_get(value, name)) is not cls:
            return "invalid_type"
    phase = _get(value, "phase")
    if phase is not None and (
        type(phase) is not PhaseObservation or type(_get(phase, "basis")) is not BasisRef
    ):
        return "invalid_type"
    if type(_get(value, "claims")) is not tuple:
        return "invalid_type"
    for holder, slot in _SINGULAR_SLOTS:
        if _ref_class_code(_get(_get(value, holder), slot)) is not None:
            return "invalid_type"
    spec = _get(_get(value, "wait"), "spec")
    if spec is not None and (
        type(spec) is not WaitSpec or type(_get(spec, "source")) is not BasisRef
    ):
        return "invalid_type"
    for holder, slot in (("controls", "basis"), ("obligations", "refs")):
        if type(_get(_get(value, holder), slot)) is not tuple:
            return "invalid_type"
    return None


def _local_tuples(value: object) -> tuple[object, ...]:
    return (
        _get(_get(value, "controls"), "basis"),
        _get(_get(value, "obligations"), "refs"),
        _get(value, "clearance"),
        _get(value, "related_holds"),
        _get(value, "claims"),
    )


def _facts_v1b(value: object) -> Code:
    """V1b: local tuple caps by ``len()`` before any element is read."""
    for items in _local_tuples(value):
        assert type(items) is tuple
        if len(items) > LOCAL_TUPLE_CAP:
            return "too_many_refs"
    return None


def _facts_elements(value: object) -> Code:
    """Structural element classes of the bounded collections."""
    for holder, slot in (("controls", "basis"), ("obligations", "refs")):
        items = _get(_get(value, holder), slot)
        assert type(items) is tuple
        if any(type(item) is not BasisRef for item in items):
            return "invalid_type"
    collections: tuple[tuple[str, Callable[[object], Code]], ...] = (
        ("clearance", _cell_shape),
        ("related_holds", _hold_shape),
        ("claims", _claim_shape),
    )
    for name, shape in collections:
        items = _get(value, name)
        assert type(items) is tuple
        for item in items:
            code = shape(item)
            if code is not None:
                return code
    return None


def _basis_occurrences(facts: UnitFacts) -> int:
    """Structural count of every ``BasisRef`` occurrence in ``facts`` (§4.6a)."""
    count = len(facts.controls.basis) + len(facts.obligations.refs)
    for holder, slot in _SINGULAR_SLOTS:
        if _get(_get(facts, holder), slot) is not None:
            count += 1
    if facts.wait.spec is not None:
        count += 1
    if facts.phase is not None:
        count += 1
    for cell in facts.clearance:
        count += (cell.applicability_basis is not None) + (cell.state_basis is not None)
    count += sum(hold.relation_basis is not None for hold in facts.related_holds)
    return count + len(facts.claims)


def _unique_code(items: tuple[object, ...], keys: list[object]) -> Code:
    """Exact duplicate versus same key with changed content."""
    seen: dict[object, object] = {}
    for item, item_key in zip(items, keys, strict=True):
        if item_key in seen:
            return "duplicate_entry" if seen[item_key] == item else "conflicting_entry"
        seen[item_key] = item
    return None


def _facts_code(value: object) -> Code:
    code = _facts_v1a(value) or _facts_v1b(value) or _facts_elements(value)
    if code is not None:
        return code
    assert type(value) is UnitFacts
    if _basis_occurrences(value) > AGGREGATE_BASIS_CAP:
        return "too_many_refs"
    code = (
        _binding_code(value.binding)
        or _clock_code(value.observed_at)
        or _controls_code(value.controls)
        or _status_role_code(value.integrity, INTEGRITY_VALUES, _K_INTEGRITY)
        or _status_role_code(value.coherence, COHERENCE_VALUES, _K_COHERENCE)
        or _status_role_code(value.policy_hold, POLICY_VALUES, _K_POLICY)
        or _attempt_code(value.attempt)
    )
    if code is not None:
        return code
    for cell in value.clearance:
        code = _cell_code(cell)
        if code is not None:
            return code
    code = (
        _unique_code(value.clearance, [_cell_key(c) for c in value.clearance])
        or _status_role_code(value.clearance_coverage, COVERAGE_VALUES, _K_DEPENDENCY)
        or _user_decision_code(value.user_decision)
        or _wait_code(value.wait)
        or _obligation_code(value.obligations)
        or _readiness_code(value.readiness)
    )
    if code is not None:
        return code
    for hold in value.related_holds:
        code = _hold_code(hold)
        if code is not None:
            return code
    code = (
        _unique_code(value.related_holds, [h.hold_ref for h in value.related_holds])
        or _status_role_code(value.related_holds_coverage, COVERAGE_VALUES, _K_DEPENDENCY)
        or _status_role_code(value.failure, FAILURE_VALUES, _K_FAILURE)
        or _status_role_code(value.constraint_conflict, CONFLICT_VALUES, _K_CONFLICT)
    )
    if code is not None:
        return code
    if value.phase is not None:
        code = _phase_observation_code(value.phase)
        if code is not None:
            return code
    for claim in value.claims:
        code = _claim_code(claim)
        if code is not None:
            return code
    return _unique_code(value.claims, [c.code for c in value.claims])


@dataclass(frozen=True, slots=True)
class PhaseEnvelope:
    phase_id: str
    source: BasisRef
    started_at: ClockReadingMs
    max_duration: DurationMs
    freshness_max_age: DurationMs

    def __post_init__(self) -> None:
        _raise_if(_phase_envelope_code(self))


def _phase_envelope_code(value: object) -> Code:
    if type(value) is not PhaseEnvelope:
        return "invalid_type"
    max_duration = _get(value, "max_duration")
    freshness = _get(value, "freshness_max_age")
    code = (
        _token_code(_get(value, "phase_id"))
        or _basis_code(_get(value, "source"), _K_PHASE)
        or _clock_code(_get(value, "started_at"))
        or _duration_code(max_duration)
        or _duration_code(freshness)
    )
    if code is not None:
        return code
    assert type(max_duration) is DurationMs and type(freshness) is DurationMs
    if (
        max_duration.value == 0
        or freshness.value == 0
        or freshness.value > max_duration.value
    ):
        return "phase_invalid"
    return None


@dataclass(frozen=True, slots=True)
class DeadlineProfile:
    """Mandatory finite deadline profile of one bound unit."""

    binding: Binding
    profile_id: str
    revision: int
    progress_timeout: DurationMs
    hard_timeout: DurationMs
    observation_max_age: DurationMs
    phase: PhaseEnvelope | None

    def __post_init__(self) -> None:
        _raise_if(_profile_code(self))


def _profile_code(value: object) -> Code:
    if type(value) is not DeadlineProfile:
        return "invalid_type"
    progress = _get(value, "progress_timeout")
    hard = _get(value, "hard_timeout")
    observation = _get(value, "observation_max_age")
    phase = _get(value, "phase")
    code = (
        _binding_code(_get(value, "binding"))
        or _token_code(_get(value, "profile_id"))
        or _int_code(_get(value, "revision"), 1)
        or _duration_code(progress)
        or _duration_code(hard)
        or _duration_code(observation)
    )
    if code is not None:
        return code
    assert type(progress) is DurationMs and type(hard) is DurationMs
    assert type(observation) is DurationMs
    if (
        progress.value == 0
        or hard.value == 0
        or observation.value == 0
        or progress.value > hard.value
    ):
        return "profile_invalid"
    if phase is None:
        return None
    code = _phase_envelope_code(phase)
    if code is not None:
        return code
    assert type(phase) is PhaseEnvelope
    if phase.max_duration.value > hard.value:
        return "phase_invalid"
    return None


@dataclass(frozen=True, slots=True)
class EvidenceId:
    """Identity of one progress observation; distinct from the S2a EventId."""

    value: str

    def __post_init__(self) -> None:
        _raise_if(_evidence_id_code(self))


def _evidence_id_code(value: object) -> Code:
    if type(value) is not EvidenceId:
        return "invalid_type"
    return _token_code(_get(value, "value"))


@dataclass(frozen=True, slots=True)
class ClaimKey:
    """Semantic identity of an accepted or diagnostic criterion revision."""

    kind: str
    criterion_ref: str
    revision: int

    def __post_init__(self) -> None:
        _raise_if(_claim_key_code(self))


def _claim_key_code(value: object) -> Code:
    if type(value) is not ClaimKey:
        return "invalid_type"
    return (
        _enum_code(_get(value, "kind"), CLAIM_KEY_KINDS)
        or _token_code(_get(value, "criterion_ref"))
        or _int_code(_get(value, "revision"), 1)
    )


def _key_order(key: ClaimKey) -> tuple[str, str, int]:
    return (key.kind, key.criterion_ref, key.revision)


@dataclass(frozen=True, slots=True)
class ProgressClaim:
    binding: Binding
    evidence_id: EvidenceId
    sequence: int
    observed_at: ClockReadingMs
    kind: str
    claim_key: ClaimKey | None
    activity_kind: str | None
    basis: BasisRef

    def __post_init__(self) -> None:
        _raise_if(_progress_claim_code(self))


def _progress_claim_code(value: object) -> Code:
    if type(value) is not ProgressClaim:
        return "invalid_type"
    kind = _get(value, "kind")
    claim_key = _get(value, "claim_key")
    activity_kind = _get(value, "activity_kind")
    code = (
        _binding_code(_get(value, "binding"))
        or _evidence_id_code(_get(value, "evidence_id"))
        or _int_code(_get(value, "sequence"), 1)
        or _clock_code(_get(value, "observed_at"))
        or _enum_code(kind, PROGRESS_KINDS)
    )
    if code is not None:
        return code
    assert type(kind) is str
    if kind == "activity":
        if claim_key is not None:
            return "detail_mismatch"
        code = (
            _enum_code(activity_kind, ACTIVITY_KINDS)
            if activity_kind is not None
            else "detail_mismatch"
        )
    else:
        if claim_key is None or activity_kind is not None:
            return "detail_mismatch"
        code = _claim_key_code(claim_key)
        if code is None and _get(claim_key, "kind") != kind:
            code = "detail_mismatch"
    return code or _basis_code(_get(value, "basis"), _K_PROGRESS[kind])


@dataclass(frozen=True, slots=True)
class ProgressFrontier:
    """Immutable accepted-progress history of one bound unit; S is ``started_at``."""

    binding: Binding
    started_at: ClockReadingMs
    last_sequence: int
    last_observed_at: ClockReadingMs
    last_acceptance_at: ClockReadingMs | None
    accepted_keys: tuple[ClaimKey, ...]
    diagnostic_keys: tuple[ClaimKey, ...]
    seen: tuple[ProgressClaim, ...]

    def __post_init__(self) -> None:
        _raise_if(_frontier_code(self))
        object.__setattr__(self, "accepted_keys", tuple(sorted(self.accepted_keys, key=_key_order)))
        object.__setattr__(
            self, "diagnostic_keys", tuple(sorted(self.diagnostic_keys, key=_key_order))
        )


def _frontier_code(value: object) -> Code:
    if type(value) is not ProgressFrontier:
        return "invalid_type"
    binding = _get(value, "binding")
    started = _get(value, "started_at")
    last_sequence = _get(value, "last_sequence")
    last_observed = _get(value, "last_observed_at")
    last_acceptance = _get(value, "last_acceptance_at")
    accepted = _get(value, "accepted_keys")
    diagnostic = _get(value, "diagnostic_keys")
    seen = _get(value, "seen")
    code = (
        _binding_code(binding)
        or _clock_code(started)
        or _int_code(last_sequence, 0)
        or _clock_code(last_observed)
        or _optional_clock_code(last_acceptance)
    )
    if code is not None:
        return code
    for keys in (accepted, diagnostic):
        if type(keys) is not tuple:
            return "invalid_type"
    if type(seen) is not tuple:
        return "invalid_type"
    assert type(accepted) is tuple and type(diagnostic) is tuple
    if len(seen) > MAX_FRONTIER_SEEN or len(accepted) + len(diagnostic) > len(seen):
        return "frontier_invalid"
    for keys in (accepted, diagnostic):
        for key in keys:
            code = _claim_key_code(key)
            if code is not None:
                return code
    for claim in seen:
        code = _progress_claim_code(claim)
        if code is not None:
            return code
    return _reconstruction_code(value)


def _reconstruction_code(value: object) -> Code:
    """Recompute every derived field of the frontier from its seen history."""
    assert type(value) is ProgressFrontier
    started = value.started_at
    expected_accepted: set[ClaimKey] = set()
    expected_diagnostic: set[ClaimKey] = set()
    identities: set[str] = set()
    acceptance_at: ClockReadingMs | None = None
    previous_sequence = 0
    previous_clock = started
    for claim in value.seen:
        if (
            claim.binding != value.binding
            or claim.kind == "activity"
            or claim.observed_at.epoch_id != started.epoch_id
            or claim.observed_at.elapsed_ms < previous_clock.elapsed_ms
            or claim.sequence <= previous_sequence
            or claim.evidence_id.value in identities
        ):
            return "frontier_invalid"
        identities.add(claim.evidence_id.value)
        previous_sequence = claim.sequence
        previous_clock = claim.observed_at
        assert claim.claim_key is not None
        if claim.kind in ACCEPTANCE_KINDS:
            if claim.claim_key not in expected_accepted:
                expected_accepted.add(claim.claim_key)
                acceptance_at = claim.observed_at
        else:
            expected_diagnostic.add(claim.claim_key)
    if (
        value.last_sequence != previous_sequence
        or value.last_observed_at != previous_clock
        or value.last_acceptance_at != acceptance_at
        or len(set(value.accepted_keys)) != len(value.accepted_keys)
        or len(set(value.diagnostic_keys)) != len(value.diagnostic_keys)
        or set(value.accepted_keys) != expected_accepted
        or set(value.diagnostic_keys) != expected_diagnostic
    ):
        return "frontier_invalid"
    return None


# --------------------------------------------------------------------------- results


def _codes_code(values: object, allowed: frozenset[str]) -> Code:
    if type(values) is not tuple:
        return "invalid_type"
    for item in values:
        code = _enum_code(item, allowed)
        if code is not None:
            return code
    if list(values) != sorted(set(values)):
        return "detail_mismatch"
    return None


def _diagnostics_code(value: object) -> Code:
    code = _codes_code(_get(value, "reasons"), REASON_CODES)
    code = code or _codes_code(_get(value, "claims"), CLAIM_CODES)
    if code is not None:
        return code
    basis = _get(value, "basis")
    if type(basis) is not tuple:
        return "invalid_type"
    for item in basis:
        code = _ref_payload_code(item)
        if code is not None:
            return code
    keys = [_ref_key(item) for item in basis]
    return None if keys == sorted(set(keys)) else "detail_mismatch"


@dataclass(frozen=True, slots=True)
class Assessed:
    state: str
    primary_reason: str
    hint: str
    reasons: tuple[str, ...]
    liveness: str
    claims: tuple[str, ...]
    basis: tuple[BasisRef, ...]
    tag: str = field(default="assessed", init=False)

    def __post_init__(self) -> None:
        code = _enum_code(self.state, STATES)
        if code is None:
            code = _enum_code(self.primary_reason, PRIMARY_REASONS[self.state])
        code = code or _enum_code(self.hint, HINTS) or _enum_code(self.liveness, LIVENESS_VALUES)
        _raise_if(code or _diagnostics_code(self))


@dataclass(frozen=True, slots=True)
class Indeterminate:
    code: str
    reasons: tuple[str, ...]
    claims: tuple[str, ...]
    basis: tuple[BasisRef, ...]
    tag: str = field(default="indeterminate", init=False)
    hint: str = field(default="facts_required", init=False)

    def __post_init__(self) -> None:
        _raise_if(_enum_code(self.code, INDETERMINATE_CODES) or _diagnostics_code(self))


@dataclass(frozen=True, slots=True)
class Deferred:
    feature: str
    reason: str
    reasons: tuple[str, ...]
    claims: tuple[str, ...]
    basis: tuple[BasisRef, ...]
    tag: str = field(default="deferred", init=False)
    hint: str = field(default="evaluation_deferred", init=False)

    def __post_init__(self) -> None:
        code = _enum_code(self.feature, frozenset(DEFERRED_PAIRS))
        if code is None and self.reason != DEFERRED_PAIRS[self.feature]:
            code = "invalid_enum"
        _raise_if(code or _diagnostics_code(self))


AssessmentResult = Assessed | Indeterminate | Deferred


@dataclass(frozen=True, slots=True)
class ProgressUpdate:
    disposition: str
    frontier: ProgressFrontier

    def __post_init__(self) -> None:
        _raise_if(_enum_code(self.disposition, DISPOSITIONS) or _frontier_code(self.frontier))


# --------------------------------------------------------------------------- assess


def _fact_clocks(facts: UnitFacts) -> list[ClockReadingMs]:
    clocks = [facts.observed_at]
    for clock in (facts.attempt.started_at, facts.attempt.last_liveness_at):
        if clock is not None:
            clocks.append(clock)
    if facts.wait.spec is not None:
        clocks.append(facts.wait.spec.established_at)
    if facts.phase is not None:
        clocks.append(facts.phase.last_observed_at)
    return clocks


def _frontier_clocks(frontier: ProgressFrontier) -> list[ClockReadingMs]:
    clocks = [frontier.started_at, frontier.last_observed_at]
    if frontier.last_acceptance_at is not None:
        clocks.append(frontier.last_acceptance_at)
    clocks.extend(claim.observed_at for claim in frontier.seen)
    return clocks


def _args_v1a(facts: object, frontier: object, profile: object, now: object) -> Code:
    """V1a for the four arguments and the fixed-depth holders of frontier and profile."""
    if (
        type(facts) is not UnitFacts
        or type(frontier) is not ProgressFrontier
        or type(profile) is not DeadlineProfile
        or type(now) is not ClockReadingMs
    ):
        return "invalid_type"
    frontier_slots: tuple[tuple[str, type], ...] = (
        ("binding", Binding),
        ("started_at", ClockReadingMs),
        ("last_observed_at", ClockReadingMs),
        ("accepted_keys", tuple),
        ("diagnostic_keys", tuple),
        ("seen", tuple),
    )
    for name, cls in frontier_slots:
        if type(_get(frontier, name)) is not cls:
            return "invalid_type"
    last_acceptance = _get(frontier, "last_acceptance_at")
    if last_acceptance is not None and type(last_acceptance) is not ClockReadingMs:
        return "invalid_type"
    profile_slots: tuple[tuple[str, type], ...] = (
        ("binding", Binding),
        ("progress_timeout", DurationMs),
        ("hard_timeout", DurationMs),
        ("observation_max_age", DurationMs),
    )
    for name, cls in profile_slots:
        if type(_get(profile, name)) is not cls:
            return "invalid_type"
    phase = _get(profile, "phase")
    if phase is not None and (
        type(phase) is not PhaseEnvelope or type(_get(phase, "source")) is not BasisRef
    ):
        return "invalid_type"
    return None


def _structural_code(
    facts: object, frontier: object, profile: object, now: object
) -> Code:
    code = _args_v1a(facts, frontier, profile, now)
    if code is not None:
        return code
    for value, check in (
        (facts, _facts_code),
        (frontier, _frontier_code),
        (profile, _profile_code),
        (now, _clock_code),
    ):
        code = check(value)
        if code is not None:
            return code
    assert type(facts) is UnitFacts and type(frontier) is ProgressFrontier
    assert type(profile) is DeadlineProfile and type(now) is ClockReadingMs
    if not (facts.binding == frontier.binding == profile.binding):
        return "binding_mismatch"
    current = _fact_clocks(facts) + _frontier_clocks(frontier)
    if profile.phase is not None:
        current.append(profile.phase.started_at)
    next_check = [] if facts.wait.spec is None else [facts.wait.spec.next_check_at]
    if any(clock.epoch_id != now.epoch_id for clock in current + next_check):
        return "epoch_mismatch"
    if any(clock.elapsed_ms > now.elapsed_ms for clock in current):
        return "future_observation"
    attempt = facts.attempt
    if attempt.status == "admitted":
        assert attempt.started_at is not None
        if frontier.started_at.elapsed_ms > attempt.started_at.elapsed_ms:
            return "detail_mismatch"
        if (
            attempt.last_liveness_at is not None
            and attempt.last_liveness_at.elapsed_ms < attempt.started_at.elapsed_ms
        ):
            return "detail_mismatch"
    return None


def _reached(anchor: ClockReadingMs, now: ClockReadingMs, threshold: DurationMs) -> bool:
    return elapsed_between(anchor, now).value >= threshold.value


def _clean(cell: ClearanceCell) -> bool:
    return cell.replay_clearance == "clear" and cell.outcome == "settled"


_K_CODES: Final = (
    "cancel_requested",
    "pause_requested",
    "drain_requested",
    "integrity_refused",
    "inconsistent_observations",
    "outcome_unresolved",
    "clearance_unresolved",
    "policy_hold",
)
_K_HINTS: Final = (
    "none",
    "none",
    "none",
    "review_integrity",
    "review_integrity",
    "review_unresolved_outcome",
    "review_clearance",
    "review_policy",
)
_G_CODES: Final = ("dependency_on_held_unit", "authority_denied", "other_owner_present")


def _k_facts(facts: UnitFacts) -> tuple[bool, ...]:
    applies = [cell for cell in facts.clearance if cell.applicability == "applies"]
    none = facts.attempt.status == "none"
    return (
        facts.controls.cancel == "requested",
        facts.controls.pause == "requested",
        facts.controls.drain == "requested",
        facts.integrity.status == "refused",
        facts.coherence.status == "inconsistent",
        none and any(cell.outcome == "unresolved" for cell in applies),
        none and any(cell.replay_clearance == "unresolved" for cell in applies),
        facts.policy_hold.status == "held",
    )


def _g_facts(facts: UnitFacts) -> tuple[bool, ...]:
    return (
        any(hold.relation == "dependent" for hold in facts.related_holds),
        facts.readiness.authority == "denied",
        facts.readiness.other_owner == "present",
    )


def _k_context(facts: UnitFacts) -> bool:
    return (
        facts.user_decision.status == "none_pending"
        and facts.wait.status == "none"
        and facts.attempt.status == "none"
        and facts.obligations.status in {"all_satisfied", "none_declared"}
        and facts.readiness.eligibility == "admissible"
    )


def _unknown_diagnostics(facts: UnitFacts) -> set[str]:
    cells = facts.clearance
    readiness = facts.readiness
    pairs = (
        (
            "unknown" in (facts.controls.cancel, facts.controls.pause, facts.controls.drain),
            "control_unknown",
        ),
        (facts.integrity.status == "unknown", "integrity_unknown"),
        (facts.coherence.status == "unknown", "coherence_unknown"),
        (facts.policy_hold.status == "unknown", "policy_unknown"),
        (facts.attempt.status == "unknown", "attempt_unknown"),
        (any(c.applicability == "unknown" for c in cells), "applicability_unknown"),
        (
            any("unknown" in (c.replay_clearance, c.outcome) for c in cells),
            "clearance_unknown",
        ),
        (facts.user_decision.status == "unknown", "user_decision_unknown"),
        (facts.wait.status == "unknown", "wait_unknown"),
        (facts.obligations.status == "unknown", "obligations_unknown"),
        (readiness.eligibility == "unknown", "readiness_unknown"),
        (readiness.other_owner == "unknown", "owner_unknown"),
        (readiness.authority == "unknown", "authority_unknown"),
        (any(h.relation == "unknown" for h in facts.related_holds), "independence_unknown"),
        (facts.clearance_coverage.status == "unknown", "clearance_coverage_unknown"),
        (facts.related_holds_coverage.status == "unknown", "related_holds_coverage_unknown"),
        (facts.failure.status == "unknown", "failure_unknown"),
        (facts.constraint_conflict.status == "unknown", "conflict_unknown"),
    )
    return {code for flag, code in pairs if flag}


def _base_reasons(facts: UnitFacts, stale: bool, now: ClockReadingMs) -> set[str]:
    """Rules 2-6 of §5.6: true facts, independent of the selected row."""
    reasons = {code for flag, code in zip(_k_facts(facts), _K_CODES, strict=True) if flag}
    reasons |= {code for flag, code in zip(_g_facts(facts), _G_CODES, strict=True) if flag}
    reasons |= _unknown_diagnostics(facts)
    if stale:
        reasons.add("stale_observation")
    admitted = facts.attempt.status == "admitted"
    waiting = facts.wait.status == "waiting"
    obligations = facts.obligations.status
    applies = [cell for cell in facts.clearance if cell.applicability == "applies"]
    attempted = facts.attempt.status != "none"
    spec = facts.wait.spec
    pairs = (
        (admitted, "attempt_admitted"),
        (waiting and admitted, "attempt_admitted_during_wait"),
        (obligations == "pending" and admitted, "obligations_pending_during_attempt"),
        (obligations == "all_satisfied" and admitted, "obligations_satisfied_during_attempt"),
        (
            facts.readiness.eligibility == "admissible" and admitted,
            "transition_admissible_during_attempt",
        ),
        (
            attempted and any(c.outcome == "unresolved" for c in applies),
            "proposed_transition_outcome_unresolved",
        ),
        (
            attempted and any(c.replay_clearance == "unresolved" for c in applies),
            "proposed_transition_clearance_unresolved",
        ),
        (
            spec is not None and now.elapsed_ms >= spec.next_check_at.elapsed_ms,
            "external_observation_due",
        ),
        (facts.failure.status == "recoverable_classified", "recoverable_failure_known"),
        (facts.constraint_conflict.status == "asserted", "constraint_conflict_asserted"),
    )
    reasons |= {code for flag, code in pairs if flag}
    return reasons


def _phase_exemption(
    facts: UnitFacts, profile: DeadlineProfile, now: ClockReadingMs
) -> bool:
    envelope = profile.phase
    observed = facts.phase
    started = facts.attempt.started_at
    if envelope is None or observed is None or started is None:
        return False
    return (
        observed.phase_id == envelope.phase_id
        and observed.basis == envelope.source
        and envelope.started_at.elapsed_ms >= started.elapsed_ms
        and observed.last_observed_at.elapsed_ms >= envelope.started_at.elapsed_ms
        and not _reached(envelope.started_at, now, envelope.max_duration)
        and not _reached(observed.last_observed_at, now, envelope.freshness_max_age)
    )


def _liveness(facts: UnitFacts, profile: DeadlineProfile, now: ClockReadingMs) -> str:
    if facts.attempt.status != "admitted":
        return "not_applicable"
    last = facts.attempt.last_liveness_at
    if last is None:
        return "unobserved"
    return "stale" if _reached(last, now, profile.observation_max_age) else "fresh"


def _result_basis(facts: UnitFacts) -> tuple[BasisRef, ...]:
    refs: set[BasisRef] = set(facts.controls.basis) | set(facts.obligations.refs)
    for holder, slot in _SINGULAR_SLOTS:
        ref = _get(_get(facts, holder), slot)
        if type(ref) is BasisRef:
            refs.add(ref)
    if facts.wait.spec is not None:
        refs.add(facts.wait.spec.source)
    if facts.phase is not None:
        refs.add(facts.phase.basis)
    for cell in facts.clearance:
        for ref in (cell.applicability_basis, cell.state_basis):
            if ref is not None:
                refs.add(ref)
    for hold in facts.related_holds:
        if hold.relation_basis is not None:
            refs.add(hold.relation_basis)
    return tuple(sorted(refs, key=_ref_key))


def assess_unit(
    facts: UnitFacts,
    frontier: ProgressFrontier,
    profile: DeadlineProfile,
    now: ClockReadingMs,
) -> AssessmentResult:
    """Classify one exact-bound unit by the finite decision table of contract V3 §5.2.

    The result is conditional advice over the supplied snapshot; it never
    authorizes dispatch, retry, recovery, cancellation or completion.
    """
    _raise_if(_structural_code(facts, frontier, profile, now))
    stale = _reached(facts.observed_at, now, profile.observation_max_age)
    reasons = _base_reasons(facts, stale, now)
    claims = tuple(sorted(claim.code for claim in facts.claims))
    basis = _result_basis(facts)
    liveness = _liveness(facts, profile, now)

    def assessed(state: str, primary: str, hint: str, extra: set[str]) -> Assessed:
        codes = tuple(sorted(reasons | extra | {primary}))
        return Assessed(state, primary, hint, codes, liveness, claims, basis)

    def indeterminate(code: str) -> Indeterminate:
        return Indeterminate(code, tuple(sorted(reasons)), claims, basis)

    def deferred(feature: str) -> Deferred:
        return Deferred(feature, DEFERRED_PAIRS[feature], tuple(sorted(reasons)), claims, basis)

    hard = _reached(frontier.started_at, now, profile.hard_timeout)

    def hard_only(code: str) -> AssessmentResult:
        if hard:
            return assessed("stalled", "hard_deadline_elapsed", "observe", set())
        return indeterminate(code)

    # P: known direct holds, also under a stale snapshot.
    for flag, code, hint in zip(_k_facts(facts), _K_CODES, _K_HINTS, strict=True):
        if flag:
            return assessed("paused_policy", code, hint, set())
    # G*: proposal-only guards on a fully known K context.
    if _k_context(facts):
        for flag, code in zip(_g_facts(facts), _G_CODES, strict=True):
            if flag:
                return assessed("paused_policy", code, "none", set())
    controls = facts.controls
    attempt = facts.attempt.status
    cells = facts.clearance
    unclean = [cell for cell in cells if not _clean(cell)]
    applies = [cell for cell in cells if cell.applicability == "applies"]
    rows = (
        (stale, "stale_observation"),
        ("unknown" in (controls.cancel, controls.pause, controls.drain), "control_unknown"),
        (facts.integrity.status == "unknown", "integrity_unknown"),
        (facts.coherence.status == "unknown", "coherence_unknown"),
        (facts.policy_hold.status == "unknown", "policy_unknown"),
        (
            attempt == "unknown"
            and any(cell.applicability in {"applies", "unknown"} for cell in unclean),
            "attempt_unknown",
        ),
        (
            attempt == "none" and any(cell.applicability == "unknown" for cell in unclean),
            "applicability_unknown",
        ),
        (
            attempt == "none"
            and any("unknown" in (cell.replay_clearance, cell.outcome) for cell in applies),
            "clearance_unknown",
        ),
        (facts.user_decision.status == "unknown", "user_decision_unknown"),
    )
    for flag, code in rows:
        if flag:
            return indeterminate(code)
    if facts.user_decision.status == "pending":
        kind = facts.user_decision.kind
        assert kind is not None
        return assessed("needs_user", kind, "user_decision_required", set())

    obligations = facts.obligations.status
    wait = facts.wait
    anchor = frontier.last_acceptance_at
    if anchor is None:
        anchor = frontier.started_at
    progress_reached = _reached(anchor, now, profile.progress_timeout)

    def timed(
        state: str, primary: str, hint: str, wait_expired: bool, progress: bool
    ) -> Assessed:
        expired = [
            code
            for flag, code in (
                (hard, "hard_deadline_elapsed"),
                (wait_expired, "wait_deadline_elapsed"),
                (progress and progress_reached, "progress_deadline_elapsed"),
            )
            if flag
        ]
        extra: set[str] = set()
        if state == "working" and (profile.phase is not None or facts.phase is not None):
            exempt = _phase_exemption(facts, profile, now)
            extra.add("phase_exemption_active" if exempt else "phase_not_applicable")
        if expired:
            return assessed("stalled", expired[0], "observe", extra | set(expired) | {primary})
        return assessed(state, primary, hint, extra)

    if wait.status == "waiting":
        spec = wait.spec
        assert spec is not None
        due = now.elapsed_ms >= spec.next_check_at.elapsed_ms
        hint = "external_observation_due" if due else "observe"
        expired = _reached(spec.established_at, now, spec.overall_timeout)
        return timed("waiting_external", "external_dependency", hint, expired, False)
    if wait.status == "unknown":
        if attempt == "admitted" or obligations == "pending":
            return hard_only("wait_unknown")
        return indeterminate("wait_unknown")
    if attempt == "admitted":
        progress = not _phase_exemption(facts, profile, now)
        return timed("working", "attempt_admitted", "observe", False, progress)
    if attempt == "unknown":
        if obligations == "pending":
            return hard_only("attempt_unknown")
        return indeterminate("attempt_unknown")
    if obligations == "pending":
        return timed("verifying", "verification_pending", "verification_required", False, True)
    if obligations == "unknown":
        return indeterminate("obligations_unknown")

    conflict = facts.constraint_conflict.status
    failure = facts.failure.status
    if conflict == "asserted":
        return deferred("impossibility_evaluation")
    if conflict == "unknown":
        return indeterminate("conflict_unknown")
    if failure == "recoverable_classified":
        return deferred("recovery_evaluation")
    if failure == "unknown":
        return indeterminate("failure_unknown")
    readiness = facts.readiness
    if readiness.eligibility == "unknown":
        return indeterminate("readiness_unknown")
    if readiness.eligibility == "not_admissible":
        if obligations == "all_satisfied":
            return deferred("completion_evaluation")
        return indeterminate("no_classifiable_condition")
    readiness_rows = (
        (readiness.authority == "unknown", "authority_unknown"),
        (readiness.other_owner == "unknown", "owner_unknown"),
        (facts.related_holds_coverage.status == "unknown", "related_holds_coverage_unknown"),
        (any(h.relation == "unknown" for h in facts.related_holds), "independence_unknown"),
        (facts.clearance_coverage.status == "unknown", "clearance_coverage_unknown"),
    )
    for flag, code in readiness_rows:
        if flag:
            return indeterminate(code)
    return timed(
        "ready", "transition_admissible", "consider_existing_transition", False, True
    )


# --------------------------------------------------------------------------- progress


def advance_progress(frontier: ProgressFrontier, claim: ProgressClaim) -> ProgressUpdate:
    """Account one progress observation; refusal leaves the input unchanged.

    Only a new accepted assertion/gate/blocker key moves the acceptance anchor.
    Activity is ignored, diagnostics and semantic repeats never move it, and a
    full history refuses new identities without eviction or reset.
    """
    _raise_if(_frontier_code(frontier) or _progress_claim_code(claim))
    if claim.binding != frontier.binding:
        _raise_if("binding_mismatch")
    if claim.observed_at.epoch_id != frontier.started_at.epoch_id:
        _raise_if("epoch_mismatch")
    if claim.kind == "activity":
        return ProgressUpdate("activity_ignored", frontier)
    for previous in frontier.seen:
        if previous.evidence_id == claim.evidence_id:
            if previous == claim:
                return ProgressUpdate("exact_duplicate", frontier)
            _raise_if("evidence_identity_conflict")
    if claim.sequence <= frontier.last_sequence:
        _raise_if("sequence_regression")
    if claim.observed_at.elapsed_ms < frontier.last_observed_at.elapsed_ms:
        _raise_if("clock_regression")
    if len(frontier.seen) >= MAX_FRONTIER_SEEN:
        _raise_if("frontier_capacity_exhausted")
    key = claim.claim_key
    assert key is not None
    accepted = frontier.accepted_keys
    diagnostic = frontier.diagnostic_keys
    acceptance_at = frontier.last_acceptance_at
    if claim.kind in ACCEPTANCE_KINDS:
        if key in accepted:
            disposition = "semantic_repeat"
        else:
            disposition = "acceptance_advanced"
            accepted = accepted + (key,)
            acceptance_at = claim.observed_at
    elif key in diagnostic:
        disposition = "semantic_repeat"
    else:
        disposition = "diagnostic_advanced"
        diagnostic = diagnostic + (key,)
    updated = ProgressFrontier(
        frontier.binding,
        frontier.started_at,
        claim.sequence,
        claim.observed_at,
        acceptance_at,
        accepted,
        diagnostic,
        frontier.seen + (claim,),
    )
    return ProgressUpdate(disposition, updated)


__all__ = [
    "AGGREGATE_BASIS_CAP",
    "LOCAL_TUPLE_CAP",
    "MAX_FRONTIER_SEEN",
    "STATE_CODES",
    "Assessed",
    "AssessmentResult",
    "AttemptFact",
    "BasisRef",
    "Binding",
    "ClaimFact",
    "ClaimKey",
    "ClearanceCell",
    "CoherenceFact",
    "ConflictFact",
    "ContinuationStateError",
    "Controls",
    "Coverage",
    "DeadlineProfile",
    "Deferred",
    "EvidenceId",
    "FailureFact",
    "Indeterminate",
    "IntegrityFact",
    "ObligationFact",
    "PhaseEnvelope",
    "PhaseObservation",
    "PolicyHoldFact",
    "ProgressClaim",
    "ProgressFrontier",
    "ProgressUpdate",
    "ReadinessFact",
    "RelatedHold",
    "UnitFacts",
    "UserDecisionFact",
    "WaitFact",
    "WaitSpec",
    "advance_progress",
    "assess_unit",
]
