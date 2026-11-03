"""Inert recovery reservation ledger with actual settlement (S2b-LR, ADR-0501).

The ledger keeps durable *custody* of recovery reservations and supplied actual
observations in one bounded canonical replace-snapshot per mission.  No result
of this module grants execution, replay, cleanup or approval authority.  It has
no runtime importers, reads no clock, acquires no cost, and calls no provider.

Guarantees are limited to one physical mission namespace under a trusted
project root, cooperative writers using this module, a local filesystem and a
process crash.  Power loss, remote filesystems and hostile same-uid activity
are outside the claim.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import os
import re
import stat
import threading
from typing import Final, Literal, TypeVar

from .canonical_identity import (
    FoundationValidationError,
    canonical_json_bytes,
    verify_canonical_json_bytes,
)


INT64_MAX: Final[int] = 9_223_372_036_854_775_807
MAX_OPERATIONS: Final[int] = 256
SNAPSHOT_MAX_BYTES: Final[int] = 2_097_152
CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_value",
        "invalid_record",
        "unsupported_schema",
        "unsupported_platform",
        "not_initialized",
        "namespace_conflict",
        "unsafe_path",
        "writer_busy",
        "stale_writer",
        "custody_lost",
        "policy_conflict",
        "intent_conflict",
        "receipt_conflict",
        "unknown_operation",
        "budget_exhausted",
        "causal_pending",
        "accounting_blocked",
        "capacity_exhausted",
        "overflow",
        "io_unavailable",
        "publication_unknown",
    }
)

_SCHEMA_VERSION: Final = 1
_KIND: Final = "recovery_reservations"
_BLOCK_REASON: Final = "actual_accumulation_overflow"
_TOKEN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_DECIMAL: Final = re.compile(r"0|[1-9][0-9]{0,18}")
_ROOT_MAX_BYTES: Final = 4096
_MAX_DEPTH: Final = 6
_MISSING: Final = object()

_NAMESPACE: Final = (".unrest", "continuation", "recovery-reservations-v1")
_LOCK_NAME: Final = "writer.lock"
_SNAPSHOT_NAME: Final = "snapshot.json"
_STAGING_PREFIX: Final = ".staging-"
_DIMENSIONS: Final = ("attempts", "recoveries", "wall_ms", "cost_units")
_CAUSAL_FIELDS: Final = ("root_lineage_id", "goal_branch_id", "cause_code", "effect_family")
_OUTCOMES: Final = frozenset({"unknown", "accepted", "rejected"})
_STATES: Final = frozenset({"pending", "accounted", "unaccounted"})

# Original functions captured at import: the capability check asks whether the
# platform supports dir_fd for these calls, independent of later rebinding.
_DIR_FD_FUNCTIONS: Final = (os.open, os.mkdir, os.stat, os.unlink, os.rename)

_T = TypeVar("_T")
_Vec = tuple[int, int, int, int]


class ReservationLedgerError(Exception):
    """A closed, input-free ledger failure; ``str(error) == code``."""

    code: str

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in CODES:
            # Programmer misuse: a constant message, never the rejected value.
            raise ValueError("invalid_error_code")
        super().__init__(code)
        self.code = code


class _Refusal(Exception):
    """Internal carrier of a closed code; never escapes the module."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# Public errors are raised only after every internal handler has exited, so no
# module or OS exception becomes their ``__cause__`` or ``__context__``.


def _guarded(function: Callable[[], _T]) -> _T:
    try:
        result = function()
    except _Refusal as refusal:
        code = refusal.code
    else:
        return result
    raise ReservationLedgerError(code)


# ---------------------------------------------------------------------------
# Field validation (returns a code; never raises)


def _int64_ok(value: object) -> bool:
    return type(value) is int and 0 <= value <= INT64_MAX


def _token_ok(value: object) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _digest_ok(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _vector_tuple(value: object) -> _Vec | None:
    if type(value) is not ResourceVector:
        return None
    fields = tuple(getattr(value, name, _MISSING) for name in _DIMENSIONS)
    if not all(_int64_ok(field) for field in fields):
        return None
    attempts, recoveries, wall_ms, cost_units = fields
    assert type(attempts) is int and type(recoveries) is int
    assert type(wall_ms) is int and type(cost_units) is int
    return (attempts, recoveries, wall_ms, cost_units)


def _causal_tuple(value: object) -> tuple[str, str, str, str, str] | None:
    if type(value) is not CausalKey:
        return None
    names = ("mission_id", *_CAUSAL_FIELDS)
    fields = tuple(getattr(value, name, _MISSING) for name in names)
    if not all(_token_ok(field) for field in fields):
        return None
    mission, lineage, branch, cause, family = (str(field) for field in fields)
    return (mission, lineage, branch, cause, family)


def _reservation_shape_ok(vector: _Vec) -> bool:
    attempts, recoveries, wall_ms, cost_units = vector
    return attempts == 1 and recoveries == 1 and wall_ms > 0 and cost_units > 0


@dataclass(frozen=True, slots=True)
class _PolicyData:
    cost_unit: str
    authority_ref: str
    mission: _Vec
    lineage: _Vec
    causal: _Vec


def _policy_data(value: object) -> _PolicyData | None:
    if type(value) is not ReservationPolicy:
        return None
    cost_unit = getattr(value, "cost_unit", _MISSING)
    authority_ref = getattr(value, "authority_ref", _MISSING)
    if not _token_ok(cost_unit) or not _token_ok(authority_ref):
        return None
    mission = _vector_tuple(getattr(value, "mission_ceiling", _MISSING))
    lineage = _vector_tuple(getattr(value, "root_lineage_ceiling", _MISSING))
    causal = _vector_tuple(getattr(value, "causal_key_ceiling", _MISSING))
    if mission is None or lineage is None or causal is None:
        return None
    return _PolicyData(str(cost_unit), str(authority_ref), mission, lineage, causal)


@dataclass(frozen=True, slots=True)
class _RequestData:
    operation_id: str
    mission_id: str
    causal: tuple[str, str, str, str]
    reservation: _Vec
    cost_unit: str
    fingerprint: str


def _request_data(value: object) -> _RequestData | None:
    if type(value) is not ReservationRequest:
        return None
    operation_id = getattr(value, "operation_id", _MISSING)
    key = _causal_tuple(getattr(value, "causal_key", _MISSING))
    reservation = _vector_tuple(getattr(value, "reservation", _MISSING))
    cost_unit = getattr(value, "cost_unit", _MISSING)
    fingerprint = getattr(value, "request_fingerprint", _MISSING)
    if (
        not _token_ok(operation_id)
        or key is None
        or reservation is None
        or not _reservation_shape_ok(reservation)
        or not _token_ok(cost_unit)
        or not _digest_ok(fingerprint)
    ):
        return None
    return _RequestData(
        str(operation_id), key[0], key[1:], reservation, str(cost_unit), str(fingerprint)
    )


@dataclass(frozen=True, slots=True)
class _ObservationData:
    outcome: str
    digest: str
    actual: _Vec | None
    cost_unit: str | None


def _observation_data(value: object) -> _ObservationData | None:
    if type(value) is not Observation:
        return None
    outcome = getattr(value, "outcome", _MISSING)
    digest = getattr(value, "evidence_digest", _MISSING)
    actual = getattr(value, "actual", _MISSING)
    cost_unit = getattr(value, "cost_unit", _MISSING)
    if type(outcome) is not str or outcome not in _OUTCOMES or not _digest_ok(digest):
        return None
    if outcome == "unknown":
        if actual is not None or cost_unit is not None:
            return None
        return _ObservationData(outcome, str(digest), None, None)
    vector = _vector_tuple(actual)
    if vector is None or not _token_ok(cost_unit):
        return None
    return _ObservationData(outcome, str(digest), vector, str(cost_unit))


def _root_code(value: object) -> str | None:
    if type(value) is not str:
        return "invalid_value"
    if not value.startswith("/") or "\x00" in value or os.path.normpath(value) != value:
        return "invalid_value"
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return "invalid_value"
    if len(encoded) > _ROOT_MAX_BYTES:
        return "invalid_value"
    return None


def _platform_ok() -> bool:
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "fsync")):
        return False
    if not hasattr(fcntl, "flock"):
        return False
    supported = os.supports_dir_fd
    return all(function in supported for function in _DIR_FD_FUNCTIONS)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Refusal(code)


# ---------------------------------------------------------------------------
# Public values


@dataclass(frozen=True, slots=True, kw_only=True)
class ResourceVector:
    """Four explicit non-negative int64 dimensions; no defaults, no coercion."""

    attempts: int
    recoveries: int
    wall_ms: int
    cost_units: int

    def __post_init__(self) -> None:
        if _vector_tuple(self) is None:
            raise ReservationLedgerError("invalid_value")


@dataclass(frozen=True, slots=True, kw_only=True)
class CausalKey:
    """Caller-supplied causal identity; equality is byte equality, not semantics."""

    mission_id: str
    root_lineage_id: str
    goal_branch_id: str
    cause_code: str
    effect_family: str

    def __post_init__(self) -> None:
        if _causal_tuple(self) is None:
            raise ReservationLedgerError("invalid_value")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReservationPolicy:
    """Immutable injected policy; the store does not certify ``authority_ref``."""

    cost_unit: str
    authority_ref: str
    mission_ceiling: ResourceVector
    root_lineage_ceiling: ResourceVector
    causal_key_ceiling: ResourceVector

    def __post_init__(self) -> None:
        if _policy_data(self) is None:
            raise ReservationLedgerError("invalid_value")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReservationRequest:
    """One future recovery attempt: attempts and recoveries 1, wall/cost > 0."""

    operation_id: str
    causal_key: CausalKey
    reservation: ResourceVector
    cost_unit: str
    request_fingerprint: str

    def __post_init__(self) -> None:
        if _request_data(self) is None:
            raise ReservationLedgerError("invalid_value")


@dataclass(frozen=True, slots=True, kw_only=True)
class Observation:
    """A supplied observation: ``unknown`` or a determinate outcome with actual."""

    outcome: str
    evidence_digest: str
    actual: ResourceVector | None
    cost_unit: str | None

    def __post_init__(self) -> None:
        if _observation_data(self) is None:
            raise ReservationLedgerError("invalid_value")


# ---------------------------------------------------------------------------
# Internal state


@dataclass(frozen=True, slots=True)
class _Op:
    operation_id: str
    causal: tuple[str, str, str, str]
    fingerprint: str
    reservation: _Vec
    state: str
    unknown: str | None
    determinate: tuple[str, str, _Vec] | None


@dataclass(frozen=True, slots=True)
class _State:
    mission_id: str
    epoch: int
    policy: _PolicyData
    trigger: str | None
    operations: tuple[_Op, ...]


def _vec_wire(vector: _Vec) -> dict[str, str]:
    return {name: str(value) for name, value in zip(_DIMENSIONS, vector, strict=True)}


def _op_wire(op: _Op) -> dict[str, object]:
    observations: list[dict[str, object]] = []
    if op.unknown is not None:
        observations.append({"evidence_digest": op.unknown, "kind": "unknown"})
    if op.determinate is not None:
        outcome, digest, actual = op.determinate
        observations.append(
            {
                "actual": _vec_wire(actual),
                "evidence_digest": digest,
                "kind": "determinate",
                "outcome": outcome,
            }
        )
    return {
        "accounting_state": op.state,
        "causal_key": dict(zip(_CAUSAL_FIELDS, op.causal, strict=True)),
        "observations": observations,
        "operation_id": op.operation_id,
        "request_fingerprint": op.fingerprint,
        "reservation": _vec_wire(op.reservation),
    }


def _state_wire(state: _State) -> dict[str, object]:
    accounting: dict[str, str] = {"mode": "normal"}
    if state.trigger is not None:
        accounting = {
            "mode": "blocked",
            "reason": _BLOCK_REASON,
            "trigger_operation_id": state.trigger,
        }
    policy = state.policy
    return {
        "accounting": accounting,
        "kind": _KIND,
        "mission_id": state.mission_id,
        "operations": [_op_wire(op) for op in state.operations],
        "policy": {
            "authority_ref": policy.authority_ref,
            "causal_key_ceiling": _vec_wire(policy.causal),
            "cost_unit": policy.cost_unit,
            "mission_ceiling": _vec_wire(policy.mission),
            "root_lineage_ceiling": _vec_wire(policy.lineage),
        },
        "schema_version": _SCHEMA_VERSION,
        "writer_epoch": str(state.epoch),
    }


def _encode(state: _State) -> bytes:
    return canonical_json_bytes(_state_wire(state))


def _worst_case_size(state: _State) -> int:
    """Length of the §12 completion S*: every op unaccounted with both observations."""

    wire = _state_wire(state)
    placeholder = "0" * 64
    maximum = _vec_wire((INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX))
    wire["writer_epoch"] = str(INT64_MAX)
    wire["accounting"] = {
        "mode": "blocked",
        "reason": _BLOCK_REASON,
        "trigger_operation_id": "T" * 128,
    }
    operations = []
    for op in state.operations:
        op_wire = _op_wire(op)
        op_wire["accounting_state"] = "unaccounted"
        op_wire["observations"] = [
            {"evidence_digest": placeholder, "kind": "unknown"},
            {
                "actual": dict(maximum),
                "evidence_digest": placeholder,
                "kind": "determinate",
                "outcome": "rejected",
            },
        ]
        operations.append(op_wire)
    wire["operations"] = operations
    return len(canonical_json_bytes(wire))


# ---------------------------------------------------------------------------
# Accounting


def _in_scope(op: _Op, scope: tuple[str, object]) -> bool:
    kind, value = scope
    if kind == "mission":
        return True
    if kind == "lineage":
        return op.causal[0] == value
    return op.causal == value


def _scopes(causal: tuple[str, str, str, str]) -> tuple[tuple[str, object], ...]:
    return (("mission", None), ("lineage", causal[0]), ("causal", causal))


def _ceiling(policy: _PolicyData, scope: tuple[str, object]) -> _Vec:
    if scope[0] == "mission":
        return policy.mission
    if scope[0] == "lineage":
        return policy.lineage
    return policy.causal


def _used(operations: tuple[_Op, ...], scope: tuple[str, object]) -> list[int]:
    totals = [0, 0, 0, 0]
    for op in operations:
        if op.state == "accounted" and op.determinate is not None and _in_scope(op, scope):
            for index, value in enumerate(op.determinate[2]):
                totals[index] += value
    return totals


def _reserved(operations: tuple[_Op, ...], scope: tuple[str, object]) -> list[int]:
    totals = [0, 0, 0, 0]
    for op in operations:
        if op.state != "accounted" and _in_scope(op, scope):
            for index, value in enumerate(op.reservation):
                totals[index] += value
    return totals


def _budget_ok(state: _State, causal: tuple[str, str, str, str], request: _Vec) -> bool:
    for scope in _scopes(causal):
        ceiling = _ceiling(state.policy, scope)
        used = _used(state.operations, scope)
        reserved = _reserved(state.operations, scope)
        for index in range(4):
            limit, spent, held = ceiling[index], used[index], reserved[index]
            if spent > limit:
                return False
            if held > limit - spent:
                return False
            if request[index] > limit - spent - held:
                return False
    return True


def _overflows(state: _State, causal: tuple[str, str, str, str], actual: _Vec) -> bool:
    for scope in _scopes(causal):
        used = _used(state.operations, scope)
        for index in range(4):
            if used[index] + actual[index] > INT64_MAX:
                return True
    return False


# ---------------------------------------------------------------------------
# Reader (§5.1 steps 3-8)


def _depth_exceeded(data: bytes) -> bool:
    """One linear pass: nesting of brackets outside JSON strings, top level = 1.

    Only a measure of nesting, not JSON validation; it keeps deep input away from
    the recursive foundation parser. Malformed input (for example an unterminated
    string) is left to the verifier.
    """

    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte == 0x7B or byte == 0x5B:  # { [
            depth += 1
            if depth > _MAX_DEPTH:
                return True
        elif byte == 0x7D or byte == 0x5D:  # } ]
            depth -= 1
    return False


def _record(condition: bool) -> None:
    _require(condition, "invalid_record")


def _wire_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    _record(type(value) is dict)
    assert isinstance(value, dict)
    _record(frozenset(value) == keys)
    return value


def _wire_token(value: object) -> str:
    _record(_token_ok(value))
    return str(value)


def _wire_digest(value: object) -> str:
    _record(_digest_ok(value))
    return str(value)


def _wire_decimal(value: object) -> int:
    _record(type(value) is str and _DECIMAL.fullmatch(str(value)) is not None)
    number = int(str(value))
    _record(number <= INT64_MAX)
    return number


_VEC_KEYS: Final = frozenset(_DIMENSIONS)


def _wire_vec(value: object) -> _Vec:
    obj = _wire_object(value, _VEC_KEYS)
    return (
        _wire_decimal(obj["attempts"]),
        _wire_decimal(obj["recoveries"]),
        _wire_decimal(obj["wall_ms"]),
        _wire_decimal(obj["cost_units"]),
    )


_TOP_KEYS: Final = frozenset(
    {"accounting", "kind", "mission_id", "operations", "policy", "schema_version", "writer_epoch"}
)
_POLICY_KEYS: Final = frozenset(
    {"authority_ref", "causal_key_ceiling", "cost_unit", "mission_ceiling", "root_lineage_ceiling"}
)
_OP_KEYS: Final = frozenset(
    {
        "accounting_state",
        "causal_key",
        "observations",
        "operation_id",
        "request_fingerprint",
        "reservation",
    }
)
_CAUSAL_KEYS: Final = frozenset(_CAUSAL_FIELDS)
_UNKNOWN_KEYS: Final = frozenset({"evidence_digest", "kind"})
_DETERMINATE_KEYS: Final = frozenset({"actual", "evidence_digest", "kind", "outcome"})


def _wire_operation(value: object) -> _Op:
    obj = _wire_object(value, _OP_KEYS)
    state = obj["accounting_state"]
    _record(type(state) is str and state in _STATES)
    causal_obj = _wire_object(obj["causal_key"], _CAUSAL_KEYS)
    causal = (
        _wire_token(causal_obj["root_lineage_id"]),
        _wire_token(causal_obj["goal_branch_id"]),
        _wire_token(causal_obj["cause_code"]),
        _wire_token(causal_obj["effect_family"]),
    )
    observations = obj["observations"]
    _record(type(observations) is list)
    assert isinstance(observations, list)
    _record(len(observations) <= 2)
    unknown: str | None = None
    determinate: tuple[str, str, _Vec] | None = None
    for item in observations:
        _record(type(item) is dict)
        assert isinstance(item, dict)
        kind = item.get("kind")
        if kind == "unknown":
            # I3: unknown precedes determinate and occurs at most once.
            _record(unknown is None and determinate is None)
            unknown = _wire_digest(_wire_object(item, _UNKNOWN_KEYS)["evidence_digest"])
        elif kind == "determinate":
            _record(determinate is None)
            obs = _wire_object(item, _DETERMINATE_KEYS)
            outcome = obs["outcome"]
            _record(outcome in ("accepted", "rejected"))
            determinate = (
                str(outcome),
                _wire_digest(obs["evidence_digest"]),
                _wire_vec(obs["actual"]),
            )
        else:
            _record(False)
    return _Op(
        operation_id=_wire_token(obj["operation_id"]),
        causal=causal,
        fingerprint=_wire_digest(obj["request_fingerprint"]),
        reservation=_wire_vec(obj["reservation"]),
        state=str(state),
        unknown=unknown,
        determinate=determinate,
    )


def _parse_value(value: object, mission_id: str) -> _State:
    _record(type(value) is dict)
    assert isinstance(value, dict)
    _record(value.get("kind") == _KIND)
    version = value.get("schema_version")
    _record(type(version) is int)
    _require(version == _SCHEMA_VERSION, "unsupported_schema")
    obj = _wire_object(value, _TOP_KEYS)
    stored_mission = _wire_token(obj["mission_id"])
    epoch = _wire_decimal(obj["writer_epoch"])
    policy_obj = _wire_object(obj["policy"], _POLICY_KEYS)
    policy = _PolicyData(
        cost_unit=_wire_token(policy_obj["cost_unit"]),
        authority_ref=_wire_token(policy_obj["authority_ref"]),
        mission=_wire_vec(policy_obj["mission_ceiling"]),
        lineage=_wire_vec(policy_obj["root_lineage_ceiling"]),
        causal=_wire_vec(policy_obj["causal_key_ceiling"]),
    )
    accounting = obj["accounting"]
    _record(type(accounting) is dict)
    assert isinstance(accounting, dict)
    trigger: str | None = None
    if accounting.get("mode") == "normal":
        _wire_object(accounting, frozenset({"mode"}))
    else:
        blocked = _wire_object(accounting, frozenset({"mode", "reason", "trigger_operation_id"}))
        _record(blocked["mode"] == "blocked" and blocked["reason"] == _BLOCK_REASON)
        trigger = _wire_token(blocked["trigger_operation_id"])
    raw_operations = obj["operations"]
    _record(type(raw_operations) is list)
    assert isinstance(raw_operations, list)
    operations = tuple(_wire_operation(item) for item in raw_operations)
    _require(stored_mission == mission_id, "namespace_conflict")
    state = _State(stored_mission, epoch, policy, trigger, operations)
    _check_invariants(state)
    return state


def _check_invariants(state: _State) -> None:
    operations = state.operations
    # I1
    _record(len(operations) <= MAX_OPERATIONS)
    identifiers = [op.operation_id for op in operations]
    _record(all(a < b for a, b in zip(identifiers, identifiers[1:])))
    blocked = state.trigger is not None
    pending_keys: set[tuple[str, str, str, str]] = set()
    for op in operations:
        # I2
        _record(_reservation_shape_ok(op.reservation))
        # I4
        if op.determinate is None:
            _record(op.state == "pending")
        elif blocked:
            _record(op.state in ("accounted", "unaccounted"))
        else:
            _record(op.state == "accounted")
        # I6
        if op.state != "accounted":
            _record(op.causal not in pending_keys)
            pending_keys.add(op.causal)
    # I5: one aggregation pass over every (scope, operation) membership.
    sums: dict[tuple[str, object], tuple[list[int], list[int]]] = {}
    for op in operations:
        for scope in _scopes(op.causal):
            used, reserved = sums.setdefault(scope, ([0, 0, 0, 0], [0, 0, 0, 0]))
            if op.state == "accounted" and op.determinate is not None:
                for index, value in enumerate(op.determinate[2]):
                    used[index] += value
            elif op.state != "accounted":
                for index, value in enumerate(op.reservation):
                    reserved[index] += value
    for scope, (used, reserved) in sums.items():
        ceiling = _ceiling(state.policy, scope)
        for index in range(4):
            _record(reserved[index] <= ceiling[index])
            _record(used[index] <= INT64_MAX)
    # I7
    if state.trigger is not None:
        matches = [op for op in operations if op.operation_id == state.trigger]
        _record(len(matches) == 1)
        trigger = matches[0]
        _record(trigger.state == "unaccounted" and trigger.determinate is not None)
        assert trigger.determinate is not None
        _record(_overflows(state, trigger.causal, trigger.determinate[2]))
    # I8 (defensive: unreachable with the v1 grammar and MAX_OPERATIONS)
    _record(_worst_case_size(state) <= SNAPSHOT_MAX_BYTES)


def _parse_bytes(data: bytes, mission_id: str) -> _State:
    _record(not _depth_exceeded(data))
    failed = False
    value: object = None
    try:
        value = verify_canonical_json_bytes(data)
    except (FoundationValidationError, ValueError, RecursionError, TypeError):
        failed = True
    _record(not failed)
    return _parse_value(value, mission_id)


# ---------------------------------------------------------------------------
# Filesystem primitives


def _os_code(error: OSError) -> str:
    if isinstance(error, FileNotFoundError):
        return "not_initialized"
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return "unsafe_path"
    return "io_unavailable"


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _open_root(root: str) -> int:
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        raise _Refusal(_os_code(error)) from None
    try:
        info = os.fstat(fd)
    except OSError:
        _close_quietly(fd)
        raise _Refusal("io_unavailable") from None
    if not stat.S_ISDIR(info.st_mode):
        _close_quietly(fd)
        raise _Refusal("unsafe_path")
    return fd


def _open_dir(parent: int, name: str, *, strict: bool, create: bool) -> tuple[int, bool]:
    """Open one directory component without following symlinks."""

    created = False
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        if not create:
            raise _Refusal("not_initialized") from None
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise _Refusal(_os_code(error)) from None
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise _Refusal(_os_code(error)) from None
    except OSError as error:
        raise _Refusal(_os_code(error)) from None
    if not stat.S_ISDIR(before.st_mode):
        raise _Refusal("unsafe_path")
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
    except OSError as error:
        raise _Refusal(_os_code(error)) from None
    try:
        info = os.fstat(fd)
    except OSError:
        _close_quietly(fd)
        raise _Refusal("io_unavailable") from None
    forbidden = 0o022 if strict else 0o002
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
        or info.st_uid != os.geteuid()
        or info.st_mode & forbidden
    ):
        _close_quietly(fd)
        raise _Refusal("unsafe_path")
    return fd, created


def _file_info_ok(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o022
    )


def _stat_file(directory: int, name: str) -> os.stat_result:
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise _Refusal(_os_code(error)) from None
    _require(_file_info_ok(info), "unsafe_path")
    return info


def _open_file(directory: int, name: str, flags: int) -> int:
    before = _stat_file(directory, name)
    try:
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    except OSError as error:
        raise _Refusal(_os_code(error)) from None
    try:
        info = os.fstat(fd)
    except OSError:
        _close_quietly(fd)
        raise _Refusal("io_unavailable") from None
    if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or not _file_info_ok(info):
        _close_quietly(fd)
        raise _Refusal("unsafe_path")
    return fd


def _read_snapshot(directory: int) -> bytes:
    fd = _open_file(directory, _SNAPSHOT_NAME, os.O_RDONLY)
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            raise _Refusal("io_unavailable") from None
        _record(0 < info.st_size <= SNAPSHOT_MAX_BYTES)
        chunks: list[bytes] = []
        total = 0
        while total <= SNAPSHOT_MAX_BYTES:
            try:
                chunk = os.read(fd, SNAPSHOT_MAX_BYTES + 1 - total)
            except OSError as error:
                raise _Refusal(_os_code(error)) from None
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        try:
            after = os.fstat(fd)
        except OSError:
            raise _Refusal("io_unavailable") from None
        _record(
            len(data) == info.st_size
            and after.st_size == info.st_size
            and (after.st_dev, after.st_ino) == (info.st_dev, info.st_ino)
        )
        return data
    finally:
        _close_quietly(fd)


def _open_namespace(root: str, mission_id: str) -> int:
    """Open the existing mission directory read-only; nothing is created."""

    fd = _open_root(root)
    try:
        for index, name in enumerate(_NAMESPACE):
            child, _ = _open_dir(fd, name, strict=index > 0, create=False)
            _close_quietly(fd)
            fd = child
        child, _ = _open_dir(fd, mission_id, strict=True, create=False)
    finally:
        _close_quietly(fd)
    return child


def _cleanup_staging(directory: int, name: str, fd: int) -> None:
    try:
        on_disk = os.stat(name, dir_fd=directory, follow_symlinks=False)
        mine = os.fstat(fd)
        if (on_disk.st_dev, on_disk.st_ino) == (mine.st_dev, mine.st_ino):
            os.unlink(name, dir_fd=directory)
    except OSError:
        pass


def _publish(directory: int, data: bytes) -> None:
    """K1-K4: exclusive staging, write, file fsync, rename, directory fsync."""

    name = _STAGING_PREFIX + hashlib.sha256(data).hexdigest()
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
    except OSError:
        raise _Refusal("io_unavailable") from None
    try:
        written = True
        try:
            view = memoryview(data)
            offset = 0
            while offset < len(data):
                count = os.write(fd, view[offset:])
                if count <= 0:
                    raise OSError(errno.EIO, "short write")
                offset += count
            os.fsync(fd)
            if os.fstat(fd).st_size != len(data):
                raise OSError(errno.EIO, "size mismatch")
        except OSError:
            written = False
        if not written:
            # Own staging cleanup happens only for ordinary OS failures (E9).
            _cleanup_staging(directory, name, fd)
            raise _Refusal("io_unavailable")
        try:
            os.rename(name, _SNAPSHOT_NAME, src_dir_fd=directory, dst_dir_fd=directory)
        except OSError:
            _cleanup_staging(directory, name, fd)
            raise _Refusal("publication_unknown") from None
        try:
            os.fsync(directory)
        except OSError:
            raise _Refusal("publication_unknown") from None
    finally:
        _close_quietly(fd)


def _self_checked(state: _State) -> bytes:
    data = _encode(state)
    _parse_bytes(data, state.mission_id)
    return data


# ---------------------------------------------------------------------------
# Views


def _vector(values: _Vec | list[int]) -> ResourceVector:
    return ResourceVector(
        attempts=values[0], recoveries=values[1], wall_ms=values[2], cost_units=values[3]
    )


def _public_policy(policy: _PolicyData) -> ReservationPolicy:
    return ReservationPolicy(
        cost_unit=policy.cost_unit,
        authority_ref=policy.authority_ref,
        mission_ceiling=_vector(policy.mission),
        root_lineage_ceiling=_vector(policy.lineage),
        causal_key_ceiling=_vector(policy.causal),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationRecord:
    """A stored operation; returned by the store and never a write authority."""

    request: ReservationRequest
    accounting_state: str
    unknown_observation: Observation | None
    determinate_observation: Observation | None

    def diagnostic_overrun(self) -> ResourceVector | None:
        determinate = self.determinate_observation
        if determinate is None or determinate.actual is None:
            return None
        actual = determinate.actual
        reserved = self.request.reservation
        return ResourceVector(
            attempts=max(actual.attempts - reserved.attempts, 0),
            recoveries=max(actual.recoveries - reserved.recoveries, 0),
            wall_ms=max(actual.wall_ms - reserved.wall_ms, 0),
            cost_units=max(actual.cost_units - reserved.cost_units, 0),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ScopeTotals:
    """Derived totals; ``remaining`` is clamped at zero and is not authority."""

    ceiling: ResourceVector
    used: ResourceVector
    reserved: ResourceVector
    remaining: ResourceVector


@dataclass(frozen=True, slots=True, kw_only=True)
class BlockedAccounting:
    """Blocked inspection: no remaining, no ordinary used totals, never complete."""

    reason: str
    trigger_operation_id: str
    accounted_actual_partial: ResourceVector
    outstanding_reserved: ResourceVector
    unaccounted_operation_ids: tuple[str, ...]
    accounting_complete: bool


def _record_of(state: _State, op: _Op) -> OperationRecord:
    cost_unit = state.policy.cost_unit
    request = ReservationRequest(
        operation_id=op.operation_id,
        causal_key=CausalKey(
            mission_id=state.mission_id,
            root_lineage_id=op.causal[0],
            goal_branch_id=op.causal[1],
            cause_code=op.causal[2],
            effect_family=op.causal[3],
        ),
        reservation=_vector(op.reservation),
        cost_unit=cost_unit,
        request_fingerprint=op.fingerprint,
    )
    unknown = None
    if op.unknown is not None:
        unknown = Observation(
            outcome="unknown", evidence_digest=op.unknown, actual=None, cost_unit=None
        )
    determinate = None
    if op.determinate is not None:
        outcome, digest, actual = op.determinate
        determinate = Observation(
            outcome=outcome, evidence_digest=digest, actual=_vector(actual), cost_unit=cost_unit
        )
    return OperationRecord(
        request=request,
        accounting_state=op.state,
        unknown_observation=unknown,
        determinate_observation=determinate,
    )


class NormalAccounting:
    """Derived totals per scope in mode ``normal``."""

    __slots__ = ("_state",)

    def __init__(self, state: _State) -> None:
        self._state = state

    def _totals(self, scope: tuple[str, object]) -> ScopeTotals:
        ceiling = _ceiling(self._state.policy, scope)
        used = _used(self._state.operations, scope)
        reserved = _reserved(self._state.operations, scope)
        remaining = [max(ceiling[i] - used[i] - reserved[i], 0) for i in range(4)]
        return ScopeTotals(
            ceiling=_vector(ceiling),
            used=_vector(used),
            reserved=_vector(reserved),
            remaining=_vector(remaining),
        )

    def mission(self) -> ScopeTotals:
        return self._totals(("mission", None))

    def root_lineage(self, root_lineage_id: str) -> ScopeTotals:
        def run() -> ScopeTotals:
            _require(_token_ok(root_lineage_id), "invalid_value")
            return self._totals(("lineage", root_lineage_id))

        return _guarded(run)

    def causal_key(self, key: CausalKey) -> ScopeTotals:
        def run() -> ScopeTotals:
            causal = _causal_tuple(key)
            _require(causal is not None, "invalid_value")
            assert causal is not None
            _require(causal[0] == self._state.mission_id, "namespace_conflict")
            return self._totals(("causal", causal[1:]))

        return _guarded(run)


class LedgerView:
    """An immutable view of one validated snapshot; not a source for writes."""

    __slots__ = ("_state",)

    def __init__(self, state: _State) -> None:
        self._state = state

    @property
    def mission_id(self) -> str:
        return self._state.mission_id

    @property
    def policy(self) -> ReservationPolicy:
        return _public_policy(self._state.policy)

    @property
    def writer_epoch(self) -> int:
        return self._state.epoch

    def operation(self, operation_id: str) -> OperationRecord | None:
        def run() -> OperationRecord | None:
            _require(_token_ok(operation_id), "invalid_value")
            for op in self._state.operations:
                if op.operation_id == operation_id:
                    return _record_of(self._state, op)
            return None

        return _guarded(run)

    def pending_operation_ids(self) -> tuple[str, ...]:
        return tuple(op.operation_id for op in self._state.operations if op.state != "accounted")

    def accounting(self) -> NormalAccounting | BlockedAccounting:
        state = self._state
        if state.trigger is None:
            return NormalAccounting(state)
        mission: tuple[str, object] = ("mission", None)
        return BlockedAccounting(
            reason=_BLOCK_REASON,
            trigger_operation_id=state.trigger,
            accounted_actual_partial=_vector(_used(state.operations, mission)),
            outstanding_reserved=_vector(_reserved(state.operations, mission)),
            unaccounted_operation_ids=tuple(
                op.operation_id for op in state.operations if op.state == "unaccounted"
            ),
            accounting_complete=False,
        )


# ---------------------------------------------------------------------------
# Initialization and reading


def initialize_ledger(
    project_root: str, mission_id: str, policy: ReservationPolicy
) -> Literal["created", "already_initialized"]:
    """Explicitly create one mission namespace; an identical existing one is accepted."""

    def run() -> Literal["created", "already_initialized"]:
        _require(_root_code(project_root) is None, "invalid_value")
        _require(_token_ok(mission_id), "invalid_value")
        data = _policy_data(policy)
        _require(data is not None, "invalid_value")
        assert data is not None
        _require(_platform_ok(), "unsupported_platform")
        return _initialize(project_root, mission_id, data)

    return _guarded(run)


def _initialize(
    root: str, mission_id: str, policy: _PolicyData
) -> Literal["created", "already_initialized"]:
    chain = [_open_root(root)]
    created: list[bool] = [False]
    mission_fd = -1
    lock_fd = -1
    try:
        for index, name in enumerate(_NAMESPACE):
            fd, made = _open_dir(chain[-1], name, strict=index > 0, create=True)
            chain.append(fd)
            created.append(made)
        parent = chain[-1]
        try:
            os.mkdir(mission_id, 0o700, dir_fd=parent)
        except FileExistsError:
            return _existing(parent, mission_id, policy)
        except OSError as error:
            raise _Refusal(_os_code(error)) from None
        mission_fd, _ = _open_dir(parent, mission_id, strict=True, create=False)
        try:
            lock_fd = os.open(
                _LOCK_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=mission_fd,
            )
        except OSError:
            raise _Refusal("io_unavailable") from None
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise _Refusal("writer_busy") from None
        except OSError:
            raise _Refusal("io_unavailable") from None
        try:
            os.fsync(lock_fd)
        except OSError:
            raise _Refusal("io_unavailable") from None
        initial = _State(mission_id, 0, policy, None, ())
        _publish(mission_fd, _self_checked(initial))
        # Ancestor barriers after K4 (which synced the mission directory once):
        # the new mission entry, then each created directory's parent bottom-up.
        barriers = [chain[-1]]
        for position in range(len(chain) - 1, 0, -1):
            if not created[position]:
                break
            barriers.append(chain[position - 1])
        for fd in barriers:
            try:
                os.fsync(fd)
            except OSError:
                raise _Refusal("publication_unknown") from None
        return "created"
    finally:
        if lock_fd >= 0:
            _close_quietly(lock_fd)
        if mission_fd >= 0:
            _close_quietly(mission_fd)
        for fd in chain:
            _close_quietly(fd)


def _existing(parent: int, mission_id: str, policy: _PolicyData) -> Literal["already_initialized"]:
    mission_fd, _ = _open_dir(parent, mission_id, strict=True, create=False)
    try:
        _stat_file(mission_fd, _LOCK_NAME)
        state = _parse_bytes(_read_snapshot(mission_fd), mission_id)
    finally:
        _close_quietly(mission_fd)
    _require(state.policy == policy, "policy_conflict")
    return "already_initialized"


def read_ledger(project_root: str, mission_id: str) -> LedgerView:
    """Validate and return the current snapshot; never writes or locks."""

    def run() -> LedgerView:
        _require(_root_code(project_root) is None, "invalid_value")
        _require(_token_ok(mission_id), "invalid_value")
        _require(_platform_ok(), "unsupported_platform")
        directory = _open_namespace(project_root, mission_id)
        try:
            _stat_file(directory, _LOCK_NAME)
            state = _parse_bytes(_read_snapshot(directory), mission_id)
        finally:
            _close_quietly(directory)
        return LedgerView(state)

    return _guarded(run)


# ---------------------------------------------------------------------------
# Writer session

_SESSION_TOKEN: Final = object()


@dataclass(frozen=True, slots=True)
class _SessionStart:
    pid: int
    directory: int
    lock: int
    lock_identity: tuple[int, int]
    state: _State
    digest: str


def acquire_writer(project_root: str, mission_id: str) -> WriterSession:
    """Take nonblocking custody and publish the next writer epoch."""

    def run() -> WriterSession:
        _require(_root_code(project_root) is None, "invalid_value")
        _require(_token_ok(mission_id), "invalid_value")
        _require(_platform_ok(), "unsupported_platform")
        return WriterSession(_SESSION_TOKEN, _acquire(project_root, mission_id))

    return _guarded(run)


def _acquire(root: str, mission_id: str) -> _SessionStart:
    directory = _open_namespace(root, mission_id)
    lock = -1
    handed_over = False
    try:
        # 3b: no snapshot means no lock open, no flock and no listing.
        try:
            os.stat(_SNAPSHOT_NAME, dir_fd=directory, follow_symlinks=False)
        except OSError as error:
            raise _Refusal(_os_code(error)) from None
        lock = _open_file(directory, _LOCK_NAME, os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise _Refusal("writer_busy") from None
        except OSError:
            raise _Refusal("io_unavailable") from None
        try:
            with os.scandir(directory) as entries:
                names = {entry.name for entry in entries}
        except OSError as error:
            raise _Refusal(_os_code(error)) from None
        _require(_SNAPSHOT_NAME in names and _LOCK_NAME in names, "not_initialized")
        _require(names == {_SNAPSHOT_NAME, _LOCK_NAME}, "namespace_conflict")
        state = _parse_bytes(_read_snapshot(directory), mission_id)
        _require(state.epoch < INT64_MAX, "overflow")
        lock_info = os.fstat(lock)
        candidate = _State(
            state.mission_id, state.epoch + 1, state.policy, state.trigger, state.operations
        )
        data = _self_checked(candidate)
        _publish(directory, data)
        handed_over = True
        return _SessionStart(
            pid=os.getpid(),
            directory=directory,
            lock=lock,
            lock_identity=(lock_info.st_dev, lock_info.st_ino),
            state=candidate,
            digest=hashlib.sha256(data).hexdigest(),
        )
    except OSError:
        raise _Refusal("io_unavailable") from None
    finally:
        if not handed_over:
            if lock >= 0:
                _close_quietly(lock)
            _close_quietly(directory)


class WriterSession:
    """Exclusive cooperative custody of one mission ledger in this process."""

    __slots__ = (
        "_pid",
        "_directory",
        "_lock",
        "_lock_identity",
        "_state",
        "_digest",
        "_status",
        "_guard",
    )

    def __init__(self, token: object = None, start: object = None) -> None:
        if token is not _SESSION_TOKEN or type(start) is not _SessionStart:
            raise ReservationLedgerError("invalid_value")
        self._pid = start.pid
        self._directory: int | None = start.directory
        self._lock: int | None = start.lock
        self._lock_identity = start.lock_identity
        self._state = start.state
        self._digest = start.digest
        self._status = "active"
        self._guard = threading.Lock()

    def __enter__(self) -> WriterSession:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- S0 and dispatch -------------------------------------------------

    def _call(self, body: Callable[[], _T]) -> _T:
        code: str
        if os.getpid() != self._pid:
            code = "custody_lost"
        elif not self._guard.acquire(blocking=False):
            code = "writer_busy"
        else:
            try:
                if self._status != "active":
                    raise _Refusal("custody_lost")
                result = body()
            except _Refusal as refusal:
                code = refusal.code
            else:
                return result
            finally:
                self._guard.release()
        raise ReservationLedgerError(code)

    def _poisoning(self, body: Callable[[], _T]) -> _T:
        try:
            return body()
        except BaseException:
            self._status = "poisoned"
            raise

    def _revalidate(self) -> _State:
        directory, lock = self._directory, self._lock
        assert directory is not None and lock is not None
        try:
            held = os.fstat(lock)
        except OSError:
            raise _Refusal("io_unavailable") from None
        named = _stat_or_refuse(directory, _LOCK_NAME)
        _require(
            (held.st_dev, held.st_ino) == self._lock_identity
            and (named.st_dev, named.st_ino) == self._lock_identity
            and named.st_nlink == 1,
            "custody_lost",
        )
        data = _read_snapshot(directory)
        state = _parse_bytes(data, self._state.mission_id)
        _require(
            hashlib.sha256(data).hexdigest() == self._digest and state.epoch == self._state.epoch,
            "stale_writer",
        )
        return state

    def _commit(self, candidate: _State) -> None:
        directory = self._directory
        assert directory is not None
        data = _self_checked(candidate)
        _publish(directory, data)
        self._digest = hashlib.sha256(data).hexdigest()
        self._state = candidate

    # -- mutators --------------------------------------------------------

    def reserve_recovery(
        self, request: ReservationRequest
    ) -> Literal["newly_reserved", "already_reserved_reconcile_only"]:
        return self._call(lambda: self._reserve(request))

    def _reserve(
        self, request: ReservationRequest
    ) -> Literal["newly_reserved", "already_reserved_reconcile_only"]:
        data = _request_data(request)
        _require(data is not None, "invalid_value")
        assert data is not None
        _require(data.mission_id == self._state.mission_id, "namespace_conflict")
        _require(data.cost_unit == self._state.policy.cost_unit, "policy_conflict")
        state = self._poisoning(self._revalidate)
        for op in state.operations:
            if op.operation_id == data.operation_id:
                _require(
                    op.causal == data.causal
                    and op.reservation == data.reservation
                    and op.fingerprint == data.fingerprint,
                    "intent_conflict",
                )
                return "already_reserved_reconcile_only"
        _require(state.trigger is None, "accounting_blocked")
        _require(
            all(op.causal != data.causal or op.state == "accounted" for op in state.operations),
            "causal_pending",
        )
        _require(len(state.operations) < MAX_OPERATIONS, "capacity_exhausted")
        new_op = _Op(
            operation_id=data.operation_id,
            causal=data.causal,
            fingerprint=data.fingerprint,
            reservation=data.reservation,
            state="pending",
            unknown=None,
            determinate=None,
        )
        operations = tuple(sorted((*state.operations, new_op), key=lambda op: op.operation_id))
        candidate = _State(state.mission_id, state.epoch, state.policy, state.trigger, operations)
        _require(_worst_case_size(candidate) <= SNAPSHOT_MAX_BYTES, "capacity_exhausted")
        _require(_budget_ok(state, data.causal, data.reservation), "budget_exhausted")
        self._poisoning(lambda: self._commit(candidate))
        return "newly_reserved"

    def record_receipt(
        self, operation_id: str, observation: Observation
    ) -> Literal[
        "receipt_recorded_unknown",
        "receipt_settled",
        "receipt_duplicate",
        "receipt_recorded_accounting_blocked",
        "receipt_recorded_unaccounted",
    ]:
        return self._call(lambda: self._receipt(operation_id, observation))

    def _receipt(
        self, operation_id: str, observation: Observation
    ) -> Literal[
        "receipt_recorded_unknown",
        "receipt_settled",
        "receipt_duplicate",
        "receipt_recorded_accounting_blocked",
        "receipt_recorded_unaccounted",
    ]:
        _require(_token_ok(operation_id), "invalid_value")
        data = _observation_data(observation)
        _require(data is not None, "invalid_value")
        assert data is not None
        if data.actual is not None:
            _require(data.cost_unit == self._state.policy.cost_unit, "policy_conflict")
        state = self._poisoning(self._revalidate)
        matches = [op for op in state.operations if op.operation_id == operation_id]
        _require(len(matches) == 1, "unknown_operation")
        op = matches[0]
        result: Literal[
            "receipt_recorded_unknown",
            "receipt_settled",
            "receipt_recorded_accounting_blocked",
            "receipt_recorded_unaccounted",
        ]
        trigger = state.trigger
        if data.actual is None:
            if op.determinate is not None or op.unknown is not None:
                _require(op.unknown == data.digest, "receipt_conflict")
                return "receipt_duplicate"
            updated = _replace_op(op, unknown=data.digest)
            result = "receipt_recorded_unknown"
        else:
            determinate = (data.outcome, data.digest, data.actual)
            if op.determinate is not None:
                _require(op.determinate == determinate, "receipt_conflict")
                return "receipt_duplicate"
            if state.trigger is not None:
                updated = _replace_op(op, determinate=determinate, state="unaccounted")
                result = "receipt_recorded_unaccounted"
            elif _overflows(state, op.causal, data.actual):
                updated = _replace_op(op, determinate=determinate, state="unaccounted")
                trigger = op.operation_id
                result = "receipt_recorded_accounting_blocked"
            else:
                updated = _replace_op(op, determinate=determinate, state="accounted")
                result = "receipt_settled"
        operations = tuple(updated if item is op else item for item in state.operations)
        candidate = _State(state.mission_id, state.epoch, state.policy, trigger, operations)
        _require(_worst_case_size(candidate) <= SNAPSHOT_MAX_BYTES, "capacity_exhausted")
        self._poisoning(lambda: self._commit(candidate))
        return result

    def view(self) -> LedgerView:
        return self._call(lambda: LedgerView(self._state))

    def close(self) -> None:
        if os.getpid() != self._pid:
            # Forked child: never take the possibly inherited lock, never LOCK_UN.
            self._status = "closed"
            for fd in self._forget():
                _close_quietly(fd)
            return
        with self._guard:
            self._status = "closed"
            descriptors = self._forget()
            for fd in descriptors:
                _close_quietly(fd)

    def _forget(self) -> tuple[int, ...]:
        descriptors = tuple(fd for fd in (self._directory, self._lock) if fd is not None)
        self._directory = None
        self._lock = None
        return descriptors


def _stat_or_refuse(directory: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as error:
        raise _Refusal(_os_code(error)) from None


def _replace_op(
    op: _Op,
    *,
    unknown: str | None = None,
    determinate: tuple[str, str, _Vec] | None = None,
    state: str | None = None,
) -> _Op:
    return _Op(
        operation_id=op.operation_id,
        causal=op.causal,
        fingerprint=op.fingerprint,
        reservation=op.reservation,
        state=op.state if state is None else state,
        unknown=op.unknown if unknown is None else unknown,
        determinate=op.determinate if determinate is None else determinate,
    )


__all__ = [
    "CODES",
    "INT64_MAX",
    "MAX_OPERATIONS",
    "SNAPSHOT_MAX_BYTES",
    "BlockedAccounting",
    "CausalKey",
    "LedgerView",
    "NormalAccounting",
    "Observation",
    "OperationRecord",
    "ReservationLedgerError",
    "ReservationPolicy",
    "ReservationRequest",
    "ResourceVector",
    "ScopeTotals",
    "WriterSession",
    "acquire_writer",
    "initialize_ledger",
    "read_ledger",
]
