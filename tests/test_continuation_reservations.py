"""S2b-LR recovery reservation ledger contract tests (S2BR01-S2BR18).

Evidence classes: REAL means a genuine kernel/filesystem effect inside this one
process (separate-open flock contention, dup/OFD, rename/fsync on tmp_path);
INJECTED means a monkeypatched fault or simulation.  INJECTED tests do not
prove real fork or real process-crash behaviour (E-FORK/E-CRASH stay OPEN), and
no test here starts a process.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from decimal import Decimal
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import traceback
from typing import Any, TypeVar

import pytest

from unrest_harness import continuation_reservations as cr
from unrest_harness.canonical_identity import canonical_json_bytes
from unrest_harness.continuation_reservations import (
    CODES,
    INT64_MAX,
    MAX_OPERATIONS,
    SNAPSHOT_MAX_BYTES,
    BlockedAccounting,
    CausalKey,
    LedgerView,
    NormalAccounting,
    Observation,
    ReservationLedgerError,
    ReservationPolicy,
    ReservationRequest,
    ResourceVector,
    WriterSession,
    acquire_writer,
    initialize_ledger,
    read_ledger,
)
from unrest_harness.continuation_types import DURATION_MS_MAX

MAX = INT64_MAX
_V = TypeVar("_V")
MISSION = "m1"
UNIT = "usd-micro"
NAMESPACE = (".unrest", "continuation", "recovery-reservations-v1")
MODULE_PATH = Path(cr.__file__)
SOURCE = MODULE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# helpers


def digest(index: int) -> str:
    return f"{index:064x}"


def vec(a: int = 1, r: int = 1, w: int = 10, c: int = 10) -> ResourceVector:
    return ResourceVector(attempts=a, recoveries=r, wall_ms=w, cost_units=c)


def big(value: int = 1000) -> ResourceVector:
    return vec(value, value, value, value)


def policy(
    mission: ResourceVector | None = None,
    lineage: ResourceVector | None = None,
    causal: ResourceVector | None = None,
    unit: str = UNIT,
) -> ReservationPolicy:
    return ReservationPolicy(
        cost_unit=unit,
        authority_ref="auth-1",
        mission_ceiling=mission or big(),
        root_lineage_ceiling=lineage or big(),
        causal_key_ceiling=causal or big(),
    )


def key(
    lineage: str = "L1",
    branch: str = "G1",
    cause: str = "C1",
    family: str = "F1",
    mission: str = MISSION,
) -> CausalKey:
    return CausalKey(
        mission_id=mission,
        root_lineage_id=lineage,
        goal_branch_id=branch,
        cause_code=cause,
        effect_family=family,
    )


def req(
    op: str = "op1",
    causal: CausalKey | None = None,
    wall: int = 10,
    cost: int = 10,
    fp: int = 1,
    unit: str = UNIT,
) -> ReservationRequest:
    return ReservationRequest(
        operation_id=op,
        causal_key=causal or key(),
        reservation=vec(1, 1, wall, cost),
        cost_unit=unit,
        request_fingerprint=digest(fp),
    )


def unk(index: int = 100) -> Observation:
    return Observation(
        outcome="unknown", evidence_digest=digest(index), actual=None, cost_unit=None
    )


def det(
    actual: ResourceVector | None = None,
    index: int = 200,
    outcome: str = "accepted",
    unit: str = UNIT,
) -> Observation:
    return Observation(
        outcome=outcome, evidence_digest=digest(index), actual=actual or vec(), cost_unit=unit
    )


def mdir(root: str, mission: str = MISSION) -> Path:
    return Path(root, *NAMESPACE, mission)


def snap(root: str, mission: str = MISSION) -> bytes:
    return (mdir(root, mission) / "snapshot.json").read_bytes()


def snap_id(root: str, mission: str = MISSION) -> tuple[bytes, int]:
    """Snapshot bytes plus inode: an unchanged inode proves that nothing was republished."""

    path = mdir(root, mission) / "snapshot.json"
    return path.read_bytes(), os.stat(path).st_ino


def snap_obj(root: str, mission: str = MISSION) -> dict[str, Any]:
    value = json.loads(snap(root, mission))
    assert isinstance(value, dict)
    return value


def tree(path: str | Path) -> list[tuple[str, int, int, str]]:
    """Deterministic listing of every entry (relpath, mode, size, sha256)."""

    base = Path(path)
    result = []
    for current, dirs, files in os.walk(base):
        dirs.sort()
        for name in sorted(dirs + files):
            full = Path(current, name)
            info = full.lstat()
            content = ""
            if stat.S_ISREG(info.st_mode):
                content = hashlib.sha256(full.read_bytes()).hexdigest()
            result.append((str(full.relative_to(base)), info.st_mode, info.st_size, content))
    return result


def code_of(call: Callable[[], object]) -> str:
    with pytest.raises(ReservationLedgerError) as caught:
        call()
    return caught.value.code


def write_snapshot(root: str, data: bytes, mission: str = MISSION) -> None:
    """Replace snapshot bytes in place (keeps inode, mode 0o600, nlink 1)."""

    path = mdir(root, mission) / "snapshot.json"
    with open(path, "r+b") as handle:
        handle.truncate(0)
        handle.write(data)


def install(root: str, value: dict[str, Any], mission: str = MISSION) -> None:
    write_snapshot(root, canonical_json_bytes(value), mission)


@pytest.fixture
def root(tmp_path: Path) -> str:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    return str(project)


@pytest.fixture
def ledger(root: str) -> str:
    assert initialize_ledger(root, MISSION, policy()) == "created"
    return root


@pytest.fixture
def session(ledger: str) -> Iterator[WriterSession]:
    writer = acquire_writer(ledger, MISSION)
    try:
        yield writer
    finally:
        writer.close()


def wire_vec(a: int, r: int, w: int, c: int) -> dict[str, str]:
    return {"attempts": str(a), "cost_units": str(c), "recoveries": str(r), "wall_ms": str(w)}


def wire_op(
    op: str,
    causal: tuple[str, str, str, str] = ("L1", "G1", "C1", "F1"),
    reservation: tuple[int, int, int, int] = (1, 1, 10, 10),
    state: str = "pending",
    observations: list[dict[str, Any]] | None = None,
    fp: int = 1,
) -> dict[str, Any]:
    return {
        "accounting_state": state,
        "causal_key": {
            "cause_code": causal[2],
            "effect_family": causal[3],
            "goal_branch_id": causal[1],
            "root_lineage_id": causal[0],
        },
        "observations": observations or [],
        "operation_id": op,
        "request_fingerprint": digest(fp),
        "reservation": wire_vec(*reservation),
    }


def wire_unknown(index: int = 100) -> dict[str, Any]:
    return {"evidence_digest": digest(index), "kind": "unknown"}


def wire_det(
    actual: tuple[int, int, int, int], index: int = 200, outcome: str = "accepted"
) -> dict[str, Any]:
    return {
        "actual": wire_vec(*actual),
        "evidence_digest": digest(index),
        "kind": "determinate",
        "outcome": outcome,
    }


def wire_snapshot(
    operations: list[dict[str, Any]],
    *,
    mission: str = MISSION,
    epoch: int = 1,
    trigger: str | None = None,
    ceilings: tuple[int, int, int] | None = None,
    unit: str = UNIT,
    authority: str = "auth-1",
) -> dict[str, Any]:
    """Test-built snapshot from literals; independent of the production encoder."""

    mission_c, lineage_c, causal_c = ceilings or (1000, 1000, 1000)
    accounting: dict[str, str] = {"mode": "normal"}
    if trigger is not None:
        accounting = {
            "mode": "blocked",
            "reason": "actual_accumulation_overflow",
            "trigger_operation_id": trigger,
        }
    return {
        "accounting": accounting,
        "kind": "recovery_reservations",
        "mission_id": mission,
        "operations": operations,
        "policy": {
            "authority_ref": authority,
            "causal_key_ceiling": wire_vec(causal_c, causal_c, causal_c, causal_c),
            "cost_unit": unit,
            "mission_ceiling": wire_vec(mission_c, mission_c, mission_c, mission_c),
            "root_lineage_ceiling": wire_vec(lineage_c, lineage_c, lineage_c, lineage_c),
        },
        "schema_version": 1,
        "writer_epoch": str(epoch),
    }


def seed(root: str, value: dict[str, Any], mission: str = MISSION) -> None:
    """Create a namespace directly from test literals (REAL-reader / seeded-state)."""

    path = Path(root)
    for name in (*NAMESPACE, mission):
        path = path / name
        path.mkdir(mode=0o700, exist_ok=True)
    lock = path / "writer.lock"
    lock.touch(mode=0o600)
    snapshot = path / "snapshot.json"
    snapshot.write_bytes(canonical_json_bytes(value))
    snapshot.chmod(0o600)


class SimulatedCrash(BaseException):
    """Abrupt termination at a cut point (INJECTED simulation, not a real crash)."""


def is_reg(fd: int) -> bool:
    return stat.S_ISREG(os.fstat(fd).st_mode)


def is_dir(fd: int) -> bool:
    return stat.S_ISDIR(os.fstat(fd).st_mode)


def is_staging_fd(fd: int) -> bool:
    info = os.fstat(fd)
    return stat.S_ISREG(info.st_mode) and info.st_size > 0


def abandon(writer: WriterSession) -> None:
    """Emulate kernel release of a crashed session's descriptors (white-box)."""

    for name in ("_directory", "_lock"):
        fd = getattr(writer, name)
        if fd is not None:
            os.close(fd)
            setattr(writer, name, None)


# ---------------------------------------------------------------------------
# S2BR01 values, policy, request, observation


class IntSub(int):
    pass


class StrSub(str):
    pass


BAD_INTS = [True, False, 1.0, Decimal(1), "1", IntSub(1), -1, MAX + 1, None]


@pytest.mark.parametrize("field", ["attempts", "recoveries", "wall_ms", "cost_units"])
@pytest.mark.parametrize("bad", BAD_INTS, ids=repr)
def test_s2br01_vector_requires_exact_int64(field: str, bad: object) -> None:
    values: dict[str, object] = {"attempts": 1, "recoveries": 1, "wall_ms": 1, "cost_units": 1}
    values[field] = bad
    assert code_of(lambda: ResourceVector(**values)) == "invalid_value"  # type: ignore[arg-type]


@pytest.mark.parametrize("good", [0, 1, 2**53, 2**53 + 1, MAX])
def test_s2br01_vector_accepts_full_int64(good: int) -> None:
    vector = ResourceVector(attempts=good, recoveries=good, wall_ms=good, cost_units=good)
    assert vector.wall_ms == good


def test_s2br01_vector_has_no_defaults() -> None:
    with pytest.raises(TypeError):
        ResourceVector(attempts=1, recoveries=1, wall_ms=1)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        Observation(outcome="unknown", evidence_digest=digest(1), actual=None)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "reservation",
    [
        vec(2, 1, 1, 1),
        vec(0, 1, 1, 1),
        vec(1, 0, 1, 1),
        vec(1, 2, 1, 1),
        vec(1, 1, 0, 1),
        vec(1, 1, 1, 0),
    ],
)
def test_s2br01_reservation_shape(reservation: ResourceVector) -> None:
    assert (
        code_of(
            lambda: ReservationRequest(
                operation_id="op1",
                causal_key=key(),
                reservation=reservation,
                cost_unit=UNIT,
                request_fingerprint=digest(1),
            )
        )
        == "invalid_value"
    )


GOOD_TOKENS = ["a", "A" * 128, "a.b_c:d-e", "0x"]
BAD_TOKENS = [
    "",
    "a" * 129,
    ".a",
    "-a",
    "_a",
    ":a",
    "a/b",
    "a\x00",
    "é",
    "a b",
    "a\n",
    StrSub("a"),
    1,
    None,
]


@pytest.mark.parametrize("token", GOOD_TOKENS)
def test_s2br01_token_accepted(token: str) -> None:
    assert key(lineage=token).root_lineage_id == token


@pytest.mark.parametrize("token", BAD_TOKENS, ids=repr)
@pytest.mark.parametrize("field", ["mission", "lineage", "branch", "cause", "family"])
def test_s2br01_token_refused(field: str, token: object) -> None:
    assert code_of(lambda: key(**{field: token})) == "invalid_value"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, StrSub("a" * 64)], ids=repr
)
def test_s2br01_digest_refused(bad: str) -> None:
    assert (
        code_of(
            lambda: unk().__class__(
                outcome="unknown", evidence_digest=bad, actual=None, cost_unit=None
            )
        )
        == "invalid_value"
    )
    assert (
        code_of(
            lambda: ReservationRequest(
                operation_id="op1",
                causal_key=key(),
                reservation=vec(),
                cost_unit=UNIT,
                request_fingerprint=bad,
            )
        )
        == "invalid_value"
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"outcome": "unknown", "actual": vec(), "cost_unit": None},
        {"outcome": "unknown", "actual": None, "cost_unit": UNIT},
        {"outcome": "accepted", "actual": None, "cost_unit": UNIT},
        {"outcome": "rejected", "actual": vec(), "cost_unit": None},
        {"outcome": "settled", "actual": vec(), "cost_unit": UNIT},
    ],
)
def test_s2br01_observation_shape(kwargs: dict[str, object]) -> None:
    assert code_of(lambda: Observation(evidence_digest=digest(1), **kwargs)) == "invalid_value"  # type: ignore[arg-type]


def test_s2br01_policy_and_ceiling_types() -> None:
    with pytest.raises(ReservationLedgerError):
        ReservationPolicy(
            cost_unit=UNIT,
            authority_ref="a",
            mission_ceiling=(1, 1, 1, 1),  # type: ignore[arg-type]
            root_lineage_ceiling=big(),
            causal_key_ceiling=big(),
        )
    assert code_of(lambda: policy(unit="bad unit")) == "invalid_value"


def mutated(value: _V, field: str, new: object) -> _V:
    object.__setattr__(value, field, new)
    return value


def test_s2br01_mutated_instances_refused_at_every_boundary(ledger: str) -> None:
    bad_vector = mutated(vec(), "wall_ms", -1)
    assert (
        code_of(
            lambda: ReservationRequest(
                operation_id="op1",
                causal_key=key(),
                reservation=bad_vector,
                cost_unit=UNIT,
                request_fingerprint=digest(1),
            )
        )
        == "invalid_value"
    )
    bad_policy = mutated(policy(), "mission_ceiling", mutated(big(), "attempts", True))
    root2 = str(Path(ledger) / "other")
    os.mkdir(root2, 0o700)
    assert code_of(lambda: initialize_ledger(root2, MISSION, bad_policy)) == "invalid_value"
    assert not os.listdir(root2)
    with acquire_writer(ledger, MISSION) as writer:
        before = snap(ledger)
        assert (
            code_of(lambda: writer.reserve_recovery(mutated(req(), "operation_id", "a/b")))
            == "invalid_value"
        )
        deleted = req()
        object.__delattr__(deleted, "request_fingerprint")
        assert code_of(lambda: writer.reserve_recovery(deleted)) == "invalid_value"
        nested = req()
        object.__setattr__(nested.reservation, "cost_units", MAX + 1)
        assert code_of(lambda: writer.reserve_recovery(nested)) == "invalid_value"
        assert writer.reserve_recovery(req()) == "newly_reserved"
        obs = det()
        object.__setattr__(obs.actual, "attempts", IntSub(1))
        assert code_of(lambda: writer.record_receipt("op1", obs)) == "invalid_value"
        assert (
            code_of(lambda: writer.record_receipt("op1", mutated(unk(), "outcome", "maybe")))
            == "invalid_value"
        )
        assert code_of(lambda: writer.record_receipt("bad/op", unk())) == "invalid_value"
        accounting = writer.view().accounting()
        assert isinstance(accounting, NormalAccounting)
        assert (
            code_of(lambda: accounting.causal_key(mutated(key(), "cause_code", "")))
            == "invalid_value"
        )
        assert code_of(lambda: accounting.root_lineage("bad/lineage")) == "invalid_value"
        assert code_of(lambda: writer.view().operation("bad/op")) == "invalid_value"
        assert snap(ledger) != before  # only the valid reservation was published


def test_s2br01_constants_and_surface() -> None:
    assert INT64_MAX == DURATION_MS_MAX == 2**63 - 1
    assert MAX_OPERATIONS == 256
    assert SNAPSHOT_MAX_BYTES == 2 * 1024 * 1024
    assert len(cr.__all__) == 19
    assert set(cr.__all__) == {
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
    }
    assert CODES == frozenset(
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
    assert len(CODES) == 21


@pytest.mark.parametrize("bad", ["nope", 1, None, StrSub("overflow")], ids=repr)
def test_s2br01_error_constructor_misuse(bad: object) -> None:
    with pytest.raises(ValueError, match="^invalid_error_code$"):
        ReservationLedgerError(bad)  # type: ignore[arg-type]
    error = ReservationLedgerError("overflow")
    assert str(error) == "overflow" and repr(error) == "ReservationLedgerError('overflow')"
    assert error.args == ("overflow",)


def test_s2br01_writer_session_not_constructible() -> None:
    assert code_of(lambda: WriterSession()) == "invalid_value"
    assert code_of(lambda: WriterSession(object(), object())) == "invalid_value"


GOLDEN_INITIAL = (
    b'{"accounting":{"mode":"normal"},"kind":"recovery_reservations","mission_id":"m1",'
    b'"operations":[],"policy":{"authority_ref":"auth-1","causal_key_ceiling":'
    b'{"attempts":"1000","cost_units":"1000","recoveries":"1000","wall_ms":"1000"},'
    b'"cost_unit":"usd-micro","mission_ceiling":{"attempts":"1000","cost_units":"1000",'
    b'"recoveries":"1000","wall_ms":"1000"},"root_lineage_ceiling":{"attempts":"1000",'
    b'"cost_units":"1000","recoveries":"1000","wall_ms":"1000"}},"schema_version":1,'
    b'"writer_epoch":"0"}\n'
)

GOLDEN_ONE_OP_OPERATIONS = (
    b'"operations":[{"accounting_state":"pending","causal_key":{"cause_code":"C1",'
    b'"effect_family":"F1","goal_branch_id":"G1","root_lineage_id":"L1"},"observations":[],'
    b'"operation_id":"op1","request_fingerprint":"' + digest(1).encode() + b'",'
    b'"reservation":{"attempts":"1","cost_units":"10","recoveries":"1","wall_ms":"10"}}]'
)


def test_s2br01_golden_canonical_bytes(ledger: str) -> None:
    assert snap(ledger) == GOLDEN_INITIAL
    with acquire_writer(ledger, MISSION) as writer:
        writer.reserve_recovery(req())
    expected = GOLDEN_INITIAL.replace(b'"operations":[]', GOLDEN_ONE_OP_OPERATIONS).replace(
        b'"writer_epoch":"0"', b'"writer_epoch":"1"'
    )
    assert snap(ledger) == expected


# ---------------------------------------------------------------------------
# S2BR02 reserve, settle, precedence of reserve


def totals(
    view: LedgerView, scope: str = "mission", arg: object = None
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    accounting = view.accounting()
    assert isinstance(accounting, NormalAccounting)
    if scope == "mission":
        result = accounting.mission()
    elif scope == "lineage":
        result = accounting.root_lineage(str(arg))
    else:
        assert isinstance(arg, CausalKey)
        result = accounting.causal_key(arg)

    def t(v: ResourceVector) -> tuple[int, ...]:
        return (v.attempts, v.recoveries, v.wall_ms, v.cost_units)

    return t(result.used), t(result.reserved)


def test_s2br02_reserve_publishes_operation_and_reservation(
    session: WriterSession, ledger: str
) -> None:
    assert session.reserve_recovery(req(wall=7, cost=9)) == "newly_reserved"
    view = read_ledger(ledger, MISSION)
    record = view.operation("op1")
    assert record is not None and record.accounting_state == "pending"
    for scope, arg in (("mission", None), ("lineage", "L1"), ("causal", key())):
        assert totals(view, scope, arg) == ((0, 0, 0, 0), (1, 1, 7, 9))
    assert view.pending_operation_ids() == ("op1",)


DIM_INDEX = {"attempts": 0, "recoveries": 1, "wall_ms": 2, "cost_units": 3}


def tight(dimension: str) -> ResourceVector:
    values = [1000, 1000, 1000, 1000]
    values[DIM_INDEX[dimension]] = 1 if dimension in ("attempts", "recoveries") else 15
    return vec(*values)


@pytest.mark.parametrize("dimension", list(DIM_INDEX))
@pytest.mark.parametrize("scope", ["mission", "lineage", "causal"])
def test_s2br02_each_scope_and_dimension_exhausts(root: str, scope: str, dimension: str) -> None:
    kwargs: dict[str, ResourceVector | None] = {"mission": None, "lineage": None, "causal": None}
    kwargs[scope] = tight(dimension)
    initialize_ledger(root, MISSION, policy(**kwargs))  # type: ignore[arg-type]
    with acquire_writer(root, MISSION) as writer:
        assert writer.reserve_recovery(req("op1", key())) == "newly_reserved"
        if scope == "mission":
            second = req("op2", key(lineage="L2"))
        elif scope == "lineage":
            second = req("op2", key(cause="C2"))
        else:
            writer.record_receipt("op1", det(vec(1, 1, 10, 10)))
            second = req("op2", key())
        before = snap(root)
        assert code_of(lambda: writer.reserve_recovery(second)) == "budget_exhausted"
        assert snap(root) == before
        # The refusal is a logic refusal: the session keeps working.
        if scope != "mission":
            assert (
                writer.reserve_recovery(req("op3", key(lineage="L9", cause="C9")))
                == "newly_reserved"
            )
        else:
            assert writer.view().pending_operation_ids() == ("op1",)


@pytest.mark.parametrize("dimension", list(DIM_INDEX))
def test_s2br02_zero_ceiling_denies(root: str, dimension: str) -> None:
    values = [1000, 1000, 1000, 1000]
    values[DIM_INDEX[dimension]] = 0
    initialize_ledger(root, MISSION, policy(causal=vec(*values)))
    with acquire_writer(root, MISSION) as writer:
        assert code_of(lambda: writer.reserve_recovery(req())) == "budget_exhausted"


def test_s2br02_exact_retry_and_intent_conflicts(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req())
    before = snap_id(ledger)
    assert session.reserve_recovery(req()) == "already_reserved_reconcile_only"
    assert snap_id(ledger) == before
    conflicts = [
        req(causal=key(lineage="L2")),
        req(causal=key(branch="G2")),
        req(causal=key(cause="C2")),
        req(causal=key(family="F2")),
        req(wall=11),
        req(cost=11),
        req(fp=2),
    ]
    for conflict in conflicts:
        assert code_of(lambda: session.reserve_recovery(conflict)) == "intent_conflict"
    assert (
        code_of(lambda: session.reserve_recovery(req(causal=key(mission="m2"))))
        == "namespace_conflict"
    )
    assert code_of(lambda: session.reserve_recovery(req(unit="eur"))) == "policy_conflict"
    shaped = req()
    object.__setattr__(shaped.reservation, "attempts", 2)
    assert code_of(lambda: session.reserve_recovery(shaped)) == "invalid_value"
    assert snap_id(ledger) == before
    assert session.reserve_recovery(req("op2", key(cause="C2"))) == "newly_reserved"


def test_s2br02_precedence_args_before_disk(session: WriterSession, ledger: str) -> None:
    invalid_and_foreign = req(causal=key(mission="m2"))
    object.__setattr__(invalid_and_foreign, "request_fingerprint", "x")
    assert code_of(lambda: session.reserve_recovery(invalid_and_foreign)) == "invalid_value"
    assert (
        code_of(lambda: session.reserve_recovery(req(causal=key(mission="m2"), unit="eur")))
        == "namespace_conflict"
    )
    # Foreign disk change + unit mismatch: the argument refusal wins and does not poison.
    value = snap_obj(ledger)
    value["writer_epoch"] = "7"
    install(ledger, value)
    assert code_of(lambda: session.reserve_recovery(req(unit="eur"))) == "policy_conflict"
    assert code_of(lambda: session.reserve_recovery(req())) == "stale_writer"
    assert code_of(lambda: session.reserve_recovery(req())) == "custody_lost"


def test_s2br02_epoch_change_is_separate_from_budget(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req())
    session.close()
    before = snap_obj(ledger)
    with acquire_writer(ledger, MISSION):
        after = snap_obj(ledger)
    assert int(after.pop("writer_epoch")) == int(before.pop("writer_epoch")) + 1
    assert after == before


def test_s2br02_view_objects_are_not_write_sources(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req("x"))
    stored_x = snap_obj(ledger)["operations"][0]
    stored_policy = snap_obj(ledger)["policy"]
    view = session.view()
    record = view.operation("x")
    assert record is not None
    object.__setattr__(record.request, "request_fingerprint", digest(99))
    object.__setattr__(record.request.reservation, "wall_ms", 1)
    pol = view.policy
    object.__setattr__(pol, "cost_unit", "other")
    assert session.reserve_recovery(req("y", key(cause="C2"))) == "newly_reserved"
    stored = snap_obj(ledger)
    assert stored["operations"][0] == stored_x and stored["policy"] == stored_policy


# ---------------------------------------------------------------------------
# S2BR03 scopes and causal identity


def test_s2br03_a_b_a_accumulates_without_reset(session: WriterSession, ledger: str) -> None:
    """Same supplied causal key accumulates; not protection against a lying mapper."""

    for index, op in enumerate(("a1", "b2", "a3")):
        assert session.reserve_recovery(req(op, key(), fp=10 + index)) == "newly_reserved"
        session.record_receipt(op, det(vec(1, 1, 5, 6), index=index))
    view = read_ledger(ledger, MISSION)
    assert totals(view, "causal", key()) == ((3, 3, 15, 18), (0, 0, 0, 0))


def test_s2br03_mission_and_lineage_ceilings_bound_category_changes(root: str) -> None:
    initialize_ledger(
        root, MISSION, policy(mission=vec(2, 2, 1000, 1000), lineage=vec(1, 1, 1000, 1000))
    )
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("op1", key()))
        assert (
            code_of(lambda: writer.reserve_recovery(req("op2", key(branch="G2"))))
            == "budget_exhausted"
        )
        writer.reserve_recovery(req("op3", key(lineage="L2", cause="C9")))
        assert (
            code_of(lambda: writer.reserve_recovery(req("op4", key(lineage="L3", cause="C8"))))
            == "budget_exhausted"
        )


def test_s2br03_pending_causal_guard(session: WriterSession) -> None:
    session.reserve_recovery(req("op1"))
    assert code_of(lambda: session.reserve_recovery(req("op2", fp=2))) == "causal_pending"
    session.record_receipt("op1", unk())
    assert code_of(lambda: session.reserve_recovery(req("op2", fp=2))) == "causal_pending"
    session.record_receipt("op1", det())
    assert session.reserve_recovery(req("op2", fp=2)) == "newly_reserved"
    assert (
        code_of(lambda: session.reserve_recovery(req("op3", key(mission="mX"))))
        == "namespace_conflict"
    )


# ---------------------------------------------------------------------------
# S2BR04 receipt state table


def test_s2br04_state_table(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req("op1"))
    assert code_of(lambda: session.record_receipt("nope", unk())) == "unknown_operation"
    assert code_of(lambda: session.record_receipt("op1", det(unit="eur"))) == "policy_conflict"
    assert session.record_receipt("op1", unk(1)) == "receipt_recorded_unknown"
    assert totals(session.view()) == ((0, 0, 0, 0), (1, 1, 10, 10))  # unknown keeps R
    before = snap_id(ledger)
    assert session.record_receipt("op1", unk(1)) == "receipt_duplicate"
    assert snap_id(ledger) == before
    assert code_of(lambda: session.record_receipt("op1", unk(2))) == "receipt_conflict"
    assert session.record_receipt("op1", det(vec(1, 1, 4, 0), index=3)) == "receipt_settled"
    stored = snap_obj(ledger)["operations"][0]["observations"]
    assert [item["kind"] for item in stored] == ["unknown", "determinate"]
    before = snap_id(ledger)
    assert session.record_receipt("op1", det(vec(1, 1, 4, 0), index=3)) == "receipt_duplicate"
    assert session.record_receipt("op1", unk(1)) == "receipt_duplicate"  # E3: stored u
    assert snap_id(ledger) == before
    for conflict in (
        unk(2),
        det(vec(1, 1, 4, 0), index=4),
        det(vec(1, 1, 5, 0), index=3),
        det(vec(1, 1, 4, 0), index=3, outcome="rejected"),
    ):
        assert code_of(lambda: session.record_receipt("op1", conflict)) == "receipt_conflict"
    assert snap_id(ledger) == before
    assert totals(session.view()) == ((1, 1, 4, 0), (0, 0, 0, 0))


def test_s2br04_unknown_after_determinate_without_stored_unknown(session: WriterSession) -> None:
    session.reserve_recovery(req("op1"))
    session.record_receipt("op1", det())
    assert code_of(lambda: session.record_receipt("op1", unk(1))) == "receipt_conflict"


def test_s2br04_accepted_and_rejected_account_alike(session: WriterSession) -> None:
    session.reserve_recovery(req("op1", key(cause="A")))
    session.reserve_recovery(req("op2", key(cause="B")))
    session.record_receipt("op1", det(vec(1, 1, 3, 4), outcome="accepted"))
    session.record_receipt("op2", det(vec(1, 1, 3, 4), outcome="rejected"))
    assert (
        totals(session.view(), "causal", key(cause="A"))[0]
        == totals(session.view(), "causal", key(cause="B"))[0]
    )
    record = session.view().operation("op2")
    assert record is not None and record.accounting_state == "accounted"
    assert not any("clear" in name or "allow" in name for name in dir(record))


def test_s2br04_receipt_precedence(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req("op1"))
    bad = det(unit="eur")
    object.__setattr__(bad, "evidence_digest", "X")
    assert code_of(lambda: session.record_receipt("op1", bad)) == "invalid_value"
    value = snap_obj(ledger)
    value["writer_epoch"] = "9"
    install(ledger, value)
    assert code_of(lambda: session.record_receipt("nope", det(unit="eur"))) == "policy_conflict"
    assert code_of(lambda: session.record_receipt("nope", unk())) == "stale_writer"


def test_s2br04_zero_actual_is_explicit(session: WriterSession) -> None:
    session.reserve_recovery(req("op1"))
    assert session.record_receipt("op1", det(vec(0, 0, 0, 0))) == "receipt_settled"
    assert totals(session.view()) == ((0, 0, 0, 0), (0, 0, 0, 0))


# ---------------------------------------------------------------------------
# OS call recorder (monkeypatch of ordinary stdlib calls; no production hooks)


Hook = Callable[..., Any]


class Recorder:
    """Records and optionally faults stdlib calls; all patches end with the test."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.monkeypatch = monkeypatch
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any], Any]] = []
        self.staging_fds: set[int] = set()

    def wrap(self, owner: Any, name: str, hook: Hook | None = None) -> None:
        real = getattr(owner, name)
        label = f"{getattr(owner, '__name__', 'obj')}.{name}"

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if hook is not None:
                result = hook(real, *args, **kwargs)
            else:
                result = real(*args, **kwargs)
            self.calls.append((label, args, kwargs, result))
            if label == "os.open" and isinstance(args[0], str) and args[0].startswith(".staging-"):
                self.staging_fds.add(result)
            return result

        self.monkeypatch.setattr(owner, name, wrapper)

    def names(self, label: str) -> list[Any]:
        return [args[0] for name, args, _kwargs, _result in self.calls if name == label]

    def count(self, label: str) -> int:
        return sum(1 for name, *_ in self.calls if name == label)


@pytest.fixture
def rec(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    return Recorder(monkeypatch)


def raise_os(code: int, filename: str | None = None) -> OSError:
    return OSError(code, os.strerror(code), filename)


def fault_on_name(target: str, code: int, *, prefix: bool = False) -> Hook:
    def hook(real: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        name = args[0]
        if isinstance(name, str) and (name.startswith(target) if prefix else name == target):
            raise raise_os(code)
        return real(*args, **kwargs)

    return hook


def ino(path: str | Path) -> int:
    return os.stat(path, follow_symlinks=False).st_ino


def fd_ino(fd: int) -> int:
    return os.fstat(fd).st_ino


# ---------------------------------------------------------------------------
# S2BR05 read / init / side-effect freedom


def test_s2br05_read_never_writes(root: str) -> None:
    before = tree(root)
    assert code_of(lambda: read_ledger(root, MISSION)) == "not_initialized"
    assert tree(root) == before == []
    initialize_ledger(root, MISSION, policy())
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req())
    before = tree(root)
    view = read_ledger(root, MISSION)
    assert view.writer_epoch == 1 and view.operation("op1") is not None
    assert tree(root) == before
    write_snapshot(root, b"{corrupt\n")
    before = tree(root)
    assert code_of(lambda: read_ledger(root, MISSION)) == "invalid_record"
    assert tree(root) == before


def test_s2br05_import_and_values_have_no_filesystem_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins
    import sys
    import types

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("filesystem access")

    for name in (
        "open",
        "mkdir",
        "stat",
        "lstat",
        "listdir",
        "scandir",
        "unlink",
        "rename",
        "fsync",
    ):
        monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    probe = types.ModuleType("unrest_harness._s2br05_import_probe")
    probe.__dict__["__package__"] = "unrest_harness"
    monkeypatch.setitem(sys.modules, probe.__name__, probe)
    exec(compile(SOURCE, str(MODULE_PATH), "exec"), probe.__dict__)
    request = probe.__dict__["ReservationRequest"](
        operation_id="op1",
        causal_key=probe.__dict__["CausalKey"](
            mission_id="m",
            root_lineage_id="l",
            goal_branch_id="g",
            cause_code="c",
            effect_family="f",
        ),
        reservation=probe.__dict__["ResourceVector"](
            attempts=1, recoveries=1, wall_ms=1, cost_units=1
        ),
        cost_unit="u",
        request_fingerprint=digest(1),
    )
    assert request.operation_id == "op1"
    req(), unk(), det(), policy()


def test_s2br05_init_tree_and_idempotence(root: str) -> None:
    assert initialize_ledger(root, MISSION, policy()) == "created"
    listing = tree(root)
    assert [
        (path, stat.S_IFMT(mode), stat.S_IMODE(mode)) for path, mode, _size, _sha in listing
    ] == [
        (".unrest", stat.S_IFDIR, 0o700),
        (".unrest/continuation", stat.S_IFDIR, 0o700),
        (".unrest/continuation/recovery-reservations-v1", stat.S_IFDIR, 0o700),
        (".unrest/continuation/recovery-reservations-v1/m1", stat.S_IFDIR, 0o700),
        (".unrest/continuation/recovery-reservations-v1/m1/snapshot.json", stat.S_IFREG, 0o600),
        (".unrest/continuation/recovery-reservations-v1/m1/writer.lock", stat.S_IFREG, 0o600),
    ]
    assert (mdir(root) / "writer.lock").stat().st_size == 0
    assert snap(root) == GOLDEN_INITIAL
    assert initialize_ledger(root, MISSION, policy()) == "already_initialized"
    assert tree(root) == listing
    other = policy(causal=big(999))
    assert code_of(lambda: initialize_ledger(root, MISSION, other)) == "policy_conflict"
    renamed = ReservationPolicy(
        cost_unit=UNIT,
        authority_ref="auth-2",
        mission_ceiling=big(),
        root_lineage_ceiling=big(),
        causal_key_ceiling=big(),
    )
    assert code_of(lambda: initialize_ledger(root, MISSION, renamed)) == "policy_conflict"
    assert tree(root) == listing


@pytest.mark.parametrize("missing", ["snapshot.json", "writer.lock"])
def test_s2br05_existing_namespace_missing_file(ledger: str, missing: str, rec: Recorder) -> None:
    (mdir(ledger) / missing).unlink()
    before = tree(ledger)
    rec.wrap(fcntl, "flock")
    assert code_of(lambda: initialize_ledger(ledger, MISSION, policy())) == "not_initialized"
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "not_initialized"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "not_initialized"
    assert tree(ledger) == before
    if missing == "snapshot.json":
        assert rec.count("fcntl.flock") == 0


def test_s2br05_empty_snapshot_is_invalid_record_not_uninitialized(ledger: str) -> None:
    write_snapshot(ledger, b"")
    for call in (
        lambda: initialize_ledger(ledger, MISSION, policy()),
        lambda: read_ledger(ledger, MISSION),
        lambda: acquire_writer(ledger, MISSION),
    ):
        assert code_of(call) == "invalid_record"


def mission_ino_filter(root: str) -> Callable[[int], bool]:
    def is_mission(fd: int) -> bool:
        try:
            return fd_ino(fd) == ino(mdir(root))
        except OSError:
            return False

    return is_mission


@pytest.mark.parametrize("cut", ["lock_fsync", "staging_write"])
def test_s2br05_partial_init_is_terminal(
    root: str, cut: str, monkeypatch: pytest.MonkeyPatch, rec: Recorder
) -> None:
    if cut == "lock_fsync":

        def hook(real: Callable[..., Any], fd: int) -> Any:
            if is_reg(fd) and os.fstat(fd).st_size == 0 and fd not in rec.staging_fds:
                raise raise_os(errno.EIO)
            return real(fd)

        rec.wrap(os, "fsync", hook)
    else:
        rec.wrap(os, "open")

        def write_hook(real: Callable[..., Any], fd: int, data: Any) -> Any:
            if fd in rec.staging_fds:
                raise raise_os(errno.ENOSPC)
            return real(fd, data)

        rec.wrap(os, "write", write_hook)
    assert code_of(lambda: initialize_ledger(root, MISSION, policy())) == "io_unavailable"
    monkeypatch.undo()
    names = sorted(os.listdir(mdir(root)))
    assert names == ["writer.lock"]
    before = tree(root)
    for call in (
        lambda: initialize_ledger(root, MISSION, policy()),
        lambda: read_ledger(root, MISSION),
        lambda: acquire_writer(root, MISSION),
    ):
        assert code_of(call) == "not_initialized"
    assert tree(root) == before


def test_s2br05_lock_only_and_lock_plus_staging_partial(root: str, rec: Recorder) -> None:
    path = Path(root, *NAMESPACE, MISSION)
    path.mkdir(parents=True, mode=0o700)
    (path / "writer.lock").touch(mode=0o600)
    rec.wrap(os, "open")
    rec.wrap(fcntl, "flock")
    for staging in (False, True):
        if staging:
            (path / (".staging-" + digest(7))).write_bytes(b"x")
        before = tree(root)
        assert code_of(lambda: acquire_writer(root, MISSION)) == "not_initialized"
        assert code_of(lambda: initialize_ledger(root, MISSION, policy())) == "not_initialized"
        assert code_of(lambda: read_ledger(root, MISSION)) == "not_initialized"
        assert tree(root) == before
        assert "writer.lock" not in rec.names("os.open")
        assert rec.count("fcntl.flock") == 0


def test_s2br05_reentrant_probes_during_init(
    root: str, rec: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes: dict[str, str] = {}
    mission_path = mdir(root)

    def fsync_hook(real: Callable[..., Any], fd: int) -> Any:
        result = real(fd)
        if is_reg(fd) and fd not in rec.staging_fds and "lock" not in outcomes:
            outcomes["lock"] = "pending"
            outcomes["a"] = code_of(lambda: acquire_writer(root, MISSION))
            outcomes["c"] = code_of(lambda: initialize_ledger(root, MISSION, policy()))
            outcomes["lock"] = "done"
        elif (
            is_dir(fd)
            and mission_path.exists()
            and fd_ino(fd) == ino(mission_path)
            and "b" not in outcomes
        ):
            outcomes["b"] = code_of(lambda: acquire_writer(root, MISSION))
            outcomes["d"] = initialize_ledger(root, MISSION, policy())
        return result

    rec.wrap(os, "open")
    rec.wrap(os, "fsync", fsync_hook)
    assert initialize_ledger(root, MISSION, policy()) == "created"
    assert outcomes == {
        "lock": "done",
        "a": "not_initialized",
        "c": "not_initialized",
        "b": "writer_busy",
        "d": "already_initialized",
    }
    monkeypatch.undo()
    assert snap(root) == GOLDEN_INITIAL
    assert sorted(os.listdir(mission_path)) == ["snapshot.json", "writer.lock"]


def test_s2br05_listing_missing_required_name_wins(ledger: str, rec: Recorder) -> None:
    path = mdir(ledger)

    def scandir_hook(real: Callable[..., Any], *args: Any) -> Any:
        (path / "snapshot.json").unlink()
        (path / "extra").write_bytes(b"x")
        return real(*args)

    rec.wrap(os, "scandir", scandir_hook)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "not_initialized"
    assert sorted(os.listdir(path)) == ["extra", "writer.lock"]


# ---------------------------------------------------------------------------
# S2BR06 reader corpus (literal bytes; REAL reader)


def base_value() -> dict[str, Any]:
    return wire_snapshot(
        [
            wire_op(
                "a",
                state="accounted",
                observations=[wire_unknown(100), wire_det((1, 1, 5, 5), 200)],
            ),
            wire_op("b", causal=("L1", "G1", "C2", "F1"), fp=2),
        ]
    )


def reader_code(root: str, data: bytes) -> str:
    seed(root, base_value())
    assert read_ledger(root, MISSION).operation("a") is not None
    write_snapshot(root, data)
    before = tree(root)
    code = code_of(lambda: read_ledger(root, MISSION))
    assert tree(root) == before
    return code


def edited(edit: Callable[[dict[str, Any]], None]) -> bytes:
    value = base_value()
    edit(value)
    return canonical_json_bytes(value)


BASE = canonical_json_bytes(base_value())

RAW_CASES: dict[str, bytes] = {
    "empty": b"",
    "torn": BASE[: len(BASE) // 2],
    "missing_lf": BASE[:-1],
    "bom": b"\xef\xbb\xbf" + BASE,
    "whitespace": BASE.replace(b'{"accounting"', b'{ "accounting"', 1),
    "double_lf": BASE + b"\n",
    "duplicate_key": BASE.replace(
        b'{"accounting"', b'{"accounting":{"mode":"normal"},"accounting"', 1
    ),
    "unsorted_keys": BASE.replace(
        b'"kind":"recovery_reservations","mission_id":"m1"',
        b'"mission_id":"m1","kind":"recovery_reservations"',
        1,
    ),
    "schema_float": BASE.replace(b'"schema_version":1', b'"schema_version":1.0', 1),
    "null": BASE.replace(b'"writer_epoch":"1"', b'"writer_epoch":null', 1),
    "not_json": b"\x00\x01\n",
    "array_top": b"[]\n",
}


@pytest.mark.parametrize("case", sorted(RAW_CASES))
def test_s2br06_raw_bytes_refused(root: str, case: str) -> None:
    assert reader_code(root, RAW_CASES[case]) == "invalid_record"


def test_s2br06_oversize_refused_before_any_read(root: str, rec: Recorder) -> None:
    seed(root, base_value())
    write_snapshot(root, b" " * (SNAPSHOT_MAX_BYTES + 1))
    rec.wrap(os, "read")
    assert code_of(lambda: read_ledger(root, MISSION)) == "invalid_record"
    assert rec.count("os.read") == 0


def test_s2br06_reader_uses_os_read_only(root: str, rec: Recorder) -> None:
    seed(root, base_value())
    rec.wrap(os, "read")
    read_ledger(root, MISSION)
    assert rec.count("os.read") >= 1
    tree_calls = ast.walk(ast.parse(SOURCE))
    attributes = {node.attr for node in tree_calls if isinstance(node, ast.Attribute)}
    assert "mmap" not in attributes and "read_bytes" not in attributes
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"
        for node in ast.walk(ast.parse(SOURCE))
    )


def _set(path: list[Any], value: Any) -> Callable[[dict[str, Any]], None]:
    def edit(doc: dict[str, Any]) -> None:
        target: Any = doc
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value

    return edit


def _delete(path: list[Any]) -> Callable[[dict[str, Any]], None]:
    def edit(doc: dict[str, Any]) -> None:
        target: Any = doc
        for part in path[:-1]:
            target = target[part]
        del target[path[-1]]

    return edit


LEVELS: dict[str, tuple[list[Any], str]] = {
    "top": ([], "writer_epoch"),
    "policy": (["policy"], "cost_unit"),
    "ceiling": (["policy", "mission_ceiling"], "wall_ms"),
    "accounting": (["accounting"], "mode"),
    "operation": (["operations", 0], "request_fingerprint"),
    "causal": (["operations", 0, "causal_key"], "cause_code"),
    "reservation": (["operations", 0, "reservation"], "attempts"),
    "unknown_obs": (["operations", 0, "observations", 0], "evidence_digest"),
    "determinate_obs": (["operations", 0, "observations", 1], "outcome"),
    "actual": (["operations", 0, "observations", 1, "actual"], "cost_units"),
}


@pytest.mark.parametrize("level", sorted(LEVELS))
@pytest.mark.parametrize("change", ["extra", "missing"])
def test_s2br06_closed_key_sets(root: str, level: str, change: str) -> None:
    path, existing = LEVELS[level]
    edit = _set([*path, "zz_extra"], "x") if change == "extra" else _delete([*path, existing])
    assert reader_code(root, edited(edit)) == "invalid_record"


def _ops(edit: Callable[[list[dict[str, Any]]], None]) -> Callable[[dict[str, Any]], None]:
    def wrapper(doc: dict[str, Any]) -> None:
        edit(doc["operations"])

    return wrapper


FIELD_CASES: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "schema_2": (_set(["schema_version"], 2), "unsupported_schema"),
    "schema_0": (_set(["schema_version"], 0), "unsupported_schema"),
    "schema_true": (_set(["schema_version"], True), "invalid_record"),
    "schema_str": (_set(["schema_version"], "1"), "invalid_record"),
    "kind": (_set(["kind"], "continuations"), "invalid_record"),
    "epoch_number": (_set(["writer_epoch"], 1), "invalid_record"),
    "dec_number": (_set(["policy", "mission_ceiling", "wall_ms"], 5), "invalid_record"),
    "dec_leading_zero": (_set(["writer_epoch"], "01"), "invalid_record"),
    "dec_negative": (_set(["writer_epoch"], "-1"), "invalid_record"),
    "dec_overflow": (_set(["writer_epoch"], str(MAX + 1)), "invalid_record"),
    "dec_plus": (_set(["writer_epoch"], "+1"), "invalid_record"),
    "token": (_set(["policy", "cost_unit"], "bad unit"), "invalid_record"),
    "token_long": (
        _set(["operations", 1, "causal_key", "cause_code"], "c" * 129),
        "invalid_record",
    ),
    "digest_upper": (_set(["operations", 0, "request_fingerprint"], "A" * 64), "invalid_record"),
    "state_enum": (_set(["operations", 1, "accounting_state"], "settled"), "invalid_record"),
    "outcome_enum": (
        _set(["operations", 0, "observations", 1, "outcome"], "unknown"),
        "invalid_record",
    ),
    "obs_kind": (_set(["operations", 0, "observations", 0, "kind"], "maybe"), "invalid_record"),
    "mode_enum": (_set(["accounting"], {"mode": "paused"}), "invalid_record"),
    "mission_mismatch": (_set(["mission_id"], "m2"), "namespace_conflict"),
    "unsorted_ops": (_ops(lambda ops: ops.reverse()), "invalid_record"),
    "duplicate_op": (_ops(lambda ops: ops.append(dict(ops[1]))), "invalid_record"),
    "obs_order": (_ops(lambda ops: ops[0]["observations"].reverse()), "invalid_record"),
    "obs_three": (
        _ops(lambda ops: ops[0]["observations"].append(wire_unknown(9))),
        "invalid_record",
    ),
    "obs_two_unknown": (
        _ops(lambda ops: ops[1]["observations"].extend([wire_unknown(1), wire_unknown(2)])),
        "invalid_record",
    ),
    "reservation_shape": (
        _set(["operations", 1, "reservation", "attempts"], "2"),
        "invalid_record",
    ),
    "reservation_zero_wall": (
        _set(["operations", 1, "reservation", "wall_ms"], "0"),
        "invalid_record",
    ),
    "pending_with_determinate": (
        _set(["operations", 0, "accounting_state"], "pending"),
        "invalid_record",
    ),
    "accounted_without_determinate": (
        _set(["operations", 1, "accounting_state"], "accounted"),
        "invalid_record",
    ),
    "unaccounted_in_normal": (
        _set(["operations", 0, "accounting_state"], "unaccounted"),
        "invalid_record",
    ),
    "reserved_above_ceiling": (
        _set(["policy", "causal_key_ceiling", "wall_ms"], "9"),
        "invalid_record",
    ),
    "two_pending_same_causal": (
        _ops(lambda ops: ops.append(wire_op("c", causal=("L1", "G1", "C2", "F1"), fp=3))),
        "invalid_record",
    ),
    "w5_ns_field": (_set(["operations", 0, "wall_ns"], "1"), "invalid_record"),
    "previous_digest": (_set(["previous_digest"], digest(5)), "invalid_record"),
    "nested_envelope": (
        _set(
            ["operations", 0, "observations", 1, "actual", "wall_ms"],
            {"kind": "duration_ms", "value": "5"},
        ),
        "invalid_record",
    ),
}


@pytest.mark.parametrize("case", sorted(FIELD_CASES))
def test_s2br06_field_cases(root: str, case: str) -> None:
    edit, code = FIELD_CASES[case]
    assert reader_code(root, edited(edit)) == code


def test_s2br06_used_above_int64_refused(root: str) -> None:
    value = wire_snapshot(
        [
            wire_op(
                "a",
                ("L1", "G1", "C1", "F1"),
                state="accounted",
                observations=[wire_det((0, 0, MAX, 0))],
            ),
            wire_op(
                "b",
                ("L2", "G1", "C1", "F1"),
                state="accounted",
                observations=[wire_det((0, 0, 1, 0))],
            ),
        ]
    )
    assert reader_code(root, canonical_json_bytes(value)) == "invalid_record"


def blocked_value(trigger_actual: int) -> dict[str, Any]:
    return wire_snapshot(
        [
            wire_op("a", state="accounted", observations=[wire_det((1, 1, 1, MAX - 2))]),
            wire_op(
                "b",
                ("L1", "G1", "C2", "F1"),
                state="unaccounted",
                observations=[wire_det((1, 1, 1, trigger_actual))],
                fp=2,
            ),
        ],
        trigger="b",
        ceilings=(MAX, MAX, MAX),
    )


def test_s2br06_blocked_trigger_must_be_honest(root: str) -> None:
    seed(root, blocked_value(3))
    accounting = read_ledger(root, MISSION).accounting()
    assert isinstance(accounting, BlockedAccounting)
    assert reader_code(root, canonical_json_bytes(blocked_value(2))) == "invalid_record"
    missing = blocked_value(3)
    missing["accounting"]["trigger_operation_id"] = "zz"
    assert reader_code(root, canonical_json_bytes(missing)) == "invalid_record"
    accounted_trigger = blocked_value(3)
    accounted_trigger["accounting"]["trigger_operation_id"] = "a"
    assert reader_code(root, canonical_json_bytes(accounted_trigger)) == "invalid_record"


def test_s2br06_w5_legacy_bytes_refused(root: str) -> None:
    legacy = canonical_json_bytes(
        {"format": "continuations-v1", "previous_digest": digest(1), "records": [{"wall_ns": 5}]}
    )
    assert reader_code(root, legacy) == "invalid_record"


def test_s2br06_valid_overspend_reads(root: str) -> None:
    value = wire_snapshot(
        [wire_op("a", state="accounted", observations=[wire_det((1, 1, 5000, 5000))])],
        ceilings=(1000, 1000, 1000),
    )
    seed(root, value)
    view = read_ledger(root, MISSION)
    assert totals(view)[0] == (1, 1, 5000, 5000)
    accounting = view.accounting()
    assert isinstance(accounting, NormalAccounting)
    assert accounting.mission().remaining.wall_ms == 0


def depth_bytes(extra_depth: int) -> bytes:
    nested: Any = "1"
    for _ in range(extra_depth):
        nested = {"x": nested}
    value = base_value()
    value["operations"][0]["observations"][1]["actual"]["attempts"] = nested
    return (
        canonical_json_bytes(value)
        if extra_depth < 50
        else (
            BASE.replace(
                b'"attempts":"1","cost_units":"5"',
                b'"attempts":' + b"[" * extra_depth + b"]" * extra_depth + b',"cost_units":"5"',
                1,
            )
        )
    )


def test_s2br06_depth_bound(root: str, rec: Recorder) -> None:
    seed(root, base_value())
    rec.wrap(cr, "verify_canonical_json_bytes")
    read_ledger(root, MISSION)  # depth 6: snapshot/operations/op/observations/obs/actual
    assert rec.count("unrest_harness.continuation_reservations.verify_canonical_json_bytes") == 1
    for depth in (1, 600):
        write_snapshot(root, depth_bytes(depth))
        calls = len(rec.calls)
        assert code_of(lambda: read_ledger(root, MISSION)) == "invalid_record"
        assert len(rec.calls) == calls  # verify was never called
    tricky = base_value()
    tricky["zz"] = '[[[[[[[[{{{{\\"[[[['
    write_snapshot(root, canonical_json_bytes(tricky))
    calls = len(rec.calls)
    assert code_of(lambda: read_ledger(root, MISSION)) == "invalid_record"
    assert len(rec.calls) == calls + 1  # brackets inside strings are not depth


@pytest.mark.parametrize(
    "unit", [b'\\"', b'\\"['], ids=["escaped-quotes", "escaped-quotes-brackets"]
)
def test_s2br06_pathological_unterminated_string_near_cap(root: str, unit: bytes) -> None:
    """Linear pre-scan regression: an unterminated string near the cap is refused."""

    repeats = (SNAPSHOT_MAX_BYTES - 2) // len(unit)
    data = b'"' + unit * repeats + b"\n"
    assert len(data) <= SNAPSHOT_MAX_BYTES
    seed(root, base_value())
    write_snapshot(root, data)
    before = tree(root)
    assert code_of(lambda: read_ledger(root, MISSION)) == "invalid_record"
    assert code_of(lambda: acquire_writer(root, MISSION)) == "invalid_record"
    assert tree(root) == before


def test_s2br06_star_shaped_near_max_snapshot_reads(root: str) -> None:
    value = blocked_value(3)
    value["operations"][1]["observations"].insert(0, wire_unknown(1))
    value["writer_epoch"] = str(MAX)
    seed(root, value)
    assert read_ledger(root, MISSION).writer_epoch == MAX


# ---------------------------------------------------------------------------
# S2BR07 lock / session / fork guard / epoch


def assert_nonblocking_flock(rec: Recorder) -> None:
    def hook(real: Callable[..., Any], fd: int, operation: int) -> Any:
        assert operation & fcntl.LOCK_NB, "blocking flock"
        assert operation & fcntl.LOCK_UN == 0, "LOCK_UN"
        return real(fd, operation)

    rec.wrap(fcntl, "flock", hook)


def test_s2br07_real_separate_open_contention(ledger: str, rec: Recorder) -> None:
    """REAL: separate open-file descriptions in one process conflict under BSD flock."""

    assert_nonblocking_flock(rec)
    lock_ino = ino(mdir(ledger) / "writer.lock")
    first = acquire_writer(ledger, MISSION)
    before = snap(ledger)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "writer_busy"
    assert snap(ledger) == before
    first.reserve_recovery(req())
    first.close()
    second = acquire_writer(ledger, MISSION)
    assert second.view().writer_epoch == 2
    second.close()
    assert ino(mdir(ledger) / "writer.lock") == lock_ino


def test_s2br07_dup_ofd_retention(session: WriterSession, ledger: str) -> None:
    """REAL: closing a dup without LOCK_UN keeps the shared open-file-description lock."""

    copy = os.dup(session._lock)  # type: ignore[arg-type]
    os.close(copy)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "writer_busy"
    held = os.dup(session._lock)  # type: ignore[arg-type]
    session.close()
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "writer_busy"
    os.close(held)
    acquire_writer(ledger, MISSION).close()


def test_s2br07_negative_documentation_external_unlock(session: WriterSession, ledger: str) -> None:
    """REAL, outside the guarantee: an external LOCK_UN via a dup lets a second writer in.

    The first session notices only once the second has published its epoch.
    """

    copy = os.dup(session._lock)  # type: ignore[arg-type]
    fcntl.flock(copy, fcntl.LOCK_UN)
    os.close(copy)
    assert session.view().writer_epoch == 1  # no generic lost-lock detection
    second = acquire_writer(ledger, MISSION)
    assert code_of(lambda: session.reserve_recovery(req())) == "stale_writer"
    second.close()


def blocking_fsync(rec: Recorder, entered: threading.Event, release: threading.Event) -> None:
    state = {"armed": True}

    def hook(real: Callable[..., Any], fd: int) -> Any:
        if state["armed"] and fd in rec.staging_fds:
            state["armed"] = False
            entered.set()
            assert release.wait(10)
        return real(fd)

    rec.wrap(os, "open")
    rec.wrap(os, "fsync", hook)


def test_s2br07_same_session_threads(session: WriterSession, rec: Recorder) -> None:
    """REAL threads: concurrent entry into one session is refused without waiting."""

    entered, release = threading.Event(), threading.Event()
    blocking_fsync(rec, entered, release)
    results: list[object] = []
    worker = threading.Thread(target=lambda: results.append(session.reserve_recovery(req())))
    worker.start()
    assert entered.wait(10)
    codes = [
        code_of(lambda: session.reserve_recovery(req("op2", key(cause="C2")))),
        code_of(session.view),
    ]
    release.set()
    worker.join(10)
    assert codes == ["writer_busy", "writer_busy"]
    assert results == ["newly_reserved"]
    assert session.view().pending_operation_ids() == ("op1",)


def test_s2br07_close_waits_for_running_method(ledger: str, rec: Recorder) -> None:
    writer = acquire_writer(ledger, MISSION)
    fds = {fd for fd in (writer._directory, writer._lock) if fd is not None}
    entered, release = threading.Event(), threading.Event()
    blocking_fsync(rec, entered, release)
    closes: list[tuple[int, bool]] = []
    snapshot_path = mdir(ledger) / "snapshot.json"

    def close_hook(real: Callable[..., Any], fd: int) -> Any:
        # "after" = the running method had already published when fds were closed.
        closes.append((fd, fd in fds and b'"op1"' in snapshot_path.read_bytes()))
        return real(fd)

    rec.wrap(os, "close", close_hook)
    worker = threading.Thread(target=lambda: writer.reserve_recovery(req()))
    worker.start()
    assert entered.wait(10)
    closer = threading.Thread(target=writer.close)
    closer.start()
    closer.join(0.2)
    assert closer.is_alive()  # close blocks on the method, it does not close fds underneath
    assert not [fd for fd, _ in closes if fd in fds]
    release.set()
    worker.join(10)
    closer.join(10)
    closed = [(fd, after) for fd, after in closes if fd in fds]
    assert sorted(fd for fd, _ in closed) == sorted(fds)
    assert all(after for _, after in closed)
    count = len(closes)
    writer.close()
    assert len(closes) == count
    assert code_of(writer.view) == "custody_lost"


def test_s2br07_close_swallows_oserror_once(ledger: str, rec: Recorder) -> None:
    writer = acquire_writer(ledger, MISSION)
    fds = {fd for fd in (writer._directory, writer._lock) if fd is not None}
    attempts: list[int] = []

    def close_hook(real: Callable[..., Any], fd: int) -> Any:
        if fd in fds:
            attempts.append(fd)
            real(fd)
            raise raise_os(errno.EIO)
        return real(fd)

    rec.wrap(os, "close", close_hook)
    writer.close()
    writer.close()
    assert sorted(attempts) == sorted(fds)
    acquire_writer(ledger, MISSION).close()


def test_s2br07_method_after_close_in_other_thread(session: WriterSession, rec: Recorder) -> None:
    closer = threading.Thread(target=session.close)
    closer.start()
    closer.join(10)
    for name in ("open", "stat", "read", "fstat", "fsync"):
        rec.wrap(os, name)
    codes = [
        code_of(lambda: session.reserve_recovery(req())),
        code_of(lambda: session.record_receipt("op1", unk())),
        code_of(session.view),
    ]
    assert codes == ["custody_lost"] * 3
    assert rec.calls == []


def test_s2br07_poisoned_and_stale(session: WriterSession, ledger: str) -> None:
    session.reserve_recovery(req())
    value = snap_obj(ledger)
    value["operations"][0]["request_fingerprint"] = digest(42)  # same epoch, other bytes
    install(ledger, value)
    assert code_of(lambda: session.record_receipt("op1", unk())) == "stale_writer"
    assert code_of(session.view) == "custody_lost"
    session.close()
    with acquire_writer(ledger, MISSION) as writer:
        value = snap_obj(ledger)
        value["writer_epoch"] = str(int(value["writer_epoch"]) + 5)
        install(ledger, value)
        assert code_of(lambda: writer.reserve_recovery(req("x", key(cause="C9")))) == "stale_writer"


def test_s2br07_lock_inode_replacement(session: WriterSession, ledger: str) -> None:
    lock = mdir(ledger) / "writer.lock"
    os.rename(lock, mdir(ledger).parent / "old.lock")
    lock.touch(mode=0o600)
    assert code_of(lambda: session.reserve_recovery(req())) == "custody_lost"
    assert code_of(session.view) == "custody_lost"


def test_s2br07_epoch_and_overflow(root: str) -> None:
    initialize_ledger(root, MISSION, policy())
    for expected in (1, 2, 3):
        with acquire_writer(root, MISSION) as writer:
            assert writer.view().writer_epoch == expected
    value = snap_obj(root)
    value["writer_epoch"] = str(MAX)
    install(root, value)
    before = tree(root)
    assert code_of(lambda: acquire_writer(root, MISSION)) == "overflow"
    assert tree(root) == before
    acquire_free = acquire_writer  # lock was released after the refusal
    value["writer_epoch"] = "5"
    install(root, value)
    acquire_free(root, MISSION).close()


def test_s2br07_injected_fork_child_guard(
    session: WriterSession, ledger: str, rec: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INJECTED: a foreign PID models a fork child; real fork evidence stays OPEN."""

    held = os.dup(session._lock)  # type: ignore[arg-type]
    fds = {fd for fd in (session._directory, session._lock) if fd is not None}
    real_pid = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real_pid + 1)
    for name in ("open", "stat", "read", "fstat", "fsync", "rename", "scandir"):
        rec.wrap(os, name)
    rec.wrap(fcntl, "flock")
    codes = [
        code_of(lambda: session.reserve_recovery(req())),
        code_of(lambda: session.record_receipt("op1", unk())),
        code_of(session.view),
    ]
    assert codes == ["custody_lost"] * 3
    assert rec.calls == []
    rec.wrap(os, "close")
    session.close()
    assert sorted(rec.names("os.close")) == sorted(fds)
    assert rec.count("fcntl.flock") == 0
    monkeypatch.setattr(os, "getpid", lambda: real_pid)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "writer_busy"
    os.close(held)
    acquire_writer(ledger, MISSION).close()


def test_s2br07_owner_close_never_unlocks_explicitly(
    session: WriterSession, ledger: str, rec: Recorder
) -> None:
    held = os.dup(session._lock)  # type: ignore[arg-type]
    rec.wrap(fcntl, "flock")
    session.close()
    assert rec.count("fcntl.flock") == 0
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "writer_busy"
    os.close(held)


# ---------------------------------------------------------------------------
# S2BR08 namespace / path safety


COMPONENTS = [
    ".unrest",
    "continuation",
    "recovery-reservations-v1",
    MISSION,
    "writer.lock",
    "snapshot.json",
]


def component_path(root: str, component: str) -> Path:
    index = COMPONENTS.index(component)
    parts = (
        (*NAMESPACE, MISSION, component)[: index + 1]
        if index > 3
        else (*NAMESPACE, MISSION)[: index + 1]
    )
    return Path(root, *parts)


@pytest.mark.parametrize("component", COMPONENTS)
def test_s2br08_symlinked_component_refused(ledger: str, tmp_path: Path, component: str) -> None:
    target = component_path(ledger, component)
    sentinel = tmp_path / "sentinel"
    os.rename(target, sentinel)
    os.symlink(sentinel, target)
    sentinel_before = tree(tmp_path / "sentinel") if sentinel.is_dir() else sentinel.read_bytes()
    before = tree(ledger)
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: initialize_ledger(ledger, MISSION, policy())) == "unsafe_path"
    assert tree(ledger) == before
    assert (tree(sentinel) if sentinel.is_dir() else sentinel.read_bytes()) == sentinel_before


@pytest.mark.parametrize("name", ["writer.lock", "snapshot.json"])
def test_s2br08_hardlink_refused(ledger: str, tmp_path: Path, name: str) -> None:
    os.link(mdir(ledger) / name, tmp_path / "hard")
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "unsafe_path"


@pytest.mark.parametrize("name", ["writer.lock", "snapshot.json"])
def test_s2br08_fifo_refused_without_blocking(ledger: str, name: str) -> None:
    path = mdir(ledger) / name
    path.unlink()
    os.mkfifo(path, 0o600)
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "unsafe_path"


@pytest.mark.parametrize("component", COMPONENTS[1:])
def test_s2br08_group_writable_controlled_refused(ledger: str, component: str) -> None:
    path = component_path(ledger, component)
    os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) | 0o020)
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "unsafe_path"


def test_s2br08_unrest_permissions(ledger: str) -> None:
    path = Path(ledger, ".unrest")
    os.chmod(path, 0o770)
    read_ledger(ledger, MISSION)
    os.chmod(path, 0o702)
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsafe_path"
    assert code_of(lambda: initialize_ledger(ledger, "m2", policy())) == "unsafe_path"
    os.chmod(path, 0o700)


@pytest.mark.parametrize(
    "bad_root",
    [
        "relative",
        "",
        "/a/../b",
        "/a/",
        "/a/./b",
        "/a//b",
        "/a\x00b",
        "/a\udcff",
        "/" + "a" * 4096,
        Path("/tmp"),
        b"/tmp",
    ],
    ids=repr,
)
def test_s2br08_root_grammar(
    bad_root: object, rec: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("open", "stat", "mkdir"):
        rec.wrap(os, name)
    monkeypatch.setattr(os, "supports_dir_fd", set())
    for call in (
        lambda: initialize_ledger(bad_root, MISSION, policy()),  # type: ignore[arg-type]
        lambda: read_ledger(bad_root, MISSION),  # type: ignore[arg-type]
        lambda: acquire_writer(bad_root, MISSION),  # type: ignore[arg-type]
    ):
        with pytest.raises(ReservationLedgerError) as caught:
            call()
        assert caught.value.code == "invalid_value"
        assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert rec.calls == []


def test_s2br08_unsupported_platform_before_io(
    ledger: str, rec: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "supports_dir_fd", set())
    for name in ("open", "stat", "mkdir"):
        rec.wrap(os, name)
    assert code_of(lambda: initialize_ledger(ledger, MISSION, policy())) == "unsupported_platform"
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "unsupported_platform"
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "unsupported_platform"
    assert code_of(lambda: read_ledger(ledger, "bad/mission")) == "invalid_value"
    assert rec.calls == []


def test_s2br08_case_fold(root: str, tmp_path: Path) -> None:
    probe = tmp_path / "CaseProbe"
    probe.touch()
    insensitive = (tmp_path / "caseprobe").exists()
    initialize_ledger(root, "Am", policy())
    if insensitive:
        assert code_of(lambda: read_ledger(root, "am")) == "namespace_conflict"
        assert code_of(lambda: acquire_writer(root, "am")) == "namespace_conflict"
        assert code_of(lambda: initialize_ledger(root, "am", policy())) == "namespace_conflict"
    else:
        assert initialize_ledger(root, "am", policy()) == "created"
        assert read_ledger(root, "am").mission_id == "am"
    assert read_ledger(root, "Am").mission_id == "Am"


@pytest.mark.parametrize("extra", [".DS_Store", ".staging-" + "0" * 64, "notes"])
def test_s2br08_extra_entry_refuses_writer_not_reader(ledger: str, extra: str) -> None:
    (mdir(ledger) / extra).write_bytes(b"x")
    before = tree(ledger)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "namespace_conflict"
    assert read_ledger(ledger, MISSION).writer_epoch == 0
    assert tree(ledger) == before
    (mdir(ledger) / extra).unlink()
    acquire_writer(ledger, MISSION).close()


OS_FAULTS = [
    (errno.EACCES, "io_unavailable"),
    (errno.EIO, "io_unavailable"),
    (errno.ENOENT, "not_initialized"),
    (errno.ELOOP, "unsafe_path"),
    (errno.ENOTDIR, "unsafe_path"),
]


@pytest.mark.parametrize(("err", "code"), OS_FAULTS)
@pytest.mark.parametrize("call", ["os.open", "os.stat"])
def test_s2br08_injected_os_errors_read_acquire(
    ledger: str, rec: Recorder, err: int, code: str, call: str
) -> None:
    owner_name = call.split(".")[1]
    rec.wrap(os, owner_name, fault_on_name("snapshot.json", err))
    assert code_of(lambda: read_ledger(ledger, MISSION)) == code
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == code


@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO])
def test_s2br08_injected_read_and_listing_errors(ledger: str, rec: Recorder, err: int) -> None:
    def read_hook(real: Callable[..., Any], fd: int, size: int) -> Any:
        raise raise_os(err)

    rec.wrap(os, "read", read_hook)
    assert code_of(lambda: read_ledger(ledger, MISSION)) == "io_unavailable"
    rec.monkeypatch.undo()

    def scandir_hook(real: Callable[..., Any], *args: Any) -> Any:
        raise raise_os(err)

    rec.wrap(os, "scandir", scandir_hook)
    assert code_of(lambda: acquire_writer(ledger, MISSION)) == "io_unavailable"


@pytest.mark.parametrize(("err", "code"), OS_FAULTS)
def test_s2br08_injected_errors_poison_session(
    session: WriterSession, rec: Recorder, err: int, code: str
) -> None:
    rec.wrap(os, "open", fault_on_name("snapshot.json", err))
    assert code_of(lambda: session.reserve_recovery(req())) == code
    rec.monkeypatch.undo()
    assert code_of(lambda: session.reserve_recovery(req())) == "custody_lost"


def test_s2br08_lock_stat_error_poisons_session(session: WriterSession, rec: Recorder) -> None:
    rec.wrap(os, "stat", fault_on_name("writer.lock", errno.EIO))
    assert code_of(lambda: session.record_receipt("op1", unk())) == "io_unavailable"
    rec.monkeypatch.undo()
    assert code_of(session.view) == "custody_lost"


# ---------------------------------------------------------------------------
# S2BR09 publication fault cuts, simulated crash, reopen (INJECTED)


PUBLISH_OPS = ["epoch", "reserve", "settle", "blocked"]


def overflow_policy() -> ReservationPolicy:
    ceiling = vec(1000, 1000, 1000, MAX)
    return policy(mission=ceiling, lineage=ceiling, causal=ceiling)


def prepare(root: str, op: str) -> tuple[WriterSession | None, Callable[[], object]]:
    """Bring a fresh ledger to the state before ``op`` and return its action."""

    initialize_ledger(root, MISSION, overflow_policy() if op == "blocked" else policy())
    if op == "epoch":
        return None, lambda: acquire_writer(root, MISSION)
    writer = acquire_writer(root, MISSION)
    if op == "reserve":
        return writer, lambda: writer.reserve_recovery(req())
    if op == "settle":
        writer.reserve_recovery(req())
        return writer, lambda: writer.record_receipt("op1", det(vec(1, 1, 4, 4)))
    writer.reserve_recovery(req("op1", wall=10, cost=MAX - 2))
    writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2)))
    writer.reserve_recovery(req("op2", key(cause="C2"), cost=1, fp=2))
    return writer, lambda: writer.record_receipt("op2", det(vec(1, 1, 1, 3), index=201))


def clean_outcome(tmp_path: Path, op: str) -> bytes:
    clean = tmp_path / f"clean-{op}"
    clean.mkdir(mode=0o700)
    writer, action = prepare(str(clean), op)
    result = action()
    if isinstance(result, WriterSession):
        result.close()
    if writer is not None:
        writer.close()
    return snap(str(clean))


def staging_names(root: str) -> list[str]:
    return sorted(name for name in os.listdir(mdir(root)) if name.startswith(".staging-"))


def install_cut(rec: Recorder, root: str, cut: str, failure: BaseException) -> None:
    rec.wrap(os, "open", None)
    mission = mdir(root)

    def is_mission(fd: int) -> bool:
        return is_dir(fd) and fd_ino(fd) == ino(mission)

    if cut == "K1":
        rec.wrap(
            os,
            "open",
            lambda real, *a, **k: _raise_if(
                a[0].startswith(".staging-") if isinstance(a[0], str) else False,
                failure,
                real,
                *a,
                **k,
            ),
        )
    elif cut == "K2":
        rec.wrap(os, "fsync", lambda real, fd: _raise_if(fd in rec.staging_fds, failure, real, fd))
    elif cut == "K3":
        rec.wrap(os, "rename", lambda real, *a, **k: _raise_if(True, failure, real, *a, **k))
    elif cut == "K3_after":

        def after_rename(real: Callable[..., Any], *a: Any, **k: Any) -> Any:
            real(*a, **k)
            raise failure

        rec.wrap(os, "rename", after_rename)
    elif cut == "K4":
        rec.wrap(os, "fsync", lambda real, fd: _raise_if(is_mission(fd), failure, real, fd))
    elif cut == "K4_after":

        def after_fsync(real: Callable[..., Any], fd: int) -> Any:
            real(fd)
            if is_mission(fd):
                raise failure

        rec.wrap(os, "fsync", after_fsync)


def _raise_if(
    condition: bool, failure: BaseException, real: Callable[..., Any], *args: Any, **kwargs: Any
) -> Any:
    if condition:
        raise failure
    return real(*args, **kwargs)


FAULT_EXPECT = {
    "K1": ("io_unavailable", "old"),
    "K2": ("io_unavailable", "old"),
    "K3": ("publication_unknown", "old"),
    "K3_after": ("publication_unknown", "new"),
    "K4": ("publication_unknown", "new"),
}


@pytest.mark.parametrize("cut", sorted(FAULT_EXPECT))
@pytest.mark.parametrize("op", PUBLISH_OPS)
def test_s2br09_fault_cuts(tmp_path: Path, root: str, rec: Recorder, op: str, cut: str) -> None:
    new = clean_outcome(tmp_path, op)
    writer, action = prepare(root, op)
    old = snap(root)
    error = errno.EACCES if cut.startswith("K3") else errno.EIO
    install_cut(rec, root, cut, raise_os(error, "canary-path"))
    rec.wrap(os, "unlink")
    with pytest.raises(ReservationLedgerError) as caught:
        action()
    expected_code, disk = FAULT_EXPECT[cut]
    assert caught.value.code == expected_code
    rec.monkeypatch.undo()
    assert snap(root) == (old if disk == "old" else new)
    assert staging_names(root) == []
    if writer is not None:
        assert code_of(writer.view) == "custody_lost"  # poisoned
        writer.close()
    view = read_ledger(root, MISSION)
    with acquire_writer(root, MISSION) as reopened:
        if op == "reserve":
            assert reopened.reserve_recovery(req()) == (
                "already_reserved_reconcile_only" if disk == "new" else "newly_reserved"
            )
            assert totals(reopened.view())[1] == (1, 1, 10, 10)  # no second debit
        if op == "blocked":
            accounting = reopened.view().accounting()
            assert isinstance(accounting, BlockedAccounting) == (disk == "new")
        # Section 9.1.5: exact retry of the uncertain observation (old or new state).
        if op == "settle":
            retry = reopened.record_receipt("op1", det(vec(1, 1, 4, 4)))
            assert retry == ("receipt_duplicate" if disk == "new" else "receipt_settled")
            assert totals(reopened.view()) == ((1, 1, 4, 4), (0, 0, 0, 0))
        if op == "blocked":
            retry = reopened.record_receipt("op2", det(vec(1, 1, 1, 3), index=201))
            expected = (
                "receipt_duplicate" if disk == "new" else "receipt_recorded_accounting_blocked"
            )
            assert retry == expected
            assert isinstance(reopened.view().accounting(), BlockedAccounting)
    if op == "epoch":
        assert view.writer_epoch == (1 if disk == "new" else 0)


def test_s2br09_foreign_staging_inode_not_removed(root: str, rec: Recorder) -> None:
    writer, action = prepare(root, "reserve")
    impostor: dict[str, int] = {}

    def hook(real: Callable[..., Any], fd: int) -> Any:
        if fd in rec.staging_fds:
            name = staging_names(root)[0]
            os.unlink(mdir(root) / name)
            (mdir(root) / name).write_bytes(b"impostor")
            impostor["ino"] = ino(mdir(root) / name)
            raise raise_os(errno.EIO)
        return real(fd)

    rec.wrap(os, "open")
    rec.wrap(os, "fsync", hook)
    assert code_of(action) == "io_unavailable"
    rec.monkeypatch.undo()
    names = staging_names(root)
    assert len(names) == 1 and ino(mdir(root) / names[0]) == impostor["ino"]
    assert writer is not None
    writer.close()
    assert code_of(lambda: acquire_writer(root, MISSION)) == "namespace_conflict"


CRASH_EXPECT = {"K1": "old", "K2": "old", "K3": "old", "K3_after": "new", "K4_after": "new"}


@pytest.mark.parametrize("cut", sorted(CRASH_EXPECT))
@pytest.mark.parametrize("op", PUBLISH_OPS)
def test_s2br09_simulated_crash(
    tmp_path: Path, root: str, rec: Recorder, op: str, cut: str
) -> None:
    """INJECTED simulation of termination at a cut; not real process-crash evidence."""

    new = clean_outcome(tmp_path, op)
    writer, action = prepare(root, op)
    old = snap(root)
    install_cut(rec, root, cut, SimulatedCrash())
    rec.wrap(os, "unlink")
    with pytest.raises(SimulatedCrash):
        action()
    assert rec.count("os.unlink") == 0  # no cleanup on BaseException
    rec.monkeypatch.undo()
    if writer is not None:
        abandon(writer)
    assert snap(root) == (old if CRASH_EXPECT[cut] == "old" else new)
    orphan = cut in ("K2", "K3")
    assert bool(staging_names(root)) == orphan
    assert read_ledger(root, MISSION) is not None
    if orphan:
        assert code_of(lambda: acquire_writer(root, MISSION)) == "namespace_conflict"
    else:
        acquire_writer(root, MISSION).close()


@pytest.mark.parametrize("cut", ["K1", "K2", "K3"])
def test_s2br09_simulated_crash_in_initial_publication(root: str, rec: Recorder, cut: str) -> None:
    initialize_ledger(str(Path(root)), "warmup", policy())
    install_cut(rec, root, cut, SimulatedCrash())
    with pytest.raises(SimulatedCrash):
        initialize_ledger(root, MISSION, policy())
    rec.monkeypatch.undo()
    assert bool(staging_names(root)) == (cut != "K1")
    for call in (
        lambda: read_ledger(root, MISSION),
        lambda: acquire_writer(root, MISSION),
        lambda: initialize_ledger(root, MISSION, policy()),
    ):
        assert code_of(call) == "not_initialized"


# ---------------------------------------------------------------------------
# S2BR10 init durability ordering (INJECTED trace; call order, not power-loss proof)


def trace_init(root: str, rec: Recorder, mission: str = MISSION) -> list[tuple[str, str]]:
    names = {
        ino(root): "root",
    }
    events: list[tuple[str, str]] = []

    def label(fd: int) -> str:
        info = os.fstat(fd)
        if fd in rec.staging_fds:
            return "staging"
        if stat.S_ISREG(info.st_mode):
            return "lock"
        return names.get(info.st_ino, f"dir:{info.st_ino}")

    def mkdir_hook(real: Callable[..., Any], name: str, mode: int, *, dir_fd: int) -> Any:
        result = real(name, mode, dir_fd=dir_fd)
        names[os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_ino] = name
        events.append(("mkdir", name))
        return result

    def fsync_hook(real: Callable[..., Any], fd: int) -> Any:
        events.append(("fsync", label(fd)))
        return real(fd)

    def rename_hook(real: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        events.append(("rename", "snapshot.json"))
        return real(*args, **kwargs)

    for path in Path(root).rglob("*"):
        names[ino(path)] = path.name
    names[ino(root)] = "root"
    rec.wrap(os, "open")
    rec.wrap(os, "mkdir", mkdir_hook)
    rec.wrap(os, "fsync", fsync_hook)
    rec.wrap(os, "rename", rename_hook)
    assert initialize_ledger(root, mission, policy()) == "created"
    return events


TAIL = [("fsync", "lock"), ("fsync", "staging"), ("rename", "snapshot.json"), ("fsync", MISSION)]


def test_s2br10_fresh_root_syncs_every_created_parent(root: str, rec: Recorder) -> None:
    events = trace_init(root, rec)
    assert events == [
        ("mkdir", ".unrest"),
        ("mkdir", "continuation"),
        ("mkdir", "recovery-reservations-v1"),
        ("mkdir", MISSION),
        *TAIL,
        ("fsync", "recovery-reservations-v1"),
        ("fsync", "continuation"),
        ("fsync", ".unrest"),
        ("fsync", "root"),
    ]
    assert events.count(("fsync", MISSION)) == 1


def test_s2br10_preexisting_unrest_anchor(root: str, rec: Recorder) -> None:
    os.mkdir(Path(root, ".unrest"), 0o700)
    events = trace_init(root, rec)
    assert events == [
        ("mkdir", "continuation"),
        ("mkdir", "recovery-reservations-v1"),
        ("mkdir", MISSION),
        *TAIL,
        ("fsync", "recovery-reservations-v1"),
        ("fsync", "continuation"),
        ("fsync", ".unrest"),
    ]


def test_s2br10_all_ancestors_preexisting(ledger: str, rec: Recorder) -> None:
    events = trace_init(ledger, rec, "m2")
    assert events == [
        ("mkdir", "m2"),
        ("fsync", "lock"),
        ("fsync", "staging"),
        ("rename", "snapshot.json"),
        ("fsync", "m2"),
        ("fsync", "recovery-reservations-v1"),
    ]


INIT_FAULTS = {
    "mkdir_unrest": ("mkdir", ".unrest", "io_unavailable"),
    "mkdir_mission": ("mkdir", MISSION, "io_unavailable"),
    "open_lock": ("open", "writer.lock", "io_unavailable"),
    "open_staging": ("open", ".staging-", "io_unavailable"),
    "fsync_lock": ("fsync", "lock", "io_unavailable"),
    "fsync_staging": ("fsync", "staging", "io_unavailable"),
    "fsync_mission": ("fsync", MISSION, "publication_unknown"),
    "fsync_reservations": ("fsync", "recovery-reservations-v1", "publication_unknown"),
    "fsync_continuation": ("fsync", "continuation", "publication_unknown"),
    "fsync_unrest": ("fsync", ".unrest", "publication_unknown"),
    "fsync_root": ("fsync", "root", "publication_unknown"),
}


@pytest.mark.parametrize("err", [errno.EIO, errno.ENOSPC])
@pytest.mark.parametrize("case", sorted(INIT_FAULTS))
def test_s2br10_init_faults(root: str, rec: Recorder, case: str, err: int) -> None:
    call, target, code = INIT_FAULTS[case]
    names = {ino(root): "root"}

    def label(fd: int) -> str:
        info = os.fstat(fd)
        if fd in rec.staging_fds:
            return "staging"
        if stat.S_ISREG(info.st_mode):
            return "lock"
        return names.get(info.st_ino, "?")

    def mkdir_hook(real: Callable[..., Any], name: str, mode: int, *, dir_fd: int) -> Any:
        if call == "mkdir" and name == target:
            raise raise_os(err)
        result = real(name, mode, dir_fd=dir_fd)
        names[os.stat(name, dir_fd=dir_fd).st_ino] = name
        return result

    def open_hook(real: Callable[..., Any], name: Any, *args: Any, **kwargs: Any) -> Any:
        if call == "open" and isinstance(name, str) and name.startswith(target):
            raise raise_os(err)
        return real(name, *args, **kwargs)

    def fsync_hook(real: Callable[..., Any], fd: int) -> Any:
        if call == "fsync" and label(fd) == target:
            raise raise_os(err)
        return real(fd)

    rec.wrap(os, "open", open_hook)
    rec.wrap(os, "mkdir", mkdir_hook)
    rec.wrap(os, "fsync", fsync_hook)
    assert code_of(lambda: initialize_ledger(root, MISSION, policy())) == code


# ---------------------------------------------------------------------------
# S2BR11 restart retention


def all_totals(view: LedgerView, keys: list[CausalKey]) -> list[object]:
    accounting = view.accounting()
    assert isinstance(accounting, NormalAccounting)
    result: list[object] = [accounting.mission()]
    result.extend(accounting.root_lineage(k.root_lineage_id) for k in keys)
    result.extend(accounting.causal_key(k) for k in keys)
    return result


def test_s2br11_restart_retains_accounting(root: str) -> None:
    """Reservation persistence across sessions; not STATE-004 PASS."""

    max_policy = policy(mission=big(MAX), lineage=big(MAX), causal=big(MAX))
    initialize_ledger(root, MISSION, max_policy)
    keys = [
        key(lineage="L1", cause="C1"),
        key(lineage="L2", cause="C2"),
        key(lineage="L1", cause="C3"),
    ]
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("op1", keys[0], wall=1_000_000_001, cost=7, fp=1))
        writer.record_receipt("op1", det(vec(1, 1, 1_000_000_123, 9)))
        writer.reserve_recovery(req("op2", keys[1], wall=5, cost=5, fp=2))
        writer.record_receipt("op2", unk(5))
        remaining = MAX - 1_000_000_123 - 5
        writer.reserve_recovery(req("op3", keys[2], wall=remaining, cost=1, fp=3))
        before = all_totals(writer.view(), keys)
        pending = writer.view().pending_operation_ids()
        epoch = writer.view().writer_epoch
    with acquire_writer(root, MISSION) as writer:
        view = writer.view()
        assert view.writer_epoch == epoch + 1
        assert all_totals(view, keys) == before
        assert pending == view.pending_operation_ids() == ("op2", "op3")
        mission_totals = before[0]
        assert isinstance(mission_totals, cr.ScopeTotals)
        assert mission_totals.used.wall_ms == 1_000_000_123
        assert mission_totals.reserved.wall_ms == 5 + remaining
        assert mission_totals.remaining.wall_ms == 0
        assert (
            code_of(lambda: writer.reserve_recovery(req("op4", keys[1], fp=4))) == "causal_pending"
        )
        assert (
            writer.reserve_recovery(req("op3", keys[2], wall=remaining, cost=1, fp=3))
            == "already_reserved_reconcile_only"
        )
        assert all_totals(writer.view(), keys) == before
    assert all_totals(read_ledger(root, MISSION), keys) == before


def test_s2br11_restart_retains_blocked_marker(root: str) -> None:
    writer, action = prepare(root, "blocked")
    assert action() == "receipt_recorded_accounting_blocked"
    assert writer is not None
    before = writer.view().accounting()
    writer.close()
    for _ in range(2):
        with acquire_writer(root, MISSION) as reopened:
            assert reopened.view().accounting() == before
            assert (
                code_of(lambda: reopened.reserve_recovery(req("op9", key(cause="C9"))))
                == "accounting_blocked"
            )


# ---------------------------------------------------------------------------
# S2BR12 capacity


def tok(tag: str, index: int) -> str:
    head = f"{tag}{index:04d}"
    return head + "x" * (128 - len(head))


def test_s2br12_worst_case_size_golden() -> None:
    """White-box: private pure W(S) on the pinned fixture (contract section 12)."""

    ceiling = (MAX, MAX, MAX, MAX)
    pinned_policy = cr._PolicyData(tok("cu", 0), tok("au", 0), ceiling, ceiling, ceiling)
    operations = tuple(
        cr._Op(
            operation_id=tok("op", i),
            causal=(tok("ln", i), tok("gb", i), tok("cc", i), tok("ef", i)),
            fingerprint=digest(i),
            reservation=(1, 1, MAX, MAX),
            state="accounted",
            unknown=None,
            determinate=("accepted", digest(i), (0, 0, 0, 0)),
        )
        for i in range(256)
    )
    state = cr._State(tok("mi", 0), MAX, pinned_policy, None, operations)
    assert cr._worst_case_size(state) == 355_552
    assert cr._worst_case_size(state) < SNAPSHOT_MAX_BYTES
    cr._check_invariants(state)


def seeded_full(root: str, *, epoch: int = 1, accounted_cost: int | None = None) -> list[str]:
    """Seed 256 operations with maximal tokens (REAL reader / seeded state, not API-reached)."""

    operations = []
    ids = [tok("op", i) for i in range(256)]
    for i, op in enumerate(ids):
        causal = (tok("ln", i), tok("gb", i), tok("cc", i), tok("ef", i))
        if accounted_cost is not None and i == 0:
            operations.append(
                wire_op(
                    op,
                    causal,
                    (1, 1, 1, 1),
                    "accounted",
                    [wire_det((1, 1, 1, accounted_cost), i)],
                    fp=i,
                )
            )
        else:
            operations.append(wire_op(op, causal, (1, 1, 1, 1), fp=i))
    value = wire_snapshot(
        operations,
        mission=tok("mi", 0),
        epoch=epoch,
        ceilings=(MAX, MAX, MAX),
        unit=tok("cu", 0),
        authority=tok("au", 0),
    )
    seed(root, value, tok("mi", 0))
    return ids


def full_request(i: int, *, cost: int = 1) -> ReservationRequest:
    return ReservationRequest(
        operation_id=tok("op", i),
        causal_key=CausalKey(
            mission_id=tok("mi", 0),
            root_lineage_id=tok("ln", i),
            goal_branch_id=tok("gb", i),
            cause_code=tok("cc", i),
            effect_family=tok("ef", i),
        ),
        reservation=vec(1, 1, 1, cost),
        cost_unit=tok("cu", 0),
        request_fingerprint=digest(i),
    )


def test_s2br12_seeded_full_ledger_capacity(root: str) -> None:
    ids = seeded_full(root)
    mission = tok("mi", 0)
    assert len(read_ledger(root, mission).pending_operation_ids()) == 256
    with acquire_writer(root, mission) as writer:
        assert code_of(lambda: writer.reserve_recovery(full_request(256))) == "capacity_exhausted"
        assert writer.reserve_recovery(full_request(7)) == "already_reserved_reconcile_only"
        outcomes = []
        for index in (0, 255):
            assert writer.record_receipt(ids[index], unk(index)) == "receipt_recorded_unknown"
            maximal = Observation(
                outcome="rejected",
                evidence_digest=digest(index),
                actual=big(MAX),
                cost_unit=tok("cu", 0),
            )
            outcomes.append(writer.record_receipt(ids[index], maximal))
        assert outcomes == ["receipt_settled", "receipt_recorded_accounting_blocked"]
        assert len(snap(root, mission)) <= SNAPSHOT_MAX_BYTES


def test_s2br12_epoch_ceiling(root: str) -> None:
    seeded_full(root, epoch=MAX - 1)
    mission = tok("mi", 0)
    with acquire_writer(root, mission) as writer:
        assert writer.view().writer_epoch == MAX
    assert code_of(lambda: acquire_writer(root, mission)) == "overflow"


def test_s2br12_reachable_sizes_stay_within_worst_case(root: str) -> None:
    initialize_ledger(root, MISSION, overflow_policy())
    sizes: list[tuple[int, int]] = []

    def step(action: Callable[[], object]) -> None:
        before = cr._worst_case_size(cr._parse_bytes(snap(root), MISSION))
        action()
        sizes.append((len(snap(root)), before))

    writer = acquire_writer(root, MISSION)
    step(lambda: writer.reserve_recovery(req("a", key(cause="A"), cost=MAX - 2)))
    step(lambda: writer.reserve_recovery(req("b", key(cause="B"), cost=1)))
    step(lambda: writer.reserve_recovery(req("c", key(cause="C"), cost=1)))
    sizes.clear()
    step(lambda: writer.record_receipt("a", unk(1)))
    step(lambda: writer.record_receipt("a", det(vec(1, 1, 10, MAX - 2))))
    step(lambda: writer.record_receipt("b", unk(2)))
    step(lambda: writer.record_receipt("b", det(vec(MAX, MAX, MAX, MAX), outcome="rejected")))
    step(lambda: writer.record_receipt("c", unk(3)))
    step(lambda: writer.record_receipt("c", det(vec(MAX, MAX, MAX, MAX), outcome="rejected")))
    writer.close()
    step(lambda: acquire_writer(root, MISSION).close())
    assert isinstance(read_ledger(root, MISSION).accounting(), BlockedAccounting)
    assert all(size <= bound for size, bound in sizes)
    assert len({bound for _size, bound in sizes}) == 1  # no admission => W(S) is invariant


def test_s2br12_enospc_on_staging_write(session: WriterSession, ledger: str, rec: Recorder) -> None:
    before = snap(ledger)
    rec.wrap(os, "open")
    rec.wrap(
        os,
        "write",
        lambda real, fd, data: _raise_if(
            fd in rec.staging_fds, raise_os(errno.ENOSPC), real, fd, data
        ),
    )
    assert code_of(lambda: session.reserve_recovery(req())) == "io_unavailable"
    assert snap(ledger) == before
    assert staging_names(ledger) == []


# ---------------------------------------------------------------------------
# S2BR13 privacy

CANARY = "".join(["CAN", "ARY", "zq7"])
CANARY_DIGEST = "".join(["c0ffee"] * 10) + "c0ff"


def assert_private(error: BaseException, *canaries: str) -> None:
    assert isinstance(error, ReservationLedgerError)
    assert error.__cause__ is None
    assert error.__context__ is None
    surfaces = [
        str(error),
        repr(error),
        repr(error.args),
        repr(getattr(error, "__notes__", None)),
        repr(vars(error)),
        "".join(traceback.format_exception(error)),
    ]
    for canary in canaries:
        for surface in surfaces:
            assert canary not in surface
    assert vars(error) == {"code": error.code}


def caught(call: Callable[[], object]) -> ReservationLedgerError:
    with pytest.raises(ReservationLedgerError) as info:
        call()
    return info.value


def test_s2br13_logic_and_record_errors_private(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / CANARY
    root.mkdir(mode=0o700)
    base = str(root)
    errors = [
        caught(lambda: key(lineage=CANARY + "/x")),
        caught(lambda: read_ledger(base, CANARY)),
        caught(lambda: read_ledger(base + "/../" + CANARY, CANARY)),
        caught(
            lambda: ReservationRequest(
                operation_id=CANARY,
                causal_key=key(),
                reservation=vec(),
                cost_unit=UNIT,
                request_fingerprint=CANARY,
            )
        ),
    ]
    initialize_ledger(base, MISSION, policy())
    other = ReservationPolicy(
        cost_unit=UNIT,
        authority_ref=CANARY,
        mission_ceiling=big(),
        root_lineage_ceiling=big(),
        causal_key_ceiling=big(),
    )
    errors.append(caught(lambda: initialize_ledger(base, MISSION, other)))
    with acquire_writer(base, MISSION) as writer:
        writer.reserve_recovery(req(CANARY))
        errors.append(caught(lambda: writer.record_receipt(CANARY + "x", unk())))
        errors.append(
            caught(lambda: writer.reserve_recovery(req(CANARY, causal=key(cause=CANARY))))
        )
        errors.append(
            caught(lambda: writer.reserve_recovery(req(CANARY, causal=key(mission=CANARY))))
        )
        errors.append(caught(lambda: writer.record_receipt(CANARY, det(unit=CANARY))))
    value = snap_obj(base)
    value["zz_" + CANARY] = CANARY
    install(base, value)
    errors.append(caught(lambda: read_ledger(base, MISSION)))
    value = snap_obj(base)
    del value["zz_" + CANARY]
    value["mission_id"] = CANARY
    install(base, value)
    errors.append(caught(lambda: read_ledger(base, MISSION)))
    assert sorted({error.code for error in errors}) == sorted(
        {
            "invalid_value",
            "not_initialized",
            "policy_conflict",
            "unknown_operation",
            "intent_conflict",
            "namespace_conflict",
            "invalid_record",
        }
    )
    for error in errors:
        assert_private(error, CANARY, base)
    assert caplog.records == []


def test_s2br13_lone_surrogate_root() -> None:
    lone = chr(0xDCFF)
    surrogate_root = "/a" + lone
    error = caught(lambda: read_ledger(surrogate_root, MISSION))
    assert error.code == "invalid_value"
    assert_private(error, lone)


@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO])
def test_s2br13_os_errors_private(tmp_path: Path, rec: Recorder, err: int) -> None:
    root = tmp_path / "p"
    root.mkdir(mode=0o700)
    base = str(root)
    initialize_ledger(base, MISSION, policy())

    def failing(real: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if args and args[0] == "snapshot.json":
            raise OSError(err, CANARY, CANARY)
        return real(*args, **kwargs)

    errors = []
    rec.wrap(os, "open", failing)
    errors.append(caught(lambda: read_ledger(base, MISSION)))
    errors.append(caught(lambda: acquire_writer(base, MISSION)))
    rec.monkeypatch.undo()
    writer = acquire_writer(base, MISSION)
    rec.wrap(os, "open", failing)
    errors.append(caught(lambda: writer.reserve_recovery(req())))
    rec.monkeypatch.undo()
    writer.close()
    for cut in ("K3", "K4"):
        writer = acquire_writer(base, MISSION)
        install_cut(rec, base, cut, OSError(err, CANARY, CANARY))
        errors.append(caught(lambda: writer.reserve_recovery(req("op-" + cut, key(cause=cut)))))
        rec.monkeypatch.undo()
        writer.close()
    assert [error.code for error in errors] == ["io_unavailable"] * 3 + ["publication_unknown"] * 2
    for error in errors:
        assert_private(error, CANARY)


# ---------------------------------------------------------------------------
# S2BR14 architecture / platform

IMPORT_ALLOWLIST = {
    "__future__",
    "collections.abc",
    "dataclasses",
    "errno",
    "fcntl",
    "hashlib",
    "os",
    "re",
    "stat",
    "threading",
    "typing",
}
FOUNDATION_NAMES = {
    "canonical_json_bytes",
    "verify_canonical_json_bytes",
    "FoundationValidationError",
}


def test_s2br14_module_imports_and_forbidden_calls() -> None:
    tree_ = ast.parse(SOURCE)
    for node in ast.walk(tree_):
        if isinstance(node, ast.Import):
            assert {alias.name for alias in node.names} <= IMPORT_ALLOWLIST
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.module == "canonical_identity" and node.level == 1
                assert {alias.name for alias in node.names} <= FOUNDATION_NAMES
            else:
                assert node.module in IMPORT_ALLOWLIST
    names = {node.id for node in ast.walk(tree_) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree_) if isinstance(node, ast.Attribute)}
    for forbidden in (
        "time",
        "datetime",
        "random",
        "secrets",
        "uuid",
        "subprocess",
        "signal",
        "socket",
        "asyncio",
        "sys",
        "multiprocessing",
    ):
        assert forbidden not in names
    for forbidden_attr in ("LOCK_UN", "lockf", "platform", "fork", "kill", "system"):
        assert forbidden_attr not in attributes
    assert not any(
        isinstance(node, ast.Attribute)
        and node.attr == "fcntl"
        and isinstance(node.value, ast.Name)
        and node.value.id == "fcntl"
        for node in ast.walk(tree_)
    )
    flock_calls = [
        node
        for node in ast.walk(tree_)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "flock"
    ]
    assert flock_calls
    for call in flock_calls:
        flags = {node.attr for node in ast.walk(call.args[1]) if isinstance(node, ast.Attribute)}
        assert flags == {"LOCK_EX", "LOCK_NB"}


def test_s2br14_no_runtime_importers() -> None:
    package = MODULE_PATH.parent
    importers = [
        path.name
        for path in sorted(package.rglob("*.py"))
        if path != MODULE_PATH and "continuation_reservations" in path.read_text(encoding="utf-8")
    ]
    assert importers == []


def test_s2br14_test_module_spawns_nothing() -> None:
    tree_ = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree_):
        if isinstance(node, ast.Import):
            assert not {alias.name.split(".")[0] for alias in node.names} & {
                "subprocess",
                "multiprocessing",
                "pty",
                "signal",
            }
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in {
                "subprocess",
                "multiprocessing",
                "pty",
                "signal",
            }
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        ):
            assert node.attr not in {
                "fork",
                "forkpty",
                "kill",
                "killpg",
                "system",
                "popen",
                "posix_spawn",
                "posix_spawnp",
            }
            assert not node.attr.startswith(("exec", "spawn"))


def test_s2br14_component_map_and_index() -> None:
    repo = MODULE_PATH.parents[2]
    components = json.loads(
        (repo / "docs/architecture/component-map.json").read_text(encoding="utf-8")
    )["components"]
    entry = next(item for item in components if item["id"] == "COMP-CONTINUATION")
    assert "src/unrest_harness/continuation_reservations.py" in entry["paths"]
    assert "docs/architecture/continuation-reservations.md" in entry["specifications"]
    assert "tests/test_continuation_reservations.py" in entry["tests"]
    for field in ("paths", "specifications", "tests"):
        assert entry[field] == sorted(entry[field])
    index = (repo / "docs/architecture/index.md").read_text(encoding="utf-8")
    assert "(continuation-reservations.md)" in index
    doc = (repo / "docs/architecture/continuation-reservations.md").read_text(encoding="utf-8")
    for phrase in (
        "orphan staging",
        ".DS_Store",
        "not_initialized",
        "No cleanup, repair or reset API",
    ):
        assert phrase in doc


# ---------------------------------------------------------------------------
# S2BR15 settlement arithmetic


def test_s2br15_actual_replaces_reservation_exactly_once(
    session: WriterSession, ledger: str
) -> None:
    session.reserve_recovery(req("u1", key(cause="U")))
    session.reserve_recovery(req("o1", key(cause="O")))
    assert totals(session.view()) == ((0, 0, 0, 0), (2, 2, 20, 20))
    session.record_receipt("u1", det(vec(1, 1, 7, 7)))
    assert totals(session.view()) == ((1, 1, 7, 7), (1, 1, 10, 10))
    session.record_receipt("o1", det(vec(1, 1, 13, 13)))
    assert totals(session.view()) == ((2, 2, 20, 20), (0, 0, 0, 0))
    record = session.view().operation("o1")
    assert record is not None
    assert record.diagnostic_overrun() == vec(0, 0, 3, 3)
    under = session.view().operation("u1")
    assert under is not None and under.diagnostic_overrun() == vec(0, 0, 0, 0)
    before = snap_id(ledger)
    assert session.record_receipt("o1", det(vec(1, 1, 13, 13))) == "receipt_duplicate"
    assert snap_id(ledger) == before
    assert totals(session.view(), "causal", key(cause="O")) == ((1, 1, 13, 13), (0, 0, 0, 0))


def test_s2br15_mixed_overrun_and_underrun_apply_whole(session: WriterSession) -> None:
    session.reserve_recovery(req("m", wall=10, cost=10))
    session.record_receipt("m", det(vec(2, 0, 25, 4)))
    assert totals(session.view()) == ((2, 0, 25, 4), (0, 0, 0, 0))
    record = session.view().operation("m")
    assert record is not None and record.diagnostic_overrun() == vec(1, 0, 15, 0)
    pending = req("p", key(cause="P"))
    session.reserve_recovery(pending)
    session.record_receipt("p", unk())
    assert totals(session.view())[1] == (1, 1, 10, 10)
    record = session.view().operation("p")
    assert record is not None and record.diagnostic_overrun() is None


def test_s2br15_actual_above_ceiling_is_kept_and_denies(root: str) -> None:
    initialize_ledger(root, MISSION, policy(causal=vec(5, 5, 100, 100)))
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("a"))
        assert writer.record_receipt("a", det(vec(1, 1, 400, 1))) == "receipt_settled"
        assert totals(writer.view(), "causal", key()) == ((1, 1, 400, 1), (0, 0, 0, 0))
        assert code_of(lambda: writer.reserve_recovery(req("b", fp=2))) == "budget_exhausted"
    assert read_ledger(root, MISSION).operation("a") is not None  # U > C at R = 0 is valid
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("c", key(cause="C2"), fp=3))


# ---------------------------------------------------------------------------
# S2BR16 genuine aggregate overflow


def explicit_overflow_policy(cost: int = MAX) -> ReservationPolicy:
    ceiling = ResourceVector(attempts=100, recoveries=100, wall_ms=10_000, cost_units=cost)
    return ReservationPolicy(
        cost_unit=UNIT,
        authority_ref="auth-1",
        mission_ceiling=ceiling,
        root_lineage_ceiling=ceiling,
        causal_key_ceiling=ceiling,
    )


@pytest.mark.parametrize(
    "second_key", [key(), key(lineage="L2", cause="C2")], ids=["causal", "mission-only"]
)
def test_s2br16_overflow_blocks_atomically(root: str, second_key: CausalKey) -> None:
    initialize_ledger(root, MISSION, explicit_overflow_policy())
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("op1", key(), cost=MAX - 2))
        assert writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2))) == "receipt_settled"
        writer.reserve_recovery(req("op2", second_key, cost=1, fp=2))
        used_before, reserved_before = totals(writer.view())
        result = writer.record_receipt("op2", det(vec(1, 1, 5, 3), index=201))
        assert result == "receipt_recorded_accounting_blocked"
        accounting = writer.view().accounting()
        assert isinstance(accounting, BlockedAccounting)
        assert not hasattr(accounting, "remaining") and not hasattr(accounting, "used")
        assert accounting.accounting_complete is False
        assert accounting.reason == "actual_accumulation_overflow"
        assert accounting.trigger_operation_id == "op2"
        assert accounting.accounted_actual_partial == vec(*used_before)
        assert accounting.outstanding_reserved == vec(*reserved_before)
        assert accounting.unaccounted_operation_ids == ("op2",)
    stored = snap_obj(root)
    assert stored["accounting"] == {
        "mode": "blocked",
        "reason": "actual_accumulation_overflow",
        "trigger_operation_id": "op2",
    }
    op2 = stored["operations"][1]
    assert op2["accounting_state"] == "unaccounted"
    assert op2["observations"] == [wire_det((1, 1, 5, 3), 201)]
    assert stored["operations"][0]["observations"][0]["actual"]["cost_units"] == str(MAX - 2)


def test_s2br16_fixture_control(root: str) -> None:
    """Fixture control (not product): with cost ceiling MAX-2 the second reserve is refused."""

    initialize_ledger(root, MISSION, explicit_overflow_policy(MAX - 2))
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("op1", key(), cost=MAX - 2))
        writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2)))
        assert (
            code_of(lambda: writer.reserve_recovery(req("op2", key(cause="C2"), cost=1, fp=2)))
            == "budget_exhausted"
        )


def test_s2br16_invalid_receipts_never_block(root: str) -> None:
    initialize_ledger(root, MISSION, explicit_overflow_policy())
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("op1", key(), cost=MAX - 2))
        writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2)))
        writer.reserve_recovery(req("op2", key(cause="C2"), cost=1, fp=2))
        before = snap(root)
        assert (
            code_of(lambda: writer.record_receipt("op2", det(vec(1, 1, 5, 3), unit="eur")))
            == "policy_conflict"
        )
        assert (
            code_of(lambda: writer.record_receipt("nope", det(vec(1, 1, 5, 3))))
            == "unknown_operation"
        )
        assert (
            code_of(lambda: writer.record_receipt("op1", det(vec(1, 1, 5, 3))))
            == "receipt_conflict"
        )
        assert snap(root) == before
        assert isinstance(writer.view().accounting(), NormalAccounting)


# ---------------------------------------------------------------------------
# S2BR17 blocked ledger with other pending operations


def blocked_with_pending(root: str) -> WriterSession:
    initialize_ledger(root, MISSION, overflow_policy())
    writer = acquire_writer(root, MISSION)
    writer.reserve_recovery(req("op1", key(cause="C1"), cost=MAX - 2))
    writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2), index=1))
    writer.reserve_recovery(req("op2", key(cause="C2"), cost=1, fp=2))
    writer.reserve_recovery(req("op3", key(cause="C3"), cost=1, fp=3))
    assert (
        writer.record_receipt("op2", det(vec(1, 1, 1, 3), index=2))
        == "receipt_recorded_accounting_blocked"
    )
    return writer


def test_s2br17_blocked_mode_semantics(root: str) -> None:
    writer = blocked_with_pending(root)
    assert (
        code_of(lambda: writer.reserve_recovery(req("op4", key(lineage="L9", cause="C4"), fp=4)))
        == "accounting_blocked"
    )
    assert (
        code_of(lambda: writer.reserve_recovery(req("op5", key(cause="C3"), fp=5)))
        == "accounting_blocked"
    )
    assert (
        code_of(lambda: writer.reserve_recovery(req("op6", key(cause="C6"), cost=MAX, fp=6)))
        == "accounting_blocked"
    )
    assert (
        writer.reserve_recovery(req("op3", key(cause="C3"), cost=1, fp=3))
        == "already_reserved_reconcile_only"
    )
    assert (
        code_of(lambda: writer.reserve_recovery(req("op3", key(cause="C3"), cost=2, fp=3)))
        == "intent_conflict"
    )
    assert writer.record_receipt("op3", unk(30)) == "receipt_recorded_unknown"
    assert (
        writer.record_receipt("op3", det(vec(1, 1, 1, 1), index=31))
        == "receipt_recorded_unaccounted"
    )
    accounting = writer.view().accounting()
    assert isinstance(accounting, BlockedAccounting)
    assert accounting.unaccounted_operation_ids == ("op2", "op3")
    assert accounting.outstanding_reserved == vec(2, 2, 20, 2)
    assert accounting.accounted_actual_partial == vec(1, 1, 10, MAX - 2)
    before = snap_id(root)
    assert writer.record_receipt("op1", det(vec(1, 1, 10, MAX - 2), index=1)) == "receipt_duplicate"
    assert (
        code_of(lambda: writer.record_receipt("op1", det(vec(1, 1, 11, MAX - 2), index=1)))
        == "receipt_conflict"
    )
    assert (
        code_of(lambda: writer.record_receipt("op3", det(vec(1, 1, 2, 1), index=31)))
        == "receipt_conflict"
    )
    assert writer.record_receipt("op3", unk(30)) == "receipt_duplicate"
    assert snap_id(root) == before
    view_before = writer.view().accounting()
    writer.close()
    read_ledger(root, MISSION)
    assert snap_id(root) == before
    for _ in range(2):
        with acquire_writer(root, MISSION) as reopened:
            assert reopened.view().accounting() == view_before
            record = reopened.view().operation("op3")
            assert record is not None and record.unknown_observation is not None
            assert (
                record.determinate_observation is not None
                and record.accounting_state == "unaccounted"
            )
            assert (
                code_of(lambda: reopened.reserve_recovery(req("op7", key(cause="C7"), fp=7)))
                == "accounting_blocked"
            )


# ---------------------------------------------------------------------------
# S2BR18 blocked publication cuts and capacity


@pytest.mark.parametrize("cut", ["K3", "K3_after", "K4"])
def test_s2br18_trigger_publication_unknown(root: str, rec: Recorder, cut: str) -> None:
    writer, action = prepare(root, "blocked")
    assert writer is not None
    install_cut(rec, root, cut, raise_os(errno.EIO))
    assert code_of(action) == "publication_unknown"
    rec.monkeypatch.undo()
    writer.close()
    view = read_ledger(root, MISSION)
    record = view.operation("op2")
    assert record is not None
    if isinstance(view.accounting(), BlockedAccounting):
        assert (
            record.determinate_observation is not None and record.accounting_state == "unaccounted"
        )
        assert cut != "K3"
    else:
        assert record.determinate_observation is None and record.accounting_state == "pending"
        assert cut == "K3"
    # Section 9.1.5: an exact retry of the uncertain observation in a new session.
    with acquire_writer(root, MISSION) as reopened:
        retry = reopened.record_receipt("op2", det(vec(1, 1, 1, 3), index=201))
        expected = "receipt_recorded_accounting_blocked" if cut == "K3" else "receipt_duplicate"
        assert retry == expected
        accounting = reopened.view().accounting()
        assert isinstance(accounting, BlockedAccounting)
        assert accounting.trigger_operation_id == "op2"


def test_s2br18_seeded_full_ledger_late_evidence(root: str) -> None:
    """Seeded state (REAL reader), not API-reached: capacity for late evidence is reserved."""

    ids = seeded_full(root, accounted_cost=MAX - 2)
    mission = tok("mi", 0)
    unit = tok("cu", 0)
    with acquire_writer(root, mission) as writer:
        trigger = Observation(
            outcome="accepted", evidence_digest=digest(1), actual=vec(1, 1, 1, 3), cost_unit=unit
        )
        assert writer.record_receipt(ids[1], trigger) == "receipt_recorded_accounting_blocked"
        # Late determinate evidence for every remaining pending operation; unknown first
        # for three of them (unknown capacity is also covered by the W golden, S2BR12).
        with_unknown = {2, 128, 255}
        for i, op in enumerate(ids[2:], start=2):
            if i in with_unknown:
                assert writer.record_receipt(op, unk(i)) == "receipt_recorded_unknown"
            maximal = Observation(
                outcome="rejected", evidence_digest=digest(i), actual=big(MAX), cost_unit=unit
            )
            assert writer.record_receipt(op, maximal) == "receipt_recorded_unaccounted"
        assert writer.reserve_recovery(full_request(5)) == "already_reserved_reconcile_only"
        assert code_of(lambda: writer.reserve_recovery(full_request(300))) == "accounting_blocked"
        size = len(snap(root, mission))
        assert size <= SNAPSHOT_MAX_BYTES
    with acquire_writer(root, mission) as writer:
        accounting = writer.view().accounting()
        assert isinstance(accounting, BlockedAccounting)
        assert len(accounting.unaccounted_operation_ids) == 255
        for i in (2, 128, 255):
            record = writer.view().operation(ids[i])
            assert record is not None and record.unknown_observation is not None
            assert record.determinate_observation is not None
        again = Observation(
            outcome="rejected", evidence_digest=digest(200), actual=big(MAX), cost_unit=unit
        )
        assert writer.record_receipt(ids[200], again) == "receipt_duplicate"


def test_s2br18_small_lifecycle_through_api(root: str) -> None:
    initialize_ledger(root, MISSION, overflow_policy())
    with acquire_writer(root, MISSION) as writer:
        writer.reserve_recovery(req("a", key(cause="A"), cost=MAX - 5))
        writer.reserve_recovery(req("b", key(cause="B"), cost=2, fp=2))
        writer.reserve_recovery(req("c", key(cause="C"), cost=2, fp=3))
        writer.record_receipt("a", unk(1))
        assert writer.record_receipt("a", det(vec(1, 1, 3, MAX - 5), index=2)) == "receipt_settled"
        writer.record_receipt("b", unk(3))
        assert (
            writer.record_receipt("b", det(vec(1, 1, 3, 6), index=4))
            == "receipt_recorded_accounting_blocked"
        )
        assert writer.record_receipt("c", unk(5)) == "receipt_recorded_unknown"
    with acquire_writer(root, MISSION) as writer:
        assert (
            writer.record_receipt("c", det(vec(1, 1, 1, 1), index=6))
            == "receipt_recorded_unaccounted"
        )
        assert writer.record_receipt("b", unk(3)) == "receipt_duplicate"
        assert (
            code_of(lambda: writer.reserve_recovery(req("d", key(cause="D"), fp=7)))
            == "accounting_blocked"
        )
    view = read_ledger(root, MISSION)
    accounting = view.accounting()
    assert isinstance(accounting, BlockedAccounting)
    assert accounting.unaccounted_operation_ids == ("b", "c")
    assert accounting.accounted_actual_partial == vec(1, 1, 3, MAX - 5)
    assert accounting.outstanding_reserved == vec(2, 2, 20, 4)
    assert view.writer_epoch == 2


def test_s2br02_precedence_causal_pending_capacity_budget(root: str) -> None:
    """Seeded full ledger: causal_pending > capacity_exhausted > budget_exhausted."""

    operations = [
        wire_op(f"op{i:03d}", (f"L{i}", "G", "C", "F"), (1, 1, 1, 1), fp=i) for i in range(256)
    ]
    value = wire_snapshot(operations, ceilings=(256, MAX, MAX))
    seed(root, value)
    with acquire_writer(root, MISSION) as writer:
        same_causal = req("zz1", key(lineage="L7", branch="G", cause="C", family="F"), fp=900)
        assert code_of(lambda: writer.reserve_recovery(same_causal)) == "causal_pending"
        fresh = req("zz2", key(lineage="L999", branch="G", cause="C", family="F"), fp=901)
        assert code_of(lambda: writer.reserve_recovery(fresh)) == "capacity_exhausted"
    # Control: the same request is budget-exhausted on its own (255 ops, ceiling 255).
    control = wire_snapshot(operations[:255], mission="m2", ceilings=(255, MAX, MAX))
    seed(root, control, "m2")
    with acquire_writer(root, "m2") as writer:
        fresh = req(
            "zz2", key(lineage="L999", branch="G", cause="C", family="F", mission="m2"), fp=901
        )
        assert code_of(lambda: writer.reserve_recovery(fresh)) == "budget_exhausted"
