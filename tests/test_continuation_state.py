"""Focused contract tests for the inert continuation-state classifier (M1a-core).

Expected decision projections come from a literal row table written from the
accepted contract (``oracle`` below); production code is never used to
compute an expectation.  Every test is in-process: no subprocess, socket,
environment, clock or file effect is exercised by the module under test.
"""

from __future__ import annotations

import ast
import builtins
import dataclasses
import hashlib
import itertools
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any, Callable

import pytest

import unrest_harness.continuation_state as cs
from unrest_harness.continuation_state import (
    AGGREGATE_BASIS_CAP,
    LOCAL_TUPLE_CAP,
    MAX_FRONTIER_SEEN,
    STATE_CODES,
    Assessed,
    AttemptFact,
    BasisRef,
    Binding,
    ClaimFact,
    ClaimKey,
    ClearanceCell,
    CoherenceFact,
    ConflictFact,
    ContinuationStateError,
    Controls,
    Coverage,
    DeadlineProfile,
    Deferred,
    EvidenceId,
    FailureFact,
    Indeterminate,
    IntegrityFact,
    ObligationFact,
    PhaseEnvelope,
    PhaseObservation,
    PolicyHoldFact,
    ProgressClaim,
    ProgressFrontier,
    ProgressUpdate,
    ReadinessFact,
    RelatedHold,
    UnitFacts,
    UserDecisionFact,
    WaitFact,
    WaitSpec,
    advance_progress,
    assess_unit,
)
from unrest_harness.continuation_types import ClockReadingMs, ContinuationValueError, DurationMs

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/unrest_harness/continuation_state.py"
INT64_MAX = 2**63 - 1

EPOCH = "ep1"
HARD, PROGRESS, OBS = 10_000, 4_000, 500
WAIT_EST, WAIT_NEXT, WAIT_OVERALL = 1_000, 1_500, 5_000
B = Binding("mission-1", "cont-1", "origin-1", 1, "cand-1", "scope-1", "unit-1")


def clk(ms: int, epoch: str = EPOCH) -> ClockReadingMs:
    return ClockReadingMs(epoch, ms)


def R(kind: str, ref: str = "r") -> BasisRef:
    return BasisRef(kind, ref)


def code_of(call: Callable[[], object]) -> str:
    with pytest.raises(ContinuationStateError) as info:
        call()
    assert type(info.value) is ContinuationStateError
    assert info.value.__cause__ is None and info.value.__context__ is None
    return info.value.code


# --------------------------------------------------------------------------- spec builder

CELLSETS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "empty": (),
    "clean-applies": (("applies", "clear", "settled"),),
    "outcome-unresolved-applies": (("applies", "clear", "unresolved"),),
    "clearance-unresolved-applies": (("applies", "unresolved", "settled"),),
    "unknown-applicability-unclean": (("unknown", "unresolved", "unresolved"),),
    "unknown-applicability-clean": (("unknown", "clear", "settled"),),
    "applies-state-unknown": (("applies", "unknown", "unknown"),),
    "na-unresolved": (("not_applicable", "unresolved", "unresolved"),),
}
RELATED: dict[str, tuple[str, ...]] = {
    "empty": (),
    "independent": ("independent",),
    "dependent": ("dependent",),
    "unknown": ("unknown",),
    "dependent+unknown": ("dependent", "unknown"),
}
DEFAULT: dict[str, Any] = {
    "controls": "absent",
    "integrity": "passed",
    "coherence": "coherent",
    "policy": "none",
    "attempt": "none",
    "attempt_start": 0,
    "liveness": None,
    "cells": "empty",
    "settlement": "owner_completed",
    "clearance_cov": "complete",
    "user": "none_pending",
    "user_kind": "scope_decision_required",
    "wait": "none",
    "obligations": "none_declared",
    "eligibility": "admissible",
    "owner": "absent",
    "authority": "within_existing",
    "related": "empty",
    "related_cov": "complete",
    "failure": "none",
    "conflict": "none",
    "phase": "none",
    "claims": (),
    "now": 2_000,
    "age": 0,
    "acceptance": None,
}


def spec(**overrides: Any) -> dict[str, Any]:
    result = dict(DEFAULT)
    unknown = set(overrides) - set(DEFAULT)
    assert not unknown, unknown
    result.update(overrides)
    return result


def _controls(name: str) -> Controls:
    states = {
        "absent": ("absent", "absent", "absent"),
        "cancel": ("requested", "absent", "absent"),
        "pause": ("absent", "requested", "absent"),
        "drain": ("absent", "absent", "requested"),
        "cancel-unknown": ("unknown", "absent", "absent"),
        "all-unknown": ("unknown", "unknown", "unknown"),
    }[name]
    basis = () if name == "all-unknown" else (R("control_record", "ctl"),)
    return Controls(*states, basis)


def _status(cls: Any, status: str, kind: str, ref: str) -> Any:
    return cls(status, None if status == "unknown" else R(kind, ref))


def _attempt(s: dict[str, Any]) -> AttemptFact:
    status = s["attempt"]
    if status == "none":
        return AttemptFact("none", None, None, None, None, R("run_record", "att"))
    if status == "unknown":
        return AttemptFact("unknown", None, None, None, None, None)
    liveness = s["liveness"]
    return AttemptFact(
        "admitted",
        "att-1",
        clk(s["attempt_start"]),
        None if liveness is None else clk(liveness),
        None if liveness is None else R("attempt_observation", "live"),
        R("attempt_observation", "att"),
    )


def _cells(s: dict[str, Any]) -> tuple[ClearanceCell, ...]:
    triples = CELLSETS[s["cells"]] if isinstance(s["cells"], str) else s["cells"]
    cells = []
    for index, (app, replay, outcome) in enumerate(triples):
        known = replay != "unknown" or outcome != "unknown"
        cells.append(
            ClearanceCell(
                f"pred-{index}",
                f"res-{index}",
                app,
                None if app == "unknown" else R("dependency_assertion", f"app-{index}"),
                s["settlement"],
                replay,
                outcome,
                R("stop_record", f"st-{index}") if known else None,
            )
        )
    return tuple(cells)


def _wait(s: dict[str, Any]) -> WaitFact:
    if s["wait"] == "none":
        return WaitFact("none", None, R("external_predicate", "absent"))
    if s["wait"] == "unknown":
        return WaitFact("unknown", None, None)
    return WaitFact("waiting", wait_spec(), None)


def wait_spec(
    established: int = WAIT_EST, next_check: int = WAIT_NEXT, overall: int = WAIT_OVERALL
) -> WaitSpec:
    return WaitSpec(
        "pred-1", R("external_predicate", "wait"), clk(established), clk(next_check),
        DurationMs(overall),
    )


def _obligations(status: str) -> ObligationFact:
    if status == "pending":
        return ObligationFact("pending", (R("obligation_record", "ob-1"),), R("obligation_record", "decl"))
    if status == "all_satisfied":
        return ObligationFact(
            "all_satisfied", (R("validator_verdict", "v-1"),), R("obligation_record", "decl")
        )
    if status == "none_declared":
        return ObligationFact("none_declared", (), R("obligation_record", "decl"))
    return ObligationFact("unknown", (), None)


def _readiness(s: dict[str, Any]) -> ReadinessFact:
    elig = s["eligibility"]
    return ReadinessFact(
        elig,
        "planned_task" if elig == "admissible" else None,
        None if elig == "unknown" else R("readiness_predicate", "el"),
        s["owner"],
        None if s["owner"] == "unknown" else R("run_record", "own"),
        s["authority"],
        None if s["authority"] == "unknown" else R("authority_record", "auth"),
    )


def _holds(s: dict[str, Any]) -> tuple[RelatedHold, ...]:
    return tuple(
        RelatedHold(
            f"hold-{index}",
            relation,
            None if relation == "unknown" else R("dependency_assertion", f"rel-{index}"),
        )
        for index, relation in enumerate(RELATED[s["related"]])
    )


PHASE_REF = R("phase_observation", "ph")


def _phase(s: dict[str, Any]) -> tuple[PhaseObservation | None, PhaseEnvelope | None]:
    variant, now = s["phase"], s["now"]
    if variant == "none":
        return None, None
    observed = PhaseObservation("ph", clk(now - 100), PHASE_REF)
    envelope = PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(HARD), DurationMs(2_000))
    if variant == "f1":
        return observed, None
    if variant == "f2":
        return PhaseObservation("other", clk(now - 100), PHASE_REF), envelope
    if variant == "f3":
        return PhaseObservation("ph", clk(now - 100), R("phase_observation", "ph-x")), envelope
    if variant == "f4":
        return observed, PhaseEnvelope("ph", PHASE_REF, clk(100), DurationMs(HARD), DurationMs(2_000))
    if variant == "f5":
        return observed, PhaseEnvelope(
            "ph", PHASE_REF, clk(now - 50), DurationMs(HARD), DurationMs(2_000)
        )
    if variant == "f6":
        return observed, PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(3_000), DurationMs(2_000))
    if variant == "f7":
        return PhaseObservation("ph", clk(now - 2_000), PHASE_REF), envelope
    assert variant == "active"
    return observed, envelope


def make_facts(s: dict[str, Any]) -> UnitFacts:
    phase, _ = _phase(s)
    return UnitFacts(
        binding=B,
        observed_at=clk(s["now"] - s["age"]),
        controls=_controls(s["controls"]),
        integrity=_status(IntegrityFact, s["integrity"], "integrity_check", "int"),
        coherence=_status(CoherenceFact, s["coherence"], "run_record", "coh"),
        policy_hold=_status(PolicyHoldFact, s["policy"], "policy_record", "pol"),
        attempt=_attempt(s),
        clearance=_cells(s),
        clearance_coverage=_status(Coverage, s["clearance_cov"], "dependency_assertion", "ccov"),
        user_decision=UserDecisionFact(
            s["user"],
            s["user_kind"] if s["user"] == "pending" else None,
            None if s["user"] == "unknown" else R("user_decision_record", "ud"),
        ),
        wait=_wait(s),
        obligations=_obligations(s["obligations"]),
        readiness=_readiness(s),
        related_holds=_holds(s),
        related_holds_coverage=_status(Coverage, s["related_cov"], "dependency_assertion", "rcov"),
        failure=_status(FailureFact, s["failure"], "failure_record", "fail"),
        constraint_conflict=_status(ConflictFact, s["conflict"], "constraint_analysis", "con"),
        phase=phase,
        claims=tuple(ClaimFact(code, R("agent_claim", f"cl-{code}")) for code in s["claims"]),
    )


ACCEPT_KEY = ClaimKey("assertion_satisfied", "crit-1", 1)


def accept_claim(sequence: int, at: int, key: ClaimKey = ACCEPT_KEY, ev: str = "") -> ProgressClaim:
    kind = key.kind
    kinds = {
        "assertion_satisfied": "validator_verdict",
        "gate_satisfied": "gate_verdict",
        "blocker_cleared": "readiness_predicate",
        "diagnostic_finding": "validator_verdict",
    }
    return ProgressClaim(
        B, EvidenceId(ev or f"ev-{sequence}"), sequence, clk(at), kind, key, None,
        R(kinds[kind], f"v-{sequence}"),
    )


def empty_frontier(started: int = 0) -> ProgressFrontier:
    return ProgressFrontier(B, clk(started), 0, clk(started), None, (), (), ())


def make_frontier(s: dict[str, Any]) -> ProgressFrontier:
    if s["acceptance"] is None:
        return empty_frontier()
    at = s["acceptance"]
    claim = accept_claim(1, at)
    return ProgressFrontier(B, clk(0), 1, clk(at), clk(at), (ACCEPT_KEY,), (), (claim,))


def make_profile(s: dict[str, Any]) -> DeadlineProfile:
    _, envelope = _phase(s)
    return DeadlineProfile(
        B, "prof", 1, DurationMs(PROGRESS), DurationMs(HARD), DurationMs(OBS), envelope
    )


def run(s: dict[str, Any]) -> Assessed | Indeterminate | Deferred:
    if s["phase"] == "f4" and s["attempt"] == "admitted":
        s = dict(s, attempt_start=200)
    return assess_unit(make_facts(s), make_frontier(s), make_profile(s), clk(s["now"]))


def projection(result: object) -> tuple[Any, ...]:
    if type(result) is Assessed:
        return (result.tag, result.state, result.primary_reason, result.hint)
    if type(result) is Indeterminate:
        return (result.tag, result.code, result.hint)
    assert type(result) is Deferred
    return (result.tag, result.feature, result.reason, result.hint)


# --------------------------------------------------------------------------- literal oracle
# Rows of contract V3 §5.2 in order; timer applicability of §5.4.  Written from
# the contract text over the abstract spec, never from production code.


def A(state: str, primary: str, hint: str) -> tuple[str, ...]:
    return ("assessed", state, primary, hint)


def I(code: str) -> tuple[str, ...]:  # noqa: E743
    return ("indeterminate", code, "facts_required")


def D(feature: str, reason: str) -> tuple[str, ...]:
    return ("deferred", feature, reason, "evaluation_deferred")


def cell_flags(cells: tuple[tuple[str, str, str], ...], attempt: str) -> dict[str, bool]:
    unclean = [c for c in cells if not (c[1] == "clear" and c[2] == "settled")]
    applies = [c for c in cells if c[0] == "applies"]
    return {
        "k6": attempt == "none" and any(c[2] == "unresolved" for c in applies),
        "k7": attempt == "none" and any(c[1] == "unresolved" for c in applies),
        "i6": attempt == "unknown" and any(c[0] in ("applies", "unknown") for c in unclean),
        "i7": attempt == "none" and any(c[0] == "unknown" for c in unclean),
        "i8": attempt == "none" and any("unknown" in (c[1], c[2]) for c in applies),
    }


def oracle(s: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    now = s["now"]
    acceptance = s["acceptance"] or 0
    cells = CELLSETS[s["cells"]] if isinstance(s["cells"], str) else s["cells"]
    c = cell_flags(cells, s["attempt"])
    relations = RELATED[s["related"]]
    dependent, relation_unknown = "dependent" in relations, "unknown" in relations
    k_context = (
        s["user"] == "none_pending"
        and s["wait"] == "none"
        and s["attempt"] == "none"
        and s["obligations"] in ("all_satisfied", "none_declared")
        and s["eligibility"] == "admissible"
    )
    hard = now >= HARD
    wait_expired = s["wait"] == "waiting" and now - WAIT_EST >= WAIT_OVERALL
    progress_expired = now - acceptance >= PROGRESS
    # Active envelope starts at 0 with max_duration == HARD (see _phase).
    phase_active = s["phase"] == "active" and now < HARD
    due = now >= WAIT_NEXT

    def candidate(row: str) -> tuple[str, ...]:
        state, primary, hint = {
            "C1": (
                "waiting_external", "external_dependency",
                "external_observation_due" if due else "observe",
            ),
            "C2": ("working", "attempt_admitted", "observe"),
            "C3": ("verifying", "verification_pending", "verification_required"),
            "C4": ("ready", "transition_admissible", "consider_existing_transition"),
        }[row]
        expiries = {
            "C1": ((hard, "hard_deadline_elapsed"), (wait_expired, "wait_deadline_elapsed")),
            "C2": (
                (hard, "hard_deadline_elapsed"),
                (progress_expired and not phase_active, "progress_deadline_elapsed"),
            ),
            "C3": ((hard, "hard_deadline_elapsed"), (progress_expired, "progress_deadline_elapsed")),
            "C4": ((hard, "hard_deadline_elapsed"), (progress_expired, "progress_deadline_elapsed")),
        }[row]
        for flag, code in expiries:
            if flag:
                return A("stalled", code, "observe")
        return A(state, primary, hint)

    def hard_only(domain: bool, code: str) -> tuple[str, ...]:
        if domain and hard:
            return A("stalled", "hard_deadline_elapsed", "observe")
        return I(code)

    ctrl = s["controls"]
    rows: list[tuple[str, bool, Callable[[], tuple[str, ...]]]] = [
        ("P-k1", ctrl == "cancel", lambda: A("paused_policy", "cancel_requested", "none")),
        ("P-k2", ctrl == "pause", lambda: A("paused_policy", "pause_requested", "none")),
        ("P-k3", ctrl == "drain", lambda: A("paused_policy", "drain_requested", "none")),
        ("P-k4", s["integrity"] == "refused",
         lambda: A("paused_policy", "integrity_refused", "review_integrity")),
        ("P-k5", s["coherence"] == "inconsistent",
         lambda: A("paused_policy", "inconsistent_observations", "review_integrity")),
        ("P-k6", c["k6"], lambda: A("paused_policy", "outcome_unresolved", "review_unresolved_outcome")),
        ("P-k7", c["k7"], lambda: A("paused_policy", "clearance_unresolved", "review_clearance")),
        ("P-k8", s["policy"] == "held", lambda: A("paused_policy", "policy_hold", "review_policy")),
        ("G-g1", k_context and dependent, lambda: A("paused_policy", "dependency_on_held_unit", "none")),
        ("G-g2", k_context and s["authority"] == "denied",
         lambda: A("paused_policy", "authority_denied", "none")),
        ("G-g3", k_context and s["owner"] == "present",
         lambda: A("paused_policy", "other_owner_present", "none")),
        ("I1", s["age"] >= OBS, lambda: I("stale_observation")),
        ("I2", ctrl in ("cancel-unknown", "all-unknown"), lambda: I("control_unknown")),
        ("I3", s["integrity"] == "unknown", lambda: I("integrity_unknown")),
        ("I4", s["coherence"] == "unknown", lambda: I("coherence_unknown")),
        ("I5", s["policy"] == "unknown", lambda: I("policy_unknown")),
        ("I6", c["i6"], lambda: I("attempt_unknown")),
        ("I7", c["i7"], lambda: I("applicability_unknown")),
        ("I8", c["i8"], lambda: I("clearance_unknown")),
        ("I9", s["user"] == "unknown", lambda: I("user_decision_unknown")),
        ("N1", s["user"] == "pending",
         lambda: A("needs_user", s["user_kind"], "user_decision_required")),
        ("C1", s["wait"] == "waiting", lambda: candidate("C1")),
        ("C1u", s["wait"] == "unknown",
         lambda: hard_only(
             s["attempt"] == "admitted" or s["obligations"] == "pending", "wait_unknown"
         )),
        ("C2", s["attempt"] == "admitted", lambda: candidate("C2")),
        ("C2u", s["attempt"] == "unknown",
         lambda: hard_only(s["obligations"] == "pending", "attempt_unknown")),
        ("C3", s["obligations"] == "pending", lambda: candidate("C3")),
        ("C3u", s["obligations"] == "unknown", lambda: I("obligations_unknown")),
        ("X1", s["conflict"] == "asserted",
         lambda: D("impossibility_evaluation", "constraint_conflict_requires_dossier")),
        ("X2", s["conflict"] == "unknown", lambda: I("conflict_unknown")),
        ("X3", s["failure"] == "recoverable_classified",
         lambda: D("recovery_evaluation", "recovery_not_in_slice")),
        ("X4", s["failure"] == "unknown", lambda: I("failure_unknown")),
        ("R1", s["eligibility"] == "unknown", lambda: I("readiness_unknown")),
        ("R2c", s["eligibility"] == "not_admissible" and s["obligations"] == "all_satisfied",
         lambda: D("completion_evaluation", "terminal_predicate_not_in_slice")),
        ("R2n", s["eligibility"] == "not_admissible", lambda: I("no_classifiable_condition")),
        ("R3a", s["authority"] == "unknown", lambda: I("authority_unknown")),
        ("R3b", s["owner"] == "unknown", lambda: I("owner_unknown")),
        ("R3c", s["related_cov"] == "unknown", lambda: I("related_holds_coverage_unknown")),
        ("R3d", relation_unknown, lambda: I("independence_unknown")),
        ("R3e", s["clearance_cov"] == "unknown", lambda: I("clearance_coverage_unknown")),
        ("C4", True, lambda: candidate("C4")),
    ]
    for row_id, condition, result in rows:
        if condition:
            return row_id, result()
    raise AssertionError("unreachable: C4 is unconditional")


# --------------------------------------------------------------------------- generators (§7)


def gen_p() -> list[dict[str, Any]]:
    out = []
    for ctrl, integ, coh, pol, att, cells, fresh in itertools.product(
        ("absent", "cancel", "pause", "drain", "cancel-unknown"),
        ("passed", "refused", "unknown"),
        ("coherent", "inconsistent", "unknown"),
        ("none", "held", "unknown"),
        ("none", "admitted", "unknown"),
        tuple(CELLSETS),
        (0, 600, OBS),
    ):
        out.append(spec(
            controls=ctrl, integrity=integ, coherence=coh, policy=pol, attempt=att, cells=cells,
            age=fresh, eligibility="not_admissible",
        ))
    return out


def gen_c() -> list[dict[str, Any]]:
    out = []
    for user, wait, att, obl, con, fail, elig in itertools.product(
        ("none_pending", "pending", "unknown"),
        ("none", "waiting", "unknown"),
        ("none", "admitted", "unknown"),
        ("pending", "all_satisfied", "none_declared", "unknown"),
        ("none", "asserted", "unknown"),
        ("none", "recoverable_classified", "unknown"),
        ("admissible", "not_admissible", "unknown"),
    ):
        out.append(spec(
            user=user, wait=wait, attempt=att, obligations=obl, conflict=con, failure=fail,
            eligibility=elig,
        ))
    return out


def gen_r() -> list[dict[str, Any]]:
    out = []
    for auth, owner, rel, rcov, ccov, cells in itertools.product(
        ("within_existing", "unknown"),
        ("absent", "unknown"),
        ("empty", "independent", "unknown"),
        ("complete", "unknown"),
        ("complete", "unknown"),
        ("empty", "clean-applies", "na-unresolved", "unknown-applicability-clean"),
    ):
        out.append(spec(
            authority=auth, owner=owner, related=rel, related_cov=rcov, clearance_cov=ccov,
            cells=cells,
        ))
    return out


K_VARIANTS: dict[str, dict[str, Any]] = {
    "K": {},
    "user-unknown": {"user": "unknown"},
    "user-pending": {"user": "pending"},
    "wait-unknown": {"wait": "unknown"},
    "waiting": {"wait": "waiting"},
    "attempt-unknown": {"attempt": "unknown"},
    "admitted": {"attempt": "admitted"},
    "obligations-unknown": {"obligations": "unknown"},
    "obligations-pending": {"obligations": "pending"},
    "eligibility-unknown": {"eligibility": "unknown"},
    "not-admissible": {"eligibility": "not_admissible"},
}
G_SETS: dict[str, dict[str, Any]] = {
    "none": {},
    "g1": {"related": "dependent"},
    "g2": {"authority": "denied"},
    "g3": {"owner": "present"},
    "all": {"related": "dependent", "authority": "denied", "owner": "present"},
}


def gen_g() -> list[dict[str, Any]]:
    out = []
    for kv, gs, con, fail in itertools.product(
        K_VARIANTS, G_SETS, ("none", "asserted", "unknown"),
        ("none", "recoverable_classified", "unknown"),
    ):
        out.append(spec(**K_VARIANTS[kv], **G_SETS[gs], conflict=con, failure=fail))
    return out


T_ROWS: dict[str, dict[str, Any]] = {
    "C1": {"wait": "waiting"},
    "C1u+admitted": {"wait": "unknown", "attempt": "admitted"},
    "C1u+none+pending": {"wait": "unknown", "obligations": "pending"},
    "C1u+unknown+pending": {"wait": "unknown", "attempt": "unknown", "obligations": "pending"},
    "C1u+none+none_declared": {"wait": "unknown"},
    "C1u+none+obligations-unknown": {"wait": "unknown", "obligations": "unknown"},
    "C2u+pending": {"attempt": "unknown", "obligations": "pending"},
    "C2u+none_declared": {"attempt": "unknown"},
    "C2": {"attempt": "admitted"},
    "C3": {"obligations": "pending"},
    "C4": {},
    "P": {"policy": "held"},
    "G*": {"related": "dependent"},
    "N1": {"user": "pending"},
    "X1": {"conflict": "asserted"},
    "R2": {"eligibility": "not_admissible"},
}
T_TIMES: dict[str, dict[str, Any]] = {
    "hard-1": {"now": HARD - 1, "acceptance": 7_000},
    "hard": {"now": HARD, "acceptance": 7_000},
    "hard+1": {"now": HARD + 1, "acceptance": 7_000},
    "wait-1": {"now": WAIT_EST + WAIT_OVERALL - 1, "acceptance": 3_000},
    "wait": {"now": WAIT_EST + WAIT_OVERALL, "acceptance": 3_000},
    "progress-1": {"now": PROGRESS - 1, "acceptance": None},
    "progress": {"now": PROGRESS, "acceptance": None},
    "oldA-hard-1": {"now": HARD - 1, "acceptance": None},
}
PHASES = ("none", "active", "f1", "f2", "f3", "f4", "f5", "f6", "f7")
HARD_ONLY_ROWS = {
    "C1u+admitted", "C1u+none+pending", "C1u+unknown+pending", "C1u+none+none_declared",
    "C1u+none+obligations-unknown", "C2u+pending", "C2u+none_declared",
}


def gen_t(rows: set[str] | None = None) -> list[dict[str, Any]]:
    out = []
    for row, tm, ph in itertools.product(T_ROWS, T_TIMES, PHASES):
        if rows is None or row in rows:
            out.append(spec(**T_ROWS[row], **T_TIMES[tm], phase=ph))
    return out


GENERATORS: dict[str, Callable[[], list[dict[str, Any]]]] = {
    "GEN-P": gen_p,
    "GEN-C": gen_c,
    "GEN-R": gen_r,
    "GEN-G": gen_g,
    "GEN-T": gen_t,
}


def assert_oracle(specs: list[dict[str, Any]]) -> set[str]:
    rows: set[str] = set()
    mismatches = []
    for s in specs:
        row, expected = oracle(s)
        rows.add(row)
        actual = projection(run(s))
        if actual != expected:
            mismatches.append((row, expected, actual, {k: v for k, v in s.items() if v != DEFAULT[k]}))
    assert mismatches == [], mismatches[:5]
    return rows


# =========================================================================== VAL-01


def test_val01_result_classes_have_exact_fields() -> None:
    names = {cls: [f.name for f in dataclasses.fields(cls)] for cls in (Assessed, Indeterminate, Deferred)}
    assert names[Assessed] == [
        "state", "primary_reason", "hint", "reasons", "liveness", "claims", "basis", "tag"
    ]
    assert names[Indeterminate] == ["code", "reasons", "claims", "basis", "tag", "hint"]
    assert names[Deferred] == ["feature", "reason", "reasons", "claims", "basis", "tag", "hint"]
    assert Indeterminate("wait_unknown", (), (), ()).hint == "facts_required"
    assert Deferred("recovery_evaluation", "recovery_not_in_slice", (), (), ()).hint == (
        "evaluation_deferred"
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Assessed("recovering", "attempt_admitted", "observe", (), "fresh", (), ()),
        lambda: Assessed("impossible_verified", "x", "observe", (), "fresh", (), ()),
        lambda: Assessed("stalled", "cancel_requested", "observe", (), "fresh", (), ()),
        lambda: Assessed("ready", "transition_admissible", "run", (), "fresh", (), ()),
        lambda: Indeterminate("readiness_not_established", (), (), ()),
        lambda: Deferred("recovery_evaluation", "terminal_predicate_not_in_slice", (), (), ()),
    ],
)
def test_val01_forbidden_states_are_unrepresentable(factory: Callable[[], object]) -> None:
    assert code_of(factory) == "invalid_enum"


def test_val01_closed_code_sets() -> None:
    assert STATE_CODES == {
        "invalid_type", "out_of_range", "invalid_token", "invalid_enum", "detail_mismatch",
        "source_kind_not_allowed", "duplicate_entry", "conflicting_entry", "too_many_refs",
        "binding_mismatch", "epoch_mismatch", "future_observation", "clock_regression",
        "sequence_regression", "evidence_identity_conflict", "frontier_capacity_exhausted",
        "frontier_invalid", "profile_invalid", "phase_invalid", "wait_invalid",
    }
    assert len(cs.HINTS) == 12 and len(cs.INDETERMINATE_CODES) == 20
    assert sum(len(v) for v in cs.PRIMARY_REASONS.values()) == 21
    assert not {"run", "retry", "recover", "kill", "close"} & cs.HINTS
    assert (LOCAL_TUPLE_CAP, AGGREGATE_BASIS_CAP, MAX_FRONTIER_SEEN) == (64, 64, 1024)
    assert not hasattr(cs, "MAX_ACCEPTED_KEYS")


def test_val01_every_hint_and_code_is_reachable() -> None:
    results = [run(s) for name in GENERATORS for s in GENERATORS[name]()]
    results += [
        run(spec(user="pending", user_kind=kind))
        for kind in ("authority_decision_required", "access_decision_required")
    ]
    hints = {r.hint for r in results}
    assert hints == cs.HINTS
    primaries = {r.primary_reason for r in results if type(r) is Assessed}
    assert primaries == frozenset().union(*cs.PRIMARY_REASONS.values())
    codes = {r.code for r in results if type(r) is Indeterminate}
    assert codes == cs.INDETERMINATE_CODES
    features = {r.feature for r in results if type(r) is Deferred}
    assert features == set(cs.DEFERRED_PAIRS)


# =========================================================================== VAL-02

ALLOWED_IMPORTS = {"__future__", "dataclasses", "re", "typing"}


def test_val02_import_allowlist() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    s2a: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 1:
                assert node.module == "continuation_types"
                s2a.update(alias.name for alias in node.names)
            else:
                assert node.level == 0 and node.module is not None
                imported.add(node.module)
    assert imported <= ALLOWED_IMPORTS
    assert s2a == {"ClockReadingMs", "DurationMs", "elapsed_between", "DURATION_MS_MAX"}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not names & {
        "os", "sys", "time", "socket", "subprocess", "pathlib", "json", "open", "print",
        "encode_value", "decode_duration_ms", "decode_clock_reading_ms", "decode_event_id",
        "canonical_json_bytes", "getenv",
    }


def test_val02_module_has_no_runtime_importers() -> None:
    importers = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "src/unrest_harness").rglob("*.py"))
        if path != MODULE_PATH and "continuation_state" in path.read_text(encoding="utf-8")
    ]
    assert importers == []


class _EnvTrap:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError("environment access")

    def __getitem__(self, key: str) -> Any:
        raise AssertionError("environment access")

    def __contains__(self, key: object) -> bool:
        raise AssertionError("environment access")


def test_val02_operations_have_no_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def forbidden(name: str) -> Callable[..., Any]:
        def refuse(*args: object, **kwargs: object) -> Any:
            attempts.append(name)
            raise AssertionError(name)

        return refuse

    cases = [spec(), spec(attempt="admitted"), spec(wait="waiting"), spec(policy="held")]
    prepared = [(make_facts(s), make_frontier(s), make_profile(s), clk(s["now"])) for s in cases]
    claim = accept_claim(1, 100)
    frontier = empty_frontier()
    with monkeypatch.context() as patch:
        for owner, attr in (
            (builtins, "open"), (os, "open"), (socket, "socket"), (subprocess, "Popen"),
            (time, "time"), (time, "monotonic"), (time, "perf_counter"), (os, "getenv"),
        ):
            patch.setattr(owner, attr, forbidden(f"{owner.__name__}.{attr}"))
        patch.setattr(os, "environ", _EnvTrap())
        for args in prepared:
            assess_unit(*args)
        advance_progress(frontier, claim)
    assert attempts == []


def _permuted_facts(reverse: bool) -> UnitFacts:
    s = spec(
        cells=(
            ("applies", "clear", "settled"), ("not_applicable", "unresolved", "unresolved"),
            ("unknown", "clear", "settled"),
        ),
        related="dependent+unknown",
        claims=("done_claimed", "blocker_claimed", "scope_ambiguous_claimed"),
        eligibility="not_admissible",
    )
    facts = make_facts(s)
    if not reverse:
        return facts
    return dataclasses.replace(
        facts,
        clearance=tuple(reversed(facts.clearance)),
        related_holds=tuple(reversed(facts.related_holds)),
        claims=tuple(reversed(facts.claims)),
        controls=Controls("absent", "absent", "absent", (R("control_record", "z"), R("control_record", "a"))),
    )


def test_val02_permutations_normalize_and_results_are_equal() -> None:
    a, b = _permuted_facts(False), _permuted_facts(True)
    assert a.clearance == b.clearance and a.related_holds == b.related_holds
    assert a.claims == b.claims
    assert b.controls.basis == (R("control_record", "a"), R("control_record", "z"))
    fr, prof = empty_frontier(), make_profile(DEFAULT)
    b2 = dataclasses.replace(b, controls=a.controls)
    assert assess_unit(a, fr, prof, clk(2000)) == assess_unit(b2, fr, prof, clk(2000))


def test_val02_seen_history_is_not_normalized() -> None:
    first, second = accept_claim(1, 10), accept_claim(2, 20, ClaimKey("gate_satisfied", "g", 1))
    keys = (ACCEPT_KEY, ClaimKey("gate_satisfied", "g", 1))
    ok = ProgressFrontier(B, clk(0), 2, clk(20), clk(20), keys, (), (first, second))
    assert ok.seen == (first, second)
    assert code_of(
        lambda: ProgressFrontier(B, clk(0), 2, clk(20), clk(20), keys, (), (second, first))
    ) == "frontier_invalid"


# =========================================================================== VAL-03


@pytest.mark.parametrize(
    ("factory", "code"),
    [
        (lambda: Binding("m", "c", "o", True, "x", "s", "u"), "invalid_type"),
        (lambda: Binding("m", "c", "o", 0, "x", "s", "u"), "out_of_range"),
        (lambda: Binding("m", "c", "o", INT64_MAX + 1, "x", "s", "u"), "out_of_range"),
        (lambda: Binding("", "c", "o", 1, "x", "s", "u"), "invalid_token"),
        (lambda: Binding("a" * 129, "c", "o", 1, "x", "s", "u"), "invalid_token"),
        (lambda: Binding("m-é", "c", "o", 1, "x", "s", "u"), "invalid_token"),
        (lambda: Binding("-m", "c", "o", 1, "x", "s", "u"), "invalid_token"),
        (lambda: Binding(b"m", "c", "o", 1, "x", "s", "u"), "invalid_type"),  # type: ignore[arg-type]
        (lambda: BasisRef("agent_claims", "r"), "invalid_enum"),
        (lambda: ClaimKey("assertion_satisfied", "c", 0), "out_of_range"),
    ],
)
def test_val03_primitive_validation(factory: Callable[[], object], code: str) -> None:
    assert code_of(factory) == code


class _IntSub(int):
    pass


class _StrSub(str):
    pass


def test_val03_boundaries_accept() -> None:
    assert Binding("a", "c", "o", INT64_MAX, "x", "s", "u").generation == INT64_MAX
    assert Binding("a" * 128, "c", "o", 1, "x", "s", "u").mission_id == "a" * 128
    assert code_of(lambda: Binding("m", "c", "o", _IntSub(1), "x", "s", "u")) == "invalid_type"
    assert code_of(lambda: Binding(_StrSub("m"), "c", "o", 1, "x", "s", "u")) == "invalid_type"


def _assess(facts: UnitFacts, s: dict[str, Any] | None = None) -> object:
    s = s or DEFAULT
    return assess_unit(facts, make_frontier(s), make_profile(s), clk(s["now"]))


def test_val03_frozen_bypass_is_revalidated() -> None:
    facts = make_facts(DEFAULT)
    object.__setattr__(facts.integrity, "status", "bogus")
    assert code_of(lambda: _assess(facts)) == "invalid_enum"
    facts = make_facts(DEFAULT)
    object.__setattr__(facts, "integrity", object.__new__(IntegrityFact))
    assert code_of(lambda: _assess(facts)) == "invalid_type"

    class Sub(IntegrityFact):
        __slots__ = ()

    facts = make_facts(DEFAULT)
    object.__setattr__(facts, "integrity", Sub("passed", R("integrity_check")))
    assert code_of(lambda: _assess(facts)) == "invalid_type"
    facts = make_facts(DEFAULT)
    object.__setattr__(facts, "binding", dataclasses.replace(B))
    object.__setattr__(facts.binding, "generation", True)
    assert code_of(lambda: _assess(facts)) == "invalid_type"
    facts = make_facts(DEFAULT)
    object.__setattr__(facts.observed_at, "epoch_id", "bad epoch")
    assert code_of(lambda: _assess(facts)) == "invalid_token"


def test_val03_malformed_input_is_refused_even_with_cancel() -> None:
    facts = make_facts(spec(controls="cancel"))
    object.__setattr__(facts.coherence, "basis", None)
    assert code_of(lambda: _assess(facts, spec(controls="cancel"))) == "detail_mismatch"
    facts = make_facts(spec(controls="cancel"))
    assert code_of(lambda: assess_unit(facts, empty_frontier(), "profile", clk(2000))) == (  # type: ignore[arg-type]
        "invalid_type"
    )


def test_val03_now_argument_is_revalidated() -> None:
    now = clk(2000)
    object.__setattr__(now, "elapsed_ms", -1)
    assert code_of(lambda: assess_unit(make_facts(DEFAULT), empty_frontier(), make_profile(DEFAULT), now)) == (
        "out_of_range"
    )


# Amendment-2 §3: malformed elements are never sorted or normalized before
# validation.  Within one collection the first invalid element in caller order
# decides the code, so permutations of a multi-invalid input may differ; one
# input is always refused the same way.  Element validation of frontier.seen
# belongs to frontier validation, which follows the whole facts validation.


def _hold(ref: str, relation: str = "independent", basis_ref: str = "") -> RelatedHold:
    return RelatedHold(ref, relation, R("dependency_assertion", basis_ref or ref))


def _with_holds(holds: tuple[RelatedHold, ...]) -> Callable[[], object]:
    return lambda: dataclasses.replace(make_facts(DEFAULT), related_holds=holds)


def _bad_hold(field: str, value: str, ref: str) -> RelatedHold:
    hold = _hold(ref)
    object.__setattr__(hold, field, value)
    return hold


@pytest.mark.parametrize(
    ("holds", "code"),
    [
        ((_hold("hold-a"), _hold("hold-a", "dependent", "x"), _hold("hold-b"), _hold("hold-b")),
         "conflicting_entry"),
        ((_hold("hold-b"), _hold("hold-b"), _hold("hold-a"), _hold("hold-a", "dependent", "x")),
         "duplicate_entry"),
        ((_bad_hold("hold_ref", "not a token", "t"), _bad_hold("relation", "sideways", "e")),
         "invalid_token"),
        ((_bad_hold("relation", "sideways", "e"), _bad_hold("hold_ref", "not a token", "t")),
         "invalid_enum"),
    ],
    ids=["dup-after-conflict", "conflict-after-dup", "token-first", "enum-first"],
)
def test_val03_first_invalid_element_in_caller_order_decides(
    holds: tuple[RelatedHold, ...], code: str
) -> None:
    assert code_of(_with_holds(holds)) == code
    assert code_of(_with_holds(holds)) == code  # one input, one code


def test_val03_facts_are_validated_before_frontier_seen_elements() -> None:
    s = spec(acceptance=1_000)
    frontier = make_frontier(s)
    object.__setattr__(frontier, "seen", (object(),))
    clean = make_facts(s)
    assert code_of(lambda: assess_unit(clean, frontier, make_profile(s), clk(s["now"]))) == (
        "invalid_type"
    )
    broken = make_facts(s)
    object.__setattr__(broken.integrity, "status", "maybe")
    assert code_of(lambda: assess_unit(broken, frontier, make_profile(s), clk(s["now"]))) == (
        "invalid_enum"
    )


# =========================================================================== VAL-04

BINDING_FIELDS = [f.name for f in dataclasses.fields(Binding)]


def _other(binding: Binding, name: str) -> Binding:
    value = getattr(binding, name)
    return dataclasses.replace(binding, **{name: 2 if name == "generation" else value + "x"})


@pytest.mark.parametrize("name", BINDING_FIELDS)
def test_val04_exact_binding_in_frontier_profile_and_claim(name: str) -> None:
    assert len(BINDING_FIELDS) == 7
    other = _other(B, name)
    facts = make_facts(DEFAULT)
    frontier = dataclasses.replace(empty_frontier(), binding=other)
    profile = dataclasses.replace(make_profile(DEFAULT), binding=other)
    assert code_of(lambda: assess_unit(facts, frontier, make_profile(DEFAULT), clk(2000))) == (
        "binding_mismatch"
    )
    assert code_of(lambda: assess_unit(facts, empty_frontier(), profile, clk(2000))) == (
        "binding_mismatch"
    )
    claim = dataclasses.replace(accept_claim(1, 10), binding=other)
    assert code_of(lambda: advance_progress(empty_frontier(), claim)) == "binding_mismatch"


# =========================================================================== VAL-05


def _epoch_variants() -> list[tuple[str, Callable[[str], tuple[UnitFacts, ProgressFrontier, DeadlineProfile]]]]:
    s = spec(attempt="admitted", liveness=50, wait="waiting", phase="active", acceptance=100)

    def facts_with(epoch: str, which: str) -> tuple[UnitFacts, ProgressFrontier, DeadlineProfile]:
        facts, frontier, profile = make_facts(s), make_frontier(s), make_profile(s)
        if which == "observed_at":
            facts = dataclasses.replace(facts, observed_at=clk(2000, epoch))
        elif which == "attempt.started_at":
            attempt = dataclasses.replace(facts.attempt, started_at=clk(0, epoch))
            facts = dataclasses.replace(facts, attempt=attempt)
        elif which == "attempt.last_liveness_at":
            attempt = dataclasses.replace(facts.attempt, last_liveness_at=clk(50, epoch))
            facts = dataclasses.replace(facts, attempt=attempt)
        elif which in ("wait.established_at", "wait.next_check_at"):
            # A WaitSpec spanning two epochs cannot be constructed; bypass to
            # prove that revalidation still refuses it.
            assert facts.wait.spec is not None
            field_name = which.split(".")[1]
            object.__setattr__(
                facts.wait.spec, field_name, clk(getattr(facts.wait.spec, field_name).elapsed_ms, epoch)
            )
        elif which == "phase.last_observed_at":
            facts = dataclasses.replace(
                facts, phase=PhaseObservation("ph", clk(1900, epoch), PHASE_REF)
            )
        elif which == "frontier":
            frontier = dataclasses.replace(
                empty_frontier(), started_at=clk(0, epoch), last_observed_at=clk(0, epoch)
            )
        elif which == "profile.phase.started_at":
            envelope = PhaseEnvelope("ph", PHASE_REF, clk(0, epoch), DurationMs(HARD), DurationMs(2000))
            profile = dataclasses.replace(profile, phase=envelope)
        return facts, frontier, profile

    names = [
        "observed_at", "attempt.started_at", "attempt.last_liveness_at", "wait.established_at",
        "wait.next_check_at", "phase.last_observed_at", "frontier", "profile.phase.started_at",
    ]
    return [(n, lambda e, n=n: facts_with(e, n)) for n in names]


@pytest.mark.parametrize("name", [name for name, _ in _epoch_variants()])
def test_val05_every_clock_shares_the_epoch(name: str) -> None:
    facts, frontier, profile = dict(_epoch_variants())[name]("ep2")
    with pytest.raises(ContinuationStateError) as info:
        assess_unit(facts, frontier, profile, clk(2000))
    assert info.value.code in {"epoch_mismatch", "wait_invalid"}
    if name.startswith("wait."):
        # A WaitSpec spanning two epochs is itself invalid; revalidation reports it first.
        assert info.value.code == "wait_invalid"
    else:
        assert info.value.code == "epoch_mismatch"


def test_val05_wait_in_another_epoch_is_epoch_mismatch() -> None:
    s = spec(wait="waiting")
    facts = dataclasses.replace(
        make_facts(s),
        wait=WaitFact(
            "waiting",
            WaitSpec("p", R("external_predicate"), clk(1000, "ep2"), clk(1500, "ep2"), DurationMs(5000)),
            None,
        ),
    )
    assert code_of(lambda: assess_unit(facts, empty_frontier(), make_profile(s), clk(2000))) == (
        "epoch_mismatch"
    )


@pytest.mark.parametrize(
    "which",
    ["observed_at", "attempt.started_at", "attempt.last_liveness_at", "wait.established_at",
     "phase.last_observed_at", "frontier.acceptance", "profile.phase.started_at"],
)
def test_val05_future_clocks_are_refused(which: str) -> None:
    s = spec(attempt="admitted", liveness=50, wait="waiting", phase="active", acceptance=100)
    facts, frontier, profile = make_facts(s), make_frontier(s), make_profile(s)
    future = clk(2001)
    if which == "observed_at":
        facts = dataclasses.replace(facts, observed_at=future)
    elif which == "attempt.started_at":
        facts = dataclasses.replace(
            facts, attempt=dataclasses.replace(facts.attempt, started_at=future, last_liveness_at=clk(2002))
        )
    elif which == "attempt.last_liveness_at":
        facts = dataclasses.replace(
            facts, attempt=dataclasses.replace(facts.attempt, last_liveness_at=future)
        )
    elif which == "wait.established_at":
        facts = dataclasses.replace(
            facts, wait=WaitFact("waiting", wait_spec(2001, 2001, 5000), None)
        )
    elif which == "phase.last_observed_at":
        facts = dataclasses.replace(facts, phase=PhaseObservation("ph", future, PHASE_REF))
    elif which == "frontier.acceptance":
        frontier = make_frontier(spec(acceptance=2001))
    else:
        profile = dataclasses.replace(
            profile, phase=PhaseEnvelope("ph", PHASE_REF, future, DurationMs(HARD), DurationMs(2000))
        )
    assert code_of(lambda: assess_unit(facts, frontier, profile, clk(2000))) == "future_observation"


def test_val05_next_check_may_be_in_the_future() -> None:
    s = spec(wait="waiting")
    facts = dataclasses.replace(make_facts(s), wait=WaitFact("waiting", wait_spec(1000, 4000, 5000), None))
    result = assess_unit(facts, empty_frontier(), make_profile(s), clk(2000))
    assert projection(result) == A("waiting_external", "external_dependency", "observe")


def test_val05_int64_boundaries_without_overflow() -> None:
    start = INT64_MAX - 10
    facts = dataclasses.replace(make_facts(DEFAULT), observed_at=clk(INT64_MAX))
    frontier = empty_frontier(start)
    profile = DeadlineProfile(
        B, "p", 1, DurationMs(INT64_MAX), DurationMs(INT64_MAX), DurationMs(INT64_MAX), None
    )
    result = assess_unit(facts, frontier, profile, clk(INT64_MAX))
    assert projection(result) == A("ready", "transition_admissible", "consider_existing_transition")
    profile = DeadlineProfile(B, "p", 1, DurationMs(10), DurationMs(10), DurationMs(INT64_MAX), None)
    assert projection(assess_unit(facts, frontier, profile, clk(INT64_MAX))) == A(
        "stalled", "hard_deadline_elapsed", "observe"
    )


def test_val05_s2a_errors_never_escape() -> None:
    for call in (
        lambda: assess_unit(make_facts(DEFAULT), empty_frontier(), make_profile(DEFAULT), clk(2000, "ep2")),
        lambda: advance_progress(
            empty_frontier(), dataclasses.replace(accept_claim(1, 10), observed_at=clk(10, "ep2"))
        ),
    ):
        with pytest.raises(ContinuationStateError) as info:
            call()
        assert not isinstance(info.value, ContinuationValueError)


# =========================================================================== VAL-06


@pytest.mark.parametrize(
    ("factory", "code"),
    [
        (lambda: DeadlineProfile(B, "p", 1, DurationMs(0), DurationMs(5), DurationMs(5), None),
         "profile_invalid"),
        (lambda: DeadlineProfile(B, "p", 1, DurationMs(5), DurationMs(0), DurationMs(5), None),
         "profile_invalid"),
        (lambda: DeadlineProfile(B, "p", 1, DurationMs(5), DurationMs(5), DurationMs(0), None),
         "profile_invalid"),
        (lambda: DeadlineProfile(B, "p", 1, DurationMs(6), DurationMs(5), DurationMs(5), None),
         "profile_invalid"),
        (lambda: DeadlineProfile(B, "p", 0, DurationMs(5), DurationMs(5), DurationMs(5), None),
         "out_of_range"),
        (lambda: DeadlineProfile(
            B, "p", 1, DurationMs(5), DurationMs(10), DurationMs(5),
            PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(11), DurationMs(5))), "phase_invalid"),
        (lambda: PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(4), DurationMs(5)), "phase_invalid"),
        (lambda: PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(0), DurationMs(0)), "phase_invalid"),
        (lambda: PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(4), DurationMs(0)), "phase_invalid"),
        (lambda: PhaseEnvelope("ph", R("gate_verdict"), clk(0), DurationMs(4), DurationMs(4)),
         "source_kind_not_allowed"),
        (lambda: wait_spec(1000, 1500, 0), "wait_invalid"),
        (lambda: wait_spec(1500, 1000, 5000), "wait_invalid"),
        (lambda: wait_spec(1000, 6001, 5000), "wait_invalid"),
        (lambda: WaitSpec("p", R("external_predicate"), clk(0), clk(1, "ep2"), DurationMs(5)),
         "wait_invalid"),
    ],
)
def test_val06_profile_phase_wait_invariants(factory: Callable[[], object], code: str) -> None:
    assert code_of(factory) == code


def test_val06_boundaries_accept() -> None:
    assert DeadlineProfile(B, "p", 1, DurationMs(5), DurationMs(5), DurationMs(1), None)
    assert DeadlineProfile(
        B, "p", 1, DurationMs(5), DurationMs(10), DurationMs(5),
        PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(10), DurationMs(10)),
    )
    assert wait_spec(1000, 6000, 5000)
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "MAX_AUTOMATIC_RESTARTS" not in names and "supervision" not in names


# =========================================================================== VAL-07


def test_val07_gen_p_matches_literal_oracle() -> None:
    specs = gen_p()
    assert len(specs) == 5 * 3 * 3 * 3 * 3 * 8 * 3
    assert_oracle(specs)


def test_val07_cancel_retains_integrity_reason() -> None:
    result = run(spec(controls="cancel", integrity="refused"))
    assert projection(result) == A("paused_policy", "cancel_requested", "none")
    assert "integrity_refused" in result.reasons


def test_val07_known_hold_with_unknown_control() -> None:
    result = run(spec(controls="cancel-unknown", policy="held"))
    assert projection(result) == A("paused_policy", "policy_hold", "review_policy")
    assert "control_unknown" in result.reasons


def test_val07_unknown_diagnostics_kept_under_p() -> None:
    result = run(spec(
        policy="held", integrity="unknown", coherence="unknown", attempt="unknown",
        user="unknown", wait="unknown", obligations="unknown", eligibility="unknown",
        owner="unknown", authority="unknown", related="unknown", related_cov="unknown",
        clearance_cov="unknown", failure="unknown", conflict="unknown", controls="cancel-unknown",
        cells="applies-state-unknown",
    ))
    assert projection(result) == A("paused_policy", "policy_hold", "review_policy")
    assert set(result.reasons) >= {
        "control_unknown", "integrity_unknown", "coherence_unknown", "attempt_unknown",
        "user_decision_unknown", "wait_unknown", "obligations_unknown", "readiness_unknown",
        "owner_unknown", "authority_unknown", "independence_unknown",
        "related_holds_coverage_unknown", "clearance_coverage_unknown", "failure_unknown",
        "conflict_unknown", "clearance_unknown",
    }


# =========================================================================== VAL-08


def test_val08_integrity_and_coherence_are_holds_not_user_decisions() -> None:
    assert projection(run(spec(integrity="refused"))) == A(
        "paused_policy", "integrity_refused", "review_integrity"
    )
    assert projection(run(spec(coherence="inconsistent"))) == A(
        "paused_policy", "inconsistent_observations", "review_integrity"
    )


def test_val08_cd1_cd2_are_diagnostic_only() -> None:
    cd1 = run(spec(attempt="admitted", obligations="all_satisfied"))
    assert projection(cd1) == A("working", "attempt_admitted", "observe")
    assert "obligations_satisfied_during_attempt" in cd1.reasons
    cd2 = run(spec(attempt="admitted", eligibility="admissible"))
    assert projection(cd2) == A("working", "attempt_admitted", "observe")
    assert "transition_admissible_during_attempt" in cd2.reasons
    pending = run(spec(attempt="admitted", obligations="pending"))
    assert "obligations_pending_during_attempt" in pending.reasons


# =========================================================================== VAL-09

ALL_UNKNOWN = dict(
    controls="all-unknown", integrity="unknown", coherence="unknown", policy="unknown",
    attempt="unknown", clearance_cov="unknown", user="unknown", wait="unknown",
    obligations="unknown", eligibility="unknown", owner="unknown", authority="unknown",
    related_cov="unknown", failure="unknown", conflict="unknown",
)


def test_val09_all_unknown_is_indeterminate() -> None:
    result = run(spec(**ALL_UNKNOWN, now=HARD * 5))
    assert type(result) is Indeterminate


def test_val09_neutral_input_is_not_stalled() -> None:
    for now in (2000, HARD * 3):
        result = run(spec(eligibility="not_admissible", now=now))
        assert projection(result) == I("no_classifiable_condition")


@pytest.mark.parametrize("field", sorted(ALL_UNKNOWN))
def test_val09_no_single_unknown_becomes_ready(field: str) -> None:
    result = run(spec(**{field: ALL_UNKNOWN[field]}))
    assert projection(result)[:2] != ("assessed", "ready")
    assert type(result) is Indeterminate


def test_val09_known_hold_keeps_headline_under_unknowns() -> None:
    for unknown in ("integrity", "coherence", "controls"):
        result = run(spec(policy="held", **{unknown: ALL_UNKNOWN[unknown]}))
        assert projection(result) == A("paused_policy", "policy_hold", "review_policy")


# =========================================================================== VAL-10

TRIPLES = list(itertools.product(
    ("applies", "not_applicable", "unknown"), ("clear", "unresolved", "unknown"),
    ("settled", "unresolved", "unknown"),
))


def test_val10_single_cell_product_matches_oracle() -> None:
    specs = [
        spec(cells=(triple,), attempt=att, settlement=settlement)
        for triple in TRIPLES
        for att in ("none", "admitted", "unknown")
        for settlement in ("owner_completed", "never_dispatched", "unknown")
    ]
    assert len(specs) == 27 * 3 * 3
    assert_oracle(specs)


def test_val10_settlement_never_affects_decision() -> None:
    for triple, att in itertools.product(TRIPLES, ("none", "admitted", "unknown")):
        outcomes = {
            projection(run(spec(cells=(triple,), attempt=att, settlement=settlement)))
            for settlement in sorted(cs.SETTLEMENT_VALUES)
        }
        assert len(outcomes) == 1


def test_val10_paired_admitted_vs_none() -> None:
    for cells, k_primary in (
        ("outcome-unresolved-applies", "outcome_unresolved"),
        ("clearance-unresolved-applies", "clearance_unresolved"),
    ):
        admitted = run(spec(cells=cells, attempt="admitted"))
        assert projection(admitted) == A("working", "attempt_admitted", "observe")
        assert {
            "proposed_transition_outcome_unresolved", "proposed_transition_clearance_unresolved"
        } & set(admitted.reasons)
        none = run(spec(cells=cells, attempt="none"))
        assert projection(none)[:3] == ("assessed", "paused_policy", k_primary)


def test_val10_clean_cell_with_unknown_attempt_keeps_known_wait() -> None:
    result = run(spec(cells="clean-applies", attempt="unknown", wait="waiting"))
    assert projection(result) == A("waiting_external", "external_dependency", "external_observation_due")


def test_val10_clear_with_unresolved_outcome_is_k6() -> None:
    result = run(spec(cells=(("applies", "clear", "unresolved"),)))
    assert projection(result) == A("paused_policy", "outcome_unresolved", "review_unresolved_outcome")


def test_val10_owner_completed_is_not_clearance() -> None:
    result = run(spec(cells=(("applies", "unknown", "unknown"),), settlement="owner_completed"))
    assert projection(result) == I("clearance_unknown")


# =========================================================================== VAL-11


def test_val11_gen_r_matches_literal_oracle() -> None:
    specs = gen_r()
    assert len(specs) == 192
    assert_oracle(specs)


def test_val11_independence_requires_assertion() -> None:
    assert projection(run(spec(related="unknown"))) == I("independence_unknown")
    assert projection(run(spec(related="independent", related_cov="unknown"))) == I(
        "related_holds_coverage_unknown"
    )
    assert projection(run(spec(related="independent"))) == A(
        "ready", "transition_admissible", "consider_existing_transition"
    )


def test_val11_r3_order() -> None:
    assert projection(run(spec(authority="unknown", owner="unknown"))) == I("authority_unknown")
    assert projection(run(spec(owner="unknown", related_cov="unknown"))) == I("owner_unknown")
    assert projection(run(spec(related_cov="unknown", related="unknown"))) == I(
        "related_holds_coverage_unknown"
    )
    assert projection(run(spec(related="unknown", clearance_cov="unknown"))) == I(
        "independence_unknown"
    )
    assert projection(run(spec(clearance_cov="unknown"))) == I("clearance_coverage_unknown")


# =========================================================================== VAL-12

CLAIM_CODES = [
    "authority_required_claimed", "blocker_claimed", "contradiction_claimed",
    "dependency_unavailable_claimed", "done_claimed", "scope_ambiguous_claimed",
]


def test_val12_claim_code_domain() -> None:
    assert cs.CLAIM_CODES == frozenset(CLAIM_CODES)


@pytest.mark.parametrize(
    "base",
    [spec(), spec(attempt="admitted"), spec(policy="held"), spec(**ALL_UNKNOWN),
     spec(conflict="asserted"), spec(user="pending")],
)
def test_val12_claims_never_change_decision(base: dict[str, Any]) -> None:
    reference = run(base)
    for size in range(len(CLAIM_CODES) + 1):
        for subset in itertools.combinations(CLAIM_CODES, size):
            result = run(dict(base, claims=subset))
            assert projection(result) == projection(reference)
            assert result.reasons == reference.reasons
            assert result.basis == reference.basis
            assert getattr(result, "liveness", None) == getattr(reference, "liveness", None)
            assert result.claims == tuple(sorted(subset))


def test_val12_agent_claim_only_where_allowed() -> None:
    assert code_of(lambda: IntegrityFact("passed", R("agent_claim"))) == "source_kind_not_allowed"
    assert code_of(lambda: Coverage("complete", R("agent_claim"))) == "source_kind_not_allowed"
    assert code_of(lambda: ClaimFact("done_claimed", R("validator_verdict"))) == "source_kind_not_allowed"
    assert ClaimFact("done_claimed", R("agent_claim")).code == "done_claimed"


def test_val12_claim_identity() -> None:
    base = make_facts(DEFAULT)
    same = ClaimFact("done_claimed", R("agent_claim", "a"))
    other = ClaimFact("done_claimed", R("agent_claim", "b"))
    assert code_of(lambda: dataclasses.replace(base, claims=(same, same))) == "duplicate_entry"
    assert code_of(lambda: dataclasses.replace(base, claims=(same, other))) == "conflicting_entry"


# =========================================================================== VAL-13

TIMED_ROWS = {"C1", "C2", "C3", "C4", "P", "G*", "N1", "X1", "R2"}


def test_val13_gen_t_timed_rows_match_oracle() -> None:
    specs = gen_t(TIMED_ROWS)
    assert len(specs) == len(TIMED_ROWS) * len(T_TIMES) * len(PHASES)
    assert_oracle(specs)


@pytest.mark.parametrize(
    ("row", "primary"),
    [("C1", "external_dependency"), ("C2", "attempt_admitted"), ("C3", "verification_pending"),
     ("C4", "transition_admissible")],
)
def test_val13_stalled_keeps_candidate_reason(row: str, primary: str) -> None:
    result = run(spec(**T_ROWS[row], now=HARD))
    assert projection(result) == A("stalled", "hard_deadline_elapsed", "observe")
    assert primary in result.reasons and "hard_deadline_elapsed" in result.reasons


def test_val13_all_expiries_are_listed_and_hard_wins() -> None:
    result = run(spec(wait="waiting", now=HARD))
    assert result.reasons == tuple(sorted({
        "hard_deadline_elapsed", "wait_deadline_elapsed", "external_dependency",
        "external_observation_due",
    }))
    progress = run(spec(obligations="pending", now=HARD))
    assert {"hard_deadline_elapsed", "progress_deadline_elapsed"} <= set(progress.reasons)


@pytest.mark.parametrize("now", [PROGRESS - 1, PROGRESS, PROGRESS + 1])
def test_val13_progress_threshold(now: int) -> None:
    expected = "ready" if now < PROGRESS else "stalled"
    assert projection(run(spec(now=now)))[1] == expected


def test_val13_empty_input_with_ancient_start_is_indeterminate() -> None:
    assert type(run(spec(**ALL_UNKNOWN, now=HARD * 100))) is Indeterminate
    assert projection(run(spec(eligibility="not_admissible", now=HARD * 100))) == I(
        "no_classifiable_condition"
    )


def test_val13_untimed_rows_have_no_expiry_codes() -> None:
    for row in ("P", "G*", "N1", "X1", "R2"):
        result = run(spec(**T_ROWS[row], now=HARD * 2))
        assert not {"hard_deadline_elapsed", "progress_deadline_elapsed"} & set(result.reasons)


@pytest.mark.parametrize("age", [OBS - 1, OBS, OBS + 1])
def test_val13_liveness_threshold(age: int) -> None:
    result = run(spec(attempt="admitted", liveness=2000 - age))
    assert result.liveness == ("fresh" if age < OBS else "stale")
    assert run(spec(attempt="admitted")).liveness == "unobserved"
    assert run(spec()).liveness == "not_applicable"


# =========================================================================== VAL-14


@pytest.mark.parametrize("variant", ["f1", "f2", "f3", "f4", "f5", "f6", "f7"])
def test_val14_each_false_phase_condition(variant: str) -> None:
    result = run(spec(attempt="admitted", phase=variant, now=PROGRESS))
    assert projection(result) == A("stalled", "progress_deadline_elapsed", "observe")
    assert "phase_not_applicable" in result.reasons
    assert "phase_exemption_active" not in result.reasons


def test_val14_active_phase_suppresses_progress_only() -> None:
    active = run(spec(attempt="admitted", phase="active", now=PROGRESS))
    assert projection(active) == A("working", "attempt_admitted", "observe")
    assert "phase_exemption_active" in active.reasons
    hard = run(spec(attempt="admitted", phase="active", now=HARD))
    assert projection(hard) == A("stalled", "hard_deadline_elapsed", "observe")
    for row in ("C3", "C4"):
        result = run(spec(**T_ROWS[row], phase="active", now=PROGRESS))
        assert projection(result)[2] == "progress_deadline_elapsed"
        assert not {"phase_exemption_active", "phase_not_applicable"} & set(result.reasons)


def _late_phase(s: dict[str, Any]) -> tuple[UnitFacts, DeadlineProfile]:
    """An envelope opened later than S stays active when the lifetime deadline expires."""
    facts = dataclasses.replace(
        make_facts(s), phase=PhaseObservation("ph", clk(s["now"] - 100), PHASE_REF)
    )
    profile = dataclasses.replace(
        make_profile(s),
        phase=PhaseEnvelope("ph", PHASE_REF, clk(5_000), DurationMs(HARD), DurationMs(2_000)),
    )
    return facts, profile


def test_val14_active_phase_never_suppresses_hard() -> None:
    s = spec(attempt="admitted", now=HARD)
    facts, profile = _late_phase(s)
    result = assess_unit(facts, empty_frontier(), profile, clk(HARD))
    assert projection(result) == A("stalled", "hard_deadline_elapsed", "observe")
    assert "phase_exemption_active" in result.reasons
    early_facts, early_profile = _late_phase(spec(attempt="admitted", now=HARD - 1))
    before = assess_unit(early_facts, empty_frontier(), early_profile, clk(HARD - 1))
    assert projection(before) == A("working", "attempt_admitted", "observe")


def _phase_case(now: int, max_duration: int, observed: int) -> object:
    s = spec(attempt="admitted", now=now)
    facts = dataclasses.replace(
        make_facts(s), phase=PhaseObservation("ph", clk(observed), PHASE_REF)
    )
    profile = dataclasses.replace(
        make_profile(s),
        phase=PhaseEnvelope("ph", PHASE_REF, clk(0), DurationMs(max_duration), DurationMs(2000)),
    )
    return assess_unit(facts, empty_frontier(), profile, clk(now))


def test_val14_max_duration_and_freshness_boundaries() -> None:
    assert projection(_phase_case(4999, 5000, 4900))[1] == "working"
    assert projection(_phase_case(5000, 5000, 4900))[1] == "stalled"
    assert projection(_phase_case(5000, 6000, 3001))[1] == "working"
    assert projection(_phase_case(5000, 6000, 3000))[1] == "stalled"


# =========================================================================== VAL-15


def test_val15_due_changes_only_hint() -> None:
    assert projection(run(spec(wait="waiting", now=WAIT_NEXT - 1))) == A(
        "waiting_external", "external_dependency", "observe"
    )
    due = run(spec(wait="waiting", now=WAIT_NEXT))
    assert projection(due) == A("waiting_external", "external_dependency", "external_observation_due")
    assert "external_observation_due" in due.reasons


def test_val15_overall_timeout_boundary() -> None:
    edge = WAIT_EST + WAIT_OVERALL
    assert projection(run(spec(wait="waiting", now=edge - 1)))[1] == "waiting_external"
    assert projection(run(spec(wait="waiting", now=edge))) == A(
        "stalled", "wait_deadline_elapsed", "observe"
    )


def test_val15_waiting_with_attempt_and_old_anchor() -> None:
    result = run(spec(wait="waiting", attempt="admitted", now=PROGRESS + 500))
    assert projection(result) == A("waiting_external", "external_dependency", "external_observation_due")
    assert {"attempt_admitted_during_wait", "attempt_admitted"} <= set(result.reasons)


# =========================================================================== VAL-16


def test_val16_pause_never_moves_anchors() -> None:
    s = spec(controls="pause", now=PROGRESS + 100)
    facts, frontier, profile = make_facts(s), make_frontier(s), make_profile(s)
    before = dataclasses.replace(frontier)
    assert projection(assess_unit(facts, frontier, profile, clk(s["now"]))) == A(
        "paused_policy", "pause_requested", "none"
    )
    resumed = make_facts(dict(s, controls="absent"))
    assert projection(assess_unit(resumed, frontier, profile, clk(s["now"]))) == A(
        "stalled", "progress_deadline_elapsed", "observe"
    )
    assert frontier == before


# =========================================================================== VAL-17


def test_val17_gen_c_matches_literal_oracle() -> None:
    specs = gen_c()
    assert len(specs) == 3**6 * 4
    assert_oracle(specs)


def test_val17_excluded_ordering() -> None:
    assert projection(run(spec(conflict="asserted", failure="recoverable_classified"))) == D(
        "impossibility_evaluation", "constraint_conflict_requires_dossier"
    )
    # X3 is not lifted above X2 (REVIEW-2 R2).
    unknown = run(spec(conflict="unknown", failure="recoverable_classified"))
    assert projection(unknown) == I("conflict_unknown")
    assert "recoverable_failure_known" in unknown.reasons
    assert projection(run(spec(conflict="asserted", failure="unknown")))[1] == (
        "impossibility_evaluation"
    )
    ready_path = run(spec(failure="recoverable_classified"))
    assert projection(ready_path) == D("recovery_evaluation", "recovery_not_in_slice")
    working = run(spec(attempt="admitted", conflict="asserted"))
    assert projection(working) == A("working", "attempt_admitted", "observe")
    assert "constraint_conflict_asserted" in working.reasons
    recov = run(spec(attempt="admitted", failure="recoverable_classified"))
    assert "recoverable_failure_known" in recov.reasons


def test_val17_completion_only_when_not_admissible_and_satisfied() -> None:
    assert projection(run(spec(eligibility="not_admissible", obligations="all_satisfied"))) == D(
        "completion_evaluation", "terminal_predicate_not_in_slice"
    )
    assert projection(run(spec(eligibility="admissible", obligations="all_satisfied")))[1] == "ready"
    assert projection(run(spec(eligibility="not_admissible"))) == I("no_classifiable_condition")


# =========================================================================== VAL-18


def _activity(ev: str, sequence: int = 99, at: int = 5, kind: str = "attempt_observation") -> ProgressClaim:
    return ProgressClaim(B, EvidenceId(ev), sequence, clk(at), "activity", None, "poll", R(kind))


def test_val18_activity_is_ignored() -> None:
    frontier = make_frontier(spec(acceptance=100))
    update = advance_progress(frontier, _activity("ev-new"))
    assert update.disposition == "activity_ignored" and update.frontier is frontier
    same_id = advance_progress(frontier, _activity("ev-1", sequence=1, at=1))
    assert same_id.disposition == "activity_ignored" and same_id.frontier is frontier
    agent = advance_progress(frontier, _activity("ev-x", kind="agent_claim"))
    assert agent.disposition == "activity_ignored"


def test_val18_diagnostic_never_moves_acceptance() -> None:
    frontier = make_frontier(spec(acceptance=100))
    key = ClaimKey("diagnostic_finding", "d", 1)
    claim = ProgressClaim(B, EvidenceId("d-1"), 2, clk(200), "diagnostic_finding", key, None, R("agent_claim"))
    update = advance_progress(frontier, claim)
    assert update.disposition == "diagnostic_advanced"
    assert update.frontier.last_acceptance_at == clk(100)
    assert update.frontier.diagnostic_keys == (key,)
    repeat = dataclasses.replace(claim, evidence_id=EvidenceId("d-2"), sequence=3)
    assert advance_progress(update.frontier, repeat).disposition == "semantic_repeat"


def test_val18_agent_claim_cannot_accept() -> None:
    assert code_of(lambda: ProgressClaim(
        B, EvidenceId("e"), 1, clk(1), "assertion_satisfied", ACCEPT_KEY, None, R("agent_claim")
    )) == "source_kind_not_allowed"
    assert code_of(lambda: ProgressClaim(
        B, EvidenceId("e"), 1, clk(1), "gate_satisfied", ClaimKey("gate_satisfied", "g", 1), None,
        R("validator_verdict"),
    )) == "source_kind_not_allowed"
    assert code_of(lambda: ProgressClaim(
        B, EvidenceId("e"), 1, clk(1), "gate_satisfied", ACCEPT_KEY, None, R("gate_verdict"),
    )) == "detail_mismatch"


# =========================================================================== VAL-19


def _full_frontier(count: int, distinct_keys: bool = True) -> ProgressFrontier:
    claims = tuple(
        accept_claim(i + 1, i + 1, ClaimKey("assertion_satisfied", f"c{i if distinct_keys else 0}", 1))
        for i in range(count)
    )
    keys = sorted({c.claim_key for c in claims}, key=lambda k: (k.kind, k.criterion_ref, k.revision))
    first_new = [c for i, c in enumerate(claims) if c.claim_key not in {x.claim_key for x in claims[:i]}]
    return ProgressFrontier(
        B, clk(0), count, clk(count), first_new[-1].observed_at if first_new else None,
        tuple(keys), (), claims,
    )


def test_val19_exact_replay_after_later_sequence() -> None:
    frontier = advance_progress(empty_frontier(), accept_claim(1, 10)).frontier
    frontier = advance_progress(frontier, accept_claim(2, 20, ClaimKey("gate_satisfied", "g", 1))).frontier
    update = advance_progress(frontier, accept_claim(1, 10))
    assert update.disposition == "exact_duplicate" and update.frontier is frontier


@pytest.mark.parametrize(
    "change",
    [
        {"sequence": 5}, {"observed_at": clk(11)}, {"basis": R("validator_verdict", "other")},
        {"claim_key": ClaimKey("assertion_satisfied", "crit-2", 1)},
    ],
)
def test_val19_identity_conflict_on_any_changed_field(change: dict[str, Any]) -> None:
    frontier = advance_progress(empty_frontier(), accept_claim(1, 10)).frontier
    changed = dataclasses.replace(accept_claim(1, 10), **change)
    assert code_of(lambda: advance_progress(frontier, changed)) == "evidence_identity_conflict"


def test_val19_aba_does_not_move_acceptance() -> None:
    other = ClaimKey("gate_satisfied", "g", 1)
    f = advance_progress(empty_frontier(), accept_claim(1, 10)).frontier
    f = advance_progress(f, accept_claim(2, 20, other)).frontier
    update = advance_progress(f, accept_claim(3, 30))
    assert update.disposition == "semantic_repeat"
    assert update.frontier.last_acceptance_at == clk(20)
    assert len(update.frontier.seen) == 3
    conflict = dataclasses.replace(accept_claim(3, 30), observed_at=clk(31))
    assert code_of(lambda: advance_progress(update.frontier, conflict)) == "evidence_identity_conflict"


def test_val19_capacity_boundaries() -> None:
    almost = _full_frontier(MAX_FRONTIER_SEEN - 1)
    full = advance_progress(
        almost, accept_claim(MAX_FRONTIER_SEEN, MAX_FRONTIER_SEEN, ClaimKey("blocker_cleared", "b", 1))
    ).frontier
    assert len(full.seen) == MAX_FRONTIER_SEEN
    new = accept_claim(MAX_FRONTIER_SEEN + 1, MAX_FRONTIER_SEEN + 1, ClaimKey("gate_satisfied", "n", 1))
    assert code_of(lambda: advance_progress(full, new)) == "frontier_capacity_exhausted"
    repeat = accept_claim(MAX_FRONTIER_SEEN + 1, MAX_FRONTIER_SEEN + 1, ClaimKey("assertion_satisfied", "c0", 1))
    assert code_of(lambda: advance_progress(full, repeat)) == "frontier_capacity_exhausted"
    duplicate = full.seen[5]
    assert advance_progress(full, duplicate).disposition == "exact_duplicate"
    changed = dataclasses.replace(duplicate, observed_at=clk(7))
    assert code_of(lambda: advance_progress(full, changed)) == "evidence_identity_conflict"
    assert advance_progress(full, _activity("ev-zz")).disposition == "activity_ignored"


def test_val19_no_separate_accepted_key_cap() -> None:
    full = _full_frontier(MAX_FRONTIER_SEEN)
    assert len(full.accepted_keys) == MAX_FRONTIER_SEEN
    assert code_of(lambda: dataclasses.replace(full, seen=full.seen + (accept_claim(2000, 2000),))) == (
        "frontier_invalid"
    )


def test_val19_reconstruction_rejects_foreign_key() -> None:
    frontier = make_frontier(spec(acceptance=100))
    extra = ClaimKey("gate_satisfied", "ghost", 1)
    assert code_of(lambda: dataclasses.replace(frontier, accepted_keys=(ACCEPT_KEY, extra))) == (
        "frontier_invalid"
    )
    assert code_of(lambda: dataclasses.replace(frontier, diagnostic_keys=(extra,))) == "frontier_invalid"
    assert code_of(lambda: dataclasses.replace(frontier, last_acceptance_at=clk(99))) == "frontier_invalid"
    assert code_of(lambda: dataclasses.replace(frontier, last_sequence=2)) == "frontier_invalid"


def test_val19_repeat_identity_is_retained() -> None:
    f = advance_progress(empty_frontier(), accept_claim(1, 10)).frontier
    repeat = accept_claim(2, 20, ACCEPT_KEY, ev="ev-repeat")
    f2 = advance_progress(f, repeat).frontier
    assert f2.seen[-1] == repeat
    assert code_of(lambda: advance_progress(f2, dataclasses.replace(repeat, observed_at=clk(21)))) == (
        "evidence_identity_conflict"
    )


def test_val19_regressions() -> None:
    f = advance_progress(empty_frontier(), accept_claim(2, 20)).frontier
    assert code_of(lambda: advance_progress(f, accept_claim(2, 30, ev="x"))) == "sequence_regression"
    assert code_of(lambda: advance_progress(f, accept_claim(3, 19, ev="y"))) == "clock_regression"
    assert advance_progress(f, accept_claim(3, 20, ClaimKey("gate_satisfied", "g", 1), ev="z")).disposition == (
        "acceptance_advanced"
    )


# =========================================================================== VAL-20


def test_val20_history_is_not_current_readiness() -> None:
    s = spec(obligations="pending", acceptance=100)
    assert projection(run(s)) == A("verifying", "verification_pending", "verification_required")


# =========================================================================== VAL-21


def _bare_unknown_facts(control_refs: int, **extra: Any) -> UnitFacts:
    """All singular roles unknown; ``control_refs`` known control references."""
    s = spec(**ALL_UNKNOWN)
    facts = make_facts(s)
    controls = Controls(
        "absent", "unknown", "unknown",
        tuple(R("control_record", f"c{i:03d}") for i in range(control_refs)),
    )
    values = {f.name: getattr(facts, f.name) for f in dataclasses.fields(UnitFacts)}
    values["controls"] = controls
    values.update(extra)
    return UnitFacts(**values)


SLOT_ENABLERS: dict[str, tuple[int, dict[str, Any]]] = {
    "integrity.basis": (1, {"integrity": IntegrityFact("passed", R("integrity_check", "i"))}),
    "coherence.basis": (1, {"coherence": CoherenceFact("coherent", R("run_record", "h"))}),
    "policy_hold.basis": (1, {"policy_hold": PolicyHoldFact("none", R("policy_record", "p"))}),
    "attempt.basis": (1, {"attempt": AttemptFact("none", None, None, None, None, R("run_record", "a"))}),
    "attempt.liveness_basis": (2, {"attempt": AttemptFact(
        "admitted", "a", clk(0), clk(1), R("attempt_observation", "l"), R("run_record", "a"))}),
    "user_decision.basis": (1, {"user_decision": UserDecisionFact("none_pending", None, R("user_decision_record"))}),
    "wait.absence_basis": (1, {"wait": WaitFact("none", None, R("external_predicate", "w"))}),
    "wait.spec.source": (1, {"wait": WaitFact("waiting", wait_spec(), None)}),
    "obligations.declaration_basis": (1, {"obligations": ObligationFact("none_declared", (), R("obligation_record"))}),
    "readiness.eligibility_basis": (1, {"readiness": ReadinessFact(
        "not_admissible", None, R("readiness_predicate"), "unknown", None, "unknown", None)}),
    "readiness.owner_basis": (1, {"readiness": ReadinessFact(
        "unknown", None, None, "absent", R("run_record", "o"), "unknown", None)}),
    "readiness.authority_basis": (1, {"readiness": ReadinessFact(
        "unknown", None, None, "unknown", None, "denied", R("authority_record"))}),
    "clearance_coverage.basis": (1, {"clearance_coverage": Coverage("complete", R("dependency_assertion", "c"))}),
    "related_holds_coverage.basis": (1, {"related_holds_coverage": Coverage(
        "complete", R("dependency_assertion", "r"))}),
    "failure.basis": (1, {"failure": FailureFact("none", R("failure_record"))}),
    "constraint_conflict.basis": (1, {"constraint_conflict": ConflictFact("none", R("constraint_analysis"))}),
    "phase.basis": (1, {"phase": PhaseObservation("ph", clk(0), PHASE_REF)}),
    "clearance.applicability_basis": (1, {"clearance": (ClearanceCell(
        "p", "r", "applies", R("dependency_assertion", "x"), "unknown", "unknown", "unknown", None),)}),
    "clearance.state_basis": (1, {"clearance": (ClearanceCell(
        "p", "r", "unknown", None, "unknown", "clear", "unknown", R("stop_record", "s")),)}),
    "clearance.both": (2, {"clearance": (ClearanceCell(
        "p", "r", "applies", R("dependency_assertion", "x"), "unknown", "clear", "unknown",
        R("stop_record", "s")),)}),
    "related_holds.relation_basis": (1, {"related_holds": (RelatedHold(
        "h", "dependent", R("dependency_assertion", "d")),)}),
    "claims.basis": (1, {"claims": (ClaimFact("done_claimed", R("agent_claim")),)}),
    "obligations.refs": (2, {"obligations": ObligationFact(
        "pending", (R("obligation_record", "o1"),), R("obligation_record", "d"))}),
}


@pytest.mark.parametrize("slot", sorted(SLOT_ENABLERS))
def test_val21_every_slot_counts_toward_aggregate(slot: str) -> None:
    added, extra = SLOT_ENABLERS[slot]
    assert type(_bare_unknown_facts(AGGREGATE_BASIS_CAP - added, **extra)) is UnitFacts
    assert code_of(lambda: _bare_unknown_facts(AGGREGATE_BASIS_CAP + 1 - added, **extra)) == (
        "too_many_refs"
    )


def test_val21_singular_slot_list_is_complete() -> None:
    singular = {name for name in SLOT_ENABLERS if "." in name} - {
        "clearance.applicability_basis", "clearance.state_basis", "clearance.both",
        "related_holds.relation_basis", "claims.basis", "obligations.refs",
    }
    assert len(singular) == 17


def test_val21_aggregate_63_64_65() -> None:
    for refs, ok in ((63, True), (64, True), (65, False)):
        extra = {"integrity": IntegrityFact("passed", R("integrity_check"))}
        if ok:
            assert type(_bare_unknown_facts(refs - 1, **extra)) is UnitFacts
        else:
            assert code_of(lambda: _bare_unknown_facts(refs - 1, **extra)) == "too_many_refs"


def test_val21_same_ref_in_two_slots_counts_twice() -> None:
    shared = R("run_record", "same")
    extra = {
        "integrity": IntegrityFact("passed", shared), "coherence": CoherenceFact("coherent", shared)
    }
    assert type(_bare_unknown_facts(62, **extra)) is UnitFacts
    assert code_of(lambda: _bare_unknown_facts(63, **extra)) == "too_many_refs"


def test_val21_aggregate_before_payload_semantics() -> None:
    facts = _bare_unknown_facts(64)
    corrupt = R("control_record", "zzz")
    object.__setattr__(corrupt, "ref", "not a token!")
    object.__setattr__(facts.controls, "basis", facts.controls.basis[:-1] + (corrupt,))
    s = spec(**ALL_UNKNOWN)
    assert code_of(lambda: _assess(facts, s)) == "invalid_token"
    object.__setattr__(facts, "integrity", IntegrityFact("passed", R("integrity_check")))
    assert code_of(lambda: _assess(facts, s)) == "too_many_refs"


@pytest.mark.parametrize(
    "path",
    [("controls", "basis"), ("obligations", "refs"), (None, "clearance"), (None, "related_holds"),
     (None, "claims")],
)
def test_val21_local_cap_before_elements(path: tuple[str | None, str]) -> None:
    holder, name = path
    facts = make_facts(spec(**ALL_UNKNOWN))
    target = facts if holder is None else getattr(facts, holder)
    sentinel = tuple(object() for _ in range(LOCAL_TUPLE_CAP + 1))
    object.__setattr__(target, name, sentinel)
    assert code_of(lambda: _assess(facts, spec(**ALL_UNKNOWN))) == "too_many_refs"
    object.__setattr__(target, name, sentinel[:LOCAL_TUPLE_CAP])
    assert code_of(lambda: _assess(facts, spec(**ALL_UNKNOWN))) == "invalid_type"


def test_val21_local_cap_at_constructors() -> None:
    many = tuple(object() for _ in range(LOCAL_TUPLE_CAP + 1))
    assert code_of(lambda: Controls("absent", "absent", "absent", many)) == "too_many_refs"  # type: ignore[arg-type]
    assert code_of(lambda: ObligationFact("pending", many, R("obligation_record"))) == "too_many_refs"  # type: ignore[arg-type]
    cells = tuple(
        ClearanceCell(f"p{i}", "r", "unknown", None, "unknown", "unknown", "unknown", None)
        for i in range(LOCAL_TUPLE_CAP + 1)
    )
    assert code_of(lambda: _bare_unknown_facts(1, clearance=cells)) == "too_many_refs"
    assert type(_bare_unknown_facts(1, clearance=cells[:LOCAL_TUPLE_CAP])) is UnitFacts
    refs64 = tuple(R("obligation_record", f"o{i:02d}") for i in range(LOCAL_TUPLE_CAP))
    assert ObligationFact("pending", refs64, R("obligation_record", "d"))


# =========================================================================== VAL-22


def test_val22_advice_never_recommends_new_effect() -> None:
    allowed = {"none", "observe", "review_integrity", "review_unresolved_outcome",
               "review_clearance", "review_policy"}
    for s in gen_p() + gen_g():
        result = run(s)
        if type(result) is Assessed and result.state in ("paused_policy", "stalled"):
            assert result.hint in allowed


def test_val22_failed_work_is_not_completion() -> None:
    failed = run(spec(obligations="all_satisfied", eligibility="not_admissible",
                      failure="recoverable_classified"))
    assert projection(failed) == D("recovery_evaluation", "recovery_not_in_slice")
    unknown = run(spec(obligations="all_satisfied", eligibility="not_admissible", failure="unknown"))
    assert projection(unknown) == I("failure_unknown")


# =========================================================================== VAL-23

PINNED = {
    "src/unrest_harness/continuation_types.py":
        "af2efdfebbfa8208c986ded2bea681b0bffb4259b41b51b6c11f6e382b87e92b",
    "src/unrest_harness/continuation_reservations.py":
        "5ca0c85f5b0e6d79558e111f7b876d44217a3810f0eed42776ebedecce40e354",
    "src/unrest_harness/runtime_observability.py":
        "53dd39fbd39f1fe23ddfeb469e93e8cf79090e4b55c602588ef46ab009ed5048",
    "src/unrest_harness/supervision.py":
        "8a6983b504b95748da57305e6bb76f136fd3ad8d752b0657fc0d22669e689d23",
    "src/unrest_harness/foundation_tools.py":
        "b6925fed1c9be7b79b0ed76b517bdd9a1d2bd156d7111008862c9cedaca70df3",
    "src/unrest_harness/server.py":
        "d1abbe2f76ff874849d113919777efe1ccb8fee0a6327d5eaf27e87892fd886f",
    "src/unrest_harness/cli.py":
        "3c29151a7d66a33a6b269db7cfece6c2cb23c69a1f046b63989e5ce97dc0b648",
    "tests/test_run_control.py":
        "13ad6766039059c212f53d615e7521e67fce69bfd0e329c4ae63ea28a7b88fcf",
    "tests/test_mutation_journal.py":
        "dbaec57f5937ce7583c1de5819ee87b55dd30f45d8e4a3cc0c2d8d9b1607ea49",
    "tests/test_server.py":
        "0550689ff20fb183ea62b47606bd3e66c5fc1222b5d4166e57e74d546afbb286",
    "tests/test_run_stop_custody.py":
        "f4dd95cd2d8b066246a35a5e02686abcda1b9db4239152c1f9a77d259f8e5c4a",
    "tests/test_run_receipt_golden.py":
        "1c5d9b44cb4806e104cfef71f0de4dc41f9b10f120f23a5d3f0d1d4de96b142d",
    "uv.lock": "d7dcea4ddefcfbe87a58f83edee8be33dd612cb92f6b9dcdc5e11de5982b56d7",
    "tests/test_run_admission_recovery.py":
        "7428ed7475b139453d3a3d682ff8c1fd4c0eb2815013ba4f8fa1c6fc7f671c2d",
    "tests/test_run_record_strictness.py":
        "dd9b349ce1d8337347688155b5649271000e8ef6d38e3381b584855dc2c174aa",
}


@pytest.mark.parametrize("relative", sorted(PINNED))
def test_val23_inert_manifest(relative: str) -> None:
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    assert digest == PINNED[relative]


def test_val23_component_and_index_registration() -> None:
    import json

    document = json.loads((ROOT / "docs/architecture/component-map.json").read_text("utf-8"))
    entry = next(i for i in document["components"] if i["id"] == "COMP-CONTINUATION")
    assert "src/unrest_harness/continuation_state.py" in entry["paths"]
    assert "docs/architecture/continuation-state.md" in entry["specifications"]
    assert "tests/test_continuation_state.py" in entry["tests"]
    for field in ("paths", "specifications", "tests"):
        assert entry[field] == sorted(entry[field])
    index = (ROOT / "docs/architecture/index.md").read_text(encoding="utf-8")
    assert index.count("(continuation-state.md)") == 1


# =========================================================================== VAL-24


def render(result: object) -> str:
    """Test-only deterministic renderer of the full projection (not a codec)."""
    parts = [f"{f.name}={getattr(result, f.name)!r}" for f in dataclasses.fields(result)]  # type: ignore[arg-type]
    return f"{type(result).__name__}(" + ", ".join(parts) + ")"


def test_val24_goldens() -> None:
    assert render(run(spec(**ALL_UNKNOWN))) == (
        "Indeterminate(code='control_unknown', reasons=('attempt_unknown', "
        "'authority_unknown', 'clearance_coverage_unknown', 'coherence_unknown', 'conflict_unknown', "
        "'control_unknown', 'failure_unknown', 'integrity_unknown', 'obligations_unknown', "
        "'owner_unknown', 'policy_unknown', 'readiness_unknown', 'related_holds_coverage_unknown', "
        "'user_decision_unknown', 'wait_unknown'), claims=(), basis=(), tag='indeterminate', "
        "hint='facts_required')"
    )
    golden = run(spec(policy="held", claims=("done_claimed",), eligibility="not_admissible"))
    assert render(golden) == (
        "Assessed(state='paused_policy', primary_reason='policy_hold', hint='review_policy', "
        "reasons=('policy_hold',), liveness='not_applicable', claims=('done_claimed',), basis=("
        "BasisRef(source_kind='authority_record', ref='auth'), "
        "BasisRef(source_kind='constraint_analysis', ref='con'), "
        "BasisRef(source_kind='control_record', ref='ctl'), "
        "BasisRef(source_kind='dependency_assertion', ref='ccov'), "
        "BasisRef(source_kind='dependency_assertion', ref='rcov'), "
        "BasisRef(source_kind='external_predicate', ref='absent'), "
        "BasisRef(source_kind='failure_record', ref='fail'), "
        "BasisRef(source_kind='integrity_check', ref='int'), "
        "BasisRef(source_kind='obligation_record', ref='decl'), "
        "BasisRef(source_kind='policy_record', ref='pol'), "
        "BasisRef(source_kind='readiness_predicate', ref='el'), "
        "BasisRef(source_kind='run_record', ref='att'), "
        "BasisRef(source_kind='run_record', ref='coh'), "
        "BasisRef(source_kind='run_record', ref='own'), "
        "BasisRef(source_kind='user_decision_record', ref='ud')), tag='assessed')"
    )
    deferred = run(spec(conflict="asserted"))
    assert render(deferred).startswith(
        "Deferred(feature='impossibility_evaluation', reason='constraint_conflict_requires_dossier', "
        "reasons=('constraint_conflict_asserted',), claims=(), basis=("
    )
    assert render(deferred).endswith("tag='deferred', hint='evaluation_deferred')")


def test_val24_no_codec_surface() -> None:
    for name in ("encode", "decode", "encode_value", "to_json", "from_json", "dumps", "loads"):
        assert not hasattr(cs, name)
    assert not [n for n in cs.__all__ if "encode" in n or "decode" in n]


# =========================================================================== VAL-25


def test_val25_state_001_scenarios() -> None:
    quota = run(spec(wait="waiting"))
    assert projection(quota)[1] == "waiting_external"
    decision = run(spec(user="pending", user_kind="access_decision_required"))
    assert projection(decision) == A("needs_user", "access_decision_required", "user_decision_required")
    setup = run(spec(failure="recoverable_classified"))
    assert projection(setup) == D("recovery_evaluation", "recovery_not_in_slice")
    hung = run(spec(attempt="admitted", now=PROGRESS + 1))
    assert projection(hung) == A("stalled", "progress_deadline_elapsed", "observe")
    assert "attempt_admitted" in hung.reasons
    conflict = run(spec(conflict="asserted"))
    assert projection(conflict) == D("impossibility_evaluation", "constraint_conflict_requires_dossier")


# =========================================================================== VAL-26

X = R("run_record", "x")
MATRIX: list[tuple[str, Callable[[], object], str | None]] = [
    ("controls known basis", lambda: Controls("absent", "unknown", "unknown", (R("control_record"),)), None),
    ("controls known empty", lambda: Controls("absent", "unknown", "unknown", ()), "detail_mismatch"),
    ("controls unknown basis", lambda: Controls("unknown", "unknown", "unknown", (R("control_record"),)),
     "detail_mismatch"),
    ("controls kind", lambda: Controls("absent", "absent", "absent", (X,)), "source_kind_not_allowed"),
    ("controls dup", lambda: Controls("absent", "absent", "absent", (R("control_record"),) * 2),
     "duplicate_entry"),
    ("controls singular", lambda: Controls("absent", "absent", "absent", R("control_record")),  # type: ignore[arg-type]
     "invalid_type"),
    ("integrity unknown basis", lambda: IntegrityFact("unknown", R("integrity_check")), "detail_mismatch"),
    ("integrity known none", lambda: IntegrityFact("refused", None), "detail_mismatch"),
    ("integrity tuple", lambda: IntegrityFact("passed", (R("integrity_check"),)), "invalid_type"),  # type: ignore[arg-type]
    ("integrity enum", lambda: IntegrityFact("ok", R("integrity_check")), "invalid_enum"),
    ("coherence kind", lambda: CoherenceFact("coherent", R("gate_verdict")), "source_kind_not_allowed"),
    ("coherence known none", lambda: CoherenceFact("inconsistent", None), "detail_mismatch"),
    ("policy known none", lambda: PolicyHoldFact("none", None), "detail_mismatch"),
    ("policy unknown basis", lambda: PolicyHoldFact("unknown", R("policy_record")), "detail_mismatch"),
    ("attempt none ok", lambda: AttemptFact("none", None, None, None, None, X), None),
    ("attempt none admission", lambda: AttemptFact("none", None, None, None, None, R("admission_record")), None),
    ("attempt none no basis", lambda: AttemptFact("none", None, None, None, None, None), "detail_mismatch"),
    ("attempt none detail", lambda: AttemptFact("none", "a", None, None, None, X), "detail_mismatch"),
    ("attempt none liveness", lambda: AttemptFact("none", None, None, clk(1), None, X), "detail_mismatch"),
    ("attempt none liveness basis", lambda: AttemptFact(
        "none", None, None, None, R("attempt_observation"), X), "detail_mismatch"),
    ("attempt admitted ok", lambda: AttemptFact("admitted", "a", clk(0), None, None, X), None),
    ("attempt admitted admission kind", lambda: AttemptFact(
        "admitted", "a", clk(0), None, None, R("admission_record")), "source_kind_not_allowed"),
    ("attempt admitted no ref", lambda: AttemptFact("admitted", None, clk(0), None, None, X),
     "detail_mismatch"),
    ("attempt admitted no start", lambda: AttemptFact("admitted", "a", None, None, None, X),
     "detail_mismatch"),
    ("attempt liveness unpaired", lambda: AttemptFact("admitted", "a", clk(0), clk(1), None, X),
     "detail_mismatch"),
    ("attempt basis unpaired", lambda: AttemptFact(
        "admitted", "a", clk(0), None, R("attempt_observation"), X), "detail_mismatch"),
    ("attempt liveness kind", lambda: AttemptFact("admitted", "a", clk(0), clk(1), X, X),
     "source_kind_not_allowed"),
    ("attempt unknown basis", lambda: AttemptFact("unknown", None, None, None, None, X), "detail_mismatch"),
    ("attempt liveness tuple", lambda: AttemptFact(
        "admitted", "a", clk(0), clk(1), (R("attempt_observation"),), X), "invalid_type"),  # type: ignore[arg-type]
    ("user none_pending kind", lambda: UserDecisionFact("none_pending", "scope_decision_required",
                                                        R("user_decision_record")), "detail_mismatch"),
    ("user pending no kind", lambda: UserDecisionFact("pending", None, R("user_decision_record")),
     "detail_mismatch"),
    ("user pending bad kind", lambda: UserDecisionFact("pending", "money", R("user_decision_record")),
     "invalid_enum"),
    ("user unknown basis", lambda: UserDecisionFact("unknown", None, R("user_decision_record")),
     "detail_mismatch"),
    ("user known no basis", lambda: UserDecisionFact("none_pending", None, None), "detail_mismatch"),
    ("wait none no basis", lambda: WaitFact("none", None, None), "detail_mismatch"),
    ("wait none spec", lambda: WaitFact("none", wait_spec(), R("external_predicate")), "detail_mismatch"),
    ("wait waiting basis", lambda: WaitFact("waiting", wait_spec(), R("external_predicate")),
     "detail_mismatch"),
    ("wait waiting no spec", lambda: WaitFact("waiting", None, None), "detail_mismatch"),
    ("wait unknown basis", lambda: WaitFact("unknown", None, R("external_predicate")), "detail_mismatch"),
    ("wait source kind", lambda: WaitSpec("p", X, clk(0), clk(0), DurationMs(1)), "source_kind_not_allowed"),
    ("obl pending empty", lambda: ObligationFact("pending", (), R("obligation_record")), "detail_mismatch"),
    ("obl pending verdict kind", lambda: ObligationFact("pending", (R("validator_verdict"),),
                                                        R("obligation_record")), "source_kind_not_allowed"),
    ("obl satisfied obligation kind", lambda: ObligationFact(
        "all_satisfied", (R("obligation_record"),), R("obligation_record")), "source_kind_not_allowed"),
    ("obl satisfied gate", lambda: ObligationFact(
        "all_satisfied", (R("gate_verdict"),), R("obligation_record")), None),
    ("obl none_declared refs", lambda: ObligationFact(
        "none_declared", (R("obligation_record"),), R("obligation_record")), "detail_mismatch"),
    ("obl none_declared no decl", lambda: ObligationFact("none_declared", (), None), "detail_mismatch"),
    ("obl unknown decl", lambda: ObligationFact("unknown", (), R("obligation_record")), "detail_mismatch"),
    ("obl unknown refs", lambda: ObligationFact("unknown", (R("obligation_record"),), None),
     "detail_mismatch"),
    ("readiness admissible no kind", lambda: ReadinessFact(
        "admissible", None, R("readiness_predicate"), "absent", X, "within_existing", R("authority_record")),
     "detail_mismatch"),
    ("readiness not_admissible kind", lambda: ReadinessFact(
        "not_admissible", "planned_task", R("readiness_predicate"), "absent", X, "within_existing",
        R("authority_record")), "detail_mismatch"),
    ("readiness recovery kind", lambda: ReadinessFact(
        "admissible", "recovery", R("readiness_predicate"), "absent", X, "within_existing",
        R("authority_record")), "invalid_enum"),
    ("readiness owner unknown basis", lambda: ReadinessFact(
        "unknown", None, None, "unknown", X, "unknown", None), "detail_mismatch"),
    ("readiness owner known none", lambda: ReadinessFact(
        "unknown", None, None, "present", None, "unknown", None), "detail_mismatch"),
    ("readiness authority kind", lambda: ReadinessFact(
        "unknown", None, None, "unknown", None, "denied", X), "source_kind_not_allowed"),
    ("readiness eligibility unknown basis", lambda: ReadinessFact(
        "unknown", None, R("readiness_predicate"), "unknown", None, "unknown", None), "detail_mismatch"),
    ("coverage complete no basis", lambda: Coverage("complete", None), "detail_mismatch"),
    ("coverage unknown basis", lambda: Coverage("unknown", R("dependency_assertion")), "detail_mismatch"),
    ("cell applies no basis", lambda: ClearanceCell(
        "p", "r", "applies", None, "unknown", "unknown", "unknown", None), "detail_mismatch"),
    ("cell unknown applicability basis", lambda: ClearanceCell(
        "p", "r", "unknown", R("dependency_assertion"), "unknown", "unknown", "unknown", None),
     "detail_mismatch"),
    ("cell na no basis", lambda: ClearanceCell(
        "p", "r", "not_applicable", None, "not_applicable", "unknown", "unknown", None),
     "detail_mismatch"),
    ("cell na basis", lambda: ClearanceCell(
        "p", "r", "not_applicable", R("stop_record"), "not_applicable", "unknown", "unknown", None),
     None),
    ("cell state no basis", lambda: ClearanceCell(
        "p", "r", "unknown", None, "unknown", "clear", "unknown", None), "detail_mismatch"),
    ("cell state basis forbidden", lambda: ClearanceCell(
        "p", "r", "unknown", None, "unknown", "unknown", "unknown", R("stop_record")), "detail_mismatch"),
    ("cell state kind", lambda: ClearanceCell(
        "p", "r", "unknown", None, "unknown", "clear", "settled", R("dependency_assertion")),
     "source_kind_not_allowed"),
    ("cell settlement", lambda: ClearanceCell(
        "p", "r", "unknown", None, "done", "unknown", "unknown", None), "invalid_enum"),
    ("hold known no basis", lambda: RelatedHold("h", "independent", None), "detail_mismatch"),
    ("hold unknown basis", lambda: RelatedHold("h", "unknown", R("dependency_assertion")), "detail_mismatch"),
    ("failure known none", lambda: FailureFact("recoverable_classified", None), "detail_mismatch"),
    ("conflict kind", lambda: ConflictFact("asserted", R("failure_record")), "source_kind_not_allowed"),
    ("phase kind", lambda: PhaseObservation("ph", clk(0), X), "source_kind_not_allowed"),
    ("phase none basis", lambda: PhaseObservation("ph", clk(0), None), "invalid_type"),  # type: ignore[arg-type]
    ("claim none basis", lambda: ClaimFact("done_claimed", None), "invalid_type"),  # type: ignore[arg-type]
]


@pytest.mark.parametrize(
    ("label", "factory", "code"), MATRIX, ids=[m[0].replace(" ", "-") for m in MATRIX]
)
def test_val26_status_detail_basis_matrix(
    label: str, factory: Callable[[], object], code: str | None
) -> None:
    if code is None:
        assert factory() is not None
    else:
        assert code_of(factory) == code


SINGULAR_ROLES = [
    ("integrity", "basis"), ("coherence", "basis"), ("policy_hold", "basis"), ("attempt", "basis"),
    ("attempt", "liveness_basis"), ("user_decision", "basis"), ("wait", "absence_basis"),
    ("wait", "spec.source"), ("obligations", "declaration_basis"),
    ("readiness", "eligibility_basis"), ("readiness", "owner_basis"),
    ("readiness", "authority_basis"), ("clearance_coverage", "basis"),
    ("related_holds_coverage", "basis"), ("failure", "basis"), ("constraint_conflict", "basis"),
    ("phase", "basis"), ("clearance[0]", "applicability_basis"), ("clearance[0]", "state_basis"),
    ("related_holds[0]", "relation_basis"), ("claims[0]", "basis"),
]


@pytest.mark.parametrize(("holder", "slot"), SINGULAR_ROLES, ids=[f"{h}.{s}" for h, s in SINGULAR_ROLES])
def test_val26_tuple_in_any_singular_role_is_invalid_type(holder: str, slot: str) -> None:
    s = spec(attempt="admitted", liveness=50, wait="none", cells="clean-applies",
             related="independent", claims=("done_claimed",), phase="active")
    facts = make_facts(s)
    if holder.endswith("[0]"):
        target = getattr(facts, holder[:-3])[0]
    else:
        target = getattr(facts, holder)
    if slot == "spec.source":
        facts = dataclasses.replace(facts, wait=WaitFact("waiting", wait_spec(), None))
        target, slot = facts.wait.spec, "source"
    current = getattr(target, slot)
    assert type(current) is BasisRef
    object.__setattr__(target, slot, (current,))
    assert code_of(lambda: assess_unit(facts, make_frontier(s), make_profile(s), clk(s["now"]))) == (
        "invalid_type"
    )


def test_val26_liveness_before_start_is_refused() -> None:
    s = spec(attempt="admitted", attempt_start=100, liveness=50)
    assert code_of(lambda: run(s)) == "detail_mismatch"


def test_val26_attempt_before_frontier_start_is_refused() -> None:
    s = spec(attempt="admitted")
    facts = make_facts(s)
    assert code_of(lambda: assess_unit(facts, empty_frontier(10), make_profile(s), clk(2000))) == (
        "detail_mismatch"
    )


# Amendment-2 §2: the five roles typed ``BasisRef`` (never ``| None``) refuse
# ``None`` as ``invalid_type`` in constructors and on revalidation alike;
# conditional ``BasisRef | None`` roles keep R5 (``detail_mismatch``).
UNCONDITIONAL_NONE: list[tuple[str, Callable[[], object]]] = [
    ("WaitSpec.source",
     lambda: WaitSpec("p", None, clk(0), clk(0), DurationMs(1))),  # type: ignore[arg-type]
    ("PhaseObservation.basis",
     lambda: PhaseObservation("ph", clk(0), None)),  # type: ignore[arg-type]
    ("PhaseEnvelope.source",
     lambda: PhaseEnvelope("ph", None, clk(0), DurationMs(4), DurationMs(4))),  # type: ignore[arg-type]
    ("ClaimFact.basis",
     lambda: ClaimFact("done_claimed", None)),  # type: ignore[arg-type]
    ("ProgressClaim.basis",
     lambda: ProgressClaim(
         B, EvidenceId("ev-1"), 1, clk(0), "assertion_satisfied", ACCEPT_KEY, None,
         None)),  # type: ignore[arg-type]
]


@pytest.mark.parametrize(
    ("label", "factory"), UNCONDITIONAL_NONE, ids=[u[0] for u in UNCONDITIONAL_NONE]
)
def test_val26_unconditional_basis_none_constructor_is_invalid_type(
    label: str, factory: Callable[[], object]
) -> None:
    assert code_of(factory) == "invalid_type"


def _none_in(role: str) -> Callable[[], object]:
    s = spec(attempt="admitted", phase="active", claims=("done_claimed",), acceptance=1_000)
    facts, frontier, profile = make_facts(s), make_frontier(s), make_profile(s)
    if role == "wait.spec.source":
        facts = dataclasses.replace(facts, wait=WaitFact("waiting", wait_spec(), None))
        assert facts.wait.spec is not None
        object.__setattr__(facts.wait.spec, "source", None)
    elif role == "phase.basis":
        object.__setattr__(facts.phase, "basis", None)
    elif role == "profile.phase.source":
        object.__setattr__(profile.phase, "source", None)
    elif role == "claims[0].basis":
        object.__setattr__(facts.claims[0], "basis", None)
    elif role == "frontier.seen[0].basis":
        object.__setattr__(frontier.seen[0], "basis", None)
    elif role == "advance.claim.basis":
        claim = accept_claim(2, 1_500)
        object.__setattr__(claim, "basis", None)
        return lambda: advance_progress(frontier, claim)
    elif role == "integrity.basis":
        object.__setattr__(facts.integrity, "basis", None)
    else:
        assert role == "attempt.basis"
        object.__setattr__(facts.attempt, "basis", None)
    return lambda: assess_unit(facts, frontier, profile, clk(s["now"]))


@pytest.mark.parametrize(
    ("role", "code"),
    [
        ("wait.spec.source", "invalid_type"),
        ("phase.basis", "invalid_type"),
        ("profile.phase.source", "invalid_type"),
        ("claims[0].basis", "invalid_type"),
        ("frontier.seen[0].basis", "invalid_type"),
        ("advance.claim.basis", "invalid_type"),
        ("integrity.basis", "detail_mismatch"),
        ("attempt.basis", "detail_mismatch"),
    ],
)
def test_val26_none_basis_on_revalidation(role: str, code: str) -> None:
    assert code_of(_none_in(role)) == code


# =========================================================================== VAL-27


def test_val27_coverage_is_explicit() -> None:
    assert projection(run(spec(clearance_cov="unknown")))[:2] != ("assessed", "ready")
    assert projection(run(spec(related_cov="unknown")))[:2] != ("assessed", "ready")
    assert projection(run(spec()))[1] == "ready"
    partial = run(spec(clearance_cov="complete", cells="unknown-applicability-clean"))
    assert projection(partial)[1] == "ready"
    for row in ("C1", "C2", "C3"):
        result = run(spec(**T_ROWS[row], clearance_cov="unknown", related_cov="unknown"))
        assert type(result) is Assessed and result.state != "ready"


# =========================================================================== VAL-28


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"controls": "cancel"}, A("paused_policy", "cancel_requested", "none")),
        ({"integrity": "refused"}, A("paused_policy", "integrity_refused", "review_integrity")),
        ({"cells": "outcome-unresolved-applies"},
         A("paused_policy", "outcome_unresolved", "review_unresolved_outcome")),
        ({"related": "dependent"}, A("paused_policy", "dependency_on_held_unit", "none")),
        ({"authority": "denied"}, A("paused_policy", "authority_denied", "none")),
        ({"owner": "present"}, A("paused_policy", "other_owner_present", "none")),
    ],
)
@pytest.mark.parametrize("age", [OBS - 1, OBS, OBS + 1])
def test_val28_stale_known_negative_keeps_headline(
    overrides: dict[str, Any], expected: tuple[str, ...], age: int
) -> None:
    result = run(spec(**overrides, age=age))
    assert projection(result) == expected
    assert ("stale_observation" in result.reasons) == (age >= OBS)


@pytest.mark.parametrize(
    "overrides",
    [{}, {"related": "dependent", "eligibility": "not_admissible"}, {"attempt": "admitted"},
     {"owner": "present", "wait": "waiting"}],
)
@pytest.mark.parametrize("age", [OBS - 1, OBS, OBS + 1])
def test_val28_other_stale_is_indeterminate(overrides: dict[str, Any], age: int) -> None:
    result = run(spec(**overrides, age=age))
    if age >= OBS:
        assert projection(result) == I("stale_observation")
    else:
        assert type(result) is not Indeterminate or result.code != "stale_observation"


# =========================================================================== VAL-29


def test_val29_basis_is_distinct_sorted_and_excludes_claims() -> None:
    result = run(spec(claims=("done_claimed",), related="dependent", cells="clean-applies"))
    keys = [(b.source_kind, b.ref) for b in result.basis]
    assert keys == sorted(set(keys))
    assert all(b.source_kind != "agent_claim" for b in result.basis)
    assert ("dependency_assertion", "rel-0") in keys and ("stop_record", "st-0") in keys
    shared = R("run_record", "same")
    facts = dataclasses.replace(
        make_facts(DEFAULT),
        integrity=IntegrityFact("passed", shared), coherence=CoherenceFact("coherent", shared),
    )
    shared_basis = _assess(facts).basis  # type: ignore[attr-defined]
    assert sum(1 for b in shared_basis if b == shared) == 1


def test_val29_g_codes_are_fact_level() -> None:
    working = run(spec(attempt="admitted", related="dependent", authority="denied", owner="present"))
    assert projection(working) == A("working", "attempt_admitted", "observe")
    assert {"dependency_on_held_unit", "authority_denied", "other_owner_present"} <= set(working.reasons)
    r2 = run(spec(eligibility="not_admissible", related="dependent"))
    assert projection(r2) == I("no_classifiable_condition")
    assert "dependency_on_held_unit" in r2.reasons


def test_val29_every_variant_has_explicit_hint() -> None:
    assert [f.name for f in dataclasses.fields(Indeterminate)][-1] == "hint"
    assert [f.name for f in dataclasses.fields(Deferred)][-1] == "hint"
    indeterminate = run(spec(wait="unknown"))
    deferred = run(spec(failure="recoverable_classified"))
    assessed = run(spec())
    assert (type(indeterminate), indeterminate.hint) == (Indeterminate, "facts_required")
    assert (type(deferred), deferred.hint) == (Deferred, "evaluation_deferred")
    assert (type(assessed), assessed.hint) == (Assessed, "consider_existing_transition")


def test_val29_reasons_rules_fixed_cases() -> None:
    p = run(spec(policy="held", controls="pause"))
    assert set(p.reasons) == {"pause_requested", "policy_hold"}
    stalled = run(spec(obligations="pending", now=PROGRESS))
    assert stalled.reasons == ("progress_deadline_elapsed", "verification_pending")
    deferred = run(spec(failure="recoverable_classified"))
    assert deferred.reasons == ("recoverable_failure_known",)
    indeterminate = run(spec(wait="unknown"))
    assert indeterminate.reasons == ("wait_unknown",)
    hard_only = run(spec(wait="unknown", obligations="pending", now=HARD))
    assert hard_only.reasons == ("hard_deadline_elapsed", "wait_unknown")


# Amendment-2 §4: one exact fixed case per diagnostic code (rules 5, 6 and 8 of
# §5.6), each with a counterfactual that removes exactly the triggering fact.
DIAGNOSTIC_LITERAL = (
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
)
NA: dict[str, Any] = {"eligibility": "not_admissible"}
OUT, CLR = "outcome-unresolved-applies", "clearance-unresolved-applies"
DIAGNOSTIC_CASES: list[tuple[str, str, dict[str, Any], set[str], dict[str, Any], set[str]]] = [
    ("satisfied", "obligations_satisfied_during_attempt",
     {"attempt": "admitted", "obligations": "all_satisfied", **NA},
     {"obligations_satisfied_during_attempt"},
     {"attempt": "none", "obligations": "all_satisfied", **NA}, set()),
    ("admissible", "transition_admissible_during_attempt",
     {"attempt": "admitted"}, {"transition_admissible_during_attempt"},
     {"attempt": "admitted", **NA}, set()),
    ("pending", "obligations_pending_during_attempt",
     {"attempt": "admitted", "obligations": "pending", **NA},
     {"obligations_pending_during_attempt"},
     {"attempt": "none", "obligations": "pending", **NA}, set()),
    ("during-wait", "attempt_admitted_during_wait",
     {"attempt": "admitted", "wait": "waiting", "now": WAIT_NEXT - 1, **NA},
     {"attempt_admitted_during_wait"},
     {"attempt": "none", "wait": "waiting", "now": WAIT_NEXT - 1, **NA}, set()),
    ("outcome-admitted", "proposed_transition_outcome_unresolved",
     {"attempt": "admitted", "cells": OUT, **NA}, {"proposed_transition_outcome_unresolved"},
     {"attempt": "none", "cells": OUT, **NA}, set()),
    ("clearance-admitted", "proposed_transition_clearance_unresolved",
     {"attempt": "admitted", "cells": CLR, **NA}, {"proposed_transition_clearance_unresolved"},
     {"attempt": "none", "cells": CLR, **NA}, set()),
    ("outcome-attempt-unknown", "proposed_transition_outcome_unresolved",
     {"attempt": "unknown", "cells": OUT, **NA}, {"proposed_transition_outcome_unresolved"},
     {"attempt": "admitted", "cells": "na-unresolved", **NA}, set()),
    ("clearance-attempt-unknown", "proposed_transition_clearance_unresolved",
     {"attempt": "unknown", "cells": CLR, **NA}, {"proposed_transition_clearance_unresolved"},
     {"attempt": "admitted", "cells": "na-unresolved", **NA}, set()),
    ("exemption", "phase_exemption_active",
     {"attempt": "admitted", "phase": "active", "now": PROGRESS, **NA}, {"phase_exemption_active"},
     {"attempt": "admitted", "phase": "f1", "now": PROGRESS, **NA}, {"phase_not_applicable"}),
    ("not-applicable", "phase_not_applicable",
     {"attempt": "admitted", "phase": "f1", **NA}, {"phase_not_applicable"},
     {"attempt": "admitted", **NA}, set()),
    ("recoverable", "recoverable_failure_known",
     {"failure": "recoverable_classified"}, {"recoverable_failure_known"}, {}, set()),
    ("conflict", "constraint_conflict_asserted",
     {"conflict": "asserted"}, {"constraint_conflict_asserted"}, {}, set()),
    ("due", "external_observation_due",
     {"wait": "waiting", "now": WAIT_NEXT}, {"external_observation_due"},
     {"wait": "waiting", "now": WAIT_NEXT - 1}, set()),
]


def test_val29_diagnostic_cases_cover_every_code() -> None:
    assert frozenset(DIAGNOSTIC_LITERAL) == cs.DIAGNOSTIC_CODES
    assert {case[1] for case in DIAGNOSTIC_CASES} == set(DIAGNOSTIC_LITERAL)


@pytest.mark.parametrize(
    ("label", "code", "trigger", "expected", "counter", "counter_expected"),
    DIAGNOSTIC_CASES,
    ids=[case[0] for case in DIAGNOSTIC_CASES],
)
def test_val29_diagnostic_exact_case(
    label: str, code: str, trigger: dict[str, Any], expected: set[str],
    counter: dict[str, Any], counter_expected: set[str],
) -> None:
    assert code in expected and code not in counter_expected
    assert set(run(spec(**trigger)).reasons) & set(DIAGNOSTIC_LITERAL) == expected
    assert set(run(spec(**counter)).reasons) & set(DIAGNOSTIC_LITERAL) == counter_expected


# =========================================================================== VAL-30


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_val30_generator_matches_oracle(name: str) -> None:
    assert_oracle(GENERATORS[name]())


def test_val30_oracle_rows_are_all_exercised() -> None:
    rows: set[str] = set()
    for name in GENERATORS:
        rows |= {oracle(s)[0] for s in GENERATORS[name]()}
    rows |= {oracle(spec(cells=(t,), attempt=a))[0] for t in TRIPLES for a in ("none", "admitted", "unknown")}
    assert rows == {
        "P-k1", "P-k2", "P-k3", "P-k4", "P-k5", "P-k6", "P-k7", "P-k8", "G-g1", "G-g2", "G-g3",
        "I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "N1", "C1", "C1u", "C2", "C2u",
        "C3", "C3u", "X1", "X2", "X3", "X4", "R1", "R2c", "R2n", "R3a", "R3b", "R3c", "R3d",
        "R3e", "C4",
    }


# =========================================================================== VAL-31


def test_val31_gen_g_matches_oracle() -> None:
    specs = gen_g()
    assert len(specs) == 495
    assert_oracle(specs)


def test_val31_g_star_precedes_unknown_conflict() -> None:
    result = run(spec(related="dependent", conflict="unknown"))
    assert projection(result) == A("paused_policy", "dependency_on_held_unit", "none")
    assert "conflict_unknown" in result.reasons
    asserted = run(spec(related="dependent", conflict="asserted"))
    assert projection(asserted)[2] == "dependency_on_held_unit"
    assert "constraint_conflict_asserted" in asserted.reasons
    recov = run(spec(owner="present", failure="recoverable_classified"))
    assert projection(recov)[2] == "other_owner_present"
    assert "recoverable_failure_known" in recov.reasons


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"user": "unknown"}, I("user_decision_unknown")),
        ({"wait": "unknown"}, I("wait_unknown")),
        ({"attempt": "unknown"}, I("attempt_unknown")),
        ({"obligations": "unknown"}, I("obligations_unknown")),
        ({"eligibility": "unknown"}, I("readiness_unknown")),
        ({"user": "pending"}, A("needs_user", "scope_decision_required", "user_decision_required")),
        ({"wait": "waiting"}, A("waiting_external", "external_dependency", "external_observation_due")),
        ({"attempt": "admitted"}, A("working", "attempt_admitted", "observe")),
        ({"obligations": "pending"}, A("verifying", "verification_pending", "verification_required")),
        ({"eligibility": "not_admissible"}, I("no_classifiable_condition")),
    ],
)
def test_val31_k_field_exclusions(overrides: dict[str, Any], expected: tuple[str, ...]) -> None:
    result = run(spec(**overrides, related="dependent"))
    assert projection(result) == expected


@pytest.mark.parametrize(
    ("overrides", "code"),
    [({"controls": "cancel-unknown"}, "control_unknown"), ({"integrity": "unknown"}, "integrity_unknown"),
     ({"coherence": "unknown"}, "coherence_unknown"), ({"policy": "unknown"}, "policy_unknown"),
     ({"cells": "unknown-applicability-unclean"}, "applicability_unknown"),
     ({"cells": "applies-state-unknown"}, "clearance_unknown"), ({"age": OBS}, "stale_observation")],
)
def test_val31_g_star_precedes_i_rows(overrides: dict[str, Any], code: str) -> None:
    result = run(spec(**overrides, related="dependent"))
    assert projection(result) == A("paused_policy", "dependency_on_held_unit", "none")
    assert code in result.reasons


def test_val31_partial_known_dependency_with_unknown_coverage() -> None:
    result = run(spec(related="dependent+unknown", related_cov="unknown", clearance_cov="unknown"))
    assert projection(result) == A("paused_policy", "dependency_on_held_unit", "none")
    assert {"independence_unknown", "related_holds_coverage_unknown"} <= set(result.reasons)


def test_val31_g_priority_and_p_first() -> None:
    assert projection(run(spec(related="dependent", authority="denied", owner="present")))[2] == (
        "dependency_on_held_unit"
    )
    assert projection(run(spec(related="dependent", authority="denied")))[2] == (
        "dependency_on_held_unit"
    )
    assert projection(run(spec(related="dependent", owner="present")))[2] == (
        "dependency_on_held_unit"
    )
    assert projection(run(spec(authority="denied", owner="present")))[2] == "authority_denied"
    assert projection(run(spec(owner="present")))[2] == "other_owner_present"
    assert projection(run(spec(controls="cancel", related="dependent")))[2] == "cancel_requested"


def test_val31_k_without_g_takes_ordinary_path() -> None:
    assert projection(run(spec(conflict="unknown"))) == I("conflict_unknown")
    assert projection(run(spec(failure="recoverable_classified"))) == D(
        "recovery_evaluation", "recovery_not_in_slice"
    )
    assert projection(run(spec()))[1] == "ready"


# =========================================================================== VAL-32

HARD_DOMAIN = {
    "C1u+admitted": I("wait_unknown"),
    "C1u+none+pending": I("wait_unknown"),
    "C1u+unknown+pending": I("wait_unknown"),
    "C2u+pending": I("attempt_unknown"),
}


@pytest.mark.parametrize("row", sorted(HARD_DOMAIN))
@pytest.mark.parametrize("now", [HARD - 1, HARD, HARD + 1])
def test_val32_hard_only_threshold(row: str, now: int) -> None:
    result = run(spec(**T_ROWS[row], now=now, acceptance=7_000))
    if now < HARD:
        assert projection(result) == HARD_DOMAIN[row]
    else:
        assert projection(result) == A("stalled", "hard_deadline_elapsed", "observe")


@pytest.mark.parametrize("row", sorted(HARD_DOMAIN))
def test_val32_old_anchor_before_hard_is_not_progress_stalled(row: str) -> None:
    result = run(spec(**T_ROWS[row], now=HARD - 1, acceptance=None))
    assert projection(result) == HARD_DOMAIN[row]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"wait": "unknown", "obligations": "unknown"}, I("wait_unknown")),
        ({"wait": "unknown"}, I("wait_unknown")),
        ({"attempt": "unknown"}, I("attempt_unknown")),
        ({"attempt": "unknown", "obligations": "unknown"}, I("attempt_unknown")),
    ],
)
def test_val32_no_domain_without_admitted_or_pending(
    overrides: dict[str, Any], expected: tuple[str, ...]
) -> None:
    assert projection(run(spec(**overrides, now=HARD + 5))) == expected


def test_val32_i6_precedes_hard_only() -> None:
    result = run(spec(attempt="unknown", obligations="pending", cells="outcome-unresolved-applies",
                      now=HARD + 5))
    assert projection(result) == I("attempt_unknown")
    wait_row = run(spec(wait="unknown", attempt="unknown", obligations="pending",
                        cells="clearance-unresolved-applies", now=HARD + 5))
    assert projection(wait_row) == I("attempt_unknown")
    clean = run(spec(attempt="unknown", obligations="pending", cells="clean-applies", now=HARD + 5))
    assert projection(clean) == A("stalled", "hard_deadline_elapsed", "observe")


def test_val32_phase_never_suppresses_hard_only() -> None:
    result = run(spec(wait="unknown", attempt="admitted", phase="active", now=HARD))
    assert projection(result) == A("stalled", "hard_deadline_elapsed", "observe")
    assert not {"phase_exemption_active", "phase_not_applicable"} & set(result.reasons)
    s = spec(wait="unknown", attempt="admitted", now=HARD)
    facts, profile = _late_phase(s)
    late = assess_unit(facts, empty_frontier(), profile, clk(HARD))
    assert projection(late) == A("stalled", "hard_deadline_elapsed", "observe")
    assert not {"phase_exemption_active", "phase_not_applicable"} & set(late.reasons)


def test_val32_reasons_have_no_invented_candidate() -> None:
    pending = run(spec(wait="unknown", obligations="pending", now=HARD))
    assert pending.reasons == ("hard_deadline_elapsed", "wait_unknown")
    admitted = run(spec(wait="unknown", attempt="admitted", now=HARD))
    assert set(admitted.reasons) == {
        "hard_deadline_elapsed", "wait_unknown", "attempt_admitted",
        "transition_admissible_during_attempt",
    }
    attempt = run(spec(attempt="unknown", obligations="pending", now=HARD))
    assert attempt.reasons == ("attempt_unknown", "hard_deadline_elapsed")
    for result in (pending, admitted, attempt):
        assert not {"verification_pending", "external_dependency", "progress_deadline_elapsed",
                    "wait_deadline_elapsed"} & set(result.reasons)


def test_val32_earlier_rows_win() -> None:
    base = {"wait": "unknown", "obligations": "pending", "now": HARD + 5}
    assert projection(run(spec(**base, age=OBS))) == I("stale_observation")
    assert projection(run(spec(**base, user="pending")))[1] == "needs_user"
    assert projection(run(spec(**base, user="unknown"))) == I("user_decision_unknown")
    assert projection(run(spec(**base, policy="held")))[2] == "policy_hold"


def test_val32_gen_t_hard_only_rows_match_oracle() -> None:
    assert_oracle(gen_t(HARD_ONLY_ROWS))


# =========================================================================== update type


def test_progress_update_is_validated() -> None:
    assert code_of(lambda: ProgressUpdate("dispatched", empty_frontier())) == "invalid_enum"
    assert code_of(lambda: ProgressUpdate("exact_duplicate", "frontier")) == "invalid_type"  # type: ignore[arg-type]
