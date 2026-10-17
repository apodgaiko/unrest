"""Provider-free, explicitly selected research model; never imported by dispatch.

All transitions return new values. Persistence and sends belong to the caller:
serialize the reservation before sending, and treat a restored reservation as
possibly sent. Simulated session identifiers are not evidence of live reuse.
"""

from __future__ import annotations

import json
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

Phase = Literal["work", "validate", "correction", "recheck", "passed", "attention"]
Reason = Literal[
    "disabled",
    "dirty_base",
    "invalid_base",
    "missing_scope",
    "invalid_scope",
    "overlap",
    "shared_resource",
    "unsupported_dispatch",
    "integration_disabled",
    "invalid_lanes",
    "budget",
    "product_failure",
    "noncorrectable",
    "ambiguous_send",
    "restart",
    "expired",
    "stopped",
    "deadline",
    "extra_generation",
    "parking_capacity",
]
PRIORITY = {"recheck": 0, "correction": 1, "validate": 2, "work": 3}


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class LaneSpec(Record):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    writes: tuple[str, ...]
    targets: tuple[str, ...] = Field(min_length=1)
    resources: tuple[str, ...] = ()
    auto_merge: bool = True


class Config(Record):
    enabled: bool = False
    capacity: int = Field(default=4, ge=1)
    parking_capacity: int = Field(default=4, ge=0, le=4)
    turn_budget: int = Field(default=8, ge=2)
    final_turns: int = Field(default=2, ge=2)
    reuse: bool = True
    streaming: bool = True
    turn_timeout: int = Field(default=300, ge=1, le=300)


class Turn(Record):
    ordinal: int
    phase: Phase
    generation: int
    session: str
    process_generation: str
    candidate: int | None
    targets: tuple[str, ...]
    reserved_at: int
    deadline: int
    status: Literal["reserved", "sent", "acked", "completed", "uncertain", "cancelled"]
    outcome: Literal["sealed", "pass", "defect", "other"] | None = None


class Lease(Record):
    role: Literal["worker", "validator"]
    session: str
    process_generation: str
    parked_at: int


class Lane(Record):
    spec: LaneSpec
    phase: Phase = "work"
    admitted: bool = False
    generation: int = 0
    candidate: int | None = None
    correction_reserved: bool = False
    reuse_owner: bool = False
    parking_reserved: int = 0
    leases: tuple[Lease, ...] = ()
    turns: tuple[Turn, ...] = ()
    active: int | None = None
    blocking: Reason | None = None
    history: tuple[Reason, ...] = ()


class State(Record):
    schema_version: Literal[1] = 1
    config: Config
    base: str
    lanes: tuple[Lane, ...]
    now: int = Field(default=0, ge=0)
    halt: Literal["budget", "stopped"] | None = None

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.active_count > min(self.config.capacity, 4):
            raise ValueError("active_capacity")
        if sum(lane.parking_reserved for lane in self.lanes) > self.config.parking_capacity:
            raise ValueError("parking_capacity")
        if self.parked_count > self.config.parking_capacity:
            raise ValueError("parked_capacity")
        if sum(lane.reuse_owner for lane in self.lanes) > 1:
            raise ValueError("reuse_capacity")
        if self.turn_count + self.config.final_turns > self.config.turn_budget:
            raise ValueError("turn_budget")
        for lane in self.lanes:
            if len(lane.turns) > 6 or lane.generation not in (0, 1):
                raise ValueError("lane_bound")
            if lane.active is not None and lane.active != len(lane.turns) - 1:
                raise ValueError("active_identity")
        return self

    @property
    def active_count(self) -> int:
        return sum(lane.active is not None for lane in self.lanes)

    @property
    def parked_count(self) -> int:
        return sum(len(lane.leases) for lane in self.lanes)

    @property
    def turn_count(self) -> int:
        return sum(len(lane.turns) for lane in self.lanes)

    @property
    def halted(self) -> bool:
        return self.halt is not None or any(lane.blocking for lane in self.lanes)


class Admission(Record):
    reason: Reason | None
    state: State | None


def _copy[T: Record](record: T, **changes: object) -> T:
    # model_copy(update=...) bypasses validation, including capacity invariants.
    return type(record).model_validate(record.model_dump() | changes)


def _replace(state: State, index: int, lane: Lane) -> State:
    return _copy(state, lanes=state.lanes[:index] + (lane,) + state.lanes[index + 1 :])


def _index(state: State, lane_id: str) -> int:
    for index, lane in enumerate(state.lanes):
        if lane.spec.id == lane_id:
            return index
    raise ValueError("unknown_lane")


def admit(
    specs: tuple[LaneSpec, ...],
    *,
    base: str,
    clean: bool,
    isolated_dispatch: bool,
    config: Config = Config(),
) -> Admission:
    """Validate facts supplied by the caller; no filesystem or normal-task access."""
    reason: Reason | None = None
    if not config.enabled:
        reason = "disabled"
    elif not clean:
        reason = "dirty_base"
    elif len(base) != 40 or any(c not in "0123456789abcdef" for c in base):
        reason = "invalid_base"
    elif not isolated_dispatch:
        reason = "unsupported_dispatch"
    elif not 1 <= len(specs) <= 4 or len({s.id for s in specs}) != len(specs):
        reason = "invalid_lanes"
    elif config.reuse and config.parking_capacity < 2:
        reason = "parking_capacity"
    elif any(not s.auto_merge for s in specs):
        reason = "integration_disabled"
    elif any(not s.writes for s in specs):
        reason = "missing_scope"
    else:
        paths = [p for s in specs for p in s.writes]
        if any(
            not p
            or "\\" in p
            or any(c in p for c in "*?[]\n\r\0")
            or any(part in ("", ".", "..", ".git") for part in p.split("/"))
            or p != p.strip()
            for p in paths
        ):
            reason = "invalid_scope"
        elif any(
            a == b or a.startswith(b + "/") or b.startswith(a + "/")
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            reason = "overlap"
        else:
            resources = [r for s in specs for r in s.resources]
            if len(set(resources)) != len(resources):
                reason = "shared_resource"
            elif config.turn_budget < 2 * len(specs) + config.final_turns:
                reason = "budget"
    if reason:
        return Admission(reason=reason, state=None)
    return Admission(
        reason=None,
        state=State(
            config=config,
            base=base,
            lanes=tuple(
                Lane(spec=s, reuse_owner=config.reuse and i == 0) for i, s in enumerate(specs)
            ),
        ),
    )


def ready(state: State) -> tuple[str, ...]:
    """Priority followed by authored order; no I/O or mutation."""
    if state.halted:
        return ()
    lanes = [
        (i, lane)
        for i, lane in enumerate(state.lanes)
        if lane.active is None and lane.phase in PRIORITY
    ]
    if not state.config.streaming:
        lanes = [
            (i, lane)
            for i, lane in lanes
            if lane.phase != "validate"
            or all(
                sibling.generation > 0 or sibling.candidate is not None for sibling in state.lanes
            )
        ]
    return tuple(
        lane.spec.id
        for _, lane in sorted(
            lanes,
            key=lambda pair: (
                PRIORITY[pair[1].phase] if pair[1].admitted else 4,
                pair[0],
            ),
        )
    )


def reserve_next(state: State) -> State:
    """Return a durable-before-send reservation, or unchanged state under pressure.

    The caller MUST persist dump_state(result) before transmitting. Reservation
    counts against budget even if acknowledgment or completion is lost.
    """
    if state.halted or state.active_count >= min(state.config.capacity, 4):
        return state
    candidates = ready(state)
    if not candidates:
        return state
    if state.turn_count >= state.config.turn_budget - state.config.final_turns:
        return _close_parked(_copy(state, halt="budget"))
    for lane_id in candidates:
        index = _index(state, lane_id)
        lane = state.lanes[index]
        needs_parking = lane.reuse_owner and lane.generation == 0
        reserved = 2 if needs_parking else 0
        if reserved > lane.parking_reserved and (
            sum(item.parking_reserved for item in state.lanes) + reserved
            > state.config.parking_capacity
        ):
            continue
        if len(lane.turns) >= 6 or (lane.phase == "correction" and lane.correction_reserved):
            return _attention(state, index, "extra_generation")
        role: Literal["worker", "validator"] = (
            "worker" if lane.phase in ("work", "correction") else "validator"
        )
        old = next((lease for lease in lane.leases if lease.role == role), None)
        if needs_parking and lane.phase in ("correction", "recheck") and old is None:
            return _attention(state, index, "expired")
        ordinal = len(lane.turns)
        identity = f"{lane.spec.id}:{role}:{lane.generation}"
        if not needs_parking:
            identity += f":{ordinal}"
        turn = Turn(
            ordinal=ordinal,
            phase=lane.phase,
            generation=lane.generation,
            session=old.session if old else identity,
            process_generation=old.process_generation if old else identity,
            candidate=lane.candidate,
            targets=lane.spec.targets,
            reserved_at=state.now,
            deadline=state.now + state.config.turn_timeout,
            status="reserved",
        )
        return _replace(
            state,
            index,
            _copy(
                lane,
                admitted=True,
                active=ordinal,
                turns=lane.turns + (turn,),
                parking_reserved=reserved,
                leases=tuple(x for x in lane.leases if x.role != role),
                correction_reserved=lane.correction_reserved or lane.phase == "correction",
            ),
        )
    return state


def transmission(
    state: State, lane_id: str, ordinal: int, status: Literal["sent", "acked", "uncertain"]
) -> State:
    index = _index(state, lane_id)
    lane = state.lanes[index]
    if lane.active != ordinal:
        raise ValueError("inactive_turn")
    turn = lane.turns[ordinal]
    if status == "uncertain":
        return _attention(state, index, "ambiguous_send", uncertain=True)
    if (turn.status, status) not in (("reserved", "sent"), ("sent", "acked")):
        raise ValueError("transmission_order")
    if status == "sent" and state.halted:
        raise ValueError("dispatch_halted")
    return _replace(
        state,
        index,
        _copy(
            lane,
            turns=lane.turns[:-1] + (_copy(turn, status=status),),
        ),
    )


def _attention(state: State, index: int, reason: Reason, *, uncertain: bool = False) -> State:
    lane = state.lanes[index]
    turns = lane.turns
    if lane.active is not None:
        turns = turns[:-1] + (_copy(turns[-1], status="uncertain" if uncertain else "cancelled"),)
    return _close_parked(
        _replace(
            state,
            index,
            _copy(
                lane,
                phase="attention",
                active=None,
                turns=turns,
                leases=(),
                parking_reserved=0,
                blocking=reason,
                history=lane.history + (reason,),
            ),
        )
    )


def _close_parked(state: State) -> State:
    return _copy(
        state, lanes=tuple(_copy(lane, leases=(), parking_reserved=0) for lane in state.lanes)
    )


def complete(
    state: State, lane_id: str, ordinal: int, outcome: Literal["sealed", "pass", "defect", "other"]
) -> State:
    """Consume one immutable completion. A sealed candidate is a model revision.

    Candidate bytes/digests and real authority enforcement belong to the later
    coordinator. Every validation turn here carries the entire original target set.
    """
    index = _index(state, lane_id)
    lane = state.lanes[index]
    if lane.active != ordinal or lane.turns[ordinal].status != "acked":
        raise ValueError("inactive_or_unacknowledged_turn")
    turn = lane.turns[ordinal]
    worker = turn.phase in ("work", "correction")
    if (worker and outcome not in ("sealed", "other")) or (not worker and outcome == "sealed"):
        raise ValueError("role_outcome")
    turns = lane.turns[:-1] + (_copy(turn, status="completed", outcome=outcome),)
    leases = lane.leases
    if lane.reuse_owner and lane.generation == 0 and not state.halted:
        leases += (
            Lease(
                role="worker" if worker else "validator",
                session=turn.session,
                process_generation=turn.process_generation,
                parked_at=state.now,
            ),
        )
    lane = _copy(lane, active=None, turns=turns, leases=leases)
    state = _replace(state, index, lane)
    if outcome == "other":
        return _attention(state, index, "noncorrectable")
    if worker:
        return _replace(
            state,
            index,
            _copy(
                lane,
                candidate=0 if lane.candidate is None else lane.candidate + 1,
                phase="recheck" if turn.phase == "correction" else "validate",
            ),
        )
    if outcome == "pass":
        return _replace(state, index, _copy(lane, phase="passed", leases=(), parking_reserved=0))
    if lane.generation == 1:
        return _attention(state, index, "product_failure")
    lane = _copy(lane, history=lane.history + ("product_failure",))
    state = _replace(state, index, lane)
    if not lane.correction_reserved:
        return _replace(state, index, _copy(lane, phase="correction"))
    return _replace(
        state,
        index,
        _copy(
            lane,
            phase="work",
            generation=1,
            leases=(),
            parking_reserved=0,
        ),
    )


def advance(state: State, now: int) -> State:
    """Controlled monotonic seconds. Expiry wins at the exact boundary."""
    if now < state.now:
        raise ValueError("clock_reversed")
    state = _copy(state, now=now)
    for index in range(len(state.lanes)):
        lane = state.lanes[index]
        if lane.active is not None and lane.turns[lane.active].deadline <= now:
            state = _attention(state, index, "deadline")
        elif any(lease.parked_at + 3600 <= now for lease in lane.leases):
            state = _attention(state, index, "expired")
    return state


def stop(state: State) -> State:
    """No new reservations/sends or integration; sent work may drain to deadline."""
    return _close_parked(_copy(state, halt="stopped"))


def restart(state: State) -> State:
    """Sessions never survive reload; an uncompleted reservation may have sent."""
    for index in range(len(state.lanes)):
        lane = state.lanes[index]
        if lane.active is not None:
            state = _attention(state, index, "ambiguous_send", uncertain=True)
        elif lane.admitted and lane.phase not in ("passed", "attention"):
            state = _attention(state, index, "restart")
    return state


def recover_fresh(state: State, lane_id: str) -> State:
    """Explicit operator decision; never an automatic scheduler transition."""
    index = _index(state, lane_id)
    lane = state.lanes[index]
    if (
        state.halt
        or state.active_count
        or lane.blocking not in ("expired", "restart")
        or lane.generation != 0
    ):
        raise ValueError("recovery_forbidden")
    if state.turn_count + 2 + state.config.final_turns > state.config.turn_budget:
        return _close_parked(_copy(state, halt="budget"))
    return _replace(
        state,
        index,
        _copy(
            lane,
            phase="work",
            generation=1,
            blocking=None,
            leases=(),
            parking_reserved=0,
        ),
    )


def dump_state(state: State) -> str:
    return json.dumps(state.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"


def load_state(data: str) -> State:
    """Loading is controller restart, never session resurrection."""
    return restart(State.model_validate_json(data))


def projection(state: State) -> str:
    """Authored semantic decisions, excluding clocks and interleaving order.

    Equal causal outcomes yield equal bytes; stop-before-pass and pass-before-stop
    need not have identical lane outcomes, but both remain incomplete.
    """
    eligible = not state.halted and all(lane.phase == "passed" for lane in state.lanes)
    value = {
        "disposition": "integration_ready" if eligible else "incomplete",
        "integration": [lane.spec.id for lane in state.lanes] if eligible else [],
        "final_targets": sorted({t for lane in state.lanes for t in lane.spec.targets}),
        "final_turns_reserved": state.config.final_turns,
        "final_gate": "pending",
        "halt": state.halt,
        "lanes": [
            {
                "id": lane.spec.id,
                "phase": lane.phase,
                "candidate": lane.candidate,
                "generation": lane.generation,
                "correction_reserved": lane.correction_reserved,
                "reuse_owner": lane.reuse_owner,
                "targets": list(lane.spec.targets),
                "history": list(lane.history),
                "blocking": lane.blocking,
                "turns": [
                    {
                        "ordinal": t.ordinal,
                        "phase": t.phase,
                        "generation": t.generation,
                        "candidate": t.candidate,
                        "targets": list(t.targets),
                        "status": t.status,
                        "outcome": t.outcome,
                    }
                    for t in lane.turns
                ],
            }
            for lane in state.lanes
        ],
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
