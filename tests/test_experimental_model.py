"""Independent scripted outcomes and finite interleavings; no live providers."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from unrest_harness.experimental_model import (
    Config,
    Lane,
    LaneSpec,
    State,
    advance,
    admit,
    complete,
    dump_state,
    load_state,
    projection,
    ready,
    recover_fresh,
    reserve_next,
    stop,
    transmission,
)

ORACLE = json.loads(
    (Path(__file__).parent / "fixtures/experimental_model/scenarios.json").read_text()
)
BASE = ORACLE["base"]


def model(count=1, **config):
    specs = tuple(
        LaneSpec(id=name, writes=(f"{name}.txt",), targets=(f"T-{name}", "COMMON"))
        for name in ("z", "a", "y", "b")[:count]
    )
    result = admit(
        specs,
        base=BASE,
        clean=True,
        isolated_dispatch=True,
        config=Config(enabled=True, turn_budget=30, **config),
    )
    assert result.reason is None
    assert result.state is not None
    return result.state


def ack(state, lane_id):
    lane = next(lane for lane in state.lanes if lane.spec.id == lane_id)
    state = transmission(state, lane_id, lane.active, "sent")
    return transmission(state, lane_id, lane.active, "acked")


def finish(state, lane_id, outcome):
    state = ack(state, lane_id)
    lane = next(lane for lane in state.lanes if lane.spec.id == lane_id)
    return complete(state, lane_id, lane.active, outcome)


def turn(state, outcome):
    state = reserve_next(state)
    return finish(state, "z", outcome)


@pytest.mark.parametrize("case", ORACLE["lifecycle"], ids=lambda c: c["name"])
@pytest.mark.parametrize("reuse", [True, False])
def test_independent_lifecycle_oracle(case, reuse):
    state = model(reuse=reuse)
    for outcome in case["outcomes"]:
        state = turn(state, outcome)
    lane = state.lanes[0]
    assert lane.phase == case["terminal"]
    assert lane.candidate == case["candidate"]
    assert len(lane.turns) == case["turns"]
    assert [t.phase for t in lane.turns] == case["phases"]
    assert [t.generation for t in lane.turns] == case["generations"]
    assert len(lane.history) == case["dissent"]
    assert all(t.targets == ("T-z", "COMMON") for t in lane.turns)
    assert state.parked_count == 0
    assert reserve_next(state) == state  # No seventh turn or second rotation.
    with pytest.raises(ValueError, match="recovery_forbidden"):
        recover_fresh(state, "z")
    if len(lane.turns) >= 4:
        assert lane.correction_reserved
        assert (lane.turns[0].session == lane.turns[2].session) is reuse
        assert (lane.turns[1].process_generation == lane.turns[3].process_generation) is reuse
    data = json.loads(projection(state))
    assert data["final_gate"] == "pending"
    assert data["integration"] == (["z"] if lane.phase == "passed" else [])


@pytest.mark.parametrize(
    "reason,changes",
    [
        ("disabled", {"config": Config()}),
        ("dirty_base", {"clean": False}),
        ("invalid_base", {"base": "branch"}),
        ("unsupported_dispatch", {"isolated_dispatch": False}),
        ("invalid_lanes", {"specs": ()}),
        (
            "integration_disabled",
            {"specs": (LaneSpec(id="z", writes=("a",), targets=("T",), auto_merge=False),)},
        ),
        ("missing_scope", {"specs": (LaneSpec(id="z", writes=(), targets=("T",)),)}),
        (
            "overlap",
            {
                "specs": (
                    LaneSpec(id="z", writes=("a",), targets=("T",)),
                    LaneSpec(id="a", writes=("a/b",), targets=("Q",)),
                )
            },
        ),
        (
            "shared_resource",
            {
                "specs": (
                    LaneSpec(id="z", writes=("a",), targets=("T",), resources=("port:1",)),
                    LaneSpec(id="a", writes=("b",), targets=("Q",), resources=("port:1",)),
                )
            },
        ),
        ("budget", {"config": Config(enabled=True, turn_budget=3)}),
        ("parking_capacity", {"config": Config(enabled=True, parking_capacity=1)}),
    ],
)
def test_rejection_has_no_state_or_input_mutation(reason, changes):
    normal_tasks = {"work": "pending", "validate": "pending"}
    before = json.dumps(normal_tasks)
    inputs = dict(
        specs=(LaneSpec(id="z", writes=("a",), targets=("T",)),),
        base=BASE,
        clean=True,
        isolated_dispatch=True,
        config=Config(enabled=True),
    )
    inputs.update(changes)
    original = repr(inputs)
    result = admit(**inputs)
    assert result.reason == reason and result.state is None
    assert repr(inputs) == original and json.dumps(normal_tasks) == before


@pytest.mark.parametrize(
    "path",
    ["", "/a", "../a", "a/../b", "a//b", "./a", "a/", "a\\b", ".git/config", "a/*", "a\n", " a"],
)
def test_invalid_paths(path):
    result = admit(
        (LaneSpec(id="z", writes=(path,), targets=("T",)),),
        base=BASE,
        clean=True,
        isolated_dispatch=True,
        config=Config(enabled=True),
    )
    assert result.reason == "invalid_scope"


@pytest.mark.parametrize("case", ORACLE["timing"], ids=lambda c: c["name"])
@pytest.mark.parametrize("streaming,reuse", itertools.product([False, True], repeat=2))
def test_timing_oracle_four_arms(case, streaming, reuse):
    state = model(2, capacity=2, streaming=streaming, reuse=reuse)
    pending = {}
    starts = []
    while any(lane.phase != "passed" for lane in state.lanes):
        while True:
            new = reserve_next(state)
            if new == state:
                break
            state = new
            for index, lane in enumerate(state.lanes):
                if lane.active is not None and lane.spec.id not in pending:
                    t = lane.turns[lane.active]
                    duration = case["workers" if t.phase == "work" else "validators"][index]
                    pending[lane.spec.id] = (state.now + duration, t.phase)
                    starts.append([lane.spec.id, t.phase, state.now])
        assert pending, "scheduler deadlocked"
        now = min(end for end, _ in pending.values())
        state = advance(state, now)
        for lane_id, (end, phase) in list(pending.items()):
            if end == now:
                state = finish(state, lane_id, "sealed" if phase == "work" else "pass")
                del pending[lane_id]
    assert starts == case["streaming_starts" if streaming else "barrier_starts"]
    assert json.loads(projection(state))["integration"] == ["z", "a"]


def test_all_ready_priority_pairs_and_authored_ties():
    ordered = ["recheck", "correction", "validate", "work"]
    for left, right in itertools.product(ordered, repeat=2):
        state = model(2)
        state = State(
            config=state.config,
            base=BASE,
            lanes=(
                Lane(spec=state.lanes[0].spec, admitted=True, phase=left),
                Lane(spec=state.lanes[1].spec, admitted=True, phase=right),
            ),
        )
        expected = ("z", "a") if ordered.index(left) <= ordered.index(right) else ("a", "z")
        assert ready(state) == expected
    state = model(2)
    state = State(
        config=state.config,
        base=BASE,
        lanes=(state.lanes[0], Lane(spec=state.lanes[1].spec, admitted=True)),
    )
    assert ready(state) == ("a", "z")  # Admitted work before unrelated admission.


@pytest.mark.parametrize("capacity", [1, 2, 3, 4, 8])
@pytest.mark.parametrize("parking_capacity", [2, 4])
def test_exhaustive_four_lane_interleavings(capacity, parking_capacity):
    terminals = set()
    visited = set()
    count = 0

    def explore(state):
        nonlocal count
        while True:
            new = reserve_next(state)
            if new == state:
                break
            state = new
        serialized = dump_state(state)
        if serialized in visited:
            return
        visited.add(serialized)
        count += 1
        assert state.active_count <= min(capacity, 4)
        assert state.parked_count <= 4
        assert sum(lane.parking_reserved for lane in state.lanes) <= 4
        assert [lane.spec.id for lane in state.lanes if lane.reuse_owner] == ["z"]
        if state.lanes[0].admitted and state.lanes[0].phase != "passed":
            assert state.lanes[0].parking_reserved == 2
        active = [lane for lane in state.lanes if lane.active is not None]
        if not active:
            assert all(lane.phase == "passed" for lane in state.lanes), "deadlock"
            terminals.add(projection(state))
        for lane in active:
            explore(finish(state, lane.spec.id, "sealed" if lane.phase == "work" else "pass"))

    explore(model(4, capacity=capacity, parking_capacity=parking_capacity))
    assert count >= 9
    assert len(terminals) == 1
    assert json.loads(terminals.pop())["integration"] == ["z", "a", "y", "b"]


def test_parking_reservation_precedes_work():
    state = model()
    reserved = reserve_next(state)
    assert reserved.lanes[0].parking_reserved == 2 and reserved.parked_count == 0
    parked = finish(reserved, "z", "sealed")
    assert parked.parked_count == 1 and parked.lanes[0].parking_reserved == 2


@pytest.mark.parametrize("offset", [3599, 3600, 3601])
def test_ttl_and_serialized_reload_boundary(offset):
    state = turn(model(), "sealed")
    snapshot = dump_state(state)
    at = advance(state, offset)
    assert (at.lanes[0].blocking == "expired") is (offset >= 3600)
    assert (at.parked_count == 1) is (offset < 3600)
    restored = load_state(dump_state(at))
    assert restored.parked_count == 0
    assert restored.lanes[0].blocking == ("restart" if offset < 3600 else "expired")
    assert reserve_next(restored) == restored
    recovered = recover_fresh(restored, "z")
    assert recovered.lanes[0].generation == 1
    assert recovered.lanes[0].candidate == 0
    recovered = turn(turn(recovered, "sealed"), "defect")
    assert recovered.lanes[0].blocking == "product_failure"
    with pytest.raises(ValueError, match="recovery_forbidden"):
        recover_fresh(recovered, "z")
    assert dump_state(state) == snapshot


@pytest.mark.parametrize("stage", ["reserved", "sent", "acked"])
def test_durable_continuation_crash_windows_consume_allowance(stage):
    state = turn(turn(model(), "sealed"), "defect")
    state = reserve_next(state)
    assert state.lanes[0].correction_reserved
    assert state.lanes[0].turns[-1].status == "reserved"
    if stage in ("sent", "acked"):
        state = transmission(state, "z", 2, "sent")
    if stage == "acked":
        state = transmission(state, "z", 2, "acked")
    restarted = load_state(dump_state(state))
    lane = restarted.lanes[0]
    assert lane.turns[-1].status == "uncertain"
    assert lane.blocking == "ambiguous_send" and lane.correction_reserved
    assert restarted.turn_count == 3 and restarted.parked_count == 0
    assert reserve_next(restarted) == restarted
    with pytest.raises(ValueError, match="recovery_forbidden"):
        recover_fresh(restarted, "z")
    for _ in range(2):
        restarted = load_state(dump_state(restarted))
        assert restarted.turn_count == 3 and restarted.lanes[0].correction_reserved


def test_duplicate_late_wrong_role_and_uncertain_carriers():
    state = ack(reserve_next(model()), "z")
    with pytest.raises(ValueError, match="role_outcome"):
        complete(state, "z", 0, "pass")
    state = complete(state, "z", 0, "sealed")
    with pytest.raises(ValueError, match="inactive_or_unacknowledged_turn"):
        complete(state, "z", 0, "sealed")
    state = reserve_next(state)
    with pytest.raises(ValueError, match="inactive_or_unacknowledged_turn"):
        complete(state, "z", 0, "sealed")
    state = transmission(state, "z", 1, "uncertain")
    assert state.lanes[0].blocking == "ambiguous_send"
    assert reserve_next(state) == state


@pytest.mark.parametrize("events", list(itertools.permutations(["pass", "failure", "stop"])))
def test_attention_successful_sibling_stop_permutations(events):
    state = model(2)
    state = reserve_next(reserve_next(state))
    state = finish(finish(state, "z", "sealed"), "a", "sealed")
    state = ack(ack(reserve_next(reserve_next(state)), "z"), "a")
    for event in events:
        if event == "stop":
            state = stop(state)
        else:
            state = complete(
                state, "z" if event == "pass" else "a", 1, "pass" if event == "pass" else "other"
            )
        if state.halted:
            assert reserve_next(state) == state
    assert state.lanes[0].phase == "passed"
    assert state.lanes[1].history == ("noncorrectable",)
    assert state.active_count == state.parked_count == 0
    result = json.loads(projection(state))
    assert result["disposition"] == "incomplete" and result["integration"] == []
    assert result["final_targets"] == ["COMMON", "T-a", "T-z"]


@pytest.mark.parametrize("events", list(itertools.permutations(["complete", "expire", "stop"])))
def test_expiry_completion_stop_races(events):
    state = ack(reserve_next(model()), "z")
    for event in events:
        if event == "stop":
            state = stop(state)
        elif event == "expire":
            state = advance(state, 3600)
        elif state.lanes[0].active is not None:
            state = complete(state, "z", 0, "sealed")
        else:
            with pytest.raises(ValueError, match="inactive_or_unacknowledged_turn"):
                complete(state, "z", 0, "sealed")
    assert state.active_count == state.parked_count == 0
    assert json.loads(projection(state))["disposition"] == "incomplete"


def test_budget_before_recheck_keeps_final_reservation_and_dissent():
    state = model()
    state = State(config=Config(enabled=True, turn_budget=5), base=BASE, lanes=state.lanes)
    for outcome in ("sealed", "defect", "sealed"):
        state = turn(state, outcome)
    state = reserve_next(state)
    assert state.halt == "budget" and state.turn_count == 3
    assert state.lanes[0].phase == "recheck"
    assert state.lanes[0].history == ("product_failure",)
    assert json.loads(projection(state))["final_turns_reserved"] == 2
    state = advance(state, 3600)
    assert state.parked_count == 0


def test_active_drain_is_bounded_and_clock_cannot_reverse():
    state = stop(ack(reserve_next(model()), "z"))
    assert advance(state, 299).active_count == 1
    state = advance(state, 300)
    assert state.active_count == 0 and state.lanes[0].blocking == "deadline"
    with pytest.raises(ValueError, match="clock_reversed"):
        advance(state, 299)


def halt_with_sibling_turn(cause, stage):
    state = model(2)
    if cause == "budget":
        state = State(config=Config(enabled=True, turn_budget=6), base=BASE, lanes=state.lanes)
    if cause == "expiry":
        state = finish(reserve_next(state), "z", "sealed")
        state = advance(state, 3500)
    state = reserve_next(reserve_next(state))
    if stage in ("sent", "acked"):
        state = transmission(state, "a", 0, "sent")
    if stage == "acked":
        state = transmission(state, "a", 0, "acked")
    before = dump_state(state)
    if cause == "stop":
        halted = stop(state)
    elif cause == "attention":
        halted = finish(state, "z", "other")
    elif cause == "budget":
        halted = finish(state, "z", "sealed")
        halted = finish(reserve_next(halted), "z", "defect")
        halted = finish(reserve_next(halted), "z", "sealed")
        halted = reserve_next(halted)
    else:
        halted = advance(state, 3600)
    assert dump_state(state) == before
    assert halted.halted and halted.lanes[1].turns[0].status == stage
    return halted


@pytest.mark.parametrize("cause", ["stop", "attention", "budget", "expiry"])
def test_halt_blocks_reserved_first_send_without_refund_or_mutation(cause):
    state = halt_with_sibling_turn(cause, "reserved")
    before = dump_state(state)
    for _ in range(2):
        with pytest.raises(ValueError, match="^dispatch_halted$"):
            transmission(state, "a", 0, "sent")
        with pytest.raises(ValueError, match="transmission_order"):
            transmission(state, "a", 0, "acked")
        assert reserve_next(state) == state
        assert dump_state(state) == before
    assert stop(stop(state)) == stop(state)
    restored = load_state(before)
    assert restored.turn_count == state.turn_count
    assert restored.lanes[1].turns[0].status == "uncertain"
    assert restored.lanes[1].blocking == "ambiguous_send"
    assert load_state(dump_state(restored)) == restored
    with pytest.raises(ValueError, match="inactive_turn"):
        transmission(restored, "a", 0, "sent")
    expired = advance(state, state.lanes[1].turns[0].deadline)
    assert expired.lanes[1].turns[0].status == "cancelled"
    assert expired.turn_count == state.turn_count
    assert dump_state(state) == before


@pytest.mark.parametrize("cause", ["stop", "attention", "budget", "expiry"])
@pytest.mark.parametrize("stage", ["sent", "acked"])
def test_halt_allows_sent_drain_only_before_original_deadline(cause, stage):
    state = halt_with_sibling_turn(cause, stage)
    before = dump_state(state)
    deadline = state.lanes[1].turns[0].deadline
    draining = advance(state, deadline - 1)
    if stage == "sent":
        draining = transmission(draining, "a", 0, "acked")
    drained = complete(draining, "a", 0, "sealed")
    assert drained.lanes[1].turns[0].status == "completed"
    assert drained.lanes[1].active is None and drained.parked_count == 0
    assert drained.turn_count == state.turn_count and drained.halted
    assert json.loads(projection(drained))["disposition"] == "incomplete"
    with pytest.raises(ValueError, match="inactive_or_unacknowledged_turn"):
        complete(drained, "a", 0, "sealed")
    expired = advance(state, deadline)
    with pytest.raises(ValueError, match="inactive_turn"):
        transmission(expired, "a", 0, "acked")
    with pytest.raises(ValueError, match="inactive_or_unacknowledged_turn"):
        complete(expired, "a", 0, "sealed")
    assert dump_state(state) == before


def test_halted_correction_reservation_keeps_entitlement_consumed():
    state = reserve_next(turn(turn(model(), "sealed"), "defect"))
    halted = stop(state)
    with pytest.raises(ValueError, match="dispatch_halted"):
        transmission(halted, "z", 2, "sent")
    for current in (halted, load_state(dump_state(halted))):
        assert current.turn_count == 3 and current.lanes[0].correction_reserved
        assert current.lanes[0].history[:1] == ("product_failure",)
        assert reserve_next(current) == current


def test_pure_library_trace_in_disposable_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "production-must-not-exist"))
    state = model()
    for outcome in ORACLE["lifecycle"][2]["outcomes"]:
        state = turn(state, outcome)
    assert json.loads(projection(state))["integration"] == ["z"]
    assert list(tmp_path.iterdir()) == []


def test_capacity_pressure_delays_without_eviction_or_entitlement_transfer():
    state = model(4, capacity=2, parking_capacity=2)
    state = reserve_next(reserve_next(state))
    assert reserve_next(state) == state
    assert state.lanes[0].parking_reserved == 2
    state = finish(state, "a", "sealed")  # Non-owner finishes first.
    state = reserve_next(state)
    assert state.lanes[1].phase == "validate" and state.lanes[1].active == 1
    assert state.lanes[0].reuse_owner and not state.lanes[1].reuse_owner
    state = finish(state, "a", "pass")
    state = reserve_next(state)
    assert state.lanes[2].active == 0
    assert state.lanes[0].parking_reserved == 2


def test_restart_after_unsealed_mutation_retains_last_seal_and_history():
    state = turn(turn(model(), "sealed"), "defect")
    state = ack(reserve_next(state), "z")
    restarted = load_state(dump_state(state))
    assert restarted.lanes[0].candidate == 0
    assert restarted.lanes[0].correction_reserved
    assert restarted.lanes[0].history == ("product_failure", "ambiguous_send")
    assert json.loads(projection(restarted))["integration"] == []


def test_restart_after_correction_uses_only_remaining_fresh_generation():
    state = turn(turn(turn(model(), "sealed"), "defect"), "sealed")
    state = load_state(dump_state(state))
    state = recover_fresh(state, "z")
    assert state.lanes[0].correction_reserved and state.lanes[0].candidate == 1
    state = turn(state, "sealed")
    state = load_state(dump_state(state))
    with pytest.raises(ValueError, match="recovery_forbidden"):
        recover_fresh(state, "z")
    assert state.lanes[0].generation == 1 and state.lanes[0].candidate == 2


def test_stop_and_attention_release_parking_without_losing_seal():
    state = turn(model(), "sealed")
    halted = stop(state)
    assert halted.lanes[0].candidate == 0
    assert halted.parked_count == 0
    assert halted.lanes[0].parking_reserved == 0
    assert reserve_next(halted) == halted


def test_recovery_insufficient_budget_is_incomplete():
    state = model()
    state = State(config=Config(enabled=True, turn_budget=4), base=BASE, lanes=state.lanes)
    state = load_state(dump_state(turn(state, "sealed")))
    state = recover_fresh(state, "z")
    assert state.halt == "budget"
    assert state.turn_count == 1 and state.lanes[0].generation == 0


def test_exhaustive_four_lane_correction_rotation_contention():
    scripts = {
        "z": ("sealed", "defect", "sealed", "defect", "sealed", "pass"),
        "a": ("sealed", "defect", "sealed", "pass"),
        "y": ("sealed", "pass"),
        "b": ("sealed", "pass"),
    }
    visited = set()
    terminals = set()

    def explore(state):
        while True:
            new = reserve_next(state)
            if new == state:
                break
            state = new
        key = dump_state(state)
        if key in visited:
            return
        visited.add(key)
        assert state.parked_count <= 2 and state.active_count <= 4
        active = [lane for lane in state.lanes if lane.active is not None]
        if not active:
            assert [lane.phase for lane in state.lanes] == ["passed"] * 4
            assert [len(lane.turns) for lane in state.lanes] == [6, 4, 2, 2]
            assert [lane.generation for lane in state.lanes] == [1, 0, 0, 0]
            assert [lane.correction_reserved for lane in state.lanes] == [True, True, False, False]
            terminals.add(projection(state))
        for lane in active:
            explore(finish(state, lane.spec.id, scripts[lane.spec.id][lane.active]))

    explore(model(4, parking_capacity=2))
    assert len(visited) > 100
    assert len(terminals) == 1


def test_simultaneous_completion_batches_have_authored_ties():
    projections = set()
    for order in itertools.permutations(("z", "a", "y", "b")):
        state = model(4)
        for _ in range(4):
            state = reserve_next(state)
        for lane_id in order:
            state = finish(state, lane_id, "sealed")
        assert ready(state) == ("z", "a", "y", "b")
        for _ in range(4):
            state = reserve_next(state)
        for lane_id in reversed(order):
            state = finish(state, lane_id, "pass")
        projections.add(projection(state))
    assert len(projections) == 1
