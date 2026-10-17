"""Four-arm provider-free flow probe; symbolic evidence, never live adoption evidence."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

from unrest_harness.experimental_model import (
    Config, LaneSpec, admit, advance, complete, projection, reserve_next, transmission,
)


class MoreOrders(Exception):
    def __init__(self, due: tuple[int, ...]):
        self.due = due


def simulate(case: dict[str, Any], streaming: bool, reuse: bool,
             base: str, completion_order: tuple[tuple[int, ...], ...]) -> dict[str, Any]:
    count = len(case["workers"])
    admitted = admit(tuple(LaneSpec(id=f"lane-{i}", writes=(f"lane_{chr(97 + i)}.txt",),
                                    targets=(f"VAL-{chr(65 + i)}",)) for i in range(count)),
                     base=base, clean=True, isolated_dispatch=True,
                     config=Config(enabled=True, streaming=streaming, reuse=reuse,
                                   capacity=4, turn_budget=case["budget"]))
    if admitted.state is None:
        raise ValueError(admitted.reason)
    state = admitted.state
    pending: dict[int, int] = {}
    events: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    active_time = parked_time = 0
    first_failure = None
    tie_index = 0
    while True:
        while True:
            next_state = reserve_next(state)
            if next_state == state:
                break
            state = next_state
            for index, lane in enumerate(state.lanes):
                if lane.active is not None and index not in pending:
                    turn = lane.turns[lane.active]
                    state = transmission(state, lane.spec.id, turn.ordinal, "sent")
                    state = transmission(state, lane.spec.id, turn.ordinal, "acked")
                    duration = case["workers" if turn.phase in ("work", "correction")
                                    else "validators"][index]
                    pending[index] = state.now + duration
                    events.append({"lane": index, "ordinal": turn.ordinal, "phase": turn.phase,
                                   "start": state.now, "end": pending[index],
                                   "session": turn.session, "process": turn.process_generation,
                                   "candidate": turn.candidate, "targets": list(turn.targets),
                                   "generation": turn.generation,
                                   "active_count": state.active_count,
                                   "parked_count": state.parked_count,
                                   "leases": [lease.session for lease in state.lanes[index].leases]})
        if not pending:
            break
        now = min(pending.values())
        active_time += (now - state.now) * state.active_count
        parked_time += (now - state.now) * state.parked_count
        state = advance(state, now)
        due = tuple(index for index, end in pending.items() if end == now)
        if len(due) > 1:
            if tie_index == len(completion_order):
                raise MoreOrders(due)
            due = completion_order[tie_index]
            tie_index += 1
        for index in due:
            lane = state.lanes[index]
            assert lane.active is not None
            outcome = case["outcomes"][lane.active]
            state = complete(state, lane.spec.id, lane.active, outcome)
            after = state.lanes[index]
            transitions.append({"lane": index, "ordinal": lane.active,
                                "next_phase": after.phase, "next_candidate": after.candidate,
                                "generation": after.generation,
                                "leases": [lease.session for lease in after.leases],
                                "parking_reserved": after.parking_reserved})
            if outcome in ("defect", "other") and first_failure is None:
                first_failure = now
            del pending[index]
    result = json.loads(projection(state))
    passed = all(lane.phase == "passed" for lane in state.lanes) and state.halt is None
    return {
        "arm": f"{'streaming' if streaming else 'barrier'}/{'reuse' if reuse else 'fresh'}",
        "case": case["id"], "completion_order": [list(order) for order in completion_order],
        "evidence_kind": "simulation", "time_unit": "scripted seconds",
        "events": events, "transitions": transitions, "projection": result,
        "first_validator_start": min((e["start"] for e in events
                                       if e["phase"] == "validate"), default=None),
        "first_actionable_failure": first_failure,
        "integration_ready": state.now if passed else None,
        "fresh_gate_completion": None, "final_gate": "pending",
        "active_time": active_time, "parked_time": parked_time,
        "terminal_authority": [{"active": lane.active, "leases": [x.session for x in lane.leases],
                                "parking_reserved": lane.parking_reserved,
                                "writes": list(lane.spec.writes)} for lane in state.lanes],
        "turn_count": state.turn_count,
        "session_count": len({e["session"] for e in events}),
        "process_count": len({e["process"] for e in events}),
        "corrections": sum(lane.correction_reserved for lane in state.lanes),
        "rotations": sum(lane.generation for lane in state.lanes),
        "attention": any(lane.blocking is not None for lane in state.lanes),
        "halt": state.halt, "terminal": [lane.phase for lane in state.lanes],
        "conflicts": None, "cleanup": "symbolic only", "operator_actions": 0,
        "tokens": None, "cost": None,
    }


def verify_fixture_files(root: Path, manifest: dict[str, Any], stage: str) -> None:
    expected = manifest["fixture_bytes"]
    paths = sorted(root.rglob("*"))
    if any(p.is_symlink() for p in paths) or {
        str(p.relative_to(root)) for p in paths if p.is_file()
    } != set(expected):
        raise ValueError("fixture paths differ from independent oracle")
    if any((root / name).read_bytes() != spec[stage].encode()
           for name, spec in expected.items()):
        raise ValueError("fixture bytes differ from independent oracle")


def verify_trace(row: dict[str, Any], case: dict[str, Any], manifest: dict[str, Any]) -> bool:
    """Compare observations to authored transitions, never to another model run."""
    expected = {**case["expected"], **case.get("expected_by_arm", {}).get(row["arm"], {})}
    if any(row[key] != value for key, value in expected.items()):
        return False
    sequence = manifest["transitions"][case["transition_oracle"]]
    authority = manifest["authority"]
    reuse = row["arm"].endswith("/reuse")
    if len(row["events"]) != len(sequence) * len(case["workers"]) or len(
            row["transitions"]) != len(row["events"]):
        return False
    lanes = []
    for index in range(len(case["workers"])):
        target = [f"VAL-{chr(65 + index)}"]
        owner = reuse and index == authority["reuse_lane"]
        history: list[str] = []
        expected_turns = []
        leases: dict[str, str] = {}
        observed = [e for e in row["events"] if e["lane"] == index]
        transitions = [e for e in row["transitions"] if e["lane"] == index]
        if len(observed) != len(sequence) or len(transitions) != len(sequence):
            return False
        for ordinal, (step, event, transition) in enumerate(zip(
                sequence, observed, transitions, strict=True)):
            role = "worker" if step["phase"] in ("work", "correction") else "validator"
            paired = owner and step["generation"] == 0
            identity = f"lane-{index}:{role}:{step['generation']}"
            if not paired:
                identity += f":{ordinal}"
            leases.pop(role, None)
            fields = {"ordinal": ordinal, "phase": step["phase"],
                      "generation": step["generation"], "candidate": step["candidate"],
                      "targets": target, "session": identity, "process": identity,
                      "leases": list(leases.values())}
            if any(event[k] != v for k, v in fields.items()):
                return False
            if not (1 <= event["active_count"] <= authority["max_active"]
                    and 0 <= event["parked_count"] <= authority["max_parked"]):
                return False
            if paired:
                leases[role] = identity
            rotated = step["next_phase"] == "work"
            closed = rotated or step["next_phase"] in ("passed", "attention")
            if closed:
                leases.clear()
            after = {"lane": index, "ordinal": ordinal, "next_phase": step["next_phase"],
                     "next_candidate": step["next_candidate"],
                     "generation": 1 if rotated else step["generation"],
                     "leases": list(leases.values()),
                     "parking_reserved": 2 if paired and not closed else 0}
            if transition != after:
                return False
            if step["outcome"] in ("defect", "other"):
                history.append("noncorrectable" if step["outcome"] == "other" else "product_failure")
            expected_turns.append({k: fields[k] for k in
                                   ("ordinal", "phase", "generation", "candidate", "targets")} |
                                  {"status": "completed", "outcome": step["outcome"]})
        last = sequence[-1]
        lanes.append({"id": f"lane-{index}", "phase": last["next_phase"],
                      "candidate": last["next_candidate"], "generation": last["generation"],
                      "correction_reserved": len(sequence) >= 3, "reuse_owner": owner,
                      "targets": target, "history": history,
                      "blocking": "noncorrectable" if last["outcome"] == "other" else None,
                      "turns": expected_turns})
    if row["terminal_authority"] != [
        {"active": None, "leases": [], "parking_reserved": 0,
         "writes": [f"lane_{chr(97 + i)}.txt"]} for i in range(len(lanes))
    ]:
        return False
    identities = {e["session"] for e in row["events"]}
    if row["session_count"] != len(identities) or row["process_count"] != len(identities):
        return False
    passed = all(lane["phase"] == "passed" for lane in lanes) and expected["halt"] is None
    projection_expected = {
        "disposition": "integration_ready" if passed else "incomplete",
        "integration": [lane["id"] for lane in lanes] if passed else [],
        "final_targets": sorted(t for lane in lanes for t in lane["targets"]),
        "final_turns_reserved": authority["final_turns_reserved"],
        "final_gate": authority["final_gate"], "halt": expected["halt"], "lanes": lanes}
    return row["projection"] == projection_expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--mode", choices=("simulated",), default="simulated")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.case_manifest.read_text())
    for stage in ("base", "final"):
        verify_fixture_files(args.case_manifest.parent / "flow-files" / stage, manifest, stage)
    rows = []
    for case in manifest["cases"]:
        for streaming, reuse in itertools.product((False, True), repeat=2):
            pending_orders: list[tuple[tuple[int, ...], ...]] = [()]
            projections = set()
            while pending_orders:
                order = pending_orders.pop()
                try:
                    row = simulate(case, streaming, reuse, manifest["base"], order)
                except MoreOrders as exc:
                    pending_orders.extend(order + (permutation,)
                                          for permutation in itertools.permutations(exc.due))
                    continue
                row["oracle_ok"] = verify_trace(row, case, manifest)
                projections.add(json.dumps(row["projection"], sort_keys=True))
                rows.append(row)
            if len(projections) != 1:
                raise ValueError("causally equivalent completion orders changed decisions")
    import unrest_harness.experimental_model as model
    args.output.write_text(json.dumps({
        "manifest_sha256": hashlib.sha256(args.case_manifest.read_bytes()).hexdigest(),
        "model_sha256": hashlib.sha256(Path(model.__file__).read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixture_evidence": "independent synthetic input bytes checked; no coordinator integration",
        "live_benefit": "unmeasured", "production_reference": "not simulated",
        "samples": rows}, indent=2, sort_keys=True) + "\n")
    return 0 if all(row["oracle_ok"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
