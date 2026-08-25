from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from typing import Any, Iterator
import uuid

import pytest

import tools.v04_speed_runner as runner

from tools.v04_speed_runner import (
    FIXTURE_SHA256,
    SpeedRunnerError,
    load_fixture,
    run_guarded_benchmark,
    stable_signature,
    validate_result,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/v04_speed_workloads.json"
SCHEMA = ROOT / "src/unrest_harness/schemas/v04-speed-result.schema.json"
HEAD = "c90a98626d7d595b40a3ac0d1ac954f24e1e12ad"
TREE = "d05eec79be56cfa8a9011bfa8859e0a65bfc05ad"


@pytest.fixture(scope="module")
def fixture() -> dict[str, Any]:
    return load_fixture(FIXTURE)


@pytest.fixture(scope="module")
def speed_runs(tmp_path_factory: pytest.TempPathFactory) -> tuple[tuple[dict[str, Any], Path], ...]:
    parent = tmp_path_factory.mktemp("v04-speed-runs")
    roots = tuple(parent / f"run-{index}" for index in range(5))
    results = []
    artifact_roots = []
    for root in roots:
        artifact_root = root / "artifacts"
        output = root / "speed-result.json"
        subprocess.run(
            (
                sys.executable,
                str(ROOT / "tools/v04_speed_runner.py"),
                "--fixture", str(FIXTURE),
                "--schema", str(SCHEMA),
                "--result-root", str(artifact_root),
                "--output", str(output),
                "--candidate-head", HEAD,
                "--candidate-tree", TREE,
            ),
            cwd=ROOT,
            env={"LANG": "C", "LC_ALL": "C", "PYTHONUTF8": "1", "TZ": "UTC"},
            check=True,
        )
        results.append(json.loads(output.read_bytes()))
        artifact_roots.append(artifact_root)
    return tuple(zip(results, artifact_roots, strict=True))


def _row(result: dict[str, Any], row_id: str) -> dict[str, Any]:
    return next(row for row in result["rows"] if row["id"] == row_id)


def _raw(result_root: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    return json.loads((result_root / artifact["path"]).read_bytes())


def _artifacts(row: dict[str, Any]) -> list[dict[str, Any]]:
    columns = row["raw_artifacts"]
    keys = ("runtime_uuid", "kind", "path", "bytes", "sha256")
    return [
        dict(zip(keys, values, strict=True))
        for values in zip(*(columns[key] for key in keys), strict=True)
    ]


def _timing(row: dict[str, Any]) -> list[dict[str, Any]]:
    offsets = {"primitive": 0, "adapter": 0}
    records = []
    for pair_index, first in enumerate(row["pair_order"]):
        for pair_position, arm in enumerate(
            (first, "adapter" if first == "primitive" else "primitive")
        ):
            offset = offsets[arm]
            records.append({
                "arm": arm,
                "duration_ns": row[arm]["samples_ns"][offset],
                "pair_index": pair_index,
                "pair_position": pair_position,
                "runtime_uuid": row[arm]["runtime_uuids"][offset + 1],
            })
            offsets[arm] += 1
    return records


def _store_artifact(row: dict[str, Any], index: int, artifact: dict[str, Any]) -> None:
    for key, value in artifact.items():
        row["raw_artifacts"][key][index] = value


def _trace_path_accesses(
    monkeypatch: pytest.MonkeyPatch,
    *,
    archive_work: Path,
    external_roots: set[Path],
) -> list[tuple[str, str, str]]:
    trace: list[tuple[str, str, str]] = []
    archive_path = os.path.abspath(os.fspath(archive_work))
    external_paths = tuple(
        sorted(os.path.abspath(os.fspath(path)) for path in external_roots)
    )

    def is_within(candidate: str, parent: str) -> bool:
        return candidate == parent or candidate.startswith(f"{parent}{os.sep}")

    def instrument(operation: str, original: Any) -> Any:
        def traced(path: Path, *args: Any, **kwargs: Any) -> Any:
            candidate = os.path.abspath(os.fspath(path))
            location = "other"
            if any(is_within(candidate, parent) for parent in external_paths):
                location = "outside"
            elif is_within(candidate, archive_path):
                location = "archive"
            trace.append((operation, location, candidate))
            return original(path, *args, **kwargs)

        return traced

    for operation in (
        "exists", "is_dir", "is_file", "is_symlink", "lstat", "open",
        "read_bytes", "resolve", "stat",
    ):
        monkeypatch.setattr(
            Path, operation, instrument(operation, getattr(Path, operation))
        )
    return trace


def _schema_validator() -> Any:
    schema = json.loads(SCHEMA.read_bytes())
    jsonschema = importlib.import_module("jsonschema")
    validator_class = jsonschema.Draft202012Validator
    validator_class.check_schema(schema)
    return validator_class(schema, format_checker=jsonschema.FormatChecker())


def _schema_objects(value: object) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from _schema_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _schema_objects(child)


def test_frozen_fixture_has_exact_planning_byte_identity() -> None:
    assert len(FIXTURE.read_bytes()) == 4485
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256


def test_result_schema_closes_every_declared_object_and_accepts_real_result(speed_runs) -> None:
    schema = json.loads(SCHEMA.read_bytes())
    assert all(item.get("additionalProperties") is False for item in _schema_objects(schema))
    result, result_root = speed_runs[0]
    _schema_validator().validate(result)
    validate_result(result, result_root, load_fixture(FIXTURE))


def test_result_uses_exact_frozen_field_inventory(speed_runs, fixture) -> None:
    result = speed_runs[0][0]
    declared = fixture["result_schema"]
    assert set(result) == set(declared["required_top_level"])
    for row in result["rows"]:
        assert set(row) == set(declared["row_required"])
        assert set(row["primitive"]) == set(declared["arm_required"])
        assert set(row["adapter"]) == set(declared["arm_required"])
        assert set(row["raw_artifacts"]) == set(declared["artifact_required"])
        assert all(set(gate) == set(declared["gate_required"]) for gate in row["gates"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.pop("fixture_sha256"),
        lambda value: value.update({"network_attempts": "0"}),
        lambda value: value["rows"].pop(),
        lambda value: value["rows"].reverse(),
        lambda value: value["rows"][0]["primitive"]["runtime_uuids"].pop(),
        lambda value: value["rows"][0]["raw_artifacts"].update({"unknown": []}),
        lambda value: value["rows"][0]["gates"][0].pop("reason"),
        lambda value: value["rows"][0]["gates"][0].pop("observed"),
    ],
)
def test_closed_schema_rejects_unknown_missing_type_cardinality_and_order(speed_runs, fixture, mutate) -> None:
    invalid = deepcopy(speed_runs[0][0])
    mutate(invalid)
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


def _remove_warmup(value: dict[str, Any]) -> None:
    kinds = value["rows"][0]["raw_artifacts"]["kind"]
    kinds[kinds.index("primitive_warmup")] = "primitive_recorded"


def _duplicate_artifact_identity(value: dict[str, Any], field: str) -> None:
    identities = value["rows"][0]["raw_artifacts"][field]
    identities[1] = identities[0]


def _remove_gate(value: dict[str, Any]) -> None:
    value["rows"][0]["gates"].pop()


def _duplicate_gate(value: dict[str, Any]) -> None:
    value["rows"][0]["gates"][1] = deepcopy(value["rows"][0]["gates"][0])


def _wrong_gate(value: dict[str, Any]) -> None:
    value["rows"][0]["gates"][0]["name"] = "adapter_median_ratio_max"


def _reuse_cross_arm_uuid(
    value: dict[str, Any], row_index: int, source_arm: str, position: int
) -> None:
    target_arm = "adapter" if source_arm == "primitive" else "primitive"
    value["rows"][row_index][target_arm]["runtime_uuids"][position] = (
        value["rows"][row_index][source_arm]["runtime_uuids"][position]
    )


def _plausible_median_increment(value: dict[str, Any]) -> None:
    value["rows"][0]["primitive"]["median_ns"] += 1


@pytest.mark.parametrize(
    "mutate",
    [
        _remove_warmup,
        lambda value: _duplicate_artifact_identity(value, "runtime_uuid"),
        lambda value: _duplicate_artifact_identity(value, "path"),
        lambda value: _duplicate_artifact_identity(value, "sha256"),
        _remove_gate,
        _duplicate_gate,
        _wrong_gate,
        lambda value: value.update({"release_pass": False}),
    ],
    ids=[
        "missing-warmup-eleven-recorded",
        "duplicate-artifact-uuid",
        "duplicate-artifact-path",
        "duplicate-artifact-digest",
        "missing-gate",
        "duplicate-gate",
        "wrong-gate",
        "release-pass-inconsistent",
    ],
)
def test_draft_2020_12_schema_rejects_fixture_invariant_regressions(speed_runs, mutate) -> None:
    invalid = deepcopy(speed_runs[0][0])
    mutate(invalid)
    assert list(_schema_validator().iter_errors(invalid))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"accepted_base": "0" * 40}),
        lambda value: value["rows"][0]["raw_artifacts"]["path"].__setitem__(0, "."),
        lambda value: value["rows"][0]["raw_artifacts"]["path"].__setitem__(0, "./raw/evidence.json"),
        lambda value: _reuse_cross_arm_uuid(value, 0, "primitive", 1),
        lambda value: value["rows"][0].update({"normalization": ["/made/up"]}),
        lambda value: value["rows"][0].update({"status": "failed"}),
        lambda value: value["rows"][0]["gates"][0].update({"passed": False, "reason": "ok"}),
        lambda value: value.update({"release_pass": False}),
    ],
    ids=[
        "wrong-base", "dot-path", "dot-segment-path", "cross-arm-uuid",
        "arbitrary-normalization", "false-status",
        "inconsistent-gate-reason", "false-release",
    ],
)
def test_schema_alone_rejects_all_amended_candidate_regressions(speed_runs, mutate) -> None:
    invalid = deepcopy(speed_runs[0][0])
    mutate(invalid)
    assert list(_schema_validator().iter_errors(invalid))


def test_median_arithmetic_is_a_python_layer_invariant(speed_runs, fixture) -> None:
    """Stock schema owns safe shape; validate_result owns sibling arithmetic."""

    invalid = deepcopy(speed_runs[0][0])
    _plausible_median_increment(invalid)
    assert not list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError, match="time:median"):
        validate_result(invalid, speed_runs[0][1], fixture)


@pytest.mark.parametrize("row_index", range(3))
@pytest.mark.parametrize("position", range(11))
@pytest.mark.parametrize("source_arm", ("primitive", "adapter"))
def test_schema_and_python_reject_cross_arm_uuid_reuse_in_every_row_and_position(
    speed_runs, fixture, row_index: int, position: int, source_arm: str
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    _reuse_cross_arm_uuid(invalid, row_index, source_arm, position)
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


def test_schema_and_python_reject_within_arm_uuid_reuse(speed_runs, fixture) -> None:
    invalid = deepcopy(speed_runs[0][0])
    invalid["rows"][2]["primitive"]["runtime_uuids"][10] = (
        invalid["rows"][2]["primitive"]["runtime_uuids"][0]
    )
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


@pytest.mark.parametrize(
    ("source_row", "target_row"),
    [(source, target) for source in range(3) for target in range(3) if source != target],
)
@pytest.mark.parametrize("arm", ("primitive", "adapter"))
@pytest.mark.parametrize("position", range(11))
def test_schema_and_python_reject_same_arm_cross_row_uuid_reuse(
    speed_runs, fixture, source_row: int, target_row: int, arm: str, position: int
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    invalid["rows"][target_row][arm]["runtime_uuids"][position] = (
        invalid["rows"][source_row][arm]["runtime_uuids"][position]
    )
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


def test_pair_schedule_uuid_roots_medians_and_complete_raw_bytes(speed_runs, fixture) -> None:
    result, result_root = speed_runs[0]
    pair_order = fixture["protocol"]["pair_order"]
    all_uuids: set[str] = set()
    all_roots: set[str] = set()
    for row in result["rows"]:
        assert row["pair_order"] == pair_order
        artifacts = _artifacts(row)
        timing = _timing(row)
        assert len(artifacts) == 22
        for arm_name in ("primitive", "adapter"):
            samples = [item["duration_ns"] for item in timing if item["arm"] == arm_name]
            assert len(samples) == 10
            assert len({item["runtime_uuid"] for item in timing if item["arm"] == arm_name}) == 10
            parsed = [uuid.UUID(value) for value in row[arm_name]["runtime_uuids"]]
            assert {value.version for value in parsed} == {4}
            assert {value.variant for value in parsed} == {uuid.RFC_4122}
            expected_nibble = runner._UUID_DOMAIN_NIBBLES[(row["id"], arm_name)]
            assert {value.int >> 124 for value in parsed} == {expected_nibble}
            arm_artifacts = [item for item in artifacts if item["kind"].startswith(arm_name)]
            assert [item["kind"] for item in arm_artifacts].count(f"{arm_name}_warmup") == 1
            assert [item["kind"] for item in arm_artifacts].count(f"{arm_name}_recorded") == 10
        for artifact in artifacts:
            path = result_root / artifact["path"]
            raw_bytes = path.read_bytes()
            raw = json.loads(raw_bytes)
            assert len(raw_bytes) == artifact["bytes"]
            assert hashlib.sha256(raw_bytes).hexdigest() == artifact["sha256"]
            assert raw["runtime_uuid"] == artifact["runtime_uuid"]
            assert raw["runtime_uuid"] not in all_uuids
            assert raw["absolute_root"] not in all_roots
            all_uuids.add(raw["runtime_uuid"])
            all_roots.add(raw["absolute_root"])
        for pair_index, first in enumerate(pair_order):
            pair = [item for item in timing if item["pair_index"] == pair_index]
            assert [item["arm"] for item in pair] == [first, "adapter" if first == "primitive" else "primitive"]
    assert len(all_uuids) == len(all_roots) == 66


def test_uuid_domains_are_disjoint_and_retain_118_random_bits() -> None:
    assert set(runner._UUID_DOMAIN_NIBBLES) == {
        (row_id, arm)
        for row_id in ("improvement-v1", "project-v1", "task-v1")
        for arm in ("primitive", "adapter")
    }
    assert len(set(runner._UUID_DOMAIN_NIBBLES.values())) == 6
    assert all(0 <= value < 16 for value in runner._UUID_DOMAIN_NIBBLES.values())
    assert 122 - 4 == 118


def _uuid_syntax_mutation(value: str, mutation: str) -> str:
    if mutation == "malformed":
        return value.replace("-", "")
    index, replacement = {
        "version": (14, "1"),
        "variant": (19, "7"),
    }[mutation]
    return value[:index] + replacement + value[index + 1:]


@pytest.mark.parametrize("row_index", range(3))
@pytest.mark.parametrize("mutation", ("malformed", "version", "variant"))
def test_schema_and_python_reject_noncanonical_row_uuid(
    speed_runs, fixture, row_index: int, mutation: str
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    current = invalid["rows"][row_index]["runtime_uuid"]
    invalid["rows"][row_index]["runtime_uuid"] = _uuid_syntax_mutation(
        current, mutation
    )
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError, match="schema:row_uuid"):
        validate_result(invalid, speed_runs[0][1], fixture)


@pytest.mark.parametrize("row_index", range(3))
@pytest.mark.parametrize("arm", ("primitive", "adapter"))
@pytest.mark.parametrize("position", range(11))
@pytest.mark.parametrize("mutation", ("malformed", "version", "variant"))
def test_schema_and_python_reject_noncanonical_arm_uuid(
    speed_runs, fixture, row_index: int, arm: str, position: int, mutation: str
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    ids = invalid["rows"][row_index][arm]["runtime_uuids"]
    ids[position] = _uuid_syntax_mutation(ids[position], mutation)
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


@pytest.mark.parametrize("row_index", range(3))
@pytest.mark.parametrize("position", range(22))
@pytest.mark.parametrize("mutation", ("malformed", "version", "variant"))
def test_schema_and_python_reject_noncanonical_artifact_uuid(
    speed_runs, fixture, row_index: int, position: int, mutation: str
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    ids = invalid["rows"][row_index]["raw_artifacts"]["runtime_uuid"]
    ids[position] = _uuid_syntax_mutation(ids[position], mutation)
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError):
        validate_result(invalid, speed_runs[0][1], fixture)


@pytest.mark.parametrize("row_index", range(3))
@pytest.mark.parametrize("position", range(22))
def test_schema_and_python_reject_cross_row_artifact_uuid_domain(
    speed_runs, fixture, row_index: int, position: int
) -> None:
    invalid = deepcopy(speed_runs[0][0])
    ids = invalid["rows"][row_index]["raw_artifacts"]["runtime_uuid"]
    replacement_nibble = (4, 8, 0)[row_index]
    ids[position] = f"{replacement_nibble:x}{ids[position][1:]}"
    assert list(_schema_validator().iter_errors(invalid))
    with pytest.raises(SpeedRunnerError, match="schema:artifact_uuid_domain"):
        validate_result(invalid, speed_runs[0][1], fixture)


def test_task_exact_calls_outcome_parity_and_gates(speed_runs) -> None:
    result, result_root = speed_runs[0]
    row = _row(result, "task-v1")
    artifacts = _artifacts(row)
    raw = [_raw(result_root, item) for item in artifacts]
    assert {tuple(item["outcome"]["operation_sequence"]) for item in raw} == {
        ("open_inquiry", "advance_inquiry", "handoff_inquiry", "inspect_inquiry")
    }
    assert {item["outcome"]["terminal"] for item in raw} == {"completed"}
    assert {item["outcome"]["summary"] for item in raw} == {"alpha"}
    assert row["primitive"]["public_invocations"] == 4
    assert row["adapter"]["public_invocations"] == 1
    assert len(row["primitive"]["normalized_sha256"]) == 64
    assert row["primitive"]["normalized_sha256"] == row["adapter"]["normalized_sha256"]
    assert len({item["sha256"] for item in artifacts}) == 22
    assert all(gate["passed"] for gate in row["gates"])


def test_project_real_serial_parallel_topology_and_persisted_results(speed_runs) -> None:
    result, result_root = speed_runs[0]
    row = _row(result, "project-v1")
    raw = [_raw(result_root, item) for item in _artifacts(row)]
    for item in raw:
        outcome = item["outcome"]
        assert outcome["attempts"] == 3
        assert [entry["task_id"] for entry in outcome["result_artifacts"]] == ["leaf-a", "leaf-b", "join"]
        events = {event["id"]: event for event in outcome["leaf_events"]}
        if item["arm"] == "primitive":
            assert events["leaf-a"]["end_ns"] <= events["leaf-b"]["start_ns"]
        else:
            assert max(events["leaf-a"]["start_ns"], events["leaf-b"]["start_ns"]) < min(events["leaf-a"]["end_ns"], events["leaf-b"]["end_ns"])
            assert len(set(outcome["workspace_identities"].values())) == 2
    samples = {
        arm: sorted(
            item["duration_ns"] for item in _timing(row) if item["arm"] == arm
        )
        for arm in ("primitive", "adapter")
    }
    medians = {
        arm: (values[4] + values[5]) // 2 for arm, values in samples.items()
    }
    assert medians["adapter"] / medians["primitive"] <= 0.75
    assert all(gate["passed"] for gate in row["gates"])


def test_project_workspace_identity_handles_a_symlinked_root(
    fixture, tmp_path: Path
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    root = alias / "sample"
    root.mkdir()
    project_row = next(row for row in fixture["rows"] if row["id"] == "project-v1")
    outcome = runner._project_workload("adapter", project_row, root)
    assert outcome["workspace_identities"] == {
        "leaf-a": "isolated/leaf-a",
        "leaf-b": "isolated/leaf-b",
    }


def test_improvement_is_executed_provider_free_and_stops_before_decision(speed_runs) -> None:
    result, result_root = speed_runs[0]
    row = _row(result, "improvement-v1")
    raw = [_raw(result_root, item) for item in _artifacts(row)]
    expected_calls = ("open_campaign", "add_candidate", "evaluate_candidate", "review_candidate", "inspect_campaign")
    for item in raw:
        outcome = item["outcome"]
        assert tuple(outcome["operation_sequence"]) == expected_calls
        assert outcome["evaluation"] == "completed_pass"
        assert outcome["review"] == "approve"
        assert outcome["campaign_phase"] == "reviewed"
        assert outcome["terminal"] == "decision_needed"
        assert outcome["candidate_before_sha256"] == outcome["candidate_after_sha256"]
        assert outcome["promotions"] == outcome["rollbacks"] == 0
    assert row["primitive"]["public_invocations"] == 5
    assert row["adapter"]["public_invocations"] == 1
    assert all(gate["passed"] for gate in row["gates"])


def _independent_chain(seed: bytes, rounds: int) -> str:
    value = seed
    for _ in range(rounds):
        value = hashlib.sha256(value).digest()
    return "sha256:" + value.hex()


def test_improvement_retains_full_evaluation_and_review_chains(speed_runs, fixture) -> None:
    assert runner.IMPROVEMENT_EVALUATION_DIGEST_ROUNDS == 16_384
    assert runner.IMPROVEMENT_REVIEW_DIGEST_ROUNDS == 8_192
    result, result_root = speed_runs[0]
    row = _row(result, "improvement-v1")
    fixture_row = next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    candidate_bytes = fixture_row["input"]["candidate_bytes_utf8"].encode("utf-8")
    evaluation_digest = _independent_chain(
        candidate_bytes, runner.IMPROVEMENT_EVALUATION_DIGEST_ROUNDS
    )
    review_digest = _independent_chain(
        evaluation_digest.encode("ascii"), runner.IMPROVEMENT_REVIEW_DIGEST_ROUNDS
    )

    raw = [_raw(result_root, artifact) for artifact in _artifacts(row)]
    assert {item["outcome"]["evaluation_digest"] for item in raw} == {
        evaluation_digest
    }
    assert {item["outcome"]["review_digest"] for item in raw} == {review_digest}
    assert {item["arm"] for item in raw} == {"primitive", "adapter"}
    expected_projection = runner._canonical(runner._projection(raw[0]))
    assert row["primitive"]["normalized_sha256"] == hashlib.sha256(
        expected_projection
    ).hexdigest()
    assert row["adapter"]["normalized_sha256"] == hashlib.sha256(
        expected_projection
    ).hexdigest()

    inflated_evaluation_digest = _independent_chain(candidate_bytes, 131_072)
    inflated_review_digest = _independent_chain(
        inflated_evaluation_digest.encode("ascii"), 65_536
    )
    assert evaluation_digest != inflated_evaluation_digest
    assert review_digest != inflated_review_digest
    assert inflated_evaluation_digest not in {
        item["outcome"]["evaluation_digest"] for item in raw
    }
    assert inflated_review_digest not in {
        item["outcome"]["review_digest"] for item in raw
    }


def test_improvement_input_byte_changes_retained_evidence_for_both_arms(
    fixture, tmp_path: Path
) -> None:
    row = deepcopy(
        next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    )
    baseline: dict[str, dict[str, Any]] = {}
    changed: dict[str, dict[str, Any]] = {}
    for arm in ("primitive", "adapter"):
        root = tmp_path / f"baseline-{arm}"
        root.mkdir()
        baseline[arm] = asyncio.run(runner._improvement_workload(arm, row, root))

    row["input"]["candidate_bytes_utf8"] = "setting=adapteq\n"
    for arm in ("primitive", "adapter"):
        root = tmp_path / f"changed-{arm}"
        root.mkdir()
        changed[arm] = asyncio.run(runner._improvement_workload(arm, row, root))

    for values in (baseline, changed):
        primitive_mechanics = values["primitive"].pop("mechanics")
        adapter_mechanics = values["adapter"].pop("mechanics")
        assert values["primitive"] == values["adapter"]
        for key in (
            "dispatcher_configuration_identity", "logical_events",
            "logical_operations", "validation_calls",
        ):
            assert primitive_mechanics[key] == adapter_mechanics[key]
    for field in (
        "candidate_before_sha256",
        "candidate_after_sha256",
        "evaluation_digest",
        "review_digest",
    ):
        assert baseline["primitive"][field] != changed["primitive"][field]


def test_validator_rejects_discarded_constant_review_digest(
    speed_runs, fixture, tmp_path: Path
) -> None:
    result = deepcopy(speed_runs[0][0])
    root = tmp_path / "discarded-review"
    shutil.copytree(speed_runs[0][1], root)
    row = _row(result, "improvement-v1")
    artifact = _artifacts(row)[0]
    path = root / artifact["path"]
    raw = json.loads(path.read_bytes())
    raw["outcome"]["review_digest"] = runner._digest("review")
    encoded = runner._canonical(raw)
    path.write_bytes(encoded)
    artifact["bytes"] = len(encoded)
    artifact["sha256"] = hashlib.sha256(encoded).hexdigest()
    _store_artifact(row, 0, artifact)

    with pytest.raises(SpeedRunnerError, match="nondeterministic:raw_projection"):
        validate_result(result, root, fixture)


def test_improvement_uses_one_generic_transaction_per_public_invocation(
    fixture, tmp_path: Path
) -> None:
    row = next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    (tmp_path / "primitive").mkdir()
    primitive = asyncio.run(
        runner._improvement_workload("primitive", row, tmp_path / "primitive")
    )
    (tmp_path / "adapter").mkdir()
    adapter = asyncio.run(
        runner._improvement_workload("adapter", row, tmp_path / "adapter")
    )
    primitive_mechanics = primitive.pop("mechanics")
    adapter_mechanics = adapter.pop("mechanics")
    assert primitive == adapter
    assert primitive_mechanics["dispatcher_configuration_identity"] == (
        adapter_mechanics["dispatcher_configuration_identity"]
    )
    assert primitive_mechanics["logical_events"] == adapter_mechanics["logical_events"]
    assert primitive_mechanics["validation_calls"] == adapter_mechanics["validation_calls"]
    assert primitive_mechanics["transaction_count"] == 5
    assert adapter_mechanics["transaction_count"] == 1
    assert primitive_mechanics["public_invocation_boundaries"] == row["primitive_calls"]
    assert adapter_mechanics["public_invocation_boundaries"] == row["adapter_calls"]
    assert [event["kind"] for event in adapter_mechanics["logical_events"]] == [
        "campaign_opened",
        "candidate_added",
        "evaluation_completed",
        "review_completed",
        "campaign_inspected",
    ]


def test_each_recorded_sample_collects_before_clock_and_restores_gc(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row = next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    events: list[str] = []
    enabled = True

    def isenabled() -> bool:
        return enabled

    def collect() -> int:
        events.append("collect")
        return 0

    def disable() -> None:
        nonlocal enabled
        enabled = False
        events.append("disable")

    def enable() -> None:
        nonlocal enabled
        enabled = True
        events.append("enable")

    class Clock:
        def __call__(self) -> int:
            assert enabled is False
            events.append("clock")
            return 100

    async def workload(_row: Any, _arm: str, _root: Path) -> dict[str, Any]:
        assert enabled is False
        events.append("workload")
        return {"_measured_duration_ns": 25}

    monkeypatch.setattr(runner.gc, "isenabled", isenabled)
    monkeypatch.setattr(runner.gc, "collect", collect)
    monkeypatch.setattr(runner.gc, "disable", disable)
    monkeypatch.setattr(runner.gc, "enable", enable)
    monkeypatch.setattr(runner, "CLOCK", Clock())
    monkeypatch.setattr(runner, "_execute_workload", workload)

    duration, _, _ = asyncio.run(
        runner._one_run(row, "primitive", tmp_path, "recorded", 0, 0)
    )

    assert duration == 25
    assert events == ["collect", "disable", "clock", "workload", "enable"]
    assert enabled is True


def test_improvement_measures_equal_real_digest_work_for_both_arms(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row = next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    original_sha256 = runner.hashlib.sha256
    counts: dict[str, int] = {"primitive": 0, "adapter": 0}

    for arm in ("primitive", "adapter"):
        def counted_sha256(value: bytes = b"", *, _arm: str = arm):
            counts[_arm] += 1
            return original_sha256(value)

        monkeypatch.setattr(runner.hashlib, "sha256", counted_sha256)
        root = tmp_path / arm
        root.mkdir()
        outcome = asyncio.run(runner._improvement_workload(arm, row, root))
        assert outcome["terminal"] == "decision_needed"
        assert outcome["operation_sequence"] == row["primitive_calls"]

    # Both arms perform the same candidate, evaluation, review, and result
    # hashing. The transaction rule is generic and has no arm input.
    assert counts["primitive"] == counts["adapter"]
    assert counts["primitive"] >= (
        runner.IMPROVEMENT_EVALUATION_DIGEST_ROUNDS
        + runner.IMPROVEMENT_REVIEW_DIGEST_ROUNDS
    )


def test_runner_source_has_no_workload_padding_or_sample_selection() -> None:
    source = inspect.getsource(runner)
    assert "131_072" not in source
    assert "65_536" not in source
    run_row_source = inspect.getsource(runner._run_row)
    for forbidden in ("sleep", "retry", "discard", "outlier", "affinity", "shuffle"):
        assert forbidden not in run_row_source.lower()
    assert "for pair_index, first in enumerate(pair_order)" in run_row_source
    assert "for pair_position, arm in enumerate((first, second))" in run_row_source


def test_task_uses_symmetric_lifecycle_and_generic_invocation_transactions(
    fixture, tmp_path: Path
) -> None:
    row = next(item for item in fixture["rows"] if item["id"] == "task-v1")
    outcomes = {
        arm: asyncio.run(runner._task_workload(arm, row, tmp_path / arm))
        for arm in ("primitive", "adapter")
    }
    primitive_mechanics = outcomes["primitive"].pop("mechanics")
    adapter_mechanics = outcomes["adapter"].pop("mechanics")
    assert outcomes["primitive"] == outcomes["adapter"] == {
        "manual_checkpoints": 0,
        "operation_sequence": row["primitive_calls"],
        "summary": "alpha",
        "terminal": "completed",
    }
    assert runner.TASK_EVIDENCE_DIGEST_ROUNDS == 4_096
    assert primitive_mechanics["logical_operations"] == row["primitive_calls"]
    assert adapter_mechanics["logical_operations"] == row["primitive_calls"]
    assert primitive_mechanics["validation_calls"] == adapter_mechanics["validation_calls"]
    assert primitive_mechanics["dispatcher_configuration_identity"] == (
        adapter_mechanics["dispatcher_configuration_identity"]
    )
    assert primitive_mechanics["transaction_count"] == 4
    assert adapter_mechanics["transaction_count"] == 1
    assert primitive_mechanics["public_invocation_boundaries"] == row["primitive_calls"]
    assert adapter_mechanics["public_invocation_boundaries"] == row["adapter_calls"]
    source = inspect.getsource(runner)
    for forbidden in ("adapter_dispatch", "batch_events", "current_adapter"):
        assert forbidden not in source
    for dependency in (
        runner._InvocationJournal,
        runner._TaskLifecycle,
        runner._LocalImprovementManager,
    ):
        dependency_source = inspect.getsource(dependency)
        assert "if arm" not in dependency_source
        assert "if adapter" not in dependency_source
        assert "arm ==" not in dependency_source
        assert "adapter ==" not in dependency_source
        assert "arm" not in inspect.signature(dependency).parameters
        assert "adapter" not in inspect.signature(dependency).parameters
    assert "_records" not in inspect.getsource(runner._TaskLifecycle)
    assert "/outcome/mechanics/logical_events" in runner.PROJECTION_PATHS["task-v1"]
    raw = {
        "absolute_root": str(tmp_path.resolve()),
        "arm": "adapter",
        "duration_ns": 1,
        "kind": "recorded",
        "outcome": {**outcomes["adapter"], "mechanics": adapter_mechanics},
        "pair_index": 0,
        "pair_position": 1,
        "row_id": "task-v1",
        "runtime_uuid": str(uuid.uuid4()),
        "timestamp_ns": 1,
    }
    expected_projection = runner._projection(raw)
    without_mechanics = deepcopy(raw)
    without_mechanics["outcome"].pop("mechanics")
    with pytest.raises(SpeedRunnerError, match="schema:outcome_keys"):
        runner._projection(without_mechanics)
    skipped_validation = deepcopy(raw)
    skipped_validation["outcome"]["mechanics"]["validation_calls"] = []
    assert runner._projection(skipped_validation) != expected_projection


def test_inflated_improvement_workload_fails_before_evidence_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(runner, "IMPROVEMENT_EVALUATION_DIGEST_ROUNDS", 131_072)
    monkeypatch.setattr(runner, "IMPROVEMENT_REVIEW_DIGEST_ROUNDS", 65_536)
    result_root = tmp_path / "inflated"
    with pytest.raises(SpeedRunnerError, match="binding:improvement_workload"):
        run_guarded_benchmark(FIXTURE, result_root, HEAD, TREE)
    assert not result_root.exists()


def test_inflated_task_workload_fails_before_evidence_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(runner, "TASK_EVIDENCE_DIGEST_ROUNDS", 32_768)
    result_root = tmp_path / "inflated-task"
    with pytest.raises(SpeedRunnerError, match="binding:task_workload"):
        run_guarded_benchmark(FIXTURE, result_root, HEAD, TREE)
    assert not result_root.exists()


def test_failed_timing_gate_retains_complete_row_evidence(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    row = next(item for item in fixture["rows"] if item["id"] == "improvement-v1")
    result_root = tmp_path / "evidence"
    calls = {"primitive": 0, "adapter": 0}

    async def one_run(
        row_value: dict[str, Any],
        arm: str,
        root: Path,
        kind: str,
        pair_index: int | None,
        pair_position: int | None,
    ) -> tuple[int, str, dict[str, Any]]:
        calls[arm] += 1
        runtime_uuid = str(uuid.uuid4())
        outcome = runner._expected_projection(row_value)["outcome"]
        mechanics = outcome["mechanics"]
        mechanics.update({
            "logical_event_count": mechanics["logical_operation_count"],
            "physical_write_count": 0,
            "physical_writes": [],
            "public_invocation_boundaries": row_value[f"{arm}_calls"],
            "public_invocation_count": len(row_value[f"{arm}_calls"]),
            "transaction_boundaries": [],
            "transaction_count": len(row_value[f"{arm}_calls"]),
            "validation_count": len(mechanics["validation_calls"]),
        })
        raw = {
            "absolute_root": str((root / "work" / runtime_uuid).resolve()),
            "arm": arm,
            "duration_ns": 120 if arm == "adapter" else 100,
            "kind": kind,
            "outcome": outcome,
            "pair_index": pair_index,
            "pair_position": pair_position,
            "row_id": row_value["id"],
            "runtime_uuid": runtime_uuid,
            "timestamp_ns": calls[arm],
        }
        relative = Path("raw") / arm / f"{runtime_uuid}.json"
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        encoded = runner._canonical(raw)
        target.write_bytes(encoded)
        artifact = {
            "bytes": len(encoded),
            "kind": f"{arm}_{kind}",
            "path": relative.as_posix(),
            "runtime_uuid": runtime_uuid,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
        return raw["duration_ns"], runtime_uuid, artifact

    monkeypatch.setattr(runner, "_one_run", one_run)
    failed = asyncio.run(
        runner._run_row(row, fixture["protocol"]["pair_order"], result_root)
    )

    assert failed["status"] == "failed"
    assert failed["gates"][-1] == {
        "limit": 1.1,
        "name": "adapter_median_ratio_max",
        "observed": 1.2,
        "passed": False,
        "reason": "time",
    }
    assert len(_artifacts(failed)) == 22
    assert all((result_root / artifact["path"]).is_file() for artifact in _artifacts(failed))


def test_environment_network_subprocess_and_two_run_reproducibility(speed_runs) -> None:
    first, second = speed_runs[0][0], speed_runs[1][0]
    assert first["environment"] == second["environment"] == {
        "clock": "time.perf_counter_ns",
        "command_guard_probes": ["os.system", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"],
        "encoding": "UTF-8",
        "environment_keys": ["LANG", "LC_ALL", "PYTHONUTF8", "TZ"],
        "locale": "C",
        "network_guard_probes": list(runner._network_guard_names()),
        "provider_attempts": 0,
        "secret_keys_removed": True,
        "subprocess_attempts": 0,
    }
    assert first["network_attempts"] == second["network_attempts"] == 0
    assert stable_signature(first) == stable_signature(second)
    first_uuids = {item["runtime_uuid"] for row in first["rows"] for item in _artifacts(row)}
    second_uuids = {item["runtime_uuid"] for row in second["rows"] for item in _artifacts(row)}
    assert first_uuids.isdisjoint(second_uuids)


def test_validator_rejects_result_structure_uuid_and_gate_tampering(speed_runs, fixture) -> None:
    result, result_root = speed_runs[0]
    mutations = []
    unknown = deepcopy(result)
    unknown["rows"][0]["unknown"] = True
    mutations.append(unknown)
    missing = deepcopy(result)
    missing["rows"][0]["adapter"].pop("terminal")
    mutations.append(missing)
    duplicate = deepcopy(result)
    duplicate["rows"][0]["adapter"]["runtime_uuids"][1] = duplicate["rows"][0]["primitive"]["runtime_uuids"][1]
    mutations.append(duplicate)
    order = deepcopy(result)
    order["rows"].reverse()
    mutations.append(order)
    gate = deepcopy(result)
    gate["rows"][0]["gates"][-1]["limit"] = 0.0
    mutations.append(gate)
    for invalid in mutations:
        with pytest.raises(SpeedRunnerError):
            validate_result(invalid, result_root, fixture)


def test_validator_rejects_missing_digest_escape_raw_field_nondeterminism_and_sequence(speed_runs, fixture, tmp_path: Path) -> None:
    original_result, original_root = speed_runs[0]
    for case in ("missing", "digest", "escape", "raw_field", "nondeterministic", "sequence"):
        result = deepcopy(original_result)
        root = tmp_path / case
        shutil.copytree(original_root, root)
        artifact = _artifacts(result["rows"][2])[0]
        path = root / artifact["path"]
        if case == "missing":
            path.unlink()
        elif case == "digest":
            path.write_bytes(path.read_bytes() + b"x")
        elif case == "escape":
            artifact["path"] = "../escape.json"
        else:
            raw = json.loads(path.read_bytes())
            if case == "raw_field":
                raw["undeclared"] = True
            elif case == "nondeterministic":
                raw["outcome"]["summary"] = "beta"
            else:
                raw["pair_index"] = 99
            encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode() + b"\n"
            path.write_bytes(encoded)
            artifact["bytes"] = len(encoded)
            artifact["sha256"] = hashlib.sha256(encoded).hexdigest()
        _store_artifact(result["rows"][2], 0, artifact)
        with pytest.raises(SpeedRunnerError):
            validate_result(result, root, fixture)


def test_validator_reopens_complete_raw_archive_after_original_roots_are_deleted(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result_root = tmp_path / "original"
    result = run_guarded_benchmark(FIXTURE, result_root, HEAD, TREE)
    external_roots = {
        Path(_raw(result_root, artifact)["absolute_root"])
        for row in result["rows"]
        for artifact in _artifacts(row)
    }
    assert len(external_roots) == 66
    archive = tmp_path / "archive"
    shutil.copytree(result_root / "raw", archive / "raw")
    shutil.copytree(result_root / "work", archive / "raw" / "work")
    shutil.rmtree(result_root)

    archive_work = archive / "raw" / "work"
    with monkeypatch.context() as access_patch:
        access_trace = _trace_path_accesses(
            access_patch,
            archive_work=archive_work,
            external_roots=external_roots,
        )
        validate_result(result, archive, fixture)
    assert [entry for entry in access_trace if entry[1] == "outside"] == []
    archive_samples_accessed = {
        Path(path).relative_to(archive_work).parts[0]
        for _, location, path in access_trace
        if location == "archive" and Path(path) != archive_work
    }
    assert archive_samples_accessed == {path.name for path in external_roots}
    assert sorted(path.name for path in archive.iterdir()) == ["raw"]

    project_row = _row(result, "project-v1")
    project_artifact = next(
        artifact
        for artifact in _artifacts(project_row)
        if artifact["kind"] == "primitive_recorded"
    )
    raw = _raw(archive, project_artifact)
    archived_sample = archive / "raw" / "work" / Path(raw["absolute_root"]).name

    missing_archive = tmp_path / "missing-archive"
    shutil.copytree(archive, missing_archive)
    shutil.rmtree(missing_archive / "raw" / "work" / archived_sample.name)

    external_sample = Path(raw["absolute_root"])
    external_sample.parent.mkdir(parents=True)
    shutil.copytree(archived_sample, external_sample)
    try:
        with monkeypatch.context() as access_patch:
            missing_trace = _trace_path_accesses(
                access_patch,
                archive_work=missing_archive / "raw" / "work",
                external_roots=external_roots,
            )
            with pytest.raises(SpeedRunnerError, match="binding:sample_root"):
                validate_result(result, missing_archive, fixture)
        assert [entry for entry in missing_trace if entry[1] == "outside"] == []

        tampered_archive = tmp_path / "tampered-archive"
        shutil.copytree(archive, tampered_archive)
        tampered_result = (
            tampered_archive
            / "raw"
            / "work"
            / archived_sample.name
            / "result/leaf-a.txt"
        )
        tampered_result.write_bytes(b"CORRUPTED\n")
        with monkeypatch.context() as access_patch:
            tampered_trace = _trace_path_accesses(
                access_patch,
                archive_work=tampered_archive / "raw" / "work",
                external_roots=external_roots,
            )
            with pytest.raises(SpeedRunnerError, match="digest:project_result"):
                validate_result(result, tampered_archive, fixture)
        assert [entry for entry in tampered_trace if entry[1] == "outside"] == []
    finally:
        shutil.rmtree(result_root)


def test_task_summary_is_derived_from_the_inspected_answered_branch(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = runner._TaskLifecycle._record

    def beta_record(self: Any) -> dict[str, object]:
        value = original(self)
        if value["state"] == "answered":
            value["branch_outcomes"] = {"alpha": "pending", "beta": "answered"}
        return value

    monkeypatch.setattr(runner._TaskLifecycle, "_record", beta_record)
    task_row = next(row for row in fixture["rows"] if row["id"] == "task-v1")
    outcomes = [
        asyncio.run(runner._task_workload(arm, task_row, tmp_path / arm))
        for arm in ("primitive", "adapter")
    ]
    assert [outcome["summary"] for outcome in outcomes] == ["beta", "beta"]


@pytest.mark.parametrize(
    "case",
    [
        "corrupt-result", "nonexistent-root", "false-primitive-overlap",
        "wrong-attempts", "retry-event",
    ],
)
def test_project_validation_reopens_results_and_recomputes_topology(
    speed_runs, fixture, case: str
) -> None:
    result, result_root = speed_runs[0]
    candidate = deepcopy(result)
    row = _row(candidate, "project-v1")
    artifacts = _artifacts(row)
    index = next(
        index
        for index, artifact in enumerate(artifacts)
        if artifact["kind"] == "primitive_recorded"
    )
    artifact = artifacts[index]
    raw_path = result_root / artifact["path"]
    original_raw = raw_path.read_bytes()
    raw = json.loads(original_raw)
    changed_path: Path | None = None
    original_result_bytes: bytes | None = None
    try:
        if case == "corrupt-result":
            changed_path = Path(raw["absolute_root"]) / "result/leaf-a.txt"
            original_result_bytes = changed_path.read_bytes()
            changed_path.write_bytes(b"CORRUPTED\n")
        elif case == "nonexistent-root":
            raw["absolute_root"] = str(Path(raw["absolute_root"]).with_name("does-not-exist"))
        elif case == "false-primitive-overlap":
            events = {event["id"]: event for event in raw["outcome"]["leaf_events"]}
            events["leaf-a"]["end_ns"] = events["leaf-b"]["start_ns"] + 1
        elif case == "wrong-attempts":
            raw["outcome"]["attempts"] = 2
        else:
            raw["outcome"]["leaf_events"].append(
                deepcopy(raw["outcome"]["leaf_events"][0])
            )
        if case != "corrupt-result":
            encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode() + b"\n"
            raw_path.write_bytes(encoded)
            artifact["bytes"] = len(encoded)
            artifact["sha256"] = hashlib.sha256(encoded).hexdigest()
            _store_artifact(row, index, artifact)
        with pytest.raises(SpeedRunnerError):
            validate_result(candidate, result_root, fixture)
    finally:
        raw_path.write_bytes(original_raw)
        if changed_path is not None and original_result_bytes is not None:
            changed_path.write_bytes(original_result_bytes)


def test_every_available_network_and_command_route_is_guarded_counted_and_restored(
    tmp_path: Path,
) -> None:
    socket_type = socket.socket
    network_targets = [
        *((socket, name) for name in runner._SOCKET_MODULE_GUARDS if hasattr(socket, name)),
        *((socket_type, name) for name in runner._SOCKET_METHOD_GUARDS if hasattr(socket_type, name)),
    ]
    command_targets = [(owner, name) for owner, name, _ in runner._COMMAND_GUARDS]
    originals = {
        (id(owner), name): getattr(owner, name)
        for owner, name in [*network_targets, *command_targets]
    }
    marker = tmp_path / "command-ran"

    with runner._guards() as state:
        for name in runner._SOCKET_MODULE_GUARDS:
            if not hasattr(socket, name):
                continue
            before = state["network_attempts"]
            with pytest.raises(SpeedRunnerError, match="network:socket_attempt"):
                getattr(socket, name)()
            assert state["network_attempts"] == before + 1
        for name in runner._SOCKET_METHOD_GUARDS:
            if not hasattr(socket_type, name):
                continue
            before = state["network_attempts"]
            with pytest.raises(SpeedRunnerError, match="network:socket_attempt"):
                getattr(socket_type, name)(None)
            assert state["network_attempts"] == before + 1

        for owner, name, _ in runner._COMMAND_GUARDS:
            before = state["subprocess_attempts"]
            with pytest.raises(SpeedRunnerError, match="network:subprocess_attempt"):
                getattr(owner, name)()
            assert state["subprocess_attempts"] == before + 1
        with pytest.raises(SpeedRunnerError):
            os.system(f"touch {marker}")
        with pytest.raises(SpeedRunnerError):
            subprocess.run(("touch", str(marker)), check=False)
        assert not marker.exists()

    for owner, name in [*network_targets, *command_targets]:
        assert getattr(owner, name) is originals[(id(owner), name)]


def test_guard_nested_and_exception_scopes_restore_exact_objects() -> None:
    original_env = dict(os.environ)
    original_socket = socket.socket
    original_getaddrinfo = socket.getaddrinfo
    with runner._guards() as outer:
        with pytest.raises(SpeedRunnerError):
            socket.getaddrinfo("invalid.example", 443)
        with runner._guards() as inner:
            with pytest.raises(SpeedRunnerError):
                socket.gethostbyname("invalid.example")
        assert inner["network_attempts"] == 1
        assert outer["network_attempts"] == 1
        with pytest.raises(SpeedRunnerError):
            original_socket.sendall(None, b"x")
        assert outer["network_attempts"] == 2
        assert socket.socket is not original_socket

    with pytest.raises(RuntimeError, match="forced"):
        with runner._guards():
            raise RuntimeError("forced")

    assert socket.socket is original_socket
    assert socket.getaddrinfo is original_getaddrinfo
    assert os.environ == original_env

    left, right = socket.socketpair()
    try:
        left.sendall(b"inert")
        assert right.recv(5) == b"inert"
    finally:
        left.close()
        right.close()


def _isolated_python(source: str) -> dict[str, Any]:
    completed = subprocess.run(
        (sys.executable, "-c", source),
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_precaptured_constructor_resolver_and_command_aliases_are_audit_denied(
    tmp_path: Path,
) -> None:
    marker_system = tmp_path / "system-marker"
    marker_run = tmp_path / "run-marker"
    observed = _isolated_python(
        f"""
import json, os, socket, subprocess
import tools.v04_speed_runner as runner
socket_alias = socket.socket
resolver_alias = socket.getaddrinfo
system_alias = os.system
run_alias = subprocess.run
observed = []
with runner._guards() as state:
    for name, call in (
        ("socket", lambda: socket_alias()),
        ("resolver", lambda: resolver_alias("alias-guard.invalid", 443)),
        ("system", lambda: system_alias("/usr/bin/touch {marker_system}")),
        ("run", lambda: run_alias(("/usr/bin/touch", "{marker_run}"), check=False)),
    ):
        before = (state["network_attempts"], state["subprocess_attempts"])
        try:
            call()
        except runner.SpeedRunnerError as error:
            observed.append([name, str(error), before,
                (state["network_attempts"], state["subprocess_attempts"])])
        else:
            observed.append([name, "BYPASS", before, before])
print(json.dumps({{"observed": observed,
    "system_marker": os.path.exists("{marker_system}"),
    "run_marker": os.path.exists("{marker_run}")}}, sort_keys=True))
"""
    )
    assert observed == {
        "observed": [
            ["socket", "network:socket_attempt", [0, 0], [1, 0]],
            ["resolver", "network:socket_attempt", [1, 0], [2, 0]],
            ["system", "network:subprocess_attempt", [2, 0], [2, 1]],
            ["run", "network:subprocess_attempt", [2, 1], [2, 2]],
        ],
        "run_marker": False,
        "system_marker": False,
    }


@pytest.mark.parametrize("method", runner._SOCKET_METHOD_GUARDS)
def test_preexisting_socket_and_bound_alias_refuse_entry_before_payload(
    method: str,
) -> None:
    observed = _isolated_python(
        f"""
import json, socket
import tools.v04_speed_runner as runner
left, right = socket.socketpair()
send_alias = getattr(left, "{method}")
entered = False
try:
    with runner._guards():
        entered = True
except runner.SpeedRunnerError as error:
    refusal = str(error)
    count = error.guard_state["network_attempts"]
    evidence = list(error.socket_evidence)
right.setblocking(False)
try:
    payload = right.recv(64).hex()
except BlockingIOError:
    payload = ""
left.close(); right.close()
print(json.dumps({{"entered": entered, "refusal": refusal, "count": count,
    "evidence": evidence, "payload": payload}}, sort_keys=True))
"""
    )
    assert observed["entered"] is False
    assert observed["refusal"] == "network:preexisting_socket"
    assert observed["count"] == 1
    assert observed["evidence"]
    assert observed["payload"] == ""


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize("detached", [False, True])
def test_preexisting_network_socket_objects_and_descriptors_refuse_entry_once(
    family: int, detached: bool
) -> None:
    observed = _isolated_python(
        f"""
import json, os, socket
import tools.v04_speed_runner as runner
live = socket.socket({family}, socket.SOCK_STREAM)
descriptor = live.detach() if {detached!r} else None
try:
    try:
        with runner._guards():
            entered = True
    except runner.SpeedRunnerError as error:
        entered = False
        refusal = str(error)
        count = error.guard_state["network_attempts"]
        evidence = list(error.socket_evidence)
finally:
    if descriptor is None:
        live.close()
    else:
        os.close(descriptor)
print(json.dumps({{"entered": entered, "refusal": refusal, "count": count,
    "evidence": evidence}}, sort_keys=True))
"""
    )
    assert observed["entered"] is False
    assert observed["refusal"] == "network:preexisting_socket"
    assert observed["count"] == 1
    assert observed["evidence"]


def test_local_control_sockets_and_event_loop_survive_guard_and_runner(
    tmp_path: Path,
) -> None:
    observed = _isolated_python(
        f"""
import asyncio, json, socket, tempfile
import os
from pathlib import Path
import tools.v04_speed_runner as runner
padding = [os.pipe() for _ in range(12)]
loop = asyncio.new_event_loop()
left, right = socket.socketpair()
before = [[item.fileno(), item.family, item.type, item.getblocking()]
          for item in (left, right)]
with runner._guards() as state:
    guarded_attempts = state["network_attempts"]
with tempfile.TemporaryDirectory(dir={str(tmp_path)!r}) as root:
    result = runner.run_guarded_benchmark(
        Path({str(FIXTURE)!r}), Path(root) / "result", {HEAD!r}, {TREE!r})
after = [[item.fileno(), item.family, item.type, item.getblocking()]
         for item in (left, right)]
print(json.dumps({{"before": before, "after": after,
    "guarded_attempts": guarded_attempts, "release_pass": result["release_pass"],
    "loop_closed": loop.is_closed(), "minimum_fd": min(item[0] for item in before)}},
    sort_keys=True))
left.close(); right.close(); loop.close()
for pair in padding:
    for descriptor in pair:
        os.close(descriptor)
"""
    )
    assert observed == {
        "after": observed["before"],
        "before": observed["before"],
        "guarded_attempts": 0,
        "loop_closed": False,
        "minimum_fd": observed["minimum_fd"],
        "release_pass": True,
    }
    assert observed["minimum_fd"] > 7


def test_socket_classification_contains_no_host_or_descriptor_whitelist() -> None:
    source = inspect.getsource(runner._open_socket_evidence)
    assert "pytest" not in source
    assert "asyncio" not in source
    assert "descriptor ==" not in source


def test_async_task_adapter_then_guard_regression_runs_in_one_process() -> None:
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_task_adapter.py::test_nominal_bounded_completion_and_handoff",
            "tests/test_v04_speed_runner.py::test_every_available_network_and_command_route_is_guarded_counted_and_restored",
        ),
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "2 passed" in completed.stdout


def test_closed_socket_is_not_a_preflight_false_positive_and_audit_is_inert_after_exit() -> None:
    closed = socket.socket()
    closed.close()
    with runner._guards() as state:
        assert state["network_attempts"] == 0
        with pytest.raises(SpeedRunnerError):
            socket.socket()
        assert state["network_attempts"] == 1

    left, right = socket.socketpair()
    try:
        left.sendall(b"post-exit")
        assert right.recv(9) == b"post-exit"
    finally:
        left.close()
        right.close()


def test_audit_and_wrapper_denials_each_count_exactly_once() -> None:
    socket_alias = socket.socket
    system_alias = os.system
    with runner._guards() as state:
        attempts = (
            lambda: socket.socket(),
            lambda: socket_alias(),
            lambda: os.system("true"),
            lambda: system_alias("true"),
        )
        for expected_index, attempt in enumerate(attempts, start=1):
            before = state["network_attempts"] + state["subprocess_attempts"]
            with pytest.raises(SpeedRunnerError):
                attempt()
            assert state["network_attempts"] + state["subprocess_attempts"] == before + 1
            assert before + 1 == expected_index


def test_audit_guard_reaches_worker_threads() -> None:
    socket_alias = socket.socket
    with runner._guards() as state:
        with runner.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket_alias)
            with pytest.raises(SpeedRunnerError, match="network:socket_attempt"):
                future.result()
        assert state["network_attempts"] == 1


def test_process_installs_only_one_audit_hook_across_reload() -> None:
    observed = _isolated_python(
        """
import importlib, json
import tools.v04_speed_runner as runner
first = runner._audit_controller["installations"]
controller = id(runner._audit_controller)
runner = importlib.reload(runner)
print(json.dumps({"first": first,
    "after": runner._audit_controller["installations"],
    "same_controller": controller == id(runner._audit_controller)}))
"""
    )
    assert observed == {"after": 1, "first": 1, "same_controller": True}


def test_detached_socket_descriptor_is_preflight_evidence() -> None:
    observed = _isolated_python(
        """
import json, os, socket
import tools.v04_speed_runner as runner
live = socket.socket()
descriptor = live.detach()
try:
    try:
        with runner._guards():
            entered = True
    except runner.SpeedRunnerError as error:
        entered = False
        refusal = str(error)
        evidence = list(error.socket_evidence)
finally:
    os.close(descriptor)
print(json.dumps({"entered": entered, "refusal": refusal,
    "descriptor_seen": any(item.startswith("descriptor:") for item in evidence)}))
"""
    )
    assert observed == {
        "descriptor_seen": True,
        "entered": False,
        "refusal": "network:preexisting_socket",
    }


@pytest.mark.parametrize("route", ["sendto", "sendmsg", "os_system"])
def test_forced_new_routes_abort_before_a_release_result(
    fixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, route: str
) -> None:
    original = runner._execute_workload

    async def forced(row: Any, arm: str, root: Path) -> dict[str, Any]:
        if route == "sendto":
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))
        elif route == "sendmsg":
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendmsg((b"x",), (), 0, ("127.0.0.1", 9))
        else:
            os.system("true")
        return await original(row, arm, root)

    monkeypatch.setattr(runner, "_execute_workload", forced)
    with pytest.raises(SpeedRunnerError, match="network"):
        run_guarded_benchmark(FIXTURE, tmp_path / route, HEAD, TREE)


def test_multiple_honest_fresh_runs_recompute_medians_and_meet_limits(speed_runs) -> None:
    for result, _ in speed_runs:
        assert result["release_pass"] is True
        for row in result["rows"]:
            timing = _timing(row)
            medians = {}
            for arm in ("primitive", "adapter"):
                samples = sorted(item["duration_ns"] for item in timing if item["arm"] == arm)
                medians[arm] = (samples[4] + samples[5]) // 2
            time_gate = row["gates"][-1]
            assert medians["adapter"] / medians["primitive"] <= time_gate["limit"]
