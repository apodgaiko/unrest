"""Candidate-bound compact status contract manifest."""

from __future__ import annotations

from pathlib import Path

import pytest


SCENARIOS = (
    (
        "VAL-STATUS-001",
        "schema-v2-states-codes-age-and-rendering",
        "tests/test_runtime_observability.py::test_projection_sorts_bounds_ids_and_emits_each_closed_code",
    ),
    (
        "VAL-STATUS-002",
        "multi-project-exit-and-failure-matrix",
        "tests/test_cli.py::TestObserveProject::test_all_exit_matrix_and_failure_isolation",
    ),
    (
        "VAL-STATUS-003",
        "observation-is-read-only-and-authority-free",
        "tests/test_runtime_observability.py::test_observation_is_read_only_and_does_not_import_authority",
    ),
    (
        "VAL-HARDCUT-STATUS-001",
        "observer-v1-and-detail-surfaces-are-absent",
        "tests/test_runtime_observability.py::test_observer_v1_and_detail_surfaces_are_absent",
    ),
    (
        "VAL-IMPORT-002",
        "ordinary-entrypoints-keep-status-lazy",
        "tests/test_runtime_observability.py::test_fresh_entrypoint_import_boundary",
    ),
)

ASSERTION_TO_SCENARIOS = {
    assertion_id: (scenario_id,) for assertion_id, scenario_id, _ in SCENARIOS
}


@pytest.mark.parametrize(
    ("assertion_id", "scenario_id", "candidate_node"),
    SCENARIOS,
    ids=[f"{assertion_id}__{scenario_id}" for assertion_id, scenario_id, _ in SCENARIOS],
)
def test_candidate_contract_scenario(
    assertion_id: str,
    scenario_id: str,
    candidate_node: str,
    lean_reference_run,
    repository_root: Path,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert candidate_node in lean_reference_run.nodes
    assert lean_reference_run.returncode == 0, lean_reference_run.output
    assert repository_root.is_dir()
