"""Immutable scheduler scenarios characterized at the fixed reference."""

from __future__ import annotations

import pytest


SCENARIOS = (
    (
        "VAL-SCHED-001",
        "multiple-ready-work-selects-one-authored-task",
        "tests/test_runnable_selection.py::TestRunnableSelection::test_capacity_slice_containing_work_selects_one_authored_task",
    ),
    (
        "VAL-SCHED-002",
        "validator-capacity-is-bounded-and-ordered",
        "tests/test_runnable_selection.py::TestRunnableSelection::test_validator_only_capacity_is_clamped_and_filled",
    ),
    (
        "VAL-SCHED-003",
        "missing-validator-items-prevent-gate-clear",
        "tests/test_coordinator.py::TestValidatorDissentFailsGate::test_validator_omitting_items_fails_gate",
    ),
)

ASSERTION_TO_SCENARIOS = {
    assertion_id: (scenario_id,) for assertion_id, scenario_id, _ in SCENARIOS
}


@pytest.mark.parametrize(
    ("assertion_id", "scenario_id", "reference_node"),
    SCENARIOS,
    ids=[f"{assertion_id}__{scenario_id}" for assertion_id, scenario_id, _ in SCENARIOS],
)
def test_reference_contract_scenario(
    assertion_id: str,
    scenario_id: str,
    reference_node: str,
    lean_reference_run,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert reference_node in lean_reference_run.nodes
    assert lean_reference_run.returncode == 0, lean_reference_run.output
