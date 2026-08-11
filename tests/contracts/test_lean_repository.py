"""Candidate-bound repository slice contract manifest."""

from __future__ import annotations

from pathlib import Path

import pytest


SCENARIOS = (
    (
        "VAL-REPO-001",
        "reject-every-finite-rule-family",
        "tests/test_repository_contract.py::test_each_rule_family_emits_its_bounded_code",
    ),
    (
        "VAL-REPO-002",
        "removed-commands-are-unknown",
        "tests/test_repository_contract.py::test_withdrawn_commands_are_unknown_and_absent_from_help",
    ),
    (
        "VAL-REPO-003",
        "baseline-and-bindings-are-absent",
        "tests/test_repository_contract.py::test_removed_repository_surfaces_have_no_maintained_source",
    ),
    (
        "VAL-REPO-004",
        "component-ownership-is-complete",
        "tests/test_repository_contract.py::test_component_ownership_is_complete",
    ),
    (
        "VAL-REPO-005",
        "accepted-authority-is-registered",
        "tests/test_documentation_contract.py::test_adr_0002_and_scope_package_are_accepted_and_registered",
    ),
    (
        "VAL-IMPORT-001",
        "ordinary-entrypoints-keep-checker-lazy",
        "tests/test_repository_contract.py::test_real_entrypoint_import_boundary",
    ),
    (
        "VAL-HARDCUT-GOV-001",
        "governance-product-surface-is-absent",
        "tests/test_repository_contract.py::test_governance_responsibility_inventory_is_absent",
    ),
    (
        "VAL-HARDCUT-SCHEMA-001",
        "root-schemas-and-direct-dependencies-are-absent",
        "tests/test_repository_contract.py::test_root_schemas_and_obsolete_direct_dependencies_are_absent",
    ),
    (
        "VAL-HARDCUT-EVIDENCE-001",
        "root-raw-evidence-is-absent",
        "tests/test_repository_contract.py::test_root_raw_evidence_is_absent",
    ),
    (
        "VAL-SLICE-001",
        "candidate-check-is-deterministic-and-read-only",
        "tests/test_repository_contract.py::test_current_repository_passes_deterministically_without_writes",
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
