"""Immutable lifecycle scenarios characterized at the fixed reference."""

from __future__ import annotations

from pathlib import Path

import pytest


SCENARIOS = (
    (
        "VAL-LIFE-001",
        "invalid-start-leaves-no-partial-project",
        "tests/test_server.py::test_start_project_rejects_invalid_codex_worker_effort_without_persisting",
    ),
    (
        "VAL-LIFE-002",
        "validator-dissent-prevents-gate-clear",
        "tests/test_coordinator.py::TestValidatorDissentFailsGate::test_dissent_raises_gate_failed_not_checkpoint",
    ),
    (
        "VAL-LIFE-003",
        "running-task-cannot-be-superseded",
        "tests/test_task_list_patch.py::TestSupersede::test_running_cannot_be_superseded",
    ),
    (
        "VAL-LIFE-004",
        "terminal-review-timeout-does-not-seal",
        "tests/test_terminal_review.py::TestTerminalReviewerFailure::test_production_timeout_handoff_is_persisted_and_does_not_seal",
    ),
    (
        "VAL-LIFE-005",
        "duplicate-contract-owner-is-rejected",
        "tests/test_task_validation.py::TestCoverage::test_over_covered",
    ),
    (
        "VAL-LIFE-006",
        "aborted-project-cannot-resume",
        "local::aborted-project-resume-rejection",
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
    tmp_path: Path,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert reference_node in lean_reference_run.nodes
    if reference_node == "local::aborted-project-resume-rejection":
        from unrest_harness.config import HarnessConfig
        from unrest_harness.controller import ProjectController, ToolError
        from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
        from unrest_harness.models import TaskList, TerminalReviewHandoff, WorkHandoff

        bundled = Path(__file__).resolve().parents[2] / "src/unrest_harness/bundled"
        home = tmp_path / "home"
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        config = HarnessConfig(
            bundled_dir=bundled,
            harness_home=home,
            projects_dir=home / "projects",
            orchestrator_provider_name="claude",
            worker_provider_name="claude",
            worker_acp_command=None,
            validator_provider_name=None,
            validator_acp_command=None,
            terminal_reviewer_provider_name=None,
            terminal_reviewer_acp_command=None,
            max_parallel_nodes=1,
        )
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id, done=True, report="done"
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="done")),
        )
        started = controller.start_project("abort boundary", str(workspace))
        project_id = started.projectId
        aborted = controller.abort_project(project_id, "operator requested")
        assert aborted.state.state == "aborted"
        with pytest.raises(ToolError, match="requires MissionPlanning; got aborted"):
            controller.submit_plan(project_id, TaskList(tasks=[]))
        assert controller.store.load_state(project_id).state == "aborted"
    assert lean_reference_run.returncode == 0, lean_reference_run.output
