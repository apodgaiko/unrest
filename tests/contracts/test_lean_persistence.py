"""Immutable persistence scenarios characterized at the fixed reference."""

from __future__ import annotations

from pathlib import Path

import pytest


SCENARIOS = (
    (
        "VAL-PERSIST-001",
        "durable-runtime-root-shims-stay-separated",
        "local::misplaced-runtime-cursor-is-rejected",
    ),
    (
        "VAL-PERSIST-002",
        "schema-v1-recovery-fixture-remains-readable",
        "tests/test_storage.py::TestProjectLifecycle::test_project_worker_overrides_round_trip_and_legacy_defaults",
    ),
    (
        "VAL-PERSIST-003",
        "landed-handoff-resumes-once",
        "tests/test_coordinator.py::TestResume::test_resume_picks_up_attempt_landed_while_down",
    ),
    (
        "VAL-PERSIST-004",
        "missing-handoff-records-bounded-failure",
        "tests/test_acp_runner.py::test_synthesize_missing_handoff_records_failure",
    ),
    (
        "VAL-PERSIST-005",
        "repeated-attempt-write-is-deterministic",
        "local::atomic-write-preserves-prior-generation-on-replace-failure",
    ),
)

ASSERTION_TO_SCENARIOS = {
    assertion_id: (scenario_id,) for assertion_id, scenario_id, _ in SCENARIOS
}


def _assert_no_runtime_cursors(durable_root: Path) -> None:
    misplaced = sorted(
        path.relative_to(durable_root).as_posix()
        for path in durable_root.rglob("*.json")
        if path.name in {"state.json", "tasks.json", "task-state.json"}
    )
    if misplaced:
        raise AssertionError(f"runtime cursor under durable root: {misplaced}")


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert ASSERTION_TO_SCENARIOS[assertion_id] == (scenario_id,)
    assert reference_node in lean_reference_run.nodes
    if reference_node == "local::misplaced-runtime-cursor-is-rejected":
        from unrest_harness.config import HarnessConfig
        from unrest_harness.controller import ProjectController
        from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
        from unrest_harness.models import TerminalReviewHandoff, WorkHandoff

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
        dispatcher = MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                done=True,
                report="candidate persistence probe",
            )
        )
        reviewer = MockTerminalReviewer(
            TerminalReviewHandoff(done=True, report="candidate persistence probe")
        )
        controller = ProjectController(config, dispatcher, reviewer)
        started = controller.start_project("real persistence boundary", str(workspace))
        project_id = started.projectId
        durable = controller.store.unrest_dir(project_id)
        runtime = controller.store.unrest_runtime_dir(project_id)
        durable_inventory = tuple(
            sorted(path.relative_to(durable).as_posix() for path in durable.rglob("*"))
        )
        runtime_inventory = tuple(
            sorted(path.relative_to(runtime).as_posix() for path in runtime.rglob("*"))
        )
        assert {"AGENTS.md", "MEMORY.md", "brief.md", "missions"} <= set(
            durable_inventory
        )
        assert {"project.json", "state.json", "missions"} <= set(runtime_inventory)
        assert all((workspace / host / "skills").is_symlink() for host in (
            ".agents",
            ".claude",
            ".codex",
        ))
        _assert_no_runtime_cursors(durable)

        restarted = ProjectController(config, dispatcher, reviewer)
        assert restarted.store.load_state(project_id) is not None
        actual_cursor = runtime / "state.json"
        (durable / "state.json").write_bytes(actual_cursor.read_bytes())
        with pytest.raises(AssertionError, match="runtime cursor under durable root"):
            _assert_no_runtime_cursors(durable)
    elif reference_node == (
        "local::atomic-write-preserves-prior-generation-on-replace-failure"
    ):
        import unrest_harness.storage as storage

        target = tmp_path / "state.json"
        storage.atomic_write_json(
            target,
            {"generation": 1, "value": "stable"},
            trusted_root=tmp_path,
        )
        before = target.read_bytes()

        def reject_replace(source: Path, destination: Path) -> None:
            raise OSError(f"injected replacement failure: {source} -> {destination}")

        with monkeypatch.context() as patch:
            patch.setattr(storage.os, "replace", reject_replace)
            with pytest.raises(OSError, match="injected replacement failure"):
                storage.atomic_write_json(
                    target,
                    {"generation": 2, "value": "incomplete"},
                    trusted_root=tmp_path,
                )
        assert target.read_bytes() == before
        storage.atomic_write_json(
            target,
            {"generation": 1, "value": "stable"},
            trusted_root=tmp_path,
        )
        assert target.read_bytes() == before
    assert lean_reference_run.returncode == 0, lean_reference_run.output
