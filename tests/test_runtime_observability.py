"""Read-only runtime observation contracts and regression tests."""
from __future__ import annotations

import os
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import unrest_harness.runtime_observability as runtime_observability
from unrest_harness.config import HarnessConfig
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    AttentionNeeded,
    Done,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.runtime_observability import (
    RuntimeObservationError,
    observation_json,
    observe_all_projects_runtime,
    observe_project_runtime,
    render_runtime_observation,
    shadow_selected_task_ids,
)
from unrest_harness.storage import ProjectStore


ROOT = Path(__file__).resolve().parents[1]


def _config(harness_home: Path, *, capacity: int = 2) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=ROOT / "src" / "unrest_harness" / "bundled",
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=capacity,
    )


def _task(
    task_id: str,
    task_type: str,
    *,
    depends_on: list[str] | None = None,
) -> Task:
    return Task(
        id=task_id,
        type=task_type,  # type: ignore[arg-type]
        body="" if task_type == "gate" else f"{task_id} body",
        targets=["VAL-A"],
        skill=None if task_type == "gate" else "s",
        depends_on=depends_on or [],
    )


def _save_running_project(
    store: ProjectStore,
    workspace: Path,
    task_list: TaskList,
    task_state: TaskStateFile,
) -> tuple[str, str]:
    project_id = "safe-iteration-test"
    mission_id = "mission-001"
    record = store.create_project(
        "Safe iteration test.",
        workspace,
        project_id=project_id,
    )
    record.current_mission_id = mission_id
    store.save_project(record)
    store.save_task_list(project_id, mission_id, task_list)
    store.save_task_state(project_id, mission_id, task_state)
    store.save_state(project_id, MissionRunning(mission_id=mission_id))
    return project_id, mission_id


def _write_contract(store: ProjectStore, project_id: str, item_id: str) -> None:
    contract_dir = store.ensure_contract_dir(project_id, "mission-001")
    (contract_dir / f"{item_id}.md").write_text(
        f"# {item_id}: Safe iteration characterization\n\n"
        "Surface: other.\n"
        "Needs: none.\n"
        "Behavior: Preserve the observed runtime transition.\n"
        "Evidence: Focused controller test.\n",
        encoding="utf-8",
    )


def _tree_snapshot(root: Path) -> dict[str, tuple[str, bytes, int, int]]:
    snapshot: dict[str, tuple[str, bytes, int, int]] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            kind = "file"
            payload = path.read_bytes()
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
            payload = b""
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
            payload = os.fsencode(os.readlink(path))
        else:
            kind = "other"
            payload = b""
        snapshot[str(path.relative_to(root))] = (
            kind,
            payload,
            info.st_mtime_ns,
            stat.S_IMODE(info.st_mode),
        )
    return snapshot


def test_runtime_observation_is_read_only_and_reports_shadow_dispatch(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(
        tasks=[
            _task("unrelated-work", "work"),
            _task("validator-a", "validate"),
            _task("validator-b", "validate"),
            _task(
                "gate-a",
                "gate",
                depends_on=["validator-a", "validator-b"],
            ),
        ]
    )
    task_state = TaskStateFile()
    for task in task_list.tasks:
        task_state.set_status(task.id, "pending")
    project_id, _mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    before = _tree_snapshot(store.bucket_root(project_id))

    def unexpected_mutation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("observer called a persistence method")

    for method_name in (
        "create_project",
        "save_project",
        "save_state",
        "save_task_list",
        "ensure_contract_dir",
        "save_task_state",
        "save_contract_state",
        "save_attempt",
        "save_attention",
        "clear_attention",
        "append_decision_record",
        "save_terminal_review_config",
        "save_terminal_review",
    ):
        monkeypatch.setattr(ProjectStore, method_name, unexpected_mutation)

    observation = observe_project_runtime(
        store,
        project_id,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )

    assert observation.persisted_state == "mission_running"
    assert observation.derived_state == "runnable"
    assert observation.shadow_scheduler.action == "dispatch_ready"
    assert observation.shadow_scheduler.task_ids == ("validator-a", "validator-b")
    assert observation.shadow_scheduler.dispatch_performed is False
    assert observation.anomalies == ()
    assert _tree_snapshot(store.bucket_root(project_id)) == before
    assert "runtime_observability" not in (
        ROOT / "src" / "unrest_harness" / "coordinator.py"
    ).read_text(encoding="utf-8")


def test_draft_observation_schema_v1_is_exact(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id = "schema-golden"
    store.create_project("Schema golden.", workspace, project_id=project_id)
    project_cursor = store.unrest_runtime_dir(project_id) / "project.json"
    modified_at = datetime(2026, 8, 6, 11, 0, tzinfo=UTC).timestamp()
    os.utime(project_cursor, (modified_at, modified_at))

    observation = observe_project_runtime(
        store,
        project_id,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )

    assert observation.model_dump(mode="json") == {
        "schema_version": 1,
        "observed_at": "2026-08-06T12:00:00Z",
        "project_id": "schema-golden",
        "mission_id": None,
        "persisted_state": "draft",
        "derived_state": "draft",
        "freshness": {
            "source": "file_mtime",
            "state_cursor_age_seconds": None,
            "task_cursor_age_seconds": None,
            "newest_runtime_input_age_seconds": 3600.0,
        },
        "progress": {
            "authored_task_total": 0,
            "active_task_total": 0,
            "cleared_task_total": 0,
            "assertion_total": 0,
            "passed_assertion_total": 0,
        },
        "task_counts": {
            "by_type": [
                {"name": "work", "count": 0},
                {"name": "validate", "count": 0},
                {"name": "gate", "count": 0},
            ],
            "by_status": [
                {"name": "pending", "count": 0},
                {"name": "running", "count": 0},
                {"name": "cleared", "count": 0},
                {"name": "failed", "count": 0},
                {"name": "superseded", "count": 0},
            ],
        },
        "assertion_counts": {
            "by_status": [
                {"name": "pending", "count": 0},
                {"name": "passed", "count": 0},
                {"name": "failed", "count": 0},
            ]
        },
        "attention_counts": {
            "by_kind": [
                {"name": "node_failed", "count": 0},
                {"name": "node_attention", "count": 0},
                {"name": "gate_failed", "count": 0},
                {"name": "gate_checkpoint", "count": 0},
                {"name": "terminal_review", "count": 0},
            ]
        },
        "gate_readiness": {"count": 0, "task_ids": []},
        "tasks": [],
        "timings": [],
        "anomalies": [],
        "shadow_scheduler": {
            "action": "none",
            "task_ids": [],
            "reason_code": "not_planning",
            "dispatch_performed": False,
        },
    }


def test_shadow_selection_matches_the_authoritative_coordinator(
    harness_home: Path,
) -> None:
    config = _config(harness_home, capacity=3)
    store = ProjectStore(config)
    task_list = TaskList(
        tasks=[
            _task("work-a", "work"),
            _task("validator-a", "validate"),
            _task("validator-b", "validate"),
            _task(
                "gate-a",
                "gate",
                depends_on=["validator-a", "validator-b"],
            ),
        ]
    )
    task_state = TaskStateFile()
    for task in task_list.tasks:
        task_state.set_status(task.id, "pending")
    coordinator = MissionCoordinator(
        store,
        "unused",
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                done=True,
                report="",
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    runnable = coordinator._all_runnable_tasks(task_list, task_state)
    authoritative = tuple(
        task.id
        for task in coordinator._select_dispatch_tasks(
            task_list,
            task_state,
            runnable,
        )
    )

    assert shadow_selected_task_ids(
        task_list,
        task_state,
        max_parallel_nodes=config.max_parallel_nodes,
    ) == authoritative


def test_shadow_selection_parity_across_capacity_and_graph_shapes(
    harness_home: Path,
) -> None:
    cases = [
        (
            [_task("work-a", "work"), _task("work-b", "work")],
            {},
            3,
        ),
        (
            [
                _task("validator-a", "validate"),
                _task("validator-b", "validate"),
                _task("validator-c", "validate"),
            ],
            {},
            2,
        ),
        (
            [_task("validator-a", "validate"), _task("work-a", "work")],
            {},
            2,
        ),
        (
            [_task("work-a", "work"), _task("validator-a", "validate")],
            {},
            2,
        ),
        (
            [
                _task("unrelated-work", "work"),
                _task("validator-a", "validate"),
                _task("validator-b", "validate"),
                _task(
                    "gate-a",
                    "gate",
                    depends_on=["validator-a", "validator-b"],
                ),
            ],
            {},
            4,
        ),
        (
            [
                _task("setup", "work"),
                _task("validator-a", "validate", depends_on=["setup"]),
                _task(
                    "gate-a",
                    "gate",
                    depends_on=["setup", "validator-a"],
                ),
            ],
            {"setup": "cleared"},
            2,
        ),
        (
            [
                _task("validator-a", "validate"),
                _task("gate-a", "gate", depends_on=["validator-a"]),
                _task("validator-b", "validate"),
                _task("gate-b", "gate", depends_on=["validator-b"]),
            ],
            {},
            1,
        ),
    ]

    for tasks, explicit_statuses, capacity in cases:
        config = _config(harness_home, capacity=capacity)
        store = ProjectStore(config)
        task_list = TaskList(tasks=tasks)
        task_state = TaskStateFile()
        for task in tasks:
            task_state.set_status(
                task.id,
                explicit_statuses.get(task.id, "pending"),  # type: ignore[arg-type]
            )
        dispatcher = MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id,
                done=True,
                report="",
            )
        )
        coordinator = MissionCoordinator(
            store,
            "unused",
            dispatcher,
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        runnable = coordinator._all_runnable_tasks(task_list, task_state)
        authoritative = tuple(
            task.id
            for task in coordinator._select_dispatch_tasks(
                task_list,
                task_state,
                runnable,
            )
        )

        assert shadow_selected_task_ids(
            task_list,
            task_state,
            max_parallel_nodes=capacity,
        ) == authoritative
        assert dispatcher.calls == []


def test_runtime_observation_distinguishes_stale_and_recovery_ready(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(tasks=[_task("work-a", "work")])
    task_state = TaskStateFile()
    task_state.set_status("work-a", "running")
    spawn_ts = "2026-08-06T08-00-00Z"
    task_state.set_last_attempt("work-a", spawn_ts)
    project_id, mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)

    stale = observe_project_runtime(
        store,
        project_id,
        stale_after_seconds=60,
        now=now,
    )
    assert stale.derived_state == "stale_running_candidate"
    assert stale.shadow_scheduler.action == "inspect_stale_attempt"
    assert [anomaly.code for anomaly in stale.anomalies] == [
        "stale_running_candidate"
    ]

    store.save_attempt(
        project_id,
        mission_id,
        spawn_ts,
        "work-a",
        WorkHandoff(node_id="work-a", done=True, report="complete"),
    )
    recovery = observe_project_runtime(store, project_id, now=now)
    assert recovery.derived_state == "recovery_ready"
    assert recovery.shadow_scheduler.action == "reconcile_completed_attempt"
    assert recovery.timings[0].completion_observed is True
    assert recovery.timings[0].observed_attempt_duration_seconds is not None
    assert recovery.timings[0].observed_duration_source == "file_mtime"

    later_ts = "2026-08-06T09-00-00Z"
    store.save_attempt(
        project_id,
        mission_id,
        later_ts,
        "work-a",
        WorkHandoff(node_id="work-a", done=True, report="newer complete"),
    )
    nonmatching_latest = observe_project_runtime(store, project_id, now=now)
    assert nonmatching_latest.derived_state == "recovery_ready"
    assert nonmatching_latest.timings[0].cursor_spawn_ts == spawn_ts
    assert nonmatching_latest.timings[0].observed_attempt_ts == later_ts

    malformed_ts = "2026-08-06T10-00-00Z"
    malformed_path = store.attempt_path(
        project_id,
        mission_id,
        malformed_ts,
        "work-a",
    )
    malformed_path.write_text("{not-json}\n", encoding="utf-8")
    malformed = observe_project_runtime(store, project_id, now=now)
    assert malformed.derived_state == "inconsistent"
    assert malformed.shadow_scheduler.action == "inspect_malformed_attempt"
    assert malformed.timings[0].malformed_completion is True
    assert [anomaly.code for anomaly in malformed.anomalies] == [
        "attempt_cursor_mismatch",
        "malformed_attempt_handoff",
    ]

    valid_second_ts = "2026-08-06T11-00-00Z"
    task_state.set_status("work-b", "running")
    task_state.set_last_attempt("work-b", valid_second_ts)
    store.save_task_state(project_id, mission_id, task_state)
    store.save_attempt(
        project_id,
        mission_id,
        valid_second_ts,
        "work-b",
        WorkHandoff(node_id="work-b", done=True, report="valid second"),
    )
    for ordered_tasks in (
        [_task("work-a", "work"), _task("work-b", "work")],
        [_task("work-b", "work"), _task("work-a", "work")],
    ):
        store.save_task_list(project_id, mission_id, TaskList(tasks=ordered_tasks))
        mixed = observe_project_runtime(store, project_id, now=now)
        assert mixed.derived_state == "inconsistent"
        assert mixed.shadow_scheduler.action == "inspect_malformed_attempt"
        assert mixed.shadow_scheduler.task_ids == ("work-a",)


def test_runtime_observation_classifies_gate_quiescent_and_public_states(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(
        tasks=[
            _task("validator-a", "validate"),
            _task("gate-a", "gate", depends_on=["validator-a"]),
        ]
    )
    task_state = TaskStateFile()
    task_state.set_status("validator-a", "cleared")
    task_state.set_status("gate-a", "pending")
    project_id, mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)

    gate_ready = observe_project_runtime(store, project_id, now=now)
    assert gate_ready.derived_state == "gate_ready"
    assert gate_ready.shadow_scheduler.action == "evaluate_gate"

    task_state.set_status("gate-a", "cleared")
    store.save_task_state(project_id, mission_id, task_state)
    quiescent = observe_project_runtime(store, project_id, now=now)
    assert quiescent.derived_state == "quiescent"
    assert quiescent.shadow_scheduler.action == "closure_candidate"

    store.save_state(project_id, AttentionNeeded(items=[]))
    attention = observe_project_runtime(store, project_id, now=now)
    assert attention.derived_state == "attention"
    assert attention.shadow_scheduler.action == "attention_decision_required"

    store.save_state(project_id, MissionPlanning(mission_id=mission_id))
    planning = observe_project_runtime(store, project_id, now=now)
    assert planning.derived_state == "planning"

    store.save_state(project_id, Done())
    terminal = observe_project_runtime(store, project_id, now=now)
    assert terminal.derived_state == "terminal"

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(
            store,
            project_id,
            mission_id="mission-999",
            now=now,
        )
    assert captured.value.code == "malformed_cursor"


def test_runtime_observation_projects_immutable_structural_facts(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(
        tasks=[
            _task("work-a", "work"),
            _task("validator-a", "validate", depends_on=["work-a"]),
            _task("gate-a", "gate", depends_on=["validator-a"]),
        ]
    )
    task_state = TaskStateFile()
    task_state.set_status("work-a", "cleared")
    task_state.set_status("validator-a", "pending")
    task_state.set_status("gate-a", "superseded")
    project_id, _mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    _write_contract(store, project_id, "VAL-A")
    before = _tree_snapshot(store.bucket_root(project_id))

    observation = observe_project_runtime(
        store,
        project_id,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )

    assert [task.task_id for task in observation.tasks] == [
        "work-a",
        "validator-a",
        "gate-a",
    ]
    assert [task.ordinal for task in observation.tasks] == [0, 1, 2]
    assert observation.tasks[1].blocked_by == ()
    assert observation.tasks[1].runnable is True
    assert observation.progress.authored_task_total == 3
    assert observation.progress.active_task_total == 2
    assert observation.progress.cleared_task_total == 1
    assert observation.progress.assertion_total == 1
    assert observation.progress.passed_assertion_total == 0
    assert _tree_snapshot(store.bucket_root(project_id)) == before
    with pytest.raises(ValidationError, match="frozen"):
        observation.progress.active_task_total = 99
    with pytest.raises(ValidationError, match="frozen"):
        observation.tasks[0].status = "failed"
    with pytest.raises(AttributeError):
        observation.tasks[0].depends_on.append("new-dependency")  # type: ignore[attr-defined]
    serialized = observation_json(observation)
    assert "work-a body" not in serialized
    assert "estimated" not in serialized.lower()
    assert "heartbeat" not in serialized.lower()
    assert "eta" not in serialized.lower()
    rendered = render_runtime_observation(observation)
    assert "task[0]=work-a" in rendered
    assert max(map(len, rendered.splitlines())) <= 240


def test_runtime_observation_rejects_cursor_symlinks_without_reading_them(
    harness_home: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        TaskStateFile(),
    )
    state_path = store.unrest_runtime_dir(project_id) / "state.json"
    outside = tmp_path / "outside-state.json"
    outside.write_text('{"state":"done","secret":"OUTSIDE-SENTINEL"}', encoding="utf-8")
    state_path.unlink()
    state_path.symlink_to(outside)

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, project_id)
    assert captured.value.code == "unsafe_cursor"
    assert "OUTSIDE-SENTINEL" not in str(captured.value)


def test_runtime_observation_rejects_a_symlinked_projects_root(
    harness_home: Path,
    tmp_path: Path,
) -> None:
    real_projects = harness_home / "real-projects"
    real_projects.mkdir(parents=True)
    linked_projects = tmp_path / "linked-projects"
    linked_projects.symlink_to(real_projects, target_is_directory=True)
    config = replace(_config(harness_home), projects_dir=linked_projects)

    with pytest.raises(RuntimeObservationError) as captured:
        observe_all_projects_runtime(ProjectStore(config))

    assert captured.value.code == "unsafe_project_path"


def test_runtime_observation_rejects_a_symlinked_durable_root(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        TaskStateFile(),
    )
    project_root = store.bucket_root(project_id)
    durable_root = project_root / ".unrest"
    relocated = project_root / "relocated-unrest"
    durable_root.rename(relocated)
    durable_root.symlink_to(relocated, target_is_directory=True)

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, project_id)

    assert captured.value.code == "unsafe_cursor"


def test_runtime_observation_rejects_malformed_attempt_identifiers(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_state = TaskStateFile()
    task_state.set_status("work-a", "running")
    task_state.set_last_attempt("work-a", "not-a-filesafe-timestamp-SECRET")
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        task_state,
    )

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, project_id)

    assert captured.value.code == "malformed_cursor"
    assert "SECRET" not in str(captured.value)


def test_runtime_observation_retries_a_changed_snapshot(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        TaskStateFile(),
    )
    actual_identity = runtime_observability._current_identity_generation
    calls = 0

    def one_change(root: Path) -> tuple[tuple[str, int, int, int, int], ...]:
        nonlocal calls
        calls += 1
        actual = actual_identity(root)
        if calls == 1:
            return (*actual, ("changed", 0, 0, 0, 0))
        return actual

    monkeypatch.setattr(
        runtime_observability, "_current_identity_generation", one_change
    )

    observation = observe_project_runtime(store, project_id)

    assert observation.project_id == project_id
    assert calls == 2


def test_runtime_observation_retries_a_real_atomic_cursor_replacement(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[]),
        TaskStateFile(),
    )
    actual_projection = runtime_observability._observation_from_capture
    calls = 0

    def replace_state_once(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            state_path = store.unrest_runtime_dir(project_id) / "state.json"
            replacement = state_path.with_suffix(".replacement")
            replacement.write_text(
                Done().model_dump_json(),
                encoding="utf-8",
            )
            os.replace(replacement, state_path)
        return actual_projection(*args, **kwargs)

    monkeypatch.setattr(
        runtime_observability,
        "_observation_from_capture",
        replace_state_once,
    )

    observation = observe_project_runtime(store, project_id)

    assert observation.persisted_state == "done"
    assert observation.derived_state == "terminal"
    assert calls == 2


def test_runtime_observation_fails_after_three_changed_snapshots(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        TaskStateFile(),
    )
    actual_identity = runtime_observability._current_identity_generation
    calls = 0

    def always_changed(root: Path) -> tuple[tuple[str, int, int, int, int], ...]:
        nonlocal calls
        calls += 1
        return (*actual_identity(root), (f"changed-{calls}", 0, 0, 0, 0))

    monkeypatch.setattr(
        runtime_observability, "_current_identity_generation", always_changed
    )

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, project_id)

    assert captured.value.code == "snapshot_changed"
    assert calls == 3


def test_runtime_observation_rejects_a_non_regular_cursor(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[]),
        TaskStateFile(),
    )
    os.mkfifo(store.unrest_runtime_dir(project_id) / "non-regular.json")

    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, project_id)

    assert captured.value.code == "unsafe_cursor"


def test_all_project_observation_is_complete_and_isolates_corruption(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    store.create_project("good", workspace, project_id="good-project")
    bad = store.config.projects_dir / "bad-project" / ".unrest-runtime"
    bad.mkdir(parents=True)
    (bad / "project.json").write_text("{not-json}", encoding="utf-8")
    unsafe = store.config.projects_dir / "../escape"
    del unsafe  # the selector cannot influence aggregation paths

    collection = observe_all_projects_runtime(
        store,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )

    assert [project.project_id for project in collection.projects] == [
        "good-project"
    ]
    assert [(failure.project_id, failure.code) for failure in collection.failures] == [
        ("bad-project", "malformed_cursor")
    ]
    assert {project.observed_at for project in collection.projects} == {
        collection.observed_at
    }
