"""Read-only runtime observation contracts and regression tests."""
from __future__ import annotations

import errno
import gc
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import tracemalloc
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from click.testing import CliRunner
from pydantic import BaseModel, ValidationError

import unrest_harness.runtime_observability as runtime_observability
from unrest_harness.cli import cli
from unrest_harness.config import HarnessConfig
from unrest_harness.coordinator import MissionCoordinator, StepResult
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    AttentionNeeded,
    AttentionItemInternal,
    ContractStateEntry,
    ContractStateFile,
    Done,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from unrest_harness.runtime_observability import (
    RuntimeAnomaly,
    RuntimeObservation,
    RuntimeObservationCollection,
    RuntimeObservationError,
    observation_json,
    observe_all_projects_runtime,
    observe_project_runtime,
    render_runtime_collection,
    render_runtime_observation,
    shadow_selected_task_ids,
)
from unrest_harness.storage import ProjectStore


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_V1_CORPUS = ROOT / "tests" / "fixtures" / "runtime_observability_schema_v1.json"


class _CurrentSchemaScenario(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}

    id: str
    kind: Literal["single", "derived", "failure", "collection", "selector", "configuration"]
    expected_state: str | None = None
    expected_code: str | None = None
    expected_model: Literal["observation", "collection"] | None = None
    expected_exit: int | None = None
    fixture: Literal["success", "mixed", "all_failed"] | None = None
    format: Literal["text", "json"] | None = None
    strict: bool = False
    selector: str | None = None
    variable: str | None = None
    value: str | None = None


_SCHEMA_CORPUS_PAYLOAD = json.loads(SCHEMA_V1_CORPUS.read_text(encoding="utf-8"))
SCHEMA_V1_SCENARIOS = tuple(
    _CurrentSchemaScenario.model_validate(item)
    for item in _SCHEMA_CORPUS_PAYLOAD["scenarios"]
)


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


def _strptime_spawn_ts(value: str) -> datetime | None:
    match = re.fullmatch(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)(?:-\d{4})?",
        value,
    )
    if match is None:
        return None
    try:
        return datetime.strptime(
            match.group("timestamp"), "%Y-%m-%dT%H-%M-%SZ"
        ).replace(tzinfo=UTC)
    except ValueError:
        return None


def test_spawn_timestamp_parser_preserves_every_leap_day() -> None:
    for year in range(1, 10_000):
        value = f"{year:04d}-02-29T00-00-00Z"

        assert runtime_observability._parse_spawn_ts(value) == _strptime_spawn_ts(
            value
        )


def test_spawn_timestamp_parser_preserves_every_calendar_boundary() -> None:
    month_lengths = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    for year in range(1, 10_000):
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        for month, ordinary_last_day in enumerate(month_lengths, start=1):
            last_day = ordinary_last_day + int(month == 2 and leap)
            for day in (0, 1, last_day, last_day + 1):
                value = f"{year:04d}-{month:02d}-{day:02d}T00-00-00Z"
                assert runtime_observability._parse_spawn_ts(
                    value
                ) == _strptime_spawn_ts(value)

    for value in (
        "0001-00-01T00-00-00Z",
        "0001-13-01T00-00-00Z",
        "9999-00-01T00-00-00Z",
        "9999-13-01T00-00-00Z",
    ):
        assert runtime_observability._parse_spawn_ts(value) == _strptime_spawn_ts(
            value
        )


def test_spawn_timestamp_parser_preserves_clock_boundaries() -> None:
    for hour, minute, second in (
        (0, 0, 0),
        (23, 59, 59),
        (24, 0, 0),
        (0, 60, 0),
        (0, 0, 60),
    ):
        value = f"2024-02-29T{hour:02d}-{minute:02d}-{second:02d}Z"

        assert runtime_observability._parse_spawn_ts(value) == _strptime_spawn_ts(
            value
        )


def test_spawn_timestamp_parser_preserves_every_parallel_suffix() -> None:
    expected = datetime(2024, 2, 29, 23, 59, 59, tzinfo=UTC)

    for suffix in range(10_000):
        value = f"2024-02-29T23-59-59Z-{suffix:04d}"
        assert runtime_observability._parse_spawn_ts(value) == expected
        assert runtime_observability._parse_spawn_ts(value) == _strptime_spawn_ts(
            value
        )

    unicode_suffix = "2024-02-29T23-59-59Z-０００１"
    assert runtime_observability._parse_spawn_ts(unicode_suffix) == expected
    assert runtime_observability._parse_spawn_ts(
        unicode_suffix
    ) == _strptime_spawn_ts(unicode_suffix)


@pytest.mark.parametrize(
    "value",
    [
        "٢٠٢٤-٠٢-٢٩T٢٣-٥٩-٥٩Z",
        "２０２４-０２-２９T２３-５９-５９Z-０００１",
    ],
)
def test_spawn_timestamp_parser_preserves_regex_unicode_digits(value: str) -> None:
    assert runtime_observability._parse_spawn_ts(value) == _strptime_spawn_ts(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0001-01-01T00-00-00Z", datetime(1, 1, 1, tzinfo=UTC)),
        ("9999-12-31T23-59-59Z", datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
        ("2000-02-29T12-34-56Z-0000", datetime(2000, 2, 29, 12, 34, 56, tzinfo=UTC)),
        ("2000-02-29T12-34-56Z-9999", datetime(2000, 2, 29, 12, 34, 56, tzinfo=UTC)),
    ],
)
def test_spawn_timestamp_parser_preserves_utc_and_suffix(
    value: str,
    expected: datetime,
) -> None:
    parsed = runtime_observability._parse_spawn_ts(value)

    assert parsed == expected
    assert parsed is not None
    assert parsed.tzinfo is UTC


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "0000-01-01T00-00-00Z",
        "2023-02-29T00-00-00Z",
        "2024-02-30T00-00-00Z",
        "2024-00-01T00-00-00Z",
        "2024-13-01T00-00-00Z",
        "2024-01-00T00-00-00Z",
        "2024-01-32T00-00-00Z",
        "2024-01-01T24-00-00Z",
        "2024-01-01T00-60-00Z",
        "2024-01-01T00-00-60Z",
        "2024-1-01T00-00-00Z",
        "2024-01-01T0-00-00Z",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00-00-00",
        "2024-01-01T00-00-00z",
        "2024-01-01T00-00-00Z-000",
        "2024-01-01T00-00-00Z-00000",
        "2024-01-01T00-00-00Z-abcd",
        "2024-01-01T00-00-00Z-0000-extra",
    ],
)
def test_spawn_timestamp_parser_preserves_invalid_inputs(value: str | None) -> None:
    assert runtime_observability._parse_spawn_ts(value) is None


def test_cold_spawn_parsing_and_observation_do_not_import_calendar_modules(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_state = TaskStateFile()
    task_state.set_status("work-a", "running")
    task_state.set_last_attempt("work-a", "2026-08-06T08-00-00Z-0001")
    project_id, _mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        task_state,
    )
    script = f"""
import sys
from datetime import UTC, datetime
from pathlib import Path

import unrest_harness.runtime_observability as runtime_observability
from unrest_harness.config import HarnessConfig
from unrest_harness.storage import ProjectStore

assert \"_strptime\" not in sys.modules
assert \"calendar\" not in sys.modules
config = HarnessConfig(
    bundled_dir=Path({str(ROOT / 'src' / 'unrest_harness' / 'bundled')!r}),
    harness_home=Path({str(harness_home)!r}),
    projects_dir=Path({str(harness_home / 'projects')!r}),
    orchestrator_provider_name=\"claude\",
    worker_provider_name=\"claude\",
    worker_acp_command=None,
    validator_provider_name=None,
    validator_acp_command=None,
    terminal_reviewer_provider_name=None,
    terminal_reviewer_acp_command=None,
    max_parallel_nodes=2,
)
parsed = runtime_observability._parse_spawn_ts(\"2026-08-06T08-00-00Z-0001\")
assert parsed == datetime(2026, 8, 6, 8, tzinfo=UTC)
observation = runtime_observability.observe_project_runtime(
    ProjectStore(config),
    {project_id!r},
    now=datetime(2026, 8, 6, 12, tzinfo=UTC),
)
assert observation.timings[0].cursor_attempt_id == \"2026-08-06T08-00-00Z-0001\"
assert \"_strptime\" not in sys.modules
assert \"calendar\" not in sys.modules
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


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


def test_ready_gate_projection_matches_live_step_in_authored_order(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(
        tasks=[
            _task("gate-z-authored-first", "gate"),
            _task("gate-a-authored-second", "gate"),
        ]
    )
    task_state = TaskStateFile()
    for task in task_list.tasks:
        task_state.set_status(task.id, "pending")
    project_id, mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    store.save_contract_state(
        project_id,
        mission_id,
        ContractStateFile(items={"VAL-A": ContractStateEntry()}),
    )
    before = _tree_snapshot(store.bucket_root(project_id))

    with monkeypatch.context() as observer_guard:
        observer_guard.setattr(
            MissionCoordinator,
            "step",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("observer invoked coordinator authority")
            ),
        )
        observation = observe_project_runtime(
            store,
            project_id,
            now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
        )

    evaluated: list[str] = []
    coordinator = MissionCoordinator(
        store,
        project_id,
        MockDispatcher(lambda request: (_ for _ in ()).throw(AssertionError(request))),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )

    def evaluate(_task_list: TaskList, gate: Task) -> object:
        evaluated.append(gate.id)
        return object()

    monkeypatch.setattr(coordinator, "_evaluate_gate", evaluate)
    monkeypatch.setattr(
        coordinator,
        "_apply_gate_event",
        lambda _mid, _tasks, _state, event: StepResult.advanced(event.gate.id),
    )
    result = coordinator.step()

    assert observation.gate_readiness.task_ids == (
        "gate-z-authored-first",
        "gate-a-authored-second",
    )
    assert observation.shadow_scheduler.action == "evaluate_gate"
    assert observation.shadow_scheduler.task_ids == ("gate-z-authored-first",)
    assert observation.shadow_scheduler.dispatch_performed is False
    assert evaluated == ["gate-z-authored-first"]
    assert result == StepResult.advanced("gate-z-authored-first")
    assert _tree_snapshot(store.bucket_root(project_id)) == before


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
        assert mixed.shadow_scheduler.task_ids == tuple(
            task.id for task in ordered_tasks
        )


def test_mixed_running_projection_covers_live_reconciliation_pass(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    tasks = [
        _task("completed", "work"),
        _task("stale", "work"),
        _task("current-running", "work"),
        _task("cursor-mismatch", "work"),
        _task("malformed", "work"),
    ]
    task_list = TaskList(tasks=tasks)
    task_state = TaskStateFile()
    attempt_ids = {
        "completed": "2026-08-06T11-00-00Z",
        "stale": "2026-08-06T08-00-00Z",
        "current-running": "2026-08-06T11-59-30Z",
        "cursor-mismatch": "2026-08-06T10-00-00Z",
        "malformed": "2026-08-06T11-30-00Z",
    }
    for task in tasks:
        task_state.set_status(task.id, "running")
        task_state.set_last_attempt(task.id, attempt_ids[task.id])
    project_id, mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    store.save_contract_state(
        project_id,
        mission_id,
        ContractStateFile(items={"VAL-A": ContractStateEntry()}),
    )
    store.save_attempt(
        project_id,
        mission_id,
        attempt_ids["completed"],
        "completed",
        WorkHandoff(node_id="completed", done=True, report="done"),
    )
    mismatch_latest = "2026-08-06T11-15-00Z"
    store.save_attempt(
        project_id,
        mission_id,
        mismatch_latest,
        "cursor-mismatch",
        WorkHandoff(node_id="cursor-mismatch", done=True, report="done"),
    )
    malformed_path = store.attempt_path(
        project_id,
        mission_id,
        attempt_ids["malformed"],
        "malformed",
    )
    malformed_path.write_text("{not-json}\n", encoding="utf-8")
    before = _tree_snapshot(store.bucket_root(project_id))

    observation = observe_project_runtime(
        store,
        project_id,
        stale_after_seconds=60,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )

    assert observation.shadow_scheduler.action == "inspect_malformed_attempt"
    assert observation.shadow_scheduler.task_ids == tuple(task.id for task in tasks)
    timings = {timing.task_id: timing for timing in observation.timings}
    assert timings["completed"].completion_observed is True
    assert timings["malformed"].malformed_completion is True
    assert timings["stale"].active_attempt_elapsed_seconds == 14_400.0
    assert timings["current-running"].active_attempt_elapsed_seconds == 30.0
    assert timings["cursor-mismatch"].latest_observed_attempt_id == mismatch_latest
    assert {
        anomaly.code: anomaly.task_ids for anomaly in observation.anomalies
    } == {
        "attempt_cursor_mismatch": ("cursor-mismatch",),
        "malformed_attempt_handoff": ("malformed",),
        "completed_attempt_unreconciled": ("completed", "cursor-mismatch"),
        "stale_running_candidate": ("stale",),
    }

    reconciled: list[str] = []
    synthesized: list[str] = []
    original_read_attempt = store.read_attempt
    read_attempts: list[str] = []

    def traced_read_attempt(
        pid: str, mid: str, spawn_ts: str, task_id: str
    ) -> WorkHandoff | ValidateHandoff | None:
        read_attempts.append(task_id)
        return original_read_attempt(pid, mid, spawn_ts, task_id)

    coordinator = MissionCoordinator(
        store,
        project_id,
        MockDispatcher(lambda request: (_ for _ in ()).throw(AssertionError(request))),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    monkeypatch.setattr(store, "read_attempt", traced_read_attempt)
    monkeypatch.setattr(
        store,
        "save_attempt",
        lambda _pid, _mid, _spawn, task_id, _handoff: synthesized.append(task_id),
    )
    monkeypatch.setattr(
        coordinator,
        "_apply_handoff_collect",
        lambda _mid, task, _handoff, _spawn: reconciled.append(task.id) or [],
    )

    with pytest.raises(json.JSONDecodeError):
        coordinator.step()

    assert reconciled == [
        "completed",
        "stale",
        "current-running",
        "cursor-mismatch",
    ]
    assert synthesized == ["stale", "current-running"]
    assert read_attempts == ["completed", "cursor-mismatch", "malformed"]
    assert _tree_snapshot(store.bucket_root(project_id)) == before


def test_failed_task_attention_correlation_is_per_mission_and_task(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_list = TaskList(
        tasks=[_task("failed-a", "work"), _task("failed-b", "work")]
    )
    task_state = TaskStateFile()
    task_state.set_status("failed-a", "failed")
    task_state.set_status("failed-b", "failed")
    project_id, _mission_id = _save_running_project(
        store, workspace, task_list, task_state
    )
    cases = [
        (
            [
                AttentionItemInternal(
                    id="att-matching",
                    kind="node_failed",
                    mission_id="mission-001",
                    node_id="failed-a",
                    report="matching",
                )
            ],
            ("failed-b",),
        ),
        (
            [
                AttentionItemInternal(
                    id="att-other-task",
                    kind="node_failed",
                    mission_id="mission-001",
                    node_id="unrelated-task",
                    report="other task",
                )
            ],
            ("failed-a", "failed-b"),
        ),
        (
            [
                AttentionItemInternal(
                    id="att-other-mission",
                    kind="node_failed",
                    mission_id="mission-999",
                    node_id="failed-a",
                    report="other mission",
                )
            ],
            ("failed-a", "failed-b"),
        ),
        (
            [
                AttentionItemInternal(
                    id="att-gate",
                    kind="gate_checkpoint",
                    mission_id="mission-001",
                    node_id="gate-a",
                    report="gate checkpoint",
                ),
                AttentionItemInternal(
                    id="att-terminal",
                    kind="terminal_review",
                    mission_id="mission-001",
                    node_id=None,
                    report="terminal review",
                ),
            ],
            ("failed-a", "failed-b"),
        ),
    ]

    for attention, expected_ids in cases:
        store.save_attention(project_id, attention)
        observation = observe_project_runtime(
            store,
            project_id,
            now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
        )
        anomaly = next(
            item
            for item in observation.anomalies
            if item.code == "failed_task_without_attention"
        )
        assert anomaly.task_ids == expected_ids

    store.save_attention(
        project_id,
        [
            AttentionItemInternal(
                id="att-a",
                kind="node_failed",
                mission_id="mission-001",
                node_id="failed-a",
                report="a",
            ),
            AttentionItemInternal(
                id="att-b",
                kind="node_attention",
                mission_id="mission-001",
                node_id="failed-b",
                report="b",
            ),
        ],
    )
    fully_correlated = observe_project_runtime(
        store,
        project_id,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )
    assert "failed_task_without_attention" not in {
        anomaly.code for anomaly in fully_correlated.anomalies
    }


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
    assert captured.value.code == "non_current_mission"


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


def test_runtime_observation_library_contains_a_regular_file_projects_root(
    harness_home: Path,
    tmp_path: Path,
) -> None:
    projects_file = tmp_path / "projects-file"
    projects_file.write_text("not a directory", encoding="utf-8")
    config = replace(_config(harness_home), projects_dir=projects_file)

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

    def one_change(
        root: Path,
        *,
        expected: tuple[object, ...] | None = None,
    ) -> tuple[tuple[str, int, int, int, int], ...]:
        nonlocal calls
        calls += 1
        actual = actual_identity(root, expected=expected)  # type: ignore[arg-type]
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

    def always_changed(
        root: Path,
        *,
        expected: tuple[object, ...] | None = None,
    ) -> tuple[tuple[str, int, int, int, int], ...]:
        nonlocal calls
        calls += 1
        return (
            *actual_identity(root, expected=expected),  # type: ignore[arg-type]
            (f"changed-{calls}", 0, 0, 0, 0),
        )

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


def test_capture_reads_only_current_bodies_and_contract_identities(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    task_state = TaskStateFile()
    task_state.set_status("work-a", "running")
    task_state.set_last_attempt("work-a", "2026-08-08T18-00-00Z")
    project_id, mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        task_state,
    )
    _write_contract(store, project_id, "VAL-CURRENT")
    store.save_attempt(
        project_id,
        mission_id,
        "2026-08-08T18-00-00Z",
        "work-a",
        WorkHandoff(node_id="work-a", done=True, report="CURRENT-HANDOFF"),
    )
    historical = (
        store.bucket_root(project_id)
        / ".unrest-runtime"
        / "missions"
        / "mission-000"
        / "attempts"
        / "2026-01-01T00-00-00Z__old.json"
    )
    historical.parent.mkdir(parents=True)
    historical.write_text('{"report":"HISTORICAL-SENTINEL"}', encoding="utf-8")
    historical_contract = (
        store.bucket_root(project_id)
        / ".unrest"
        / "missions"
        / "mission-000"
        / "contract"
        / "VAL-OLD.md"
    )
    historical_contract.parent.mkdir(parents=True)
    historical_contract.write_text("HISTORICAL-CONTRACT-SENTINEL", encoding="utf-8")

    opened: list[str] = []
    original_open = os.open

    def tracked_open(path: os.PathLike[str] | str, flags: int, *args: object) -> int:
        opened.append(Path(path).relative_to(store.bucket_root(project_id)).as_posix())
        return original_open(path, flags, *args)

    monkeypatch.setattr(os, "open", tracked_open)
    observation = observe_project_runtime(store, project_id)

    assert observation.timings[0].completion_observed is True
    assert observation.progress.assertion_total == 1
    assert not any(path.endswith(".md") for path in opened)
    assert not any("mission-000" in path for path in opened)
    assert any(path.endswith("__work-a.json") for path in opened)


def test_capture_limits_hold_at_boundary_and_fail_one_over(
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
    _write_contract(store, project_id, "VAL-A")
    _write_contract(store, project_id, "VAL-B")
    root = store.bucket_root(project_id)
    baseline = runtime_observability._capture_inputs(root)
    file_count = len(baseline)
    total_bytes = sum(len(item.data or b"") for item in baseline)
    largest_file = max(len(item.data or b"") for item in baseline)
    deepest = max(len(Path(item.relative_path).parts) for item in baseline)

    for constant, at_limit, over_limit in (
        ("MAX_CAPTURE_FILES", file_count, file_count - 1),
        ("MAX_CAPTURE_TOTAL_BYTES", total_bytes, total_bytes - 1),
        ("MAX_CAPTURE_FILE_BYTES", largest_file, largest_file - 1),
        ("MAX_CAPTURE_DEPTH", deepest, deepest - 1),
    ):
        monkeypatch.setattr(runtime_observability, constant, at_limit)
        assert observe_project_runtime(store, project_id).project_id == project_id
        monkeypatch.setattr(runtime_observability, constant, over_limit)
        with pytest.raises(RuntimeObservationError) as captured:
            observe_project_runtime(store, project_id)
        assert captured.value.code == "unsafe_cursor"
        monkeypatch.undo()


def test_irrelevant_mission_history_does_not_scale_capture_allocation(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[_task("work-a", "work")]),
        TaskStateFile(),
    )
    _write_contract(store, project_id, "VAL-A")
    root = store.bucket_root(project_id)
    fixed_now = datetime(2026, 8, 8, 20, 0, tzinfo=UTC)
    expected = observe_project_runtime(store, project_id, now=fixed_now).model_dump(
        mode="json"
    )
    scanned: set[str] = set()
    actual_scan = runtime_observability._scan_directory

    def recording_scan(
        path: Path,
        project_root: Path,
        *,
        optional: bool,
    ) -> list[os.DirEntry[str]]:
        scanned.add(path.relative_to(project_root).as_posix())
        return actual_scan(path, project_root, optional=optional)

    monkeypatch.setattr(runtime_observability, "_scan_directory", recording_scan)
    peaks: dict[int, int] = {}
    selected: dict[int, tuple[str, ...]] = {}
    prose = "IRRELEVANT-HISTORY-SENTINEL\n" + ("x" * (32 * 1024))
    existing_history = 0

    for history_count in (1, 10, 41):
        for index in range(existing_history, history_count):
            historical_id = f"mission-{index + 100:03d}"
            attempt = (
                root
                / ".unrest-runtime"
                / "missions"
                / historical_id
                / "attempts"
                / f"2026-01-01T00-00-{index:02d}Z__old.json"
            )
            attempt.parent.mkdir(parents=True)
            attempt.write_text(json.dumps({"report": prose}), encoding="utf-8")
            contract = (
                root
                / ".unrest"
                / "missions"
                / historical_id
                / "contract"
                / f"VAL-HISTORY-{index:03d}.md"
            )
            contract.parent.mkdir(parents=True)
            contract.write_text(prose, encoding="utf-8")
        existing_history = history_count

        sources = runtime_observability._capture_inputs(root)
        selected[history_count] = tuple(item.relative_path for item in sources)
        gc.collect()
        tracemalloc.start()
        observation = observe_project_runtime(store, project_id, now=fixed_now)
        _current, peaks[history_count] = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert observation.model_dump(mode="json") == expected
        assert all(
            "/missions/" not in path or f"/missions/{mission_id}/" in path
            for path in selected[history_count]
        )

    assert selected[1] == selected[10] == selected[41]
    assert peaks[41] <= peaks[1] + 32 * 1024
    assert scanned <= {
        ".unrest-runtime",
        f".unrest-runtime/missions/{mission_id}/attempts",
        f".unrest/missions/{mission_id}/contract",
    }


def test_capture_identity_matrix_rejects_every_changed_field() -> None:
    class Identity:
        st_dev = 22
        st_ino = 11
        st_size = 100
        st_mtime_ns = 20

    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns"):
        changed = Identity()
        setattr(changed, field, getattr(changed, field) + 1)
        assert not runtime_observability._same_identity(Identity(), changed)  # type: ignore[arg-type]


@pytest.mark.parametrize("phase", ["before_open", "during_read", "before_post_stat"])
def test_capture_rejects_atomic_replacement_at_each_read_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "cursor.json"
    target.write_bytes(b'{"generation":1}')
    original_open, original_read, original_close = os.open, os.read, os.close
    changed = False

    def replace() -> None:
        nonlocal changed
        if changed:
            return
        replacement = root / "replacement"
        replacement.write_bytes(b'{"generation":2}')
        os.replace(replacement, target)
        changed = True

    def opening(path: os.PathLike[str] | str, flags: int, *args: object) -> int:
        if phase == "before_open":
            replace()
        return original_open(path, flags, *args)

    def reading(descriptor: int, count: int) -> bytes:
        value = original_read(descriptor, count)
        if phase == "during_read" and value:
            replace()
        return value

    def closing(descriptor: int) -> None:
        if phase == "before_post_stat":
            replace()
        original_close(descriptor)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "read", reading)
    monkeypatch.setattr(os, "close", closing)
    with pytest.raises(RuntimeObservationError) as captured:
        runtime_observability._capture_file(
            target, root, runtime_observability._CaptureBudget()
        )
    assert captured.value.code == "snapshot_changed"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="platform has no FIFO support")
def test_non_regular_replacement_matrix_is_bounded_in_subprocess(tmp_path: Path) -> None:
    root = Path(tempfile.mkdtemp(prefix="uobs-", dir="/tmp"))
    sentinel = tmp_path / "outside-secret.json"
    sentinel.write_text("EXTERNAL-SENTINEL", encoding="utf-8")
    cases: list[tuple[str, Path]] = []
    symlink = root / "symlink.json"
    symlink.symlink_to(sentinel)
    cases.append(("symlink", symlink))
    directory = root / "directory.json"
    directory.mkdir()
    cases.append(("directory", directory))
    fifo = root / "fifo.json"
    os.mkfifo(fifo)
    cases.append(("fifo", fifo))
    if hasattr(socket, "AF_UNIX"):
        socket_path = root / "socket.json"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_path))
        except OSError:
            listener.close()
            listener = None
        else:
            cases.append(("socket", socket_path))
    else:
        listener = None

    code = """
import json, sys
from pathlib import Path
from unrest_harness.runtime_observability import _CaptureBudget, _capture_file, RuntimeObservationError
try:
    _capture_file(Path(sys.argv[2]), Path(sys.argv[1]), _CaptureBudget())
except RuntimeObservationError as exc:
    print(json.dumps({"code": exc.code}))
else:
    raise SystemExit("unexpected success")
"""
    try:
        for _name, path in cases:
            completed = subprocess.run(
                [sys.executable, "-c", code, str(root), str(path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            assert completed.returncode == 0
            assert completed.stdout.strip() == '{"code": "unsafe_cursor"}'
            assert "EXTERNAL-SENTINEL" not in completed.stdout + completed.stderr
    finally:
        if listener is not None:
            listener.close()
        shutil.rmtree(root)


def test_read_and_scan_failures_close_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "cursor.json"
    target.write_text("{}", encoding="utf-8")
    original_close = os.close
    closed: list[int] = []

    def denied_read(_descriptor: int, _count: int) -> bytes:
        raise OSError(errno.EACCES, "SECRET-PATH")

    def tracked_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(os, "read", denied_read)
    monkeypatch.setattr(os, "close", tracked_close)
    with pytest.raises(RuntimeObservationError) as captured:
        runtime_observability._capture_file(
            target, root, runtime_observability._CaptureBudget()
        )
    assert captured.value.code == "unsafe_cursor"
    assert str(captured.value) == "unsafe_cursor"
    assert len(closed) == 1

    class FailingIterator:
        closed = False

        def __enter__(self) -> "FailingIterator":
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

        def __iter__(self) -> "FailingIterator":
            return self

        def __next__(self) -> os.DirEntry[str]:
            raise OSError(errno.ENOTDIR, "SECRET-PATH")

    iterator = FailingIterator()
    monkeypatch.setattr(os, "scandir", lambda _path: iterator)
    with pytest.raises(RuntimeObservationError) as scan_error:
        runtime_observability._scan_directory(root, root, optional=False)
    assert scan_error.value.code == "unsafe_cursor"
    assert iterator.closed is True


@pytest.mark.parametrize(
    ("phase", "injected_errno", "expected_code", "expected_closes"),
    [
        ("lstat", errno.EACCES, "unsafe_cursor", 0),
        ("open", errno.ELOOP, "unsafe_cursor", 0),
        ("opened_fstat", errno.ENOTDIR, "unsafe_cursor", 1),
        ("read", errno.EACCES, "unsafe_cursor", 1),
        ("closed_fstat", errno.ENOENT, "snapshot_changed", 1),
        ("post_lstat", errno.ENOENT, "snapshot_changed", 1),
    ],
)
def test_capture_filesystem_failure_matrix_is_value_free_and_closes_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    injected_errno: int,
    expected_code: str,
    expected_closes: int,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "cursor.json"
    target.write_text("{}", encoding="utf-8")
    original_lstat = Path.lstat
    original_open = os.open
    original_read = os.read
    original_fstat = os.fstat
    original_close = os.close
    lstat_calls = 0
    fstat_calls = 0
    closed: list[int] = []

    def injected_error() -> OSError:
        return OSError(injected_errno, "SECRET-PATH")

    def failing_lstat(path: Path) -> os.stat_result:
        nonlocal lstat_calls
        if path == target:
            lstat_calls += 1
            if phase == "lstat" and lstat_calls == 1:
                raise injected_error()
            if phase == "post_lstat" and lstat_calls == 2:
                raise injected_error()
        return original_lstat(path)

    def failing_open(
        path: os.PathLike[str] | str,
        flags: int,
        *args: object,
    ) -> int:
        if phase == "open":
            raise injected_error()
        return original_open(path, flags, *args)

    def failing_read(descriptor: int, count: int) -> bytes:
        if phase == "read":
            raise injected_error()
        return original_read(descriptor, count)

    def failing_fstat(descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        fstat_calls += 1
        if phase == "opened_fstat" and fstat_calls == 1:
            raise injected_error()
        if phase == "closed_fstat" and fstat_calls == 2:
            raise injected_error()
        return original_fstat(descriptor)

    def tracked_close(descriptor: int) -> None:
        closed.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    monkeypatch.setattr(os, "open", failing_open)
    monkeypatch.setattr(os, "read", failing_read)
    monkeypatch.setattr(os, "fstat", failing_fstat)
    monkeypatch.setattr(os, "close", tracked_close)

    with pytest.raises(RuntimeObservationError) as captured:
        runtime_observability._capture_file(
            target, root, runtime_observability._CaptureBudget()
        )
    assert captured.value.code == expected_code
    assert str(captured.value) == expected_code
    assert len(closed) == expected_closes


def test_all_projects_contains_injected_capture_failure(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    store.create_project("Good", workspace, project_id="good")
    store.create_project("Bad", workspace, project_id="bad")
    original = runtime_observability._capture_inputs

    def injected(root: Path, *, requested_mission_id: str | None = None):
        if root.name == "bad":
            raise RuntimeObservationError("unsafe_cursor")
        return original(root, requested_mission_id=requested_mission_id)

    monkeypatch.setattr(runtime_observability, "_capture_inputs", injected)
    collection = observe_all_projects_runtime(store)
    assert [item.project_id for item in collection.projects] == ["good"]
    assert [(item.project_id, item.code) for item in collection.failures] == [
        ("bad", "unsafe_cursor")
    ]


@pytest.mark.skipif(not Path("/dev/fd").is_dir(), reason="descriptor inventory unavailable")
def test_repeated_capture_does_not_grow_descriptor_count(
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
    before = len(list(Path("/dev/fd").iterdir()))
    for _ in range(100):
        observe_project_runtime(store, project_id)
    after = len(list(Path("/dev/fd").iterdir()))
    assert after <= before + 1


@pytest.mark.parametrize("length", [80, 81, 96, 128])
def test_display_identifier_boundaries_are_stable_and_collision_resistant(
    length: int,
) -> None:
    value = "p" * length
    rendered = runtime_observability._display_id(value)

    assert len(rendered) <= 80
    assert rendered == runtime_observability._display_id(value)
    if length == 80:
        assert rendered == value
    else:
        assert rendered.startswith("p" * 63 + "~")
        assert rendered != runtime_observability._display_id(value[:-1] + "q")


def test_display_identifier_controls_are_value_free_and_line_safe() -> None:
    sentinel = "task\nSECRET_CONTROL\tvalue"
    rendered = runtime_observability._display_id(sentinel)

    assert len(rendered) <= 80
    assert "\n" not in rendered
    assert "\t" not in rendered
    assert sentinel not in rendered
    assert rendered.endswith(
        hashlib.sha256(sentinel.encode("utf-8")).hexdigest()[:16]
    )


def test_large_valid_observation_renders_all_anomaly_ids_with_bounded_lines(
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
    base = observe_project_runtime(
        store,
        project_id,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )
    task_ids = tuple(f"task-{index:03d}-" + "x" * 116 for index in range(100))
    observation = base.model_copy(
        update={
            "project_id": "p" * 128,
            "mission_id": "m" * 128,
            "anomalies": (
                RuntimeAnomaly(
                    code="failed_task_without_attention",
                    task_ids=task_ids,
                ),
            ),
        }
    )

    first = render_runtime_observation(observation)
    second = render_runtime_observation(observation)
    lines = first.splitlines()

    assert first.encode("utf-8") == second.encode("utf-8")
    assert max(map(len, lines)) <= 240
    assert "anomaly=failed_task_without_attention tasks=100 omitted=0" in lines
    assert sum(line.startswith("anomaly_task=") for line in lines) == 100
    assert all(
        runtime_observability._display_id(task_id) in first for task_id in task_ids
    )


def test_collection_rendering_isolates_one_project_render_failure(
    harness_home: Path,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ProjectStore(_config(harness_home))
    store.create_project("Good", workspace, project_id="good")
    store.create_project("Bad", workspace, project_id="bad")
    collection = observe_all_projects_runtime(
        store,
        now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
    )
    actual_render = runtime_observability.render_runtime_observation

    def render_one(observation: RuntimeObservation) -> str:
        if observation.project_id == "bad":
            raise RuntimeObservationError("malformed_cursor")
        return actual_render(observation)

    monkeypatch.setattr(runtime_observability, "render_runtime_observation", render_one)
    rendered = render_runtime_collection(collection)

    assert rendered.startswith("projects=1 failures=1\n")
    assert "project=good" in rendered
    assert "project=bad" not in rendered
    assert "failure=malformed_cursor ref=bad" in rendered


def test_category_counts_follow_model_literals_and_reconcile_totals() -> None:
    class ExpandedCategory(BaseModel):
        kind: Literal["alpha", "beta", "future"]

    counts = runtime_observability._canonical_counts(
        ExpandedCategory,
        "kind",
        Counter({"alpha": 2, "beta": 1}),
        expected_total=3,
    )
    assert [(item.name, item.count) for item in counts] == [
        ("alpha", 2),
        ("beta", 1),
        ("future", 0),
    ]

    with pytest.raises(RuntimeObservationError, match="malformed_cursor"):
        runtime_observability._canonical_counts(
            ExpandedCategory,
            "kind",
            Counter({"alpha": 2, "unknown": 1}),
            expected_total=3,
        )


def _assert_current_observation_payload(observation: RuntimeObservation) -> None:
    encoded = observation_json(observation)
    decoded = json.loads(encoded)
    assert list(decoded) == sorted(RuntimeObservation.model_fields)
    typed = RuntimeObservation.model_validate(decoded)
    assert typed == observation
    assert observation_json(typed) == encoded
    assert render_runtime_observation(typed) == render_runtime_observation(observation)


def _schema_running_observation(
    scenario: _CurrentSchemaScenario,
    harness_home: Path,
    workspace: Path,
) -> RuntimeObservation:
    store = ProjectStore(_config(harness_home))
    expected = scenario.expected_state
    now = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    if expected == "draft":
        store.create_project("schema", workspace, project_id="safe-iteration-test")
        return observe_project_runtime(store, "safe-iteration-test", now=now)

    tasks = [_task("work-a", "work")]
    task_state = TaskStateFile()
    if expected in {"active", "stale_running_candidate", "recovery_ready", "inconsistent"}:
        task_state.set_status("work-a", "running")
        spawn_ts = (
            "2026-08-06T11-59-30Z"
            if expected == "active"
            else "2026-08-06T08-00-00Z"
        )
        task_state.set_last_attempt("work-a", spawn_ts)
    elif expected in {"gate_ready", "quiescent"}:
        tasks = [
            _task("validator-a", "validate"),
            _task("gate-a", "gate", depends_on=["validator-a"]),
        ]
        task_state.set_status("validator-a", "cleared")
        task_state.set_status(
            "gate-a", "pending" if expected == "gate_ready" else "cleared"
        )
    project_id, mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=tasks),
        task_state,
    )
    if expected == "planning":
        store.save_state(project_id, MissionPlanning(mission_id=mission_id))
    elif expected == "attention":
        store.save_state(project_id, AttentionNeeded(items=[]))
    elif expected == "terminal":
        store.save_state(project_id, Done())
    elif expected == "recovery_ready":
        store.save_attempt(
            project_id,
            mission_id,
            "2026-08-06T08-00-00Z",
            "work-a",
            WorkHandoff(node_id="work-a", done=True, report="complete"),
        )
    elif expected == "inconsistent":
        malformed = store.attempt_path(
            project_id, mission_id, "2026-08-06T08-00-00Z", "work-a"
        )
        malformed.parent.mkdir(parents=True, exist_ok=True)
        malformed.write_text("{not-json}\n", encoding="utf-8")
    return observe_project_runtime(store, project_id, stale_after_seconds=60, now=now)


@pytest.mark.parametrize(
    "scenario",
    SCHEMA_V1_SCENARIOS,
    ids=lambda scenario: scenario.id,
)
def test_current_schema_v1_corpus_executes_typed_scenario(
    scenario: _CurrentSchemaScenario,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _SCHEMA_CORPUS_PAYLOAD["schema_version"] == 1
    harness_home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    if scenario.kind in {"single", "derived"}:
        if scenario.kind == "single":
            store = ProjectStore(_config(harness_home))
            store.create_project("schema", workspace, project_id="schema-project")
            observation = observe_project_runtime(
                store,
                "schema-project",
                now=datetime(2026, 8, 6, 12, 0, tzinfo=UTC),
            )
        else:
            observation = _schema_running_observation(
                scenario, harness_home, workspace
            )
            assert observation.derived_state == scenario.expected_state
        _assert_current_observation_payload(observation)
        return

    if scenario.kind == "collection":
        store = ProjectStore(_config(harness_home))
        if scenario.fixture in {"success", "mixed"}:
            store.create_project("good", workspace, project_id="good-one")
        if scenario.fixture in {"mixed", "all_failed"}:
            malformed = harness_home / "projects" / "broken-one" / ".unrest-runtime"
            malformed.mkdir(parents=True)
            (malformed / "project.json").write_text("{not-json}", encoding="utf-8")
        arguments = ["observe-project", "--all", "--format", scenario.format or "text"]
        if scenario.strict:
            arguments.append("--strict")
        result = CliRunner().invoke(
            cli,
            arguments,
            env={
                "UNREST_HOME": str(harness_home),
                "UNREST_PROJECTS_DIR": str(harness_home / "projects"),
            },
        )
        assert result.exit_code == scenario.expected_exit
        assert "Traceback" not in result.output
        if scenario.format == "json":
            collection = RuntimeObservationCollection.model_validate_json(result.output)
            assert observation_json(collection) == result.output
        else:
            assert result.output.startswith("projects=")
            assert result.output.endswith("\n")
        return

    if scenario.kind == "selector":
        store = ProjectStore(_config(harness_home))
        project_id, _mission_id = _save_running_project(
            store, workspace, TaskList(tasks=[]), TaskStateFile()
        )
        if scenario.expected_model == "observation":
            observation = observe_project_runtime(
                store, project_id, mission_id=scenario.selector
            )
            _assert_current_observation_payload(observation)
        else:
            with pytest.raises(RuntimeObservationError) as captured:
                observe_project_runtime(store, project_id, mission_id=scenario.selector)
            assert captured.value.code == scenario.expected_code
        return

    if scenario.kind == "configuration":
        value = scenario.value
        if value == "<regular-file>":
            regular_file = tmp_path / "SCHEMA_SENTINEL_FILE"
            regular_file.write_text("not a directory", encoding="utf-8")
            value = str(regular_file)
        assert scenario.variable is not None and value is not None
        result = CliRunner().invoke(
            cli,
            ["observe-project", "--all", "--format", "json"],
            env={
                "UNREST_HOME": str(harness_home),
                "UNREST_PROJECTS_DIR": str(harness_home / "projects"),
                scenario.variable: value,
            },
        )
        assert result.exit_code == scenario.expected_exit
        assert result.output == f"Error: {scenario.expected_code}\n"
        assert "SCHEMA_SENTINEL" not in result.output
        return

    assert scenario.kind == "failure"
    if scenario.expected_code in {
        "invalid_format",
        "invalid_project_id",
        "invalid_stale_threshold",
    }:
        arguments = {
            "invalid_format": ["observe-project", "--all", "--format", "bad"],
            "invalid_project_id": ["observe-project"],
            "invalid_stale_threshold": [
                "observe-project", "--all", "--stale-after-seconds", "0"
            ],
        }[scenario.expected_code]
        result = CliRunner().invoke(cli, arguments)
        assert result.exit_code == scenario.expected_exit
        assert result.output == f"Error: {scenario.expected_code}\n"
        return

    if scenario.expected_code == "unsafe_project_path":
        projects_file = tmp_path / "projects-file"
        projects_file.write_text("not a directory", encoding="utf-8")
        config = replace(_config(harness_home), projects_dir=projects_file)
        store = ProjectStore(config)
    else:
        store = ProjectStore(_config(harness_home))
        if scenario.expected_code != "project_not_found":
            project_id, mission_id = _save_running_project(
                store, workspace, TaskList(tasks=[]), TaskStateFile()
            )
            if scenario.expected_code == "malformed_cursor":
                project_path = store.unrest_runtime_dir(project_id) / "project.json"
                project_path.write_text("{not-json}", encoding="utf-8")
            elif scenario.expected_code == "snapshot_changed":
                monkeypatch.setattr(runtime_observability, "CAPTURE_ATTEMPTS", 0)
            elif scenario.expected_code == "unsafe_cursor":
                assert scenario.expected_code == "unsafe_cursor"
                state_path = store.unrest_runtime_dir(project_id) / "state.json"
                state_path.unlink()
                state_path.mkdir()
    with pytest.raises(RuntimeObservationError) as captured:
        if scenario.expected_code == "unsafe_project_path":
            observe_all_projects_runtime(store)
        elif scenario.expected_code == "project_not_found":
            observe_project_runtime(store, "missing-project")
        elif scenario.expected_code == "non_current_mission":
            observe_project_runtime(store, project_id, mission_id="mission-999")
        else:
            observe_project_runtime(store, project_id)
    assert captured.value.code == scenario.expected_code


def test_mission_selector_distinguishes_malformed_missing_current_and_non_current(
    harness_home: Path,
    workspace: Path,
) -> None:
    store = ProjectStore(_config(harness_home))
    project_id, mission_id = _save_running_project(
        store,
        workspace,
        TaskList(tasks=[]),
        TaskStateFile(),
    )

    assert (
        observe_project_runtime(store, project_id, mission_id=mission_id).mission_id
        == mission_id
    )
    for selector, code in (
        ("bad/mission", "malformed_cursor"),
        ("mission-999", "non_current_mission"),
    ):
        with pytest.raises(RuntimeObservationError) as captured:
            observe_project_runtime(store, project_id, mission_id=selector)
        assert captured.value.code == code

    store.create_project("Draft", workspace, project_id="draft-project")
    with pytest.raises(RuntimeObservationError) as captured:
        observe_project_runtime(store, "draft-project", mission_id="mission-001")
    assert captured.value.code == "non_current_mission"
