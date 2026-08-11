from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

import unrest_harness.runtime_observability as runtime_observability
from unrest_harness.config import HarnessConfig
from unrest_harness.models import (
    AttentionItemInternal,
    AttentionNeeded,
    Done,
    Draft,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateEntry,
    TaskStateFile,
)
from unrest_harness.runtime_observability import (
    RuntimeObservation,
    RuntimeObservationError,
    observe_all_projects_runtime,
    observe_project_runtime,
    observation_json,
    render_runtime_collection,
    render_runtime_observation,
)
from unrest_harness.storage import ProjectStore


FIXED_NOW = datetime(2026, 8, 10, 12, 0, 10, tzinfo=UTC)
FIXED_NOW_NS = int(FIXED_NOW.timestamp() * 1_000_000_000)


def _store(tmp_path: Path) -> tuple[ProjectStore, Path]:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    config = HarnessConfig(
        bundled_dir=Path(__file__).parents[1] / "src/unrest_harness/bundled",
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )
    return ProjectStore(config), workspace


def _project(
    store: ProjectStore,
    workspace: Path,
    project_id: str,
    *,
    state: object = Draft(),
    tasks: list[Task] | None = None,
    statuses: dict[str, TaskStateEntry] | None = None,
) -> None:
    record = store.create_project(project_id, workspace, project_id=project_id)
    if isinstance(state, (MissionPlanning, MissionRunning)):
        record.current_mission_id = state.mission_id
        store.save_project(record)
    store.save_state(project_id, state)  # type: ignore[arg-type]
    if record.current_mission_id is not None:
        store.save_task_list(
            project_id,
            record.current_mission_id,
            TaskList(tasks=tasks or []),
        )
        store.save_task_state(
            project_id,
            record.current_mission_id,
            TaskStateFile(tasks=statuses or {}),
        )


def _tree(root: Path) -> tuple[tuple[str, int, int, bytes], ...]:
    result: list[tuple[str, int, int, bytes]] = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        result.append(
            (
                path.relative_to(root).as_posix(),
                info.st_mode,
                info.st_mtime_ns,
                path.read_bytes() if path.is_file() else b"",
            )
        )
    return tuple(result)


def test_schema_v2_draft_json_and_text_are_exact_and_closed(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "draft-one")
    state_path = store.unrest_runtime_dir("draft-one") / "state.json"
    os.utime(state_path, ns=(FIXED_NOW_NS - 1_234_500_000,) * 2)

    observation = observe_project_runtime(store, "draft-one", now=FIXED_NOW)
    expected = {
        "schema_version": 2,
        "observed_at": "2026-08-10T12:00:10Z",
        "project_id": "draft-one",
        "mission_id": None,
        "persisted_state": "draft",
        "derived_state": "draft",
        "attention_count": 0,
        "running_task_ids": [],
        "runnable_task_ids": [],
        "failed_task_ids": [],
        "last_runtime_change_age_seconds": 1.234,
        "codes": [],
    }
    assert observation.model_dump(mode="json") == expected
    assert observation_json(observation) == json.dumps(expected, separators=(",", ":"))
    assert render_runtime_observation(observation) == (
        "schema_version=2 observed_at=2026-08-10T12:00:10Z "
        "project_id=draft-one mission_id=- persisted_state=draft derived_state=draft "
        "attention_count=0 running_task_ids=- runnable_task_ids=- failed_task_ids=- "
        "last_runtime_change_age_seconds=1.234 codes=-\n"
    )
    with pytest.raises(ValidationError):
        RuntimeObservation.model_validate({**expected, "detail": "forbidden"})


@pytest.mark.parametrize(
    ("state", "tasks", "statuses", "attention", "derived"),
    [
        (Draft(), [], {}, [], "draft"),
        (MissionPlanning(mission_id="mission-001"), [], {}, [], "planning"),
        (
            MissionRunning(mission_id="mission-001"),
            [Task(id="ready", type="work", body="PRIVATE", targets=["VAL-A"], skill="worker")],
            {},
            [],
            "active",
        ),
        (
            MissionRunning(mission_id="mission-001"),
            [],
            {},
            [],
            "quiescent",
        ),
        (AttentionNeeded(), [], {}, [], "attention"),
        (Done(), [], {}, [], "terminal"),
    ],
)
def test_derived_state_precedence(
    tmp_path: Path,
    state: object,
    tasks: list[Task],
    statuses: dict[str, TaskStateEntry],
    attention: list[AttentionItemInternal],
    derived: str,
) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "states", state=state, tasks=tasks, statuses=statuses)
    if attention:
        store.save_attention("states", attention)
    assert observe_project_runtime(store, "states", now=FIXED_NOW).derived_state == derived


def test_projection_sorts_bounds_ids_and_emits_each_closed_code(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    tasks = [
        Task(id="z-running", type="work", body="PRIVATE_BODY", targets=["VAL-A"], skill="worker"),
        Task(id="a-running", type="work", body="PRIVATE_BODY", targets=["VAL-A"], skill="worker"),
        Task(id="f-failed", type="work", body="PRIVATE_BODY", targets=["VAL-A"], skill="worker"),
        Task(id="r-ready", type="work", body="PRIVATE_BODY", targets=["VAL-A"], skill="worker"),
        Task(id="x" * 100, type="work", body="PRIVATE_BODY", targets=["VAL-A"], skill="worker"),
    ]
    statuses = {
        "z-running": TaskStateEntry(status="running"),
        "a-running": TaskStateEntry(status="running", last_attempt="not-a-time"),
        "f-failed": TaskStateEntry(status="failed"),
    }
    _project(
        store,
        workspace,
        "codes",
        state=MissionRunning(mission_id="mission-001"),
        tasks=tasks,
        statuses=statuses,
    )
    record = store.load_project("codes")
    record.current_mission_id = "mission-002"
    store.save_project(record)

    observation = observe_project_runtime(
        store,
        "codes",
        stale_after_seconds=1,
        now=FIXED_NOW,
    )
    assert observation.derived_state == "inconsistent"
    assert observation.running_task_ids == ("a-running", "z-running")
    assert observation.runnable_task_ids[0] == "r-ready"
    assert len(observation.runnable_task_ids[1]) == 80
    assert observation.failed_task_ids == ("f-failed",)
    assert observation.codes == (
        "failed_task_without_attention",
        "malformed_attempt",
        "mission_cursor_mismatch",
        "running_without_attempt",
    )
    rendered = observation_json(observation)
    assert "PRIVATE_BODY" not in rendered
    assert str(workspace) not in rendered


def test_stale_code_is_diagnostic_and_does_not_change_active_state(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(
        store,
        workspace,
        "stale",
        state=MissionRunning(mission_id="mission-001"),
        tasks=[Task(id="work", type="work", body="body", targets=["VAL-A"], skill="worker")],
        statuses={
            "work": TaskStateEntry(
                status="running",
                last_attempt="2026-08-10T11-00-00Z",
            )
        },
    )
    observation = observe_project_runtime(
        store,
        "stale",
        stale_after_seconds=60,
        now=FIXED_NOW,
    )
    assert observation.derived_state == "active"
    assert observation.codes == ("stale_running_candidate",)


def test_age_uses_exact_runtime_inputs_half_even_and_clock_skew(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(
        store,
        workspace,
        "age",
        state=MissionRunning(mission_id="mission-001"),
    )
    runtime = store.mission_runtime_dir("age", "mission-001")
    terminal = runtime / "terminal-reviews"
    terminal.mkdir()
    terminal_cursor = terminal / "review.json"
    terminal_cursor.write_text("{}", encoding="utf-8")
    old_ns = FIXED_NOW_NS - 10_000_000_000
    for path in (
        store.unrest_runtime_dir("age") / "state.json",
        store.unrest_runtime_dir("age") / "attention.json",
        runtime / "task-state.json",
    ):
        if path.exists():
            os.utime(path, ns=(old_ns, old_ns))
    half_even_ns = FIXED_NOW_NS - 1_234_500_000
    os.utime(terminal_cursor, ns=(half_even_ns, half_even_ns))
    assert (
        observe_project_runtime(store, "age", now=FIXED_NOW).last_runtime_change_age_seconds
        == 1.234
    )
    future_ns = FIXED_NOW_NS + 1_000_000_000
    os.utime(terminal_cursor, ns=(future_ns, future_ns))
    assert (
        observe_project_runtime(store, "age", now=FIXED_NOW).last_runtime_change_age_seconds
        == 0.0
    )


def test_observation_is_read_only_and_does_not_import_authority(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "readonly", state=MissionRunning(mission_id="mission-001"))
    root = store.bucket_root("readonly")
    before = _tree(root)
    first = observe_project_runtime(store, "readonly", now=FIXED_NOW)
    second = observe_project_runtime(store, "readonly", now=FIXED_NOW)
    assert observation_json(first) == observation_json(second)
    assert _tree(root) == before
    source = Path(__file__).parents[1] / "src/unrest_harness/runtime_observability.py"
    text = source.read_text(encoding="utf-8")
    assert ".coordinator" not in text
    assert "dispatch" not in text
    assert ".recovery" not in text
    assert "recover_" not in text
    assert "ETA" not in text


def test_all_projects_is_closed_ordered_and_isolates_corruption(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "z-good")
    _project(store, workspace, "a-good")
    broken = store.config.projects_dir / "m-broken" / ".unrest-runtime"
    broken.mkdir(parents=True)
    (broken / "project.json").write_text("{PRIVATE_BAD_JSON}", encoding="utf-8")
    collection = observe_all_projects_runtime(store, now=FIXED_NOW)
    assert [item.project_id for item in collection.projects] == ["a-good", "z-good"]
    assert [item.model_dump() for item in collection.failures] == [
        {"project_id": "m-broken", "code": "malformed_cursor"}
    ]
    assert "PRIVATE_BAD_JSON" not in observation_json(collection)
    assert render_runtime_collection(collection).splitlines()[-1] == (
        "failure project=m-broken code=malformed_cursor"
    )


def test_empty_collection_has_exact_wrapper_and_empty_text(tmp_path: Path) -> None:
    store, _workspace = _store(tmp_path)
    collection = observe_all_projects_runtime(store, now=FIXED_NOW)
    assert observation_json(collection) == (
        '{"schema_version":2,"observed_at":"2026-08-10T12:00:10Z",'
        '"projects":[],"failures":[]}'
    )
    assert render_runtime_collection(collection) == ""


def test_symlinked_cursor_fails_closed_without_reading_target(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "unsafe")
    sentinel = tmp_path / "PRIVATE_SENTINEL"
    sentinel.write_text("PRIVATE_VALUE", encoding="utf-8")
    state_path = store.unrest_runtime_dir("unsafe") / "state.json"
    state_path.unlink()
    state_path.symlink_to(sentinel)
    with pytest.raises(RuntimeObservationError, match="unsafe_cursor"):
        observe_project_runtime(store, "unsafe", now=FIXED_NOW)


def test_observation_retries_one_changed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, workspace = _store(tmp_path)
    _project(store, workspace, "changing")
    original = runtime_observability._capture_inputs
    calls = 0

    def replace_once(project_root: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            store.save_state("changing", Done())
        return original(project_root)

    monkeypatch.setattr(runtime_observability, "_capture_inputs", replace_once)
    observation = observe_project_runtime(store, "changing", now=FIXED_NOW)
    assert calls == 4
    assert observation.persisted_state == "done"
    assert observation.derived_state == "terminal"


def test_fresh_entrypoint_import_boundary(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    script = r'''
import importlib.abc
import json
import sys
args = json.loads(sys.argv[1])
trap = sys.argv[2] == "1"
class Trap(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if trap and fullname == "unrest_harness.runtime_observability":
            raise RuntimeError("TRAPPED_STATUS_IMPORT")
        return None
sys.meta_path.insert(0, Trap())
error = None
try:
    from unrest_harness.cli import cli
    cli.main(args=args, prog_name="unrest", standalone_mode=False)
except BaseException as exc:
    error = f"{type(exc).__name__}:{exc}"
print(json.dumps({"error": error, "loaded": "unrest_harness.runtime_observability" in sys.modules}))
'''

    def probe(args: list[str], trap: bool) -> dict[str, object]:
        result = subprocess.run(
            [sys.executable, "-c", script, json.dumps(args), "1" if trap else "0"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        assert result.returncode == 0, result.stdout
        return json.loads(result.stdout.splitlines()[-1])

    assert probe(["--help"], True)["error"] is None
    assert probe(["list-projects"], True)["error"] is None
    positive = probe(["observe-project", "--help"], False)
    assert positive == {"error": None, "loaded": True}


def test_observer_v1_and_detail_surfaces_are_absent() -> None:
    root = Path(__file__).parents[1]
    source = (root / "src/unrest_harness/runtime_observability.py").read_text(
        encoding="utf-8"
    )
    cli_source = (root / "src/unrest_harness/cli.py").read_text(encoding="utf-8")
    forbidden = (
        "Literal[1]",
        "ShadowScheduler",
        "shadow_scheduler",
        "TaskObservation",
        "AttemptTiming",
        "RuntimeAnomaly",
        "FreshnessObservation",
        "StructuralProgress",
        "detail_mode",
        "--detail",
        "schema-v1",
    )
    assert not [token for token in forbidden if token in source or token in cli_source]
