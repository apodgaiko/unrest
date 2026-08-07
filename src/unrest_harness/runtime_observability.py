"""Read-only, versioned runtime observations for operators.

The observer reads existing cursors through a content-stable snapshot.  It
never invokes the coordinator, reconciles an attempt, writes telemetry, or
dispatches work.  File timestamps are reported as diagnostics, not as
heartbeats or completion estimates.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .models import (
    Aborted,
    AttentionFile,
    AttentionNeeded,
    Done,
    Draft,
    Failed,
    MissionPlanning,
    MissionRunning,
    ProjectRecord,
    ProjectState,
    TASK_ID_REGEX,
    Task,
    TaskList,
    TaskStateFile,
    ContractStateFile,
    WorkHandoff,
    ValidateHandoff,
)
from .storage import ProjectStore


DerivedRuntimeState = Literal[
    "active",
    "attention",
    "draft",
    "gate_ready",
    "inconsistent",
    "planning",
    "quiescent",
    "recovery_ready",
    "runnable",
    "stale_running_candidate",
    "terminal",
]
ObservationFailureCode = Literal[
    "invalid_format",
    "invalid_project_id",
    "invalid_stale_threshold",
    "malformed_cursor",
    "project_not_found",
    "snapshot_changed",
    "unsafe_cursor",
    "unsafe_project_path",
]
RuntimeAnomalyCode = Literal[
    "mission_cursor_mismatch",
    "failed_task_without_attention",
    "running_without_attempt_id",
    "attempt_cursor_mismatch",
    "malformed_attempt_handoff",
    "completed_attempt_unreconciled",
    "stale_running_candidate",
]
PersistedRuntimeState = Literal[
    "draft",
    "mission_planning",
    "mission_running",
    "attention_needed",
    "done",
    "failed",
    "aborted",
]
ShadowAction = Literal[
    "none",
    "wait_for_plan",
    "attention_decision_required",
    "inspect_malformed_attempt",
    "reconcile_completed_attempt",
    "inspect_stale_attempt",
    "wait_for_attempt",
    "evaluate_gate",
    "dispatch_ready",
    "diagnose_failed_cursor",
    "closure_candidate",
]
ShadowReasonCode = Literal[
    "not_planning",
    "plan_not_submitted",
    "attention_open",
    "project_terminal",
    "malformed_attempt",
    "handoff_available",
    "running_cursor_needs_inspection",
    "running_within_threshold",
    "gate_dependencies_cleared",
    "dependencies_cleared",
    "failed_without_attention",
    "no_runnable_work",
]

PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MISSION_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
_TASK_TYPES = ("work", "validate", "gate")
_TASK_STATUSES = ("pending", "running", "cleared", "failed", "superseded")
_ASSERTION_STATUSES = ("pending", "passed", "failed")
_ATTENTION_KINDS = (
    "node_failed",
    "node_attention",
    "gate_failed",
    "gate_checkpoint",
    "terminal_review",
)
_STATE_ADAPTER: TypeAdapter[ProjectState] = TypeAdapter(ProjectState)


class RuntimeObservationError(RuntimeError):
    """A bounded observation failure safe to surface to an operator."""

    def __init__(self, code: ObservationFailureCode) -> None:
        super().__init__(code)
        self.code = code


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NamedCount(_FrozenModel):
    name: str
    count: int = Field(ge=0)


class TaskCountSummary(_FrozenModel):
    by_type: tuple[NamedCount, ...]
    by_status: tuple[NamedCount, ...]


class AssertionCountSummary(_FrozenModel):
    by_status: tuple[NamedCount, ...]


class AttentionCountSummary(_FrozenModel):
    by_kind: tuple[NamedCount, ...]


class StructuralProgress(_FrozenModel):
    authored_task_total: int = Field(ge=0)
    active_task_total: int = Field(ge=0)
    cleared_task_total: int = Field(ge=0)
    assertion_total: int = Field(ge=0)
    passed_assertion_total: int = Field(ge=0)


class FreshnessObservation(_FrozenModel):
    source: Literal["file_mtime"] = "file_mtime"
    state_cursor_age_seconds: float | None
    task_cursor_age_seconds: float | None
    newest_runtime_input_age_seconds: float | None


class TaskObservation(_FrozenModel):
    ordinal: int = Field(ge=0)
    task_id: str
    task_type: Literal["work", "validate", "gate"]
    status: Literal["pending", "running", "cleared", "failed", "superseded"]
    depends_on: tuple[str, ...]
    blocked_by: tuple[str, ...]
    runnable: bool
    attempt_count: int = Field(ge=0)
    cursor_attempt_id: str | None
    latest_observed_attempt_id: str | None


class AttemptTiming(_FrozenModel):
    task_id: str
    cursor_attempt_id: str | None
    latest_observed_attempt_id: str | None
    active_attempt_elapsed_seconds: float | None
    completion_observed: bool
    malformed_completion: bool
    observed_attempt_duration_seconds: float | None
    observed_duration_source: Literal["file_mtime"] | None

    @property
    def cursor_spawn_ts(self) -> str | None:
        """Compatibility alias for the unpublic foundation model."""

        return self.cursor_attempt_id

    @property
    def observed_attempt_ts(self) -> str | None:
        """Compatibility alias for the unpublic foundation model."""

        return self.latest_observed_attempt_id

    @property
    def age_seconds(self) -> float | None:
        """Compatibility alias for the unpublic foundation model."""

        return self.active_attempt_elapsed_seconds


class RuntimeAnomaly(_FrozenModel):
    code: RuntimeAnomalyCode
    task_ids: tuple[str, ...] = Field(default_factory=tuple)


class GateReadiness(_FrozenModel):
    count: int = Field(ge=0)
    task_ids: tuple[str, ...]


class ShadowSchedulerDecision(_FrozenModel):
    """What the current scheduler would consider; never an authority input."""

    action: ShadowAction
    task_ids: tuple[str, ...] = Field(default_factory=tuple)
    reason_code: ShadowReasonCode
    dispatch_performed: Literal[False] = False


class RuntimeObservation(_FrozenModel):
    schema_version: Literal[1] = 1
    observed_at: str
    project_id: str
    mission_id: str | None
    persisted_state: PersistedRuntimeState
    derived_state: DerivedRuntimeState
    freshness: FreshnessObservation
    progress: StructuralProgress
    task_counts: TaskCountSummary
    assertion_counts: AssertionCountSummary
    attention_counts: AttentionCountSummary
    gate_readiness: GateReadiness
    tasks: tuple[TaskObservation, ...] = Field(default_factory=tuple)
    timings: tuple[AttemptTiming, ...] = Field(default_factory=tuple)
    anomalies: tuple[RuntimeAnomaly, ...] = Field(default_factory=tuple)
    shadow_scheduler: ShadowSchedulerDecision

    @property
    def state_age_seconds(self) -> float | None:
        """Compatibility alias for the unpublic foundation model."""

        return self.freshness.state_cursor_age_seconds


class ObservationFailure(_FrozenModel):
    code: ObservationFailureCode
    project_id: str | None = None
    entry_ref: str | None = None


class RuntimeObservationCollection(_FrozenModel):
    schema_version: Literal[1] = 1
    observed_at: str
    projects: tuple[RuntimeObservation, ...] = Field(default_factory=tuple)
    failures: tuple[ObservationFailure, ...] = Field(default_factory=tuple)


class _CapturedFile(_FrozenModel):
    relative_path: str
    content_sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    data: bytes = Field(exclude=True)


def validate_project_id(project_id: str) -> bool:
    return (
        PROJECT_ID_PATTERN.fullmatch(project_id) is not None
        and project_id not in {".", ".."}
        and ".." not in project_id.split("/")
    )


def _validate_mission_id(mission_id: str | None) -> None:
    if mission_id is not None and MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        raise RuntimeObservationError("malformed_cursor")


def _validate_task_identifiers(
    task_list: TaskList,
    task_state: TaskStateFile,
) -> None:
    identifiers = [
        identifier
        for task in task_list.tasks
        for identifier in (task.id, *task.depends_on)
    ]
    identifiers.extend(task_state.tasks)
    if any(
        len(identifier) > 128 or TASK_ID_REGEX.fullmatch(identifier) is None
        for identifier in identifiers
    ):
        raise RuntimeObservationError("malformed_cursor")


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _age_seconds(now: datetime, mtime_ns: int | None) -> float | None:
    if mtime_ns is None:
        return None
    modified = datetime.fromtimestamp(mtime_ns / 1_000_000_000, UTC)
    return max(0.0, round((now - modified).total_seconds(), 3))


def _parse_spawn_ts(value: str | None) -> datetime | None:
    if value is None:
        return None
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


def _require_real_directory(path: Path, root: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeObservationError("project_not_found") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError) as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc


def _validated_project_root(store: ProjectStore, project_id: str) -> Path:
    if not validate_project_id(project_id):
        raise RuntimeObservationError("invalid_project_id")
    try:
        projects_info = store.config.projects_dir.lstat()
    except FileNotFoundError as exc:
        raise RuntimeObservationError("project_not_found") from exc
    if stat.S_ISLNK(projects_info.st_mode) or not stat.S_ISDIR(projects_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    projects_root = store.config.projects_dir.resolve()
    project_root = store.config.projects_dir / project_id
    _require_real_directory(project_root, projects_root)
    return project_root


def _safe_files_below(
    root: Path,
    *,
    project_root: Path,
    suffix: str,
    recursive: bool,
) -> list[Path]:
    try:
        info = root.lstat()
    except FileNotFoundError:
        return []
    try:
        root.resolve().relative_to(project_root.resolve())
    except (OSError, ValueError) as exc:
        raise RuntimeObservationError("unsafe_cursor") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeObservationError("unsafe_cursor")

    files: list[Path] = []
    try:
        entries = sorted(os.scandir(root), key=lambda item: os.fsencode(item.name))
    except OSError as exc:
        raise RuntimeObservationError("malformed_cursor") from exc
    for entry in entries:
        path = Path(entry.path)
        try:
            entry_info = path.lstat()
        except OSError as exc:
            raise RuntimeObservationError("unsafe_cursor") from exc
        if stat.S_ISLNK(entry_info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if stat.S_ISDIR(entry_info.st_mode):
            if recursive:
                files.extend(
                    _safe_files_below(
                        path,
                        project_root=project_root,
                        suffix=suffix,
                        recursive=True,
                    )
                )
            continue
        if path.suffix != suffix:
            continue
        if not stat.S_ISREG(entry_info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        files.append(path)
    return files


def _candidate_input_paths(project_root: Path) -> tuple[Path, ...]:
    try:
        project_info = project_root.lstat()
    except OSError as exc:
        raise RuntimeObservationError("snapshot_changed") from exc
    if stat.S_ISLNK(project_info.st_mode) or not stat.S_ISDIR(project_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    runtime_root = project_root / ".unrest-runtime"
    runtime_files = _safe_files_below(
        runtime_root,
        project_root=project_root,
        suffix=".json",
        recursive=True,
    )

    contract_files: list[Path] = []
    durable_root = project_root / ".unrest"
    try:
        durable_info = durable_root.lstat()
    except FileNotFoundError:
        return tuple(sorted(runtime_files))
    if stat.S_ISLNK(durable_info.st_mode) or not stat.S_ISDIR(durable_info.st_mode):
        raise RuntimeObservationError("unsafe_cursor")
    missions_root = durable_root / "missions"
    try:
        missions_root.lstat()
    except FileNotFoundError:
        pass
    else:
        mission_dirs = _safe_files_below(
            missions_root,
            project_root=project_root,
            suffix=".__never__",
            recursive=False,
        )
        del mission_dirs  # validates the root and its immediate entries
        for mission_entry in sorted(
            os.scandir(missions_root), key=lambda item: os.fsencode(item.name)
        ):
            mission_path = Path(mission_entry.path)
            mission_info = mission_path.lstat()
            if stat.S_ISLNK(mission_info.st_mode):
                raise RuntimeObservationError("unsafe_cursor")
            if not stat.S_ISDIR(mission_info.st_mode):
                continue
            contract_files.extend(
                _safe_files_below(
                    mission_path / "contract",
                    project_root=project_root,
                    suffix=".md",
                    recursive=False,
                )
            )

    return tuple(sorted((*runtime_files, *contract_files)))


def _capture_inputs(project_root: Path) -> tuple[_CapturedFile, ...]:
    captured: list[_CapturedFile] = []
    for path in _candidate_input_paths(project_root):
        try:
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise RuntimeObservationError("unsafe_cursor")
            data = path.read_bytes()
            after = path.lstat()
        except RuntimeObservationError:
            raise
        except OSError as exc:
            raise RuntimeObservationError("snapshot_changed") from exc
        if (
            before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise RuntimeObservationError("snapshot_changed")
        captured.append(
            _CapturedFile(
                relative_path=path.relative_to(project_root).as_posix(),
                content_sha256=hashlib.sha256(data).hexdigest(),
                device=after.st_dev,
                inode=after.st_ino,
                size=after.st_size,
                mtime_ns=after.st_mtime_ns,
                data=data,
            )
        )
    return tuple(captured)


def _identity_generation(
    files: tuple[_CapturedFile, ...],
) -> tuple[tuple[str, int, int, int, int], ...]:
    return tuple(
        (item.relative_path, item.device, item.inode, item.size, item.mtime_ns)
        for item in files
    )


def _current_identity_generation(
    project_root: Path,
) -> tuple[tuple[str, int, int, int, int], ...]:
    result: list[tuple[str, int, int, int, int]] = []
    for path in _candidate_input_paths(project_root):
        try:
            info = path.lstat()
        except OSError as exc:
            raise RuntimeObservationError("snapshot_changed") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        result.append(
            (
                path.relative_to(project_root).as_posix(),
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            )
        )
    return tuple(result)


def _source_map(files: tuple[_CapturedFile, ...]) -> dict[str, _CapturedFile]:
    return {item.relative_path: item for item in files}


def _parse_json_model(
    sources: dict[str, _CapturedFile],
    key: str,
    model: type[BaseModel],
    *,
    default: BaseModel | None = None,
) -> BaseModel:
    source = sources.get(key)
    if source is None:
        if default is not None:
            return default
        raise RuntimeObservationError("malformed_cursor")
    try:
        return model.model_validate_json(source.data)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeObservationError("malformed_cursor") from exc


def _parse_state(
    sources: dict[str, _CapturedFile],
) -> ProjectState | None:
    source = sources.get(".unrest-runtime/state.json")
    if source is None:
        return None
    try:
        return _STATE_ADAPTER.validate_json(source.data)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeObservationError("malformed_cursor") from exc


def _contract_ids(sources: dict[str, _CapturedFile], mission_id: str) -> tuple[str, ...]:
    prefix = f".unrest/missions/{mission_id}/contract/"
    result: list[str] = []
    for key in sorted(sources):
        if not key.startswith(prefix) or not key.endswith(".md"):
            continue
        stem = Path(key).stem
        if stem != "README":
            result.append(stem)
    return tuple(result)


def _attempt_sources(
    sources: dict[str, _CapturedFile], mission_id: str, task_id: str
) -> tuple[tuple[str, _CapturedFile], ...]:
    prefix = f".unrest-runtime/missions/{mission_id}/attempts/"
    attempts: list[tuple[str, _CapturedFile]] = []
    for key, source in sorted(sources.items()):
        if not key.startswith(prefix) or not key.endswith(".json"):
            continue
        stem = Path(key).stem
        if "__" not in stem:
            continue
        spawn_ts, node_id = stem.split("__", 1)
        if node_id == task_id:
            attempts.append((spawn_ts, source))
    return tuple(attempts)


def _parse_handoff(source: _CapturedFile) -> WorkHandoff | ValidateHandoff:
    try:
        data = json.loads(source.data)
        if isinstance(data, dict) and ("items" in data or "passed" in data):
            return ValidateHandoff.model_validate(data)
        return WorkHandoff.model_validate(data)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeObservationError("malformed_cursor") from exc


def _runnable_tasks(task_list: TaskList, task_state: TaskStateFile) -> list[Task]:
    return [
        task
        for task in task_list.tasks
        if task.type != "gate"
        and task_state.status_of(task.id) == "pending"
        and all(task_state.status_of(dep) == "cleared" for dep in task.depends_on)
    ]


def _ready_gates(task_list: TaskList, task_state: TaskStateFile) -> list[Task]:
    return [
        task
        for task in task_list.tasks
        if task.type == "gate"
        and task_state.status_of(task.id) == "pending"
        and all(task_state.status_of(dep) == "cleared" for dep in task.depends_on)
    ]


def shadow_selected_task_ids(
    task_list: TaskList,
    task_state: TaskStateFile,
    *,
    max_parallel_nodes: int,
) -> tuple[str, ...]:
    """Mirror current selection for differential comparison only."""

    runnable = _runnable_tasks(task_list, task_state)
    capacity = max(1, max_parallel_nodes)
    by_id = {task.id: task for task in task_list.tasks}
    runnable_validator_ids = {
        task.id for task in runnable if task.type == "validate"
    }
    for gate in (task for task in task_list.tasks if task.type == "gate"):
        if task_state.status_of(gate.id) != "pending":
            continue
        validator_dep_ids = [
            dep
            for dep in gate.depends_on
            if dep in by_id and by_id[dep].type == "validate"
        ]
        if not validator_dep_ids:
            continue
        if not all(
            task_state.status_of(dep) == "cleared"
            or dep in runnable_validator_ids
            for dep in gate.depends_on
        ):
            continue
        batch = [
            task
            for task in runnable
            if task.id in runnable_validator_ids and task.id in validator_dep_ids
        ]
        return tuple(task.id for task in batch[:capacity])

    candidates = runnable[:capacity]
    if any(task.type == "work" for task in candidates):
        candidates = candidates[:1]
    return tuple(task.id for task in candidates)


def _non_running_decision(
    state: ProjectState | None,
) -> tuple[DerivedRuntimeState, ShadowSchedulerDecision]:
    if state is None or isinstance(state, Draft):
        return "draft", ShadowSchedulerDecision(
            action="none", reason_code="not_planning"
        )
    if isinstance(state, MissionPlanning):
        return "planning", ShadowSchedulerDecision(
            action="wait_for_plan", reason_code="plan_not_submitted"
        )
    if isinstance(state, AttentionNeeded):
        return "attention", ShadowSchedulerDecision(
            action="attention_decision_required", reason_code="attention_open"
        )
    if isinstance(state, (Done, Failed, Aborted)):
        return "terminal", ShadowSchedulerDecision(
            action="none", reason_code="project_terminal"
        )
    raise TypeError(f"unsupported state: {state!r}")


def _counts(order: tuple[str, ...], values: Counter[str]) -> tuple[NamedCount, ...]:
    return tuple(NamedCount(name=name, count=values[name]) for name in order)


def _observation_from_capture(
    store: ProjectStore,
    project_id: str,
    sources: tuple[_CapturedFile, ...],
    *,
    mission_id: str | None,
    stale_after_seconds: int,
    observed_at: datetime,
) -> RuntimeObservation:
    source_by_path = _source_map(sources)
    record = _parse_json_model(
        source_by_path,
        ".unrest-runtime/project.json",
        ProjectRecord,
    )
    assert isinstance(record, ProjectRecord)
    if record.id != project_id:
        raise RuntimeObservationError("malformed_cursor")
    state = _parse_state(source_by_path)
    persisted_state = state.state if state is not None else "draft"
    selected_mission = mission_id or record.current_mission_id
    _validate_mission_id(record.current_mission_id)
    _validate_mission_id(mission_id)
    if (
        mission_id is not None
        and record.current_mission_id is not None
        and mission_id != record.current_mission_id
    ):
        raise RuntimeObservationError("malformed_cursor")
    if isinstance(state, (MissionRunning, MissionPlanning)):
        _validate_mission_id(state.mission_id)
        if mission_id is not None and state.mission_id != mission_id:
            raise RuntimeObservationError("malformed_cursor")
        selected_mission = state.mission_id

    state_source = source_by_path.get(".unrest-runtime/state.json")
    task_list = TaskList()
    task_state = TaskStateFile()
    contract_state = ContractStateFile()
    contract_ids: tuple[str, ...] = ()
    task_state_source: _CapturedFile | None = None
    if selected_mission is not None:
        mission_prefix = f".unrest-runtime/missions/{selected_mission}"
        tasks_key = f"{mission_prefix}/tasks.json"
        if tasks_key in source_by_path:
            parsed_tasks = _parse_json_model(source_by_path, tasks_key, TaskList)
            assert isinstance(parsed_tasks, TaskList)
            task_list = parsed_tasks
        elif isinstance(state, MissionRunning):
            raise RuntimeObservationError("malformed_cursor")
        task_state_key = f"{mission_prefix}/task-state.json"
        parsed_task_state = _parse_json_model(
            source_by_path,
            task_state_key,
            TaskStateFile,
            default=TaskStateFile(),
        )
        assert isinstance(parsed_task_state, TaskStateFile)
        task_state = parsed_task_state
        _validate_task_identifiers(task_list, task_state)
        task_state_source = source_by_path.get(task_state_key)
        parsed_contract_state = _parse_json_model(
            source_by_path,
            f"{mission_prefix}/contract-state.json",
            ContractStateFile,
            default=ContractStateFile(),
        )
        assert isinstance(parsed_contract_state, ContractStateFile)
        contract_state = parsed_contract_state
        contract_ids = _contract_ids(source_by_path, selected_mission)

    parsed_attention = _parse_json_model(
        source_by_path,
        ".unrest-runtime/attention.json",
        AttentionFile,
        default=AttentionFile(),
    )
    assert isinstance(parsed_attention, AttentionFile)
    attention = parsed_attention.items

    type_counts: Counter[str] = Counter(task.type for task in task_list.tasks)
    status_counts: Counter[str] = Counter(
        task_state.status_of(task.id) for task in task_list.tasks
    )
    assertion_status_counts: Counter[str] = Counter()
    for assertion_id in contract_ids:
        assertion_entry = contract_state.items.get(assertion_id)
        assertion_status_counts[
            assertion_entry.status if assertion_entry is not None else "pending"
        ] += 1
    attention_counts: Counter[str] = Counter(item.kind for item in attention)

    task_rows: list[TaskObservation] = []
    timings: list[AttemptTiming] = []
    completion_ids: list[str] = []
    malformed_ids: list[str] = []
    missing_attempt_ids: list[str] = []
    mismatch_ids: list[str] = []
    stale_ids: list[str] = []
    for ordinal, task in enumerate(task_list.tasks):
        status_value = task_state.status_of(task.id)
        entry = task_state.tasks.get(task.id)
        cursor_attempt_id = entry.last_attempt if entry is not None else None
        if cursor_attempt_id is not None and _parse_spawn_ts(cursor_attempt_id) is None:
            raise RuntimeObservationError("malformed_cursor")
        attempts = _attempt_sources(source_by_path, selected_mission or "", task.id)
        latest_attempt_id = attempts[-1][0] if attempts else None
        latest_source = attempts[-1][1] if attempts else None
        if latest_attempt_id is not None and _parse_spawn_ts(latest_attempt_id) is None:
            raise RuntimeObservationError("malformed_cursor")
        completion_observed = False
        malformed_completion = False
        if latest_source is not None:
            try:
                _parse_handoff(latest_source)
                completion_observed = True
            except RuntimeObservationError:
                malformed_completion = True
        active_elapsed: float | None = None
        if status_value == "running":
            started_at = _parse_spawn_ts(cursor_attempt_id)
            if started_at is not None:
                active_elapsed = max(
                    0.0,
                    round((observed_at - started_at).total_seconds(), 3),
                )
            if cursor_attempt_id is None:
                missing_attempt_ids.append(task.id)
            if (
                cursor_attempt_id is not None
                and latest_attempt_id is not None
                and cursor_attempt_id != latest_attempt_id
            ):
                mismatch_ids.append(task.id)
            if malformed_completion:
                malformed_ids.append(task.id)
            elif completion_observed:
                completion_ids.append(task.id)
            elif active_elapsed is not None and active_elapsed >= stale_after_seconds:
                stale_ids.append(task.id)
        duration: float | None = None
        if latest_source is not None:
            attempt_started_at = _parse_spawn_ts(latest_attempt_id)
            if attempt_started_at is not None:
                completed_at = datetime.fromtimestamp(
                    latest_source.mtime_ns / 1_000_000_000, UTC
                )
                duration = max(
                    0.0,
                    round((completed_at - attempt_started_at).total_seconds(), 3),
                )
        blocked_by = tuple(
            dep
            for dep in task.depends_on
            if task_state.status_of(dep) != "cleared"
        )
        runnable = (
            task.type != "gate" and status_value == "pending" and not blocked_by
        )
        task_rows.append(
            TaskObservation(
                ordinal=ordinal,
                task_id=task.id,
                task_type=task.type,
                status=status_value,
                depends_on=tuple(task.depends_on),
                blocked_by=blocked_by,
                runnable=runnable,
                attempt_count=len(attempts),
                cursor_attempt_id=cursor_attempt_id,
                latest_observed_attempt_id=latest_attempt_id,
            )
        )
        if status_value == "running":
            timings.append(
                AttemptTiming(
                    task_id=task.id,
                    cursor_attempt_id=cursor_attempt_id,
                    latest_observed_attempt_id=latest_attempt_id,
                    active_attempt_elapsed_seconds=active_elapsed,
                    completion_observed=completion_observed,
                    malformed_completion=malformed_completion,
                    observed_attempt_duration_seconds=duration,
                    observed_duration_source=(
                        "file_mtime" if duration is not None else None
                    ),
                )
            )

    anomalies: list[RuntimeAnomaly] = []
    if isinstance(state, (MissionRunning, MissionPlanning)) and (
        record.current_mission_id != state.mission_id
    ):
        anomalies.append(RuntimeAnomaly(code="mission_cursor_mismatch"))
    failed_ids = tuple(
        task.task_id for task in task_rows if task.status == "failed"
    )
    if isinstance(state, MissionRunning) and failed_ids and not attention:
        anomalies.append(
            RuntimeAnomaly(
                code="failed_task_without_attention", task_ids=failed_ids
            )
        )
    for code, ids in (
        ("running_without_attempt_id", missing_attempt_ids),
        ("attempt_cursor_mismatch", mismatch_ids),
        ("malformed_attempt_handoff", malformed_ids),
        ("completed_attempt_unreconciled", completion_ids),
        ("stale_running_candidate", stale_ids),
    ):
        if ids:
            anomalies.append(
                RuntimeAnomaly(code=code, task_ids=tuple(dict.fromkeys(ids)))  # type: ignore[arg-type]
            )

    ready_gates = _ready_gates(task_list, task_state)
    runnable_tasks = _runnable_tasks(task_list, task_state)
    running_ids = tuple(
        task.task_id for task in task_rows if task.status == "running"
    )
    if not isinstance(state, MissionRunning):
        derived, decision = _non_running_decision(state)
    elif malformed_ids:
        derived = "inconsistent"
        decision = ShadowSchedulerDecision(
            action="inspect_malformed_attempt",
            task_ids=tuple(malformed_ids),
            reason_code="malformed_attempt",
        )
    elif completion_ids:
        derived = "recovery_ready"
        decision = ShadowSchedulerDecision(
            action="reconcile_completed_attempt",
            task_ids=tuple(completion_ids),
            reason_code="handoff_available",
        )
    elif stale_ids or missing_attempt_ids:
        derived = "stale_running_candidate"
        decision = ShadowSchedulerDecision(
            action="inspect_stale_attempt",
            task_ids=tuple(dict.fromkeys((*missing_attempt_ids, *stale_ids))),
            reason_code="running_cursor_needs_inspection",
        )
    elif running_ids:
        derived = "active"
        decision = ShadowSchedulerDecision(
            action="wait_for_attempt",
            task_ids=running_ids,
            reason_code="running_within_threshold",
        )
    elif ready_gates:
        derived = "gate_ready"
        decision = ShadowSchedulerDecision(
            action="evaluate_gate",
            task_ids=(ready_gates[0].id,),
            reason_code="gate_dependencies_cleared",
        )
    elif runnable_tasks:
        derived = "runnable"
        decision = ShadowSchedulerDecision(
            action="dispatch_ready",
            task_ids=shadow_selected_task_ids(
                task_list,
                task_state,
                max_parallel_nodes=store.config.max_parallel_nodes,
            ),
            reason_code="dependencies_cleared",
        )
    elif failed_ids:
        derived = "inconsistent"
        decision = ShadowSchedulerDecision(
            action="diagnose_failed_cursor",
            task_ids=failed_ids,
            reason_code="failed_without_attention",
        )
    else:
        derived = "quiescent"
        decision = ShadowSchedulerDecision(
            action="closure_candidate", reason_code="no_runnable_work"
        )

    active_rows = tuple(task for task in task_rows if task.status != "superseded")
    newest_mtime = max(
        (
            item.mtime_ns
            for item in sources
            if item.relative_path.startswith(".unrest-runtime/")
        ),
        default=None,
    )
    return RuntimeObservation(
        observed_at=_utc_text(observed_at),
        project_id=project_id,
        mission_id=selected_mission,
        persisted_state=persisted_state,
        derived_state=derived,
        freshness=FreshnessObservation(
            state_cursor_age_seconds=_age_seconds(
                observed_at, state_source.mtime_ns if state_source else None
            ),
            task_cursor_age_seconds=_age_seconds(
                observed_at,
                task_state_source.mtime_ns if task_state_source else None,
            ),
            newest_runtime_input_age_seconds=_age_seconds(
                observed_at, newest_mtime
            ),
        ),
        progress=StructuralProgress(
            authored_task_total=len(task_rows),
            active_task_total=len(active_rows),
            cleared_task_total=sum(task.status == "cleared" for task in active_rows),
            assertion_total=len(contract_ids),
            passed_assertion_total=assertion_status_counts["passed"],
        ),
        task_counts=TaskCountSummary(
            by_type=_counts(_TASK_TYPES, type_counts),
            by_status=_counts(_TASK_STATUSES, status_counts),
        ),
        assertion_counts=AssertionCountSummary(
            by_status=_counts(_ASSERTION_STATUSES, assertion_status_counts)
        ),
        attention_counts=AttentionCountSummary(
            by_kind=_counts(_ATTENTION_KINDS, attention_counts)
        ),
        gate_readiness=GateReadiness(
            count=len(ready_gates),
            task_ids=tuple(task.id for task in ready_gates),
        ),
        tasks=tuple(task_rows),
        timings=tuple(timings),
        anomalies=tuple(anomalies),
        shadow_scheduler=decision,
    )


def observe_project_runtime(
    store: ProjectStore,
    project_id: str,
    *,
    mission_id: str | None = None,
    stale_after_seconds: int = 3600,
    now: datetime | None = None,
) -> RuntimeObservation:
    """Return a coherent, immutable snapshot without changing project state."""

    if stale_after_seconds <= 0:
        raise RuntimeObservationError("invalid_stale_threshold")
    project_root = _validated_project_root(store, project_id)
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    for _attempt in range(3):
        before: tuple[_CapturedFile, ...] | None = None
        try:
            before = _capture_inputs(project_root)
            observation = _observation_from_capture(
                store,
                project_id,
                before,
                mission_id=mission_id,
                stale_after_seconds=stale_after_seconds,
                observed_at=observed_at,
            )
            after_identity = _current_identity_generation(project_root)
        except RuntimeObservationError as error:
            if error.code == "snapshot_changed":
                continue
            if error.code != "malformed_cursor" or before is None:
                raise
            try:
                stable = _current_identity_generation(project_root)
            except RuntimeObservationError as recapture_error:
                if recapture_error.code == "snapshot_changed":
                    continue
                raise
            if _identity_generation(before) != stable:
                continue
            raise
        if _identity_generation(before) == after_identity:
            return observation
    raise RuntimeObservationError("snapshot_changed")


def _unsafe_entry_ref(name: str) -> str:
    digest = hashlib.sha256(os.fsencode(name)).hexdigest()[:16]
    return f"entry-sha256:{digest}"


def observe_all_projects_runtime(
    store: ProjectStore,
    *,
    stale_after_seconds: int = 3600,
    now: datetime | None = None,
) -> RuntimeObservationCollection:
    """Observe every immediate project entry, isolating bounded failures."""

    if stale_after_seconds <= 0:
        raise RuntimeObservationError("invalid_stale_threshold")
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    root = store.config.projects_dir
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return RuntimeObservationCollection(observed_at=_utc_text(observed_at))
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    try:
        entries = sorted(os.scandir(root), key=lambda item: os.fsencode(item.name))
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
    projects: list[RuntimeObservation] = []
    failures: list[ObservationFailure] = []
    project_ids: list[str] = []
    for entry in entries:
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError:
            failures.append(
                ObservationFailure(
                    code="unsafe_project_path", entry_ref=_unsafe_entry_ref(entry.name)
                )
            )
            continue
        if stat.S_ISREG(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            failures.append(
                ObservationFailure(
                    code="unsafe_project_path", entry_ref=_unsafe_entry_ref(entry.name)
                )
            )
            continue
        if not validate_project_id(entry.name):
            failures.append(
                ObservationFailure(
                    code="invalid_project_id", entry_ref=_unsafe_entry_ref(entry.name)
                )
            )
            continue
        project_ids.append(entry.name)

    def observe_one(
        selected_project_id: str,
    ) -> RuntimeObservation | ObservationFailure:
        try:
            return observe_project_runtime(
                store,
                selected_project_id,
                stale_after_seconds=stale_after_seconds,
                now=observed_at,
            )
        except RuntimeObservationError as error:
            return ObservationFailure(
                code=error.code, project_id=selected_project_id
            )

    for selected_project_id in project_ids:
        result = observe_one(selected_project_id)
        if isinstance(result, RuntimeObservation):
            projects.append(result)
        else:
            failures.append(result)
    projects.sort(key=lambda item: item.project_id)
    failures.sort(
        key=lambda item: (item.project_id or "", item.entry_ref or "", item.code)
    )
    return RuntimeObservationCollection(
        observed_at=_utc_text(observed_at),
        projects=tuple(projects),
        failures=tuple(failures),
    )


def observation_json(
    observation: RuntimeObservation | RuntimeObservationCollection,
) -> str:
    return json.dumps(
        observation.model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    )


def _display_id(value: str) -> str:
    if len(value) <= 80:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{value[:80]}~{digest}"


def _fmt_seconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}s"


def render_runtime_observation(observation: RuntimeObservation) -> str:
    """Render a compact bounded operator view with no free-form cursor text."""

    lines = [
        (
            f"project={_display_id(observation.project_id)} "
            f"mission={_display_id(observation.mission_id or '-')} "
            f"persisted={observation.persisted_state} derived={observation.derived_state} "
            f"next={observation.shadow_scheduler.action}"
        ),
        (
            f"progress tasks={observation.progress.cleared_task_total}/"
            f"{observation.progress.active_task_total} "
            f"authored={observation.progress.authored_task_total} assertions="
            f"{observation.progress.passed_assertion_total}/"
            f"{observation.progress.assertion_total} ready_gates="
            f"{observation.gate_readiness.count}"
        ),
        (
            "freshness source=file_mtime "
            f"state={_fmt_seconds(observation.freshness.state_cursor_age_seconds)} "
            f"task={_fmt_seconds(observation.freshness.task_cursor_age_seconds)} "
            f"newest={_fmt_seconds(observation.freshness.newest_runtime_input_age_seconds)}"
        ),
    ]
    for task in observation.tasks:
        if task.status == "superseded":
            continue
        lines.append(
            f"task[{task.ordinal}]={_display_id(task.task_id)} type={task.task_type} "
            f"status={task.status} runnable={str(task.runnable).lower()} "
            f"blocked={len(task.blocked_by)} attempts={task.attempt_count}"
        )
    for timing in observation.timings:
        lines.append(
            f"timing task={_display_id(timing.task_id)} source=file_mtime "
            f"active_elapsed={_fmt_seconds(timing.active_attempt_elapsed_seconds)} "
            f"observed_duration={_fmt_seconds(timing.observed_attempt_duration_seconds)}"
        )
    for anomaly in observation.anomalies:
        ids = ",".join(_display_id(value) for value in anomaly.task_ids)
        lines.append(f"anomaly={anomaly.code} tasks={ids or '-'}")
    if any(len(line) > 240 for line in lines):
        raise RuntimeObservationError("malformed_cursor")
    return "\n".join(lines) + "\n"


def render_runtime_collection(collection: RuntimeObservationCollection) -> str:
    lines = [
        f"projects={len(collection.projects)} failures={len(collection.failures)}",
        f"schema=1 observed_at={collection.observed_at}",
    ]
    for project in collection.projects:
        lines.extend(render_runtime_observation(project).rstrip("\n").splitlines())
    for failure in collection.failures:
        reference = failure.project_id or failure.entry_ref or "-"
        lines.append(
            f"failure={failure.code} ref={_display_id(reference)}"
        )
    if any(len(line) > 240 for line in lines):
        raise RuntimeObservationError("malformed_cursor")
    return "\n".join(lines) + "\n"


__all__ = [
    "AttemptTiming",
    "ObservationFailure",
    "RuntimeAnomaly",
    "RuntimeObservation",
    "RuntimeObservationCollection",
    "RuntimeObservationError",
    "ShadowSchedulerDecision",
    "observe_all_projects_runtime",
    "observe_project_runtime",
    "observation_json",
    "render_runtime_collection",
    "render_runtime_observation",
    "shadow_selected_task_ids",
    "validate_project_id",
]
