"""Read-only, versioned runtime observations for operators.

The observer reads existing cursors through a content-stable snapshot.  It
never invokes the coordinator, reconciles an attempt, writes telemetry, or
dispatches work.  File timestamps are reported as diagnostics, not as
heartbeats or completion estimates.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .models import (
    Aborted,
    AttentionFile,
    AttentionItemInternal,
    AttentionNeeded,
    ContractStateEntry,
    ContractStateFile,
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
    TaskStateEntry,
    TaskStateFile,
    WorkHandoff,
    ValidateHandoff,
)
from .storage import ProjectStore
from .task_validation import gates_in_order


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
    "non_current_mission",
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
_STATE_ADAPTER: TypeAdapter[ProjectState] = TypeAdapter(ProjectState)
MAX_DISPLAY_ID_CHARS = 80
MAX_RENDER_LINE_CHARS = 240
_DISPLAY_DIGEST_CHARS = 16
_DISPLAY_PREFIX_CHARS = MAX_DISPLAY_ID_CHARS - _DISPLAY_DIGEST_CHARS - 1
_DISPLAY_SAFE = re.compile(r"^[A-Za-z0-9._:-]+$")


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
    data: bytes | None = Field(exclude=True)


# These bounds cover the fixed cursor layout with ample room for ordinary
# missions while making every allocation and read in capture auditable.
MAX_CAPTURE_FILE_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_TOTAL_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_FILES = 4096
MAX_CAPTURE_DEPTH = 6
CAPTURE_ATTEMPTS = 3
_READ_CHUNK_BYTES = 64 * 1024


@dataclass
class _CaptureBudget:
    files: int = 0
    bytes: int = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > MAX_CAPTURE_FILES:
            raise RuntimeObservationError("unsafe_cursor")

    def add_bytes(self, count: int) -> None:
        self.bytes += count
        if self.bytes > MAX_CAPTURE_TOTAL_BYTES:
            raise RuntimeObservationError("unsafe_cursor")


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
    timestamp = match.group("timestamp")
    if not timestamp.isascii():
        return None
    try:
        return datetime(
            int(timestamp[0:4]),
            int(timestamp[5:7]),
            int(timestamp[8:10]),
            int(timestamp[11:13]),
            int(timestamp[14:16]),
            int(timestamp[17:19]),
            tzinfo=UTC,
        )
    except ValueError:
        return None


def _require_real_directory(path: Path, root: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeObservationError("project_not_found") from exc
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
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
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
    if stat.S_ISLNK(projects_info.st_mode) or not stat.S_ISDIR(projects_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    try:
        projects_root = store.config.projects_dir.resolve()
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
    project_root = store.config.projects_dir / project_id
    _require_real_directory(project_root, projects_root)
    return project_root


def _cursor_error(exc: OSError) -> RuntimeObservationError:
    if exc.errno in {errno.ENOENT, errno.ESTALE}:
        return RuntimeObservationError("snapshot_changed")
    return RuntimeObservationError("unsafe_cursor")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
    )


def _relative_cursor_path(path: Path, project_root: Path) -> str:
    try:
        relative = path.relative_to(project_root)
    except ValueError as exc:
        raise RuntimeObservationError("unsafe_cursor") from exc
    if len(relative.parts) > MAX_CAPTURE_DEPTH:
        raise RuntimeObservationError("unsafe_cursor")
    return relative.as_posix()


def _safe_directory(path: Path, project_root: Path, *, optional: bool) -> bool:
    _relative_cursor_path(path, project_root)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return False
        raise RuntimeObservationError("snapshot_changed") from None
    except OSError as exc:
        raise _cursor_error(exc) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeObservationError("unsafe_cursor")
    return True


def _scan_directory(
    path: Path,
    project_root: Path,
    *,
    optional: bool,
) -> list[os.DirEntry[str]]:
    if not _safe_directory(path, project_root, optional=optional):
        return []
    entries: list[os.DirEntry[str]] = []
    try:
        iterator = os.scandir(path)
        with iterator:
            for entry in iterator:
                entries.append(entry)
                if len(entries) > MAX_CAPTURE_FILES:
                    raise RuntimeObservationError("unsafe_cursor")
    except RuntimeObservationError:
        raise
    except OSError as exc:
        raise _cursor_error(exc) from exc
    return sorted(entries, key=lambda item: os.fsencode(item.name))


def _capture_metadata(
    path: Path,
    project_root: Path,
    budget: _CaptureBudget,
    *,
    expected: os.stat_result | None = None,
) -> _CapturedFile:
    relative_path = _relative_cursor_path(path, project_root)
    try:
        info = path.lstat()
    except OSError as exc:
        raise _cursor_error(exc) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeObservationError("unsafe_cursor")
    if expected is not None and not _same_identity(expected, info):
        raise RuntimeObservationError("snapshot_changed")
    budget.add_file()
    return _CapturedFile(
        relative_path=relative_path,
        content_sha256="",
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        data=None,
    )


def _capture_file(
    path: Path,
    project_root: Path,
    budget: _CaptureBudget,
    *,
    optional: bool = False,
    expected: os.stat_result | None = None,
) -> _CapturedFile | None:
    relative_path = _relative_cursor_path(path, project_root)
    try:
        before = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise RuntimeObservationError("snapshot_changed") from None
    except OSError as exc:
        raise _cursor_error(exc) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeObservationError("unsafe_cursor")
    if expected is not None and not _same_identity(expected, before):
        raise RuntimeObservationError("snapshot_changed")
    if before.st_size > MAX_CAPTURE_FILE_BYTES:
        raise RuntimeObservationError("unsafe_cursor")

    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if not _same_identity(before, opened):
            raise RuntimeObservationError("snapshot_changed")
        data = bytearray()
        while True:
            remaining = MAX_CAPTURE_FILE_BYTES + 1 - len(data)
            if remaining <= 0:
                raise RuntimeObservationError("unsafe_cursor")
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            data.extend(chunk)
        closed = os.fstat(descriptor)
        if not _same_identity(opened, closed) or len(data) != closed.st_size:
            raise RuntimeObservationError("snapshot_changed")
    except RuntimeObservationError:
        raise
    except OSError as exc:
        raise _cursor_error(exc) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass

    try:
        after = path.lstat()
    except OSError as exc:
        raise _cursor_error(exc) from exc
    if not _same_identity(closed, after):
        raise RuntimeObservationError("snapshot_changed")
    payload = bytes(data)
    budget.add_file()
    budget.add_bytes(len(payload))
    return _CapturedFile(
        relative_path=relative_path,
        content_sha256=hashlib.sha256(payload).hexdigest(),
        device=closed.st_dev,
        inode=closed.st_ino,
        size=closed.st_size,
        mtime_ns=closed.st_mtime_ns,
        data=payload,
    )


def _selector_mission(files: list[_CapturedFile]) -> str | None:
    selected: str | None = None
    for source in files:
        if source.data is None:
            continue
        try:
            value = json.loads(source.data)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        candidate = value.get("current_mission_id")
        if isinstance(candidate, str):
            selected = candidate
        if value.get("state") in {"mission_planning", "mission_running"}:
            candidate = value.get("mission_id")
            if isinstance(candidate, str):
                selected = candidate
    return selected


def _task_capture_needs(files: list[_CapturedFile], mission_id: str) -> tuple[set[str], set[str]]:
    sources = {item.relative_path: item for item in files}
    prefix = f".unrest-runtime/missions/{mission_id}"
    task_source = sources.get(f"{prefix}/tasks.json")
    state_source = sources.get(f"{prefix}/task-state.json")
    if task_source is None or task_source.data is None:
        return set(), set()
    try:
        task_list = TaskList.model_validate_json(task_source.data)
        task_state = (
            TaskStateFile.model_validate_json(state_source.data)
            if state_source is not None and state_source.data is not None
            else TaskStateFile()
        )
    except (ValidationError, ValueError, json.JSONDecodeError):
        return set(), set()
    task_ids = {task.id for task in task_list.tasks}
    running_ids = {
        task.id for task in task_list.tasks if task_state.status_of(task.id) == "running"
    }
    return task_ids, running_ids


def _capture_inputs(
    project_root: Path,
    *,
    requested_mission_id: str | None = None,
) -> tuple[_CapturedFile, ...]:
    try:
        project_info = project_root.lstat()
    except OSError as exc:
        raise RuntimeObservationError("snapshot_changed") from exc
    if stat.S_ISLNK(project_info.st_mode) or not stat.S_ISDIR(project_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")

    budget = _CaptureBudget()
    captured: list[_CapturedFile] = []
    runtime_root = project_root / ".unrest-runtime"
    _safe_directory(runtime_root, project_root, optional=False)
    for entry in _scan_directory(runtime_root, project_root, optional=False):
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if path.suffix == ".json" and not stat.S_ISREG(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
    for name, optional in (
        ("project.json", False),
        ("state.json", True),
        ("attention.json", True),
    ):
        source = _capture_file(runtime_root / name, project_root, budget, optional=optional)
        if source is not None:
            captured.append(source)

    mission_id = requested_mission_id or _selector_mission(captured)
    if mission_id is None or MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        return tuple(sorted(captured, key=lambda item: item.relative_path))

    mission_runtime = runtime_root / "missions" / mission_id
    for name in ("tasks.json", "task-state.json", "contract-state.json"):
        source = _capture_file(
            mission_runtime / name,
            project_root,
            budget,
            optional=True,
        )
        if source is not None:
            captured.append(source)

    task_ids, running_ids = _task_capture_needs(captured, mission_id)
    durable_root = project_root / ".unrest"
    _safe_directory(durable_root, project_root, optional=True)
    contract_dir = durable_root / "missions" / mission_id / "contract"
    for entry in _scan_directory(contract_dir, project_root, optional=True):
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISDIR(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if path.suffix != ".md":
            continue
        captured.append(
            _capture_metadata(path, project_root, budget, expected=info)
        )

    attempts_dir = mission_runtime / "attempts"
    attempts_by_task: dict[str, list[tuple[str, Path, os.stat_result]]] = {}
    for entry in _scan_directory(attempts_dir, project_root, optional=True):
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISDIR(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if path.suffix != ".json" or "__" not in path.stem:
            continue
        spawn_ts, task_id = path.stem.split("__", 1)
        if task_id not in task_ids:
            continue
        attempts_by_task.setdefault(task_id, []).append((spawn_ts, path, info))

    for task_id in sorted(attempts_by_task):
        attempts = sorted(attempts_by_task[task_id], key=lambda item: os.fsencode(item[0]))
        for index, (_spawn_ts, path, info) in enumerate(attempts):
            if task_id in running_ids and index == len(attempts) - 1:
                source = _capture_file(path, project_root, budget, expected=info)
                assert source is not None
                captured.append(source)
            else:
                captured.append(
                    _capture_metadata(path, project_root, budget, expected=info)
                )
    return tuple(sorted(captured, key=lambda item: item.relative_path))


def _identity_generation(
    files: tuple[_CapturedFile, ...],
) -> tuple[tuple[str, int, int, int, int], ...]:
    return tuple(
        (item.relative_path, item.device, item.inode, item.size, item.mtime_ns)
        for item in files
    )


def _current_identity_generation(
    project_root: Path,
    *,
    expected: tuple[_CapturedFile, ...] | None = None,
    requested_mission_id: str | None = None,
) -> tuple[tuple[str, int, int, int, int], ...]:
    if expected is None:
        return _identity_generation(
            _capture_inputs(project_root, requested_mission_id=requested_mission_id)
        )

    expected_paths = {item.relative_path for item in expected}
    mission_id = requested_mission_id or _selector_mission(list(expected))
    task_ids = _task_capture_needs(list(expected), mission_id)[0] if mission_id else set()
    current_paths: set[str] = set()
    runtime_root = project_root / ".unrest-runtime"
    for name in ("project.json", "state.json", "attention.json"):
        path = runtime_root / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        current_paths.add(_relative_cursor_path(path, project_root))

    if mission_id is not None:
        mission_runtime = runtime_root / "missions" / mission_id
        for name in ("tasks.json", "task-state.json", "contract-state.json"):
            path = mission_runtime / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise _cursor_error(exc) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeObservationError("unsafe_cursor")
            current_paths.add(_relative_cursor_path(path, project_root))
        contract_dir = project_root / ".unrest" / "missions" / mission_id / "contract"
        for entry in _scan_directory(contract_dir, project_root, optional=True):
            path = Path(entry.path)
            if path.suffix == ".md":
                current_paths.add(_relative_cursor_path(path, project_root))
        attempts_dir = mission_runtime / "attempts"
        for entry in _scan_directory(attempts_dir, project_root, optional=True):
            path = Path(entry.path)
            if path.suffix != ".json" or "__" not in path.stem:
                continue
            _spawn_ts, task_id = path.stem.split("__", 1)
            if task_id in task_ids:
                current_paths.add(_relative_cursor_path(path, project_root))

    if current_paths != expected_paths:
        raise RuntimeObservationError("snapshot_changed")
    result: list[tuple[str, int, int, int, int]] = []
    for item in expected:
        path = project_root / item.relative_path
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        result.append(
            (item.relative_path, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
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
    if source.data is None:
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
    if source.data is None:
        raise RuntimeObservationError("malformed_cursor")
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
    if source.data is None:
        raise RuntimeObservationError("malformed_cursor")
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
        for task in gates_in_order(task_list)
        if task_state.status_of(task.id) == "pending"
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


def _canonical_counts(
    model: type[BaseModel],
    field_name: str,
    values: Counter[str],
    *,
    expected_total: int,
) -> tuple[NamedCount, ...]:
    """Render one closed model Literal and reject any reconciliation drift."""

    annotation = model.model_fields[field_name].annotation
    order = tuple(value for value in get_args(annotation) if isinstance(value, str))
    if not order or len(order) != len(set(order)):
        raise RuntimeObservationError("malformed_cursor")
    if set(values) - set(order) or sum(values.values()) != expected_total:
        raise RuntimeObservationError("malformed_cursor")
    counts = tuple(NamedCount(name=name, count=values[name]) for name in order)
    if sum(item.count for item in counts) != expected_total:
        raise RuntimeObservationError("malformed_cursor")
    return counts


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
        and mission_id != record.current_mission_id
    ):
        raise RuntimeObservationError("non_current_mission")
    if isinstance(state, (MissionRunning, MissionPlanning)):
        _validate_mission_id(state.mission_id)
        if mission_id is not None and state.mission_id != mission_id:
            raise RuntimeObservationError("non_current_mission")
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
        if status_value == "running" and latest_source is not None:
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
        if status_value == "running" and latest_source is not None:
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
    attended_failed_ids = {
        item.node_id
        for item in attention
        if item.mission_id == selected_mission and item.node_id in failed_ids
    }
    unattended_failed_ids = tuple(
        task_id for task_id in failed_ids if task_id not in attended_failed_ids
    )
    if isinstance(state, MissionRunning) and unattended_failed_ids:
        anomalies.append(
            RuntimeAnomaly(
                code="failed_task_without_attention", task_ids=unattended_failed_ids
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
            task_ids=running_ids,
            reason_code="malformed_attempt",
        )
    elif completion_ids:
        derived = "recovery_ready"
        decision = ShadowSchedulerDecision(
            action="reconcile_completed_attempt",
            task_ids=running_ids,
            reason_code="handoff_available",
        )
    elif stale_ids or missing_attempt_ids:
        derived = "stale_running_candidate"
        decision = ShadowSchedulerDecision(
            action="inspect_stale_attempt",
            task_ids=running_ids,
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
            by_type=_canonical_counts(
                Task,
                "type",
                type_counts,
                expected_total=len(task_rows),
            ),
            by_status=_canonical_counts(
                TaskStateEntry,
                "status",
                status_counts,
                expected_total=len(task_rows),
            ),
        ),
        assertion_counts=AssertionCountSummary(
            by_status=_canonical_counts(
                ContractStateEntry,
                "status",
                assertion_status_counts,
                expected_total=len(contract_ids),
            )
        ),
        attention_counts=AttentionCountSummary(
            by_kind=_canonical_counts(
                AttentionItemInternal,
                "kind",
                attention_counts,
                expected_total=len(attention),
            )
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
    for _attempt in range(CAPTURE_ATTEMPTS):
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
            after_identity = _current_identity_generation(
                project_root,
                expected=before,
            )
        except RuntimeObservationError as error:
            if error.code == "snapshot_changed":
                continue
            if error.code not in {"malformed_cursor", "non_current_mission"} or before is None:
                raise
            try:
                stable = _current_identity_generation(
                    project_root,
                    expected=before,
                )
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
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeObservationError("unsafe_project_path")
    entries: list[os.DirEntry[str]] = []
    try:
        iterator = os.scandir(root)
        with iterator:
            for entry in iterator:
                entries.append(entry)
                if len(entries) > MAX_CAPTURE_FILES:
                    raise RuntimeObservationError("unsafe_project_path")
    except RuntimeObservationError:
        raise
    except OSError as exc:
        raise RuntimeObservationError("unsafe_project_path") from exc
    entries.sort(key=lambda item: os.fsencode(item.name))
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
    if len(value) <= MAX_DISPLAY_ID_CHARS and _DISPLAY_SAFE.fullmatch(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    safe_prefix = "".join(
        character if _DISPLAY_SAFE.fullmatch(character) else "_"
        for character in value
    )[:_DISPLAY_PREFIX_CHARS]
    return f"{safe_prefix}~{digest}"


def _fmt_seconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}s"


def _append_bounded_tokens(lines: list[str], tokens: tuple[str, ...]) -> None:
    current = ""
    for token in tokens:
        if len(token) > MAX_RENDER_LINE_CHARS:
            raise RuntimeObservationError("malformed_cursor")
        candidate = token if not current else f"{current} {token}"
        if len(candidate) <= MAX_RENDER_LINE_CHARS:
            current = candidate
        else:
            lines.append(current)
            current = token
    if current:
        lines.append(current)


def _append_anomaly(lines: list[str], anomaly: RuntimeAnomaly) -> None:
    display_ids = tuple(_display_id(value) for value in anomaly.task_ids)
    compact = f"anomaly={anomaly.code} tasks={','.join(display_ids) or '-'}"
    if len(compact) <= MAX_RENDER_LINE_CHARS:
        lines.append(compact)
        return
    total = len(display_ids)
    lines.append(f"anomaly={anomaly.code} tasks={total} omitted=0")
    for index, display_id in enumerate(display_ids, start=1):
        lines.append(
            f"anomaly_task={anomaly.code} index={index}/{total} task={display_id}"
        )


def render_runtime_observation(observation: RuntimeObservation) -> str:
    """Render a compact bounded operator view with no free-form cursor text."""

    lines: list[str] = []
    _append_bounded_tokens(
        lines,
        (
            f"project={_display_id(observation.project_id)}",
            f"mission={_display_id(observation.mission_id or '-')}",
            f"persisted={observation.persisted_state}",
            f"derived={observation.derived_state}",
            f"next={observation.shadow_scheduler.action}",
        ),
    )
    lines.extend(
        [
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
    )
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
        _append_anomaly(lines, anomaly)
    if any(len(line) > MAX_RENDER_LINE_CHARS for line in lines):
        raise RuntimeObservationError("malformed_cursor")
    return "\n".join(lines) + "\n"


def render_runtime_collection(collection: RuntimeObservationCollection) -> str:
    project_lines: list[str] = []
    rendered_projects = 0
    failures = list(collection.failures)
    for project in collection.projects:
        try:
            rendered = render_runtime_observation(project)
        except RuntimeObservationError as error:
            failures.append(ObservationFailure(code=error.code, project_id=project.project_id))
            continue
        project_lines.extend(rendered.rstrip("\n").splitlines())
        rendered_projects += 1
    failures.sort(key=lambda item: (item.project_id or "", item.entry_ref or "", item.code))
    lines = [
        f"projects={rendered_projects} failures={len(failures)}",
        f"schema=1 observed_at={collection.observed_at}",
        *project_lines,
    ]
    for failure in failures:
        reference = failure.project_id or failure.entry_ref or "-"
        lines.append(
            f"failure={failure.code} ref={_display_id(reference)}"
        )
    if any(len(line) > MAX_RENDER_LINE_CHARS for line in lines):
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
