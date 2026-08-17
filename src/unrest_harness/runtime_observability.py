"""Read-only schema-v2 runtime status for operators.

The observer captures existing cursors without importing or invoking runtime
authority. File ages are diagnostics only: they are not heartbeats, recovery
signals, or completion estimates.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, ROUND_HALF_EVEN
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
    ValidateHandoff,
    WorkHandoff,
)
from .storage import ProjectStore


DerivedRuntimeState = Literal[
    "draft",
    "planning",
    "active",
    "attention",
    "quiescent",
    "terminal",
    "inconsistent",
]
ObservationFailureCode = Literal[
    "invalid_project_id",
    "malformed_cursor",
    "project_not_found",
    "snapshot_changed",
    "unsafe_cursor",
    "unsafe_project_path",
]
StatusCode = Literal[
    "mission_cursor_mismatch",
    "failed_task_without_attention",
    "running_without_attempt",
    "malformed_attempt",
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

PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MISSION_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
_STATE_ADAPTER: TypeAdapter[ProjectState] = TypeAdapter(ProjectState)
MAX_DISPLAY_ID_CHARS = 80
_DISPLAY_DIGEST_CHARS = 16
_DISPLAY_PREFIX_CHARS = MAX_DISPLAY_ID_CHARS - _DISPLAY_DIGEST_CHARS - 1
_DISPLAY_SAFE = re.compile(r"^[A-Za-z0-9._:-]+$")


class RuntimeObservationError(RuntimeError):
    """A closed, value-free observation failure safe to show an operator."""

    def __init__(self, code: ObservationFailureCode) -> None:
        super().__init__(code)
        self.code = code


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RuntimeObservation(_FrozenModel):
    schema_version: Literal[2] = 2
    observed_at: str
    project_id: str
    mission_id: str | None
    persisted_state: PersistedRuntimeState
    derived_state: DerivedRuntimeState
    attention_count: int = Field(ge=0)
    running_task_ids: tuple[str, ...] = Field(default_factory=tuple)
    runnable_task_ids: tuple[str, ...] = Field(default_factory=tuple)
    failed_task_ids: tuple[str, ...] = Field(default_factory=tuple)
    last_runtime_change_age_seconds: float | None
    codes: tuple[StatusCode, ...] = Field(default_factory=tuple)


class ObservationFailure(_FrozenModel):
    project_id: str | None
    code: ObservationFailureCode


class RuntimeObservationCollection(_FrozenModel):
    schema_version: Literal[2] = 2
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
    return PROJECT_ID_PATTERN.fullmatch(project_id) is not None


def _validate_mission_id(mission_id: str | None) -> None:
    if mission_id is not None and MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        raise RuntimeObservationError("malformed_cursor")


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _datetime_ns(value: datetime) -> int:
    utc = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc - epoch
    return (
        delta.days * 86_400_000_000_000
        + delta.seconds * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _age_seconds(now: datetime, mtime_ns: int | None) -> float | None:
    if mtime_ns is None:
        return None
    difference = max(0, _datetime_ns(now) - mtime_ns)
    rounded = (Decimal(difference) / Decimal(1_000_000_000)).quantize(
        Decimal("0.001"),
        rounding=ROUND_HALF_EVEN,
    )
    return float(rounded)


def _parse_spawn_ts(value: str | None) -> datetime | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
        r"[0-9]{2}-[0-9]{2}-[0-9]{2}Z)(?:-[0-9]{4})?",
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
        with os.scandir(path) as iterator:
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


def _task_capture_needs(
    files: list[_CapturedFile], mission_id: str
) -> tuple[set[str], set[str]]:
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


def _capture_inputs(project_root: Path) -> tuple[_CapturedFile, ...]:
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

    mission_id = _selector_mission(captured)
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
    attempts_dir = mission_runtime / "attempts"
    attempts: list[tuple[str, str | None, Path, os.stat_result]] = []
    for entry in _scan_directory(attempts_dir, project_root, optional=True):
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if path.suffix != ".json":
            continue
        task_id: str | None = None
        if "__" in path.stem:
            _spawn_ts, candidate = path.stem.split("__", 1)
            if candidate in task_ids:
                task_id = candidate
        attempts.append((path.stem, task_id, path, info))
    latest_running_paths: set[Path] = set()
    for task_id in running_ids:
        matching = sorted(
            (item for item in attempts if item[1] == task_id),
            key=lambda item: os.fsencode(item[0]),
        )
        if matching:
            latest_running_paths.add(matching[-1][2])
    for _stem, _task_id, path, info in sorted(
        attempts, key=lambda item: os.fsencode(item[0])
    ):
        if path in latest_running_paths:
            source = _capture_file(path, project_root, budget, expected=info)
            assert source is not None
            captured.append(source)
        else:
            captured.append(_capture_metadata(path, project_root, budget, expected=info))

    terminal_dir = mission_runtime / "terminal-reviews"
    for entry in _scan_directory(terminal_dir, project_root, optional=True):
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise _cursor_error(exc) from exc
        if stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeObservationError("unsafe_cursor")
        if path.suffix == ".json":
            captured.append(_capture_metadata(path, project_root, budget, expected=info))

    return tuple(sorted(captured, key=lambda item: item.relative_path))


def _identity_generation(
    files: tuple[_CapturedFile, ...],
) -> tuple[tuple[str, int, int, int, int], ...]:
    return tuple(
        (item.relative_path, item.device, item.inode, item.size, item.mtime_ns)
        for item in files
    )


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


def _parse_state(sources: dict[str, _CapturedFile]) -> ProjectState | None:
    source = sources.get(".unrest-runtime/state.json")
    if source is None:
        return None
    if source.data is None:
        raise RuntimeObservationError("malformed_cursor")
    try:
        return _STATE_ADAPTER.validate_json(source.data)
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeObservationError("malformed_cursor") from exc


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


def _attempt_is_malformed(source: _CapturedFile) -> bool:
    if source.data is None:
        return False
    try:
        data = json.loads(source.data)
        if isinstance(data, dict) and ("items" in data or "passed" in data):
            ValidateHandoff.model_validate(data)
        else:
            WorkHandoff.model_validate(data)
    except (ValidationError, ValueError, json.JSONDecodeError):
        return True
    return False


def _display_id(value: str) -> str:
    if len(value) <= MAX_DISPLAY_ID_CHARS and _DISPLAY_SAFE.fullmatch(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
    safe_prefix = "".join(
        character if _DISPLAY_SAFE.fullmatch(character) else "_"
        for character in value
    )[:_DISPLAY_PREFIX_CHARS]
    return f"{safe_prefix}~{digest}"


def _display_ids(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted({_display_id(value) for value in values}, key=os.fsencode))


def _runnable_tasks(task_list: TaskList, task_state: TaskStateFile) -> list[Task]:
    return [
        task
        for task in task_list.tasks
        if task.type != "gate"
        and task_state.status_of(task.id) == "pending"
        and all(task_state.status_of(dep) == "cleared" for dep in task.depends_on)
    ]


def _observation_from_capture(
    project_id: str,
    sources: tuple[_CapturedFile, ...],
    *,
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
    _validate_mission_id(record.current_mission_id)
    state = _parse_state(source_by_path)
    persisted_state: PersistedRuntimeState = state.state if state is not None else "draft"
    selected_mission = record.current_mission_id
    codes: set[StatusCode] = set()
    inconsistent = False
    if isinstance(state, (MissionRunning, MissionPlanning)):
        _validate_mission_id(state.mission_id)
        selected_mission = state.mission_id
        if record.current_mission_id != state.mission_id:
            codes.add("mission_cursor_mismatch")
            inconsistent = True

    task_list = TaskList()
    task_state = TaskStateFile()
    if selected_mission is not None:
        prefix = f".unrest-runtime/missions/{selected_mission}"
        tasks_key = f"{prefix}/tasks.json"
        if tasks_key in source_by_path:
            parsed_tasks = _parse_json_model(source_by_path, tasks_key, TaskList)
            assert isinstance(parsed_tasks, TaskList)
            task_list = parsed_tasks
        elif isinstance(state, MissionRunning):
            raise RuntimeObservationError("malformed_cursor")
        parsed_task_state = _parse_json_model(
            source_by_path,
            f"{prefix}/task-state.json",
            TaskStateFile,
            default=TaskStateFile(),
        )
        assert isinstance(parsed_task_state, TaskStateFile)
        task_state = parsed_task_state

    task_ids = {task.id for task in task_list.tasks}
    identifiers = [
        identifier
        for task in task_list.tasks
        for identifier in (task.id, *task.depends_on)
    ]
    identifiers.extend(task_state.tasks)
    if (
        any(
            len(identifier) > 128 or TASK_ID_REGEX.fullmatch(identifier) is None
            for identifier in identifiers
        )
        or set(task_state.tasks) - task_ids
    ):
        raise RuntimeObservationError("malformed_cursor")

    parsed_attention = _parse_json_model(
        source_by_path,
        ".unrest-runtime/attention.json",
        AttentionFile,
        default=AttentionFile(),
    )
    assert isinstance(parsed_attention, AttentionFile)
    attention = parsed_attention.items

    running_raw = [
        task.id for task in task_list.tasks if task_state.status_of(task.id) == "running"
    ]
    failed_raw = [
        task.id for task in task_list.tasks if task_state.status_of(task.id) == "failed"
    ]
    runnable_raw = [task.id for task in _runnable_tasks(task_list, task_state)]

    for task_id in running_raw:
        entry = task_state.tasks.get(task_id)
        cursor_attempt_id = entry.last_attempt if entry is not None else None
        attempts = _attempt_sources(source_by_path, selected_mission or "", task_id)
        latest_id, latest_source = attempts[-1] if attempts else (None, None)
        started_at = _parse_spawn_ts(cursor_attempt_id)
        if cursor_attempt_id is None:
            codes.add("running_without_attempt")
        elif started_at is None:
            codes.add("malformed_attempt")
            inconsistent = True
        if latest_id is not None and _parse_spawn_ts(latest_id) is None:
            codes.add("malformed_attempt")
            inconsistent = True
        if latest_source is not None and _attempt_is_malformed(latest_source):
            codes.add("malformed_attempt")
            inconsistent = True
        if (
            started_at is not None
            and (observed_at - started_at).total_seconds() >= stale_after_seconds
        ):
            codes.add("stale_running_candidate")

    attended_failed_ids = {
        item.node_id
        for item in attention
        if item.mission_id == selected_mission and item.node_id in failed_raw
    }
    if isinstance(state, (MissionRunning, AttentionNeeded)) and any(
        task_id not in attended_failed_ids for task_id in failed_raw
    ):
        codes.add("failed_task_without_attention")

    if inconsistent:
        derived: DerivedRuntimeState = "inconsistent"
    elif isinstance(state, (Done, Failed, Aborted)):
        derived = "terminal"
    elif state is None or isinstance(state, Draft):
        derived = "draft"
    elif isinstance(state, MissionPlanning):
        derived = "planning"
    elif attention or isinstance(state, AttentionNeeded):
        derived = "attention"
    elif running_raw or runnable_raw:
        derived = "active"
    else:
        derived = "quiescent"

    age_paths = {
        ".unrest-runtime/state.json",
        ".unrest-runtime/attention.json",
    }
    age_prefixes: tuple[str, ...]
    if selected_mission is not None:
        prefix = f".unrest-runtime/missions/{selected_mission}"
        age_paths.update(
            {
                f"{prefix}/task-state.json",
                f"{prefix}/contract-state.json",
            }
        )
        age_prefixes = (
            f"{prefix}/attempts/",
            f"{prefix}/terminal-reviews/",
        )
    else:
        age_prefixes = ()
    newest_mtime = max(
        (
            item.mtime_ns
            for item in sources
            if item.relative_path in age_paths
            or any(item.relative_path.startswith(prefix) for prefix in age_prefixes)
        ),
        default=None,
    )
    return RuntimeObservation(
        observed_at=_utc_text(observed_at),
        project_id=project_id,
        mission_id=selected_mission,
        persisted_state=persisted_state,
        derived_state=derived,
        attention_count=len(attention),
        running_task_ids=_display_ids(running_raw),
        runnable_task_ids=_display_ids(runnable_raw),
        failed_task_ids=_display_ids(failed_raw),
        last_runtime_change_age_seconds=_age_seconds(observed_at, newest_mtime),
        codes=tuple(sorted(codes)),
    )


def observe_project_runtime(
    store: ProjectStore,
    project_id: str,
    *,
    stale_after_seconds: int = 3600,
    now: datetime | None = None,
) -> RuntimeObservation:
    """Return one coherent schema-v2 snapshot without changing project state."""

    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
    project_root = _validated_project_root(store, project_id)
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    for _attempt in range(CAPTURE_ATTEMPTS):
        before: tuple[_CapturedFile, ...] | None = None
        try:
            before = _capture_inputs(project_root)
            observation = _observation_from_capture(
                project_id,
                before,
                stale_after_seconds=stale_after_seconds,
                observed_at=observed_at,
            )
            after = _capture_inputs(project_root)
        except RuntimeObservationError as error:
            if error.code == "snapshot_changed":
                continue
            if error.code == "malformed_cursor" and before is not None:
                try:
                    stable = _capture_inputs(project_root)
                except RuntimeObservationError as recapture_error:
                    if recapture_error.code == "snapshot_changed":
                        continue
                    raise
                if _identity_generation(before) != _identity_generation(stable):
                    continue
            raise
        if _identity_generation(before) == _identity_generation(after):
            return observation
    raise RuntimeObservationError("snapshot_changed")


def _failure_project_id(value: str) -> str:
    return _display_id(value)


def observe_all_projects_runtime(
    store: ProjectStore,
    *,
    stale_after_seconds: int = 3600,
    now: datetime | None = None,
) -> RuntimeObservationCollection:
    """Observe immediate project entries while isolating closed failures."""

    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
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
        with os.scandir(root) as iterator:
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
    for entry in entries:
        path = Path(entry.path)
        try:
            info = path.lstat()
        except OSError:
            failures.append(
                ObservationFailure(
                    project_id=_failure_project_id(entry.name),
                    code="unsafe_project_path",
                )
            )
            continue
        if stat.S_ISREG(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            failures.append(
                ObservationFailure(
                    project_id=_failure_project_id(entry.name),
                    code="unsafe_project_path",
                )
            )
            continue
        if not validate_project_id(entry.name):
            failures.append(
                ObservationFailure(
                    project_id=_failure_project_id(entry.name),
                    code="invalid_project_id",
                )
            )
            continue
        try:
            projects.append(
                observe_project_runtime(
                    store,
                    entry.name,
                    stale_after_seconds=stale_after_seconds,
                    now=observed_at,
                )
            )
        except RuntimeObservationError as error:
            failures.append(ObservationFailure(project_id=entry.name, code=error.code))

    projects.sort(key=lambda item: os.fsencode(item.project_id))
    failures.sort(key=lambda item: (os.fsencode(item.project_id or ""), item.code))
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
    )


def _text_value(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, tuple):
        return ",".join(str(item) for item in value) or "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def render_runtime_observation(observation: RuntimeObservation) -> str:
    """Render the project fields in their schema order on one bounded line."""

    fields = observation.model_dump(mode="python")
    return " ".join(f"{key}={_text_value(value)}" for key, value in fields.items()) + "\n"


def render_runtime_collection(collection: RuntimeObservationCollection) -> str:
    lines = [render_runtime_observation(project).rstrip("\n") for project in collection.projects]
    lines.extend(
        f"failure project={failure.project_id or '-'} code={failure.code}"
        for failure in collection.failures
    )
    return "\n".join(lines) + ("\n" if lines else "")


__all__ = [
    "ObservationFailure",
    "RuntimeObservation",
    "RuntimeObservationCollection",
    "RuntimeObservationError",
    "observe_all_projects_runtime",
    "observe_project_runtime",
    "observation_json",
    "render_runtime_collection",
    "render_runtime_observation",
    "validate_project_id",
]
