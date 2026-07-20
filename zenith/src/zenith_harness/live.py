"""Read-only Zenith live project discovery and snapshot helpers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import HarnessConfig
from .models import (
    ContractStateFile,
    ProjectRecord,
    ProjectState,
    TaskList,
    TaskStateFile,
    ValidateHandoff,
    WorkHandoff,
)
from .storage import AttemptRecord, ProjectStore, utc_now_iso

TERMINAL_PROJECT_STATES = {"done", "failed", "aborted"}
TASK_STATUSES = ("pending", "running", "cleared", "failed", "superseded")
ASSERTION_STATUSES = ("pending", "passed", "failed")
TASK_TYPES = ("work", "validate", "gate")


class ProjectSelectionError(ValueError):
    """Raised when a project pin cannot be resolved to one project."""


@dataclass(frozen=True)
class RecentFile:
    path: str
    name: str
    modified_at: str
    mtime: float
    text: str | None
    truncated: bool


@dataclass(frozen=True)
class RecentAttempt:
    path: str
    name: str
    modified_at: str
    mtime: float
    spawn_ts: str
    node_id: str
    handoff_type: str | None
    done: bool | None
    passed: bool | None
    request_attention: bool | None
    report_path: str | None
    text: str
    truncated: bool


@dataclass(frozen=True)
class TaskSnapshot:
    id: str
    type: str
    status: str
    targets: list[str]
    depends_on: list[str]
    skill: str | None
    body: str


@dataclass(frozen=True)
class AttentionSnapshot:
    id: str
    report: str
    kind: str | None
    mission_id: str | None
    node_id: str | None


@dataclass(frozen=True)
class MissionSnapshot:
    id: str
    state: str
    task_count: int
    task_type_counts: dict[str, int]
    task_state_counts: dict[str, int]
    contract_count: int
    contract_state_counts: dict[str, int]
    tasks: list[TaskSnapshot]
    contract_ids: list[str]
    recent_attempts: list[RecentAttempt]
    recent_evidence: list[RecentFile]
    errors: list[str]


@dataclass(frozen=True)
class ProjectSnapshot:
    id: str
    project_root: str
    workspace: str
    created_at: str
    state: str
    current_mission_id: str | None
    last_activity_at: str | None
    last_activity_path: str | None
    last_activity_mtime: float
    attention_count: int
    attention_items: list[AttentionSnapshot]
    mission: MissionSnapshot | None
    recent_decisions: list[RecentFile]
    errors: list[str]


@dataclass(frozen=True)
class LiveSnapshot:
    generated_at: str
    projects_dir: str
    selected_project_id: str | None
    project_count: int
    projects: list[ProjectSnapshot]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_live_snapshot(
    *,
    config: HarnessConfig | None = None,
    projects_dir: str | Path | None = None,
    project: str | None = None,
    recent_limit: int = 5,
) -> LiveSnapshot:
    """Build a read-only snapshot of all discoverable Zenith projects.

    `projects_dir` overrides the configured project bucket directory. `project`
    is an optional focus pin and may be a project id, bucket path, path inside a
    project bucket, or a workspace path when that workspace maps to one project.
    """
    config = config or HarnessConfig.discover()
    if projects_dir is not None:
        config = replace(
            config,
            projects_dir=Path(projects_dir).expanduser().resolve(),
        )
    store = ProjectStore(config)
    records, discovery_errors = _discover_project_records(store)
    projects = [
        _build_project_snapshot(store, record, recent_limit=recent_limit)
        for record in records
    ]
    projects.sort(key=lambda item: (item.last_activity_mtime, item.created_at, item.id), reverse=True)
    selected = _select_project(projects, project)
    return LiveSnapshot(
        generated_at=utc_now_iso(),
        projects_dir=str(config.projects_dir),
        selected_project_id=selected.id if selected else None,
        project_count=len(projects),
        projects=projects,
        errors=discovery_errors,
    )


def render_live_snapshot(snapshot: LiveSnapshot) -> str:
    """Render a compact human-readable live overview."""
    lines = [
        f"Zenith live snapshot: {snapshot.generated_at}",
        f"Projects dir: {snapshot.projects_dir}",
    ]
    if snapshot.errors:
        lines.append("Project discovery errors:")
        lines.extend(f"  {error}" for error in snapshot.errors)
    if not snapshot.projects:
        lines.append("No Zenith projects found.")
        return "\n".join(lines)

    selected_id = snapshot.selected_project_id or "none"
    selected = next((p for p in snapshot.projects if p.id == snapshot.selected_project_id), None)
    if selected is None:
        lines.append(f"Selected: {selected_id}")
    else:
        lines.append(
            "Selected: "
            f"{selected.id} state={selected.state} "
            f"mission={selected.current_mission_id or '-'} "
            f"last_activity={selected.last_activity_at or '-'}"
        )
    lines.append(f"Projects: {snapshot.project_count}")

    for project in snapshot.projects:
        marker = "*" if project.id == snapshot.selected_project_id else "-"
        mission = project.mission
        lines.append(
            f"{marker} {project.id} state={project.state} "
            f"mission={project.current_mission_id or '-'} "
            f"attention={project.attention_count} "
            f"last_activity={project.last_activity_at or '-'}"
        )
        lines.append(f"  workspace: {project.workspace}")
        if project.errors:
            lines.append("  read errors:")
            lines.extend(f"    {error}" for error in project.errors)
        if project.attention_items:
            lines.append("  attention:")
            for item in project.attention_items:
                context = _attention_context(item)
                report = _truncate(_one_line(item.report), 180)
                lines.append(f"    {item.id}{context}: {report}")
        if mission is None:
            lines.append("  tasks: total=0")
            lines.append("  contracts: total=0")
            continue
        lines.append(
            "  tasks: "
            f"total={mission.task_count} "
            f"types={_format_counts(mission.task_type_counts)} "
            f"states={_format_counts(mission.task_state_counts)}"
        )
        lines.append(
            "  contracts: "
            f"total={mission.contract_count} "
            f"states={_format_counts(mission.contract_state_counts)}"
        )
        recent = _recent_activity_labels(project)
        if recent:
            lines.append(f"  recent: {'; '.join(recent)}")
        if mission.errors:
            lines.append("  mission read errors:")
            lines.extend(f"    {error}" for error in mission.errors)
    return "\n".join(lines)


def _discover_project_records(
    store: ProjectStore,
) -> tuple[list[ProjectRecord], list[str]]:
    """Discover records without hiding malformed project buckets."""
    projects_dir = store.config.projects_dir
    if not projects_dir.exists():
        return [], []
    records: list[ProjectRecord] = []
    errors: list[str] = []
    for entry in sorted(projects_dir.iterdir()):
        project_json = entry / ".zenith-runtime" / "project.json"
        if not project_json.exists():
            continue
        try:
            records.append(
                ProjectRecord.model_validate_json(
                    project_json.read_text(encoding="utf-8")
                )
            )
        except Exception as exc:  # noqa: BLE001 - observation must report all read failures
            errors.append(f"{entry.name}: project record: {type(exc).__name__}: {exc}")
    records.sort(key=lambda record: record.created_at, reverse=True)
    return records, errors


def _build_project_snapshot(
    store: ProjectStore,
    record: ProjectRecord,
    *,
    recent_limit: int,
) -> ProjectSnapshot:
    errors: list[str] = []
    state = _safe_call(
        lambda: store.load_state(record.id), errors=errors, label="project state"
    )
    state_name = _state_name(state)
    current_mission_id = record.current_mission_id or _mission_id_from_state(state)
    if current_mission_id is None:
        missions = _safe_call(
            lambda: store.list_missions(record.id),
            default=[],
            errors=errors,
            label="mission list",
        )
        current_mission_id = missions[-1] if missions else None

    mission = None
    if current_mission_id is not None:
        mission = _build_mission_snapshot(
            store,
            record.id,
            current_mission_id,
            state=state_name,
            recent_limit=recent_limit,
        )

    attention_items = _safe_call(
        lambda: store.load_attention(record.id),
        default=[],
        errors=errors,
        label="attention",
    )
    attention_snapshots = [_attention_snapshot(item) for item in attention_items]
    project_root = store.bucket_root(record.id)
    activity_mtime, activity_path = _latest_file(project_root)
    return ProjectSnapshot(
        id=record.id,
        project_root=str(project_root),
        workspace=record.workspace_dir,
        created_at=record.created_at,
        state=state_name,
        current_mission_id=current_mission_id,
        last_activity_at=_iso_from_mtime(activity_mtime),
        last_activity_path=_relative_path(activity_path, project_root) if activity_path else None,
        last_activity_mtime=activity_mtime,
        attention_count=len(attention_items),
        attention_items=attention_snapshots,
        mission=mission,
        recent_decisions=_recent_files(
            store.decisions_dir(record.id),
            project_root=project_root,
            limit=recent_limit,
        ),
        errors=errors,
    )


def _build_mission_snapshot(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    *,
    state: str,
    recent_limit: int,
) -> MissionSnapshot:
    project_root = store.bucket_root(project_id)
    errors: list[str] = []
    task_list = _safe_call(
        lambda: store.load_task_list(project_id, mission_id),
        errors=errors,
        label="task list",
    )
    task_state = _safe_call(
        lambda: store.load_task_state(project_id, mission_id),
        default=TaskStateFile(),
        errors=errors,
        label="task state",
    )
    contract_ids = _safe_call(
        lambda: store.list_contract_assertions(project_id, mission_id),
        default=[],
        errors=errors,
        label="contract inventory",
    )
    contract_state = _safe_call(
        lambda: store.load_contract_state(project_id, mission_id),
        default=ContractStateFile(),
        errors=errors,
        label="contract state",
    )

    tasks = _task_snapshots(task_list, task_state)
    return MissionSnapshot(
        id=mission_id,
        state=state,
        task_count=len(tasks),
        task_type_counts=_task_type_counts(task_list),
        task_state_counts=_task_state_counts(task_list, task_state),
        contract_count=len(contract_ids),
        contract_state_counts=_contract_state_counts(contract_ids, contract_state),
        tasks=tasks,
        contract_ids=list(contract_ids),
        recent_attempts=_recent_attempts(
            store,
            project_id,
            mission_id,
            project_root=project_root,
            limit=recent_limit,
        ),
        recent_evidence=_recent_files(
            store.mission_dir(project_id, mission_id) / "evidence",
            project_root=project_root,
            limit=recent_limit,
        ),
        errors=errors,
    )


def _select_project(
    projects: list[ProjectSnapshot],
    project_pin: str | None,
) -> ProjectSnapshot | None:
    if project_pin:
        return _resolve_project_pin(projects, project_pin)
    if not projects:
        return None
    active = [p for p in projects if p.state not in TERMINAL_PROJECT_STATES]
    candidates = active or projects
    return max(candidates, key=lambda item: (item.last_activity_mtime, item.created_at, item.id))


def _resolve_project_pin(projects: list[ProjectSnapshot], project_pin: str) -> ProjectSnapshot:
    for project in projects:
        if project.id == project_pin:
            return project

    raw = Path(project_pin).expanduser()
    candidate = raw.resolve() if raw.exists() else raw.resolve(strict=False)
    bucket_matches = [
        project
        for project in projects
        if _matches_project_bucket_path(candidate, Path(project.project_root))
    ]
    if len(bucket_matches) == 1:
        return bucket_matches[0]
    if len(bucket_matches) > 1:
        ids = ", ".join(project.id for project in bucket_matches)
        raise ProjectSelectionError(f"project path is ambiguous: {project_pin} ({ids})")

    workspace_matches = [
        project
        for project in projects
        if candidate == Path(project.workspace).expanduser().resolve(strict=False)
    ]
    if len(workspace_matches) == 1:
        return workspace_matches[0]
    if len(workspace_matches) > 1:
        ids = ", ".join(project.id for project in workspace_matches)
        raise ProjectSelectionError(
            f"workspace path matches multiple Zenith projects: {project_pin} ({ids})"
        )

    raise ProjectSelectionError(f"project not found: {project_pin}")


def _matches_project_bucket_path(candidate: Path, project_root: Path) -> bool:
    root = project_root.expanduser().resolve(strict=False)
    if candidate == root:
        return True
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _task_snapshots(
    task_list: TaskList | None,
    task_state: TaskStateFile,
) -> list[TaskSnapshot]:
    if task_list is None:
        return []
    return [
        TaskSnapshot(
            id=task.id,
            type=task.type,
            status=task_state.status_of(task.id),
            targets=list(task.targets),
            depends_on=list(task.depends_on),
            skill=task.skill,
            body=task.body,
        )
        for task in task_list.tasks
    ]


def _attention_snapshot(item: Any) -> AttentionSnapshot:
    return AttentionSnapshot(
        id=str(getattr(item, "id", "")),
        report=str(getattr(item, "report", "")),
        kind=getattr(item, "kind", None),
        mission_id=getattr(item, "mission_id", None),
        node_id=getattr(item, "node_id", None),
    )


def _task_type_counts(task_list: TaskList | None) -> dict[str, int]:
    counts = {status: 0 for status in TASK_TYPES}
    if task_list is None:
        return counts
    for task in task_list.tasks:
        counts[task.type] = counts.get(task.type, 0) + 1
    return counts


def _task_state_counts(
    task_list: TaskList | None,
    task_state: TaskStateFile,
) -> dict[str, int]:
    counts = {status: 0 for status in TASK_STATUSES}
    seen: set[str] = set()
    if task_list is not None:
        for task in task_list.tasks:
            seen.add(task.id)
            status = task_state.status_of(task.id)
            counts[status] = counts.get(status, 0) + 1
    for task_id, entry in task_state.tasks.items():
        if task_id in seen:
            continue
        counts[entry.status] = counts.get(entry.status, 0) + 1
    return counts


def _contract_state_counts(
    contract_ids: list[str],
    contract_state: ContractStateFile,
) -> dict[str, int]:
    counts = {status: 0 for status in ASSERTION_STATUSES}
    seen = set(contract_ids)
    for assertion_id in sorted(seen):
        entry = contract_state.items.get(assertion_id)
        status = entry.status if entry else "pending"
        counts[status] = counts.get(status, 0) + 1
    for assertion_id, entry in contract_state.items.items():
        if assertion_id in seen:
            continue
        counts[entry.status] = counts.get(entry.status, 0) + 1
    return counts


def _recent_attempts(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    *,
    project_root: Path,
    limit: int,
) -> list[RecentAttempt]:
    records = _safe_call(
        lambda: store.list_attempts(project_id, mission_id),
        default=[],
    )
    records = sorted(records, key=lambda record: _path_mtime(record.path), reverse=True)
    return [
        _attempt_summary(store, project_id, mission_id, record, project_root=project_root)
        for record in records[:limit]
    ]


def _attempt_summary(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    record: AttemptRecord,
    *,
    project_root: Path,
) -> RecentAttempt:
    handoff = _safe_call(
        lambda: store.read_attempt(project_id, mission_id, record.spawn_ts, record.node_id)
    )
    handoff_type = None
    done = None
    passed = None
    request_attention = None
    if isinstance(handoff, WorkHandoff):
        handoff_type = "work"
        done = handoff.done
        request_attention = handoff.request_attention
    elif isinstance(handoff, ValidateHandoff):
        handoff_type = "validate"
        done = handoff.done
        passed = handoff.passed
        request_attention = handoff.request_attention
    mtime = _path_mtime(record.path)
    report_path = store.attempt_report_path(project_id, mission_id, record.spawn_ts, record.node_id)
    if report_path.exists():
        text, truncated = _read_text(report_path)
        display_report_path = _relative_path(report_path, project_root)
    elif handoff is not None:
        text = str(getattr(handoff, "report", ""))
        truncated = False
        display_report_path = None
    else:
        text = ""
        truncated = False
        display_report_path = None
    return RecentAttempt(
        path=_relative_path(record.path, project_root),
        name=record.path.name,
        modified_at=_iso_from_mtime(mtime),
        mtime=mtime,
        spawn_ts=record.spawn_ts,
        node_id=record.node_id,
        handoff_type=handoff_type,
        done=done,
        passed=passed,
        request_attention=request_attention,
        report_path=display_report_path,
        text=text or "",
        truncated=truncated,
    )


def _recent_files(
    directory: Path,
    *,
    project_root: Path,
    limit: int,
) -> list[RecentFile]:
    if not directory.exists() or not directory.is_dir():
        return []
    files = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        mtime = _path_mtime(path)
        text, truncated = _read_text(path)
        files.append(
            RecentFile(
                path=_relative_path(path, project_root),
                name=path.name,
                modified_at=_iso_from_mtime(mtime),
                mtime=mtime,
                text=text,
                truncated=truncated,
            )
        )
    files.sort(key=lambda item: item.mtime, reverse=True)
    return files[:limit]


def _latest_file(root: Path) -> tuple[float, Path | None]:
    if not root.exists():
        return 0.0, None
    latest_mtime = 0.0
    latest_path = None
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        mtime = _path_mtime(path)
        if mtime > latest_mtime:
            latest_mtime = mtime
            latest_path = path
    return latest_mtime, latest_path


def _safe_call(func, default=None, *, errors: list[str] | None = None, label: str = "read"):
    try:
        return func()
    except Exception as exc:
        if errors is not None:
            errors.append(f"{label}: {type(exc).__name__}: {_one_line(str(exc))}")
        return default


def _path_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _read_text(path: Path, limit: int = 12000) -> tuple[str | None, bool]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        return None, False
    if b"\x00" in raw[: min(len(raw), 1024)]:
        return None, False
    truncated = len(raw) > limit
    raw = raw[:limit]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    return text, truncated


def _iso_from_mtime(mtime: float) -> str:
    if mtime <= 0:
        return ""
    return datetime.fromtimestamp(mtime, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_name(state: ProjectState | None) -> str:
    return getattr(state, "state", "draft")


def _mission_id_from_state(state: ProjectState | None) -> str | None:
    value = getattr(state, "mission_id", None)
    return value if isinstance(value, str) else None


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def _attention_context(item: AttentionSnapshot) -> str:
    parts = []
    if item.kind:
        parts.append(item.kind)
    if item.mission_id:
        parts.append(f"mission={item.mission_id}")
    if item.node_id:
        parts.append(f"node={item.node_id}")
    return f" ({', '.join(parts)})" if parts else ""


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)].rstrip() + "..."


def _recent_activity_labels(project: ProjectSnapshot) -> list[str]:
    labels = []
    if project.mission and project.mission.recent_attempts:
        labels.append(f"attempt {project.mission.recent_attempts[0].name}")
    if project.mission and project.mission.recent_evidence:
        labels.append(f"evidence {project.mission.recent_evidence[0].name}")
    if project.recent_decisions:
        labels.append(f"decision {project.recent_decisions[0].name}")
    return labels
