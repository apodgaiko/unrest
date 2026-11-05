"""Experimental read-only preflight report for one explicit task.

The report projects facts from the bytes of one existing runtime cursor capture.
It never classifies continuation state: ``assessment`` is always
``unavailable`` in schema version 1. Model defaults are never reported as
recorded facts; field presence comes from ``model_fields_set`` only.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, NamedTuple

from .models import (
    ASSERTION_ID_REGEX,
    TASK_ID_REGEX,
    AttentionFile,
    ContractStateFile,
    MissionPlanning,
    MissionRunning,
    ProjectRecord,
    TaskList,
    TaskStateFile,
)
from .runtime_observability import (
    CAPTURE_ATTEMPTS,
    MISSION_ID_PATTERN,
    PROJECT_ID_PATTERN,
    RuntimeObservationError,
    _capture_inputs,
    _identity_generation,
    _parse_json_model,
    _parse_spawn_ts,
    _parse_state,
    _source_map,
    _validated_project_root,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .runtime_observability import _CapturedFile
    from .storage import ProjectStore


ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_project_id",
        "invalid_mission_id",
        "invalid_task_id",
        "invalid_configuration",
        "project_not_found",
        "unsafe_project_path",
        "unsafe_cursor",
        "malformed_cursor",
        "snapshot_changed",
        "subject_mission_cursor_mismatch",
        "subject_mission_not_selected",
        "subject_plan_absent",
        "subject_task_absent",
        "internal_error",
    }
)
# Codes derived from captured content are confirmed against a second capture.
_CONTENT_CODES: Final[frozenset[str]] = frozenset(
    {
        "malformed_cursor",
        "subject_mission_cursor_mismatch",
        "subject_mission_not_selected",
        "subject_plan_absent",
        "subject_task_absent",
    }
)
COVERAGE: Final[tuple[tuple[str, str], ...]] = (
    ("attempt_bodies", "partial"),
    ("clock_lineage", "no_source"),
    ("control_requests", "unsupported_reader"),
    ("deadline_profile", "no_source"),
    ("external_waits", "no_source"),
    ("patch_transactions", "not_captured"),
    ("progress_history", "no_source"),
    ("project_durable_records", "not_captured"),
    ("project_runtime_cursors", "captured"),
    ("provider_review_guards", "unsupported_reader"),
    ("readiness", "not_evaluated"),
    ("run_control_records", "unsupported_reader"),
    ("supervision_snapshots", "not_captured"),
    ("terminal_reviews", "metadata_only"),
)
ASSESSMENT_REASONS: Final[tuple[str, ...]] = (
    "clock_lineage_unavailable",
    "deadline_profile_unavailable",
    "durable_records_unavailable",
    "progress_history_unavailable",
    "readiness_not_evaluated",
    "run_control_records_unavailable",
    "supervision_snapshots_unavailable",
)
ATTENTION_KINDS: Final[tuple[str, ...]] = (
    "gate_checkpoint",
    "gate_failed",
    "node_attention",
    "node_failed",
    "terminal_review",
)
STABILITY_LIMITATIONS: Final[tuple[str, ...]] = (
    "coverage_list_non_exhaustive",
    "same_stat_rewrite_undetected",
    "uncaptured_families_unchecked",
)
_RUNTIME: Final[str] = ".unrest-runtime"
_MAX_TASK_ID_CHARS: Final[int] = 128


class PreflightError(Exception):
    """A closed preflight failure whose message is exactly its code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PreflightSubject(NamedTuple):
    project_id: str
    mission_id: str
    task_id: str


def validate_subject_arguments(project_id: str, mission_id: str, task_id: str) -> None:
    if PROJECT_ID_PATTERN.fullmatch(project_id) is None:
        raise PreflightError("invalid_project_id")
    if MISSION_ID_PATTERN.fullmatch(mission_id) is None:
        raise PreflightError("invalid_mission_id")
    if len(task_id) > _MAX_TASK_ID_CHARS or TASK_ID_REGEX.fullmatch(task_id) is None:
        raise PreflightError("invalid_task_id")


def _read_clock() -> datetime:
    return datetime.now(UTC)


def _bytewise(values: list[str]) -> list[str]:
    return sorted(set(values), key=lambda value: value.encode("utf-8"))


def _source(sources: Mapping[str, _CapturedFile], path: str) -> dict[str, object]:
    item = sources.get(path)
    if item is None:
        capture = "absent"
    elif item.data is None:
        capture = "metadata_only"
    else:
        capture = "bytes"
    return {"root": "project_bucket", "path": path, "capture": capture}


def _status_cell(presence: str, value: object = None) -> dict[str, object]:
    return {"presence": presence, "value": value}


def _task_status(task_state: TaskStateFile | None, task_id: str) -> dict[str, object]:
    if task_state is None:
        return _status_cell("file_absent")
    if "tasks" not in task_state.model_fields_set:
        return _status_cell("collection_absent")
    entry = task_state.tasks.get(task_id)
    if entry is None:
        return _status_cell("entry_absent")
    if "status" not in entry.model_fields_set:
        return _status_cell("field_absent")
    return _status_cell("present", entry.status)


def _task_last_attempt(task_state: TaskStateFile | None, task_id: str) -> dict[str, object]:
    if task_state is None:
        return _status_cell("file_absent")
    if "tasks" not in task_state.model_fields_set:
        return _status_cell("collection_absent")
    entry = task_state.tasks.get(task_id)
    if entry is None:
        return _status_cell("entry_absent")
    if "last_attempt" not in entry.model_fields_set:
        return _status_cell("field_absent")
    reference = entry.last_attempt
    if reference is None:
        return _status_cell("explicit_null")
    if _parse_spawn_ts(reference) is not None:
        return _status_cell("present", reference)
    return _status_cell("malformed_reference")


def _assertion_status(
    contract_state: ContractStateFile | None, assertion_id: str
) -> dict[str, object]:
    if contract_state is None:
        return _status_cell("file_absent")
    if "items" not in contract_state.model_fields_set:
        return _status_cell("collection_absent")
    entry = contract_state.items.get(assertion_id)
    if entry is None:
        return _status_cell("entry_absent")
    if "status" not in entry.model_fields_set:
        return _status_cell("field_absent")
    return _status_cell("present", entry.status)


def _parse_present(
    sources: dict[str, _CapturedFile],
    path: str,
    model: type[TaskStateFile] | type[ContractStateFile] | type[AttentionFile],
) -> object | None:
    if path not in sources:
        return None
    parsed = _parse_json_model(sources, path, model)
    if not isinstance(parsed, model):
        raise PreflightError("malformed_cursor")
    return parsed


def _project(
    sources: Mapping[str, _CapturedFile],
    subject: PreflightSubject,
    *,
    read_at: str,
    attempts_used: int,
) -> dict[str, object]:
    """Project one captured set into the closed schema-v1 payload."""

    source_dict = dict(sources)
    project_key = f"{_RUNTIME}/project.json"
    if project_key not in source_dict:
        raise PreflightError("malformed_cursor")
    record = _parse_json_model(source_dict, project_key, ProjectRecord)
    if not isinstance(record, ProjectRecord) or record.id != subject.project_id:
        raise PreflightError("malformed_cursor")
    cursor = record.current_mission_id
    if cursor is not None and MISSION_ID_PATTERN.fullmatch(cursor) is None:
        raise PreflightError("malformed_cursor")

    state = _parse_state(source_dict)
    if isinstance(state, (MissionRunning, MissionPlanning)):
        if MISSION_ID_PATTERN.fullmatch(state.mission_id) is None:
            raise PreflightError("malformed_cursor")

    attention_key = f"{_RUNTIME}/attention.json"
    attention = _parse_present(source_dict, attention_key, AttentionFile)
    assert attention is None or isinstance(attention, AttentionFile)

    if isinstance(state, (MissionRunning, MissionPlanning)):
        if cursor != state.mission_id:
            raise PreflightError("subject_mission_cursor_mismatch")
        selected: str | None = state.mission_id
        selection_basis = "state_mission"
    else:
        selected = cursor
        selection_basis = "project_cursor"
    if selected is None or selected != subject.mission_id:
        raise PreflightError("subject_mission_not_selected")

    missions_prefix = f"{_RUNTIME}/missions/"
    mission_prefix = f"{missions_prefix}{subject.mission_id}/"
    for path in source_dict:
        if path.startswith(missions_prefix) and not path.startswith(mission_prefix):
            raise PreflightError("malformed_cursor")

    tasks_key = f"{mission_prefix}tasks.json"
    task_state_key = f"{mission_prefix}task-state.json"
    contract_key = f"{mission_prefix}contract-state.json"
    if tasks_key not in source_dict:
        if isinstance(state, MissionRunning):
            raise PreflightError("malformed_cursor")
        raise PreflightError("subject_plan_absent")
    plan = _parse_json_model(source_dict, tasks_key, TaskList)
    if not isinstance(plan, TaskList):
        raise PreflightError("malformed_cursor")
    if "tasks" not in plan.model_fields_set:
        raise PreflightError("subject_plan_absent")
    task_state = _parse_present(source_dict, task_state_key, TaskStateFile)
    assert task_state is None or isinstance(task_state, TaskStateFile)
    contract_state = _parse_present(source_dict, contract_key, ContractStateFile)
    assert contract_state is None or isinstance(contract_state, ContractStateFile)

    plan_ids = {task.id for task in plan.tasks}
    for task in plan.tasks:
        for identifier in (task.id, *task.depends_on):
            if (
                len(identifier) > _MAX_TASK_ID_CHARS
                or TASK_ID_REGEX.fullmatch(identifier) is None
            ):
                raise PreflightError("malformed_cursor")
    if task_state is not None and set(task_state.tasks) - plan_ids:
        raise PreflightError("malformed_cursor")
    matches = [task for task in plan.tasks if task.id == subject.task_id]
    if not matches:
        raise PreflightError("subject_task_absent")
    if len(matches) > 1:
        raise PreflightError("malformed_cursor")
    task = matches[0]
    for target in task.targets:
        if ASSERTION_ID_REGEX.fullmatch(target) is None:
            raise PreflightError("malformed_cursor")

    state_source = _source(source_dict, f"{_RUNTIME}/state.json")
    tasks_source = _source(source_dict, tasks_key)
    task_state_source = _source(source_dict, task_state_key)
    contract_source = _source(source_dict, contract_key)

    if state is None:
        mission_record_state: dict[str, object] = {
            "presence": "file_absent",
            "value": None,
            "source": state_source,
        }
    else:
        mission_record_state = {
            "presence": "present",
            "value": state.state,
            "source": state_source,
        }

    task_status = {**_task_status(task_state, subject.task_id), "source": task_state_source}
    last_attempt = _task_last_attempt(task_state, subject.task_id)
    task_last_attempt = {**last_attempt, "source": dict(task_state_source)}

    if last_attempt["presence"] == "present":
        attempt_key = f"{mission_prefix}attempts/{last_attempt['value']}__{subject.task_id}.json"
        attempt_source = _source(source_dict, attempt_key)
        lookup = {
            "bytes": "bytes_captured",
            "metadata_only": "metadata_only",
            "absent": "absent",
        }[str(attempt_source["capture"])]
        attempt_record: dict[str, object] = {"lookup": lookup, "source": attempt_source}
    elif last_attempt["presence"] == "explicit_null":
        attempt_record = {"lookup": "not_applicable", "source": None}
    else:
        attempt_record = {"lookup": "unavailable", "source": None}

    if "depends_on" not in task.model_fields_set:
        dependency_presence = "field_absent"
        dependency_items: list[dict[str, object]] | None = None
    else:
        dependency_presence = "present"
        dependency_items = [
            {
                "task_id": dependency,
                "plan_membership": "in_plan" if dependency in plan_ids else "not_in_plan",
                "status": _task_status(task_state, dependency),
            }
            for dependency in _bytewise(task.depends_on)
        ]
    dependencies = {
        "presence": dependency_presence,
        "association_source": dict(tasks_source),
        "status_source": dict(task_state_source),
        "items": dependency_items,
    }

    targets = {
        "presence": "present",
        "relation": "association",
        "association_source": dict(tasks_source),
        "status_source": contract_source,
        "items": [
            {"assertion_id": target, "status": _assertion_status(contract_state, target)}
            for target in _bytewise(task.targets)
        ],
    }

    attention_source = _source(source_dict, attention_key)
    if attention is None:
        attention_presence = "file_absent"
        counts: dict[str, int] | None = None
    elif "items" not in attention.model_fields_set:
        attention_presence = "collection_absent"
        counts = None
    else:
        attention_presence = "present"
        counts = dict.fromkeys(ATTENTION_KINDS, 0)
        for item in attention.items:
            if item.mission_id == subject.mission_id and item.node_id == subject.task_id:
                counts[item.kind] += 1
    attention_fact = {
        "presence": attention_presence,
        "join": "mission_id_and_node_id",
        "counts": counts,
        "excluded_sources": ["state_attention_items"],
        "join_excluded_kinds": ["terminal_review"],
        "source": attention_source,
    }

    return {
        "schema": "unrest.continuation-preflight",
        "schema_version": 1,
        "surface": "experimental_preflight",
        "read_at": read_at,
        "read_at_meaning": "read_time_only",
        "subject": {
            "project_id": subject.project_id,
            "mission_id": subject.mission_id,
            "task_id": subject.task_id,
            "selection_basis": selection_basis,
        },
        "observations": {
            "mission_record_state": mission_record_state,
            "task_type": {"presence": "present", "value": task.type, "source": dict(tasks_source)},
            "task_status": task_status,
            "task_last_attempt": task_last_attempt,
            "attempt_record": attempt_record,
            "dependencies": dependencies,
            "targets": targets,
            "attention": attention_fact,
        },
        "coverage": [{"family": family, "status": status} for family, status in COVERAGE],
        "stability": {
            "method": "stat_identity_before_after",
            "scope": "captured_project_runtime_files",
            "attempts_used": attempts_used,
            "limitations": list(STABILITY_LIMITATIONS),
        },
        "assessment": {"status": "unavailable", "reasons": list(ASSESSMENT_REASONS)},
    }


def build_preflight(store: ProjectStore, subject: PreflightSubject) -> dict[str, object]:
    """Read once per bounded attempt and return a stat-stable projection."""

    now = _read_clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise PreflightError("internal_error")
    read_at = now.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    try:
        root = _validated_project_root(store, subject.project_id)
        for attempts_used in range(1, CAPTURE_ATTEMPTS + 1):
            try:
                before = _capture_inputs(root)
            except RuntimeObservationError as error:
                if error.code == "snapshot_changed":
                    continue
                raise
            try:
                payload = _project(
                    _source_map(before),
                    subject,
                    read_at=read_at,
                    attempts_used=attempts_used,
                )
            except (PreflightError, RuntimeObservationError) as error:
                if error.code not in _CONTENT_CODES:
                    raise
                try:
                    stable = _capture_inputs(root)
                except RuntimeObservationError as recapture_error:
                    if recapture_error.code == "snapshot_changed":
                        continue
                    raise
                if _identity_generation(stable) != _identity_generation(before):
                    continue
                raise
            try:
                after = _capture_inputs(root)
            except RuntimeObservationError as error:
                if error.code == "snapshot_changed":
                    continue
                raise
            if _identity_generation(before) == _identity_generation(after):
                return payload
    except RuntimeObservationError as error:
        raise PreflightError(error.code) from None
    raise PreflightError("snapshot_changed")


def render_preflight(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"
