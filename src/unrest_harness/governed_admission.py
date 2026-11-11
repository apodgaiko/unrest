"""Governed S1 lifecycle operations, dispatch gate and inspector.

Admission (``submit_governed_plan``), abandonment and inspection are the three
lifecycle tools of governed S1; the pure gate helpers are shared by the
coordinator and the inspector so both derive reasons from one classification.
See ``docs/architecture/governed-s1.md`` and ADR-0507.
"""
from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterator, Literal, Mapping, NoReturn

from .governed_records import (
    ABANDON_LIMIT,
    ATTEMPT_ID,
    ADMISSIONS_MAX,
    EXECUTIONS_MAX,
    ID_MAX_LENGTH,
    IDEMPOTENCY_KEY,
    INTENT_LIMIT,
    MANIFEST_LIMIT,
    MISSION_ID,
    NOT_CLAIMED,
    OUTPUT_LIMIT,
    POST_IMAGE_LIMIT,
    POST_IMAGE_MEMBERS,
    PROJECT_ID,
    RENDER_VERSION,
    RESIDUE,
    SMALL_RECORD_LIMIT,
    CaptureRefusal,
    Classification,
    GovernedRecordError,
    GovernedRedactionConflict,
    GovernedTemplate,
    LegacyAfterAbandon,
    LegacyNoAdmission,
    TaskGovernance,
    anchored_open,
    build_commit,
    build_intent,
    canonical_bytes,
    canonicalize_criterion,
    capture_criteria,
    classify,
    classify_identity,
    classify_witness,
    governed_fs_capable,
    guard,
    id3,
    manifest_mapping,
    membership_fingerprint,
    mkdir_at,
    mkdir_open,
    publish,
    read_bounded_fd,
    read_member,
    read_witness_stages,
    witness_unavailable_reason,
)

from .models import ASSERTION_ID_REGEX, TASK_ID_REGEX

if TYPE_CHECKING:
    from .models import Task, TaskList
    from .storage import ProjectStore


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def refuse(code: str, details: list[Any] | None = None) -> NoReturn:
    from .controller import ToolError

    raise ToolError(code, code.replace("_", " "), details=details)


# ---------------------------------------------------------------------------
# Gate (pure functions of one classification)
# ---------------------------------------------------------------------------

GateMode = Literal["legacy_no_admission", "legacy_after_abandon", "governed_bound", "refused"]


def gate_refusal(c: Classification) -> str | None:
    """Gate column of the reason/consumer table, before route and binding."""
    status = c.admission_status
    if status == "NONE":
        return None
    if status == "AMBIGUOUS":
        return "governed_admission_unresolved"
    if status == "UNAVAILABLE":
        if c.status_reason == "platform_unsupported":
            return "governed_platform_unsupported"
        return "governed_content_unavailable"
    if c.executions_status == "unavailable":
        return "governed_content_unavailable"
    return None


def legacy_submit_refusal(c: Classification) -> str | None:
    """Legacy ``submit_plan`` eligibility: only absence or a usable abandonment."""
    status = c.admission_status
    if status == "NONE":
        if c.status_reason == "orphan_staging_present":
            return "governed_admission_present"
        return None
    if status in ("AMBIGUOUS", "COMMITTED"):
        return "governed_admission_present"
    if status == "ABANDONED" and c.executions_status != "unavailable":
        return None
    return "governed_admission_unresolved"


def legacy_mode(c: Classification) -> LegacyNoAdmission | LegacyAfterAbandon | None:
    if c.admission_status == "NONE":
        return LegacyNoAdmission()
    if c.admission_status == "ABANDONED":
        assert c.abandon is not None
        return LegacyAfterAbandon(c.abandon["abandon_id"])
    return None


def dispatch_gate(c: Classification) -> dict[str, Any]:
    """Inspector parity reason for route ``e1_e3`` and a governed-capable dispatcher."""
    reason = gate_refusal(c)
    if reason is None and c.committed and len(c.executions) >= EXECUTIONS_MAX:
        reason = "governed_witness_unavailable"
    if reason is not None:
        mode: GateMode = "refused"
    elif c.admission_status == "NONE":
        mode = "legacy_no_admission"
    elif c.admission_status == "ABANDONED":
        mode = "legacy_after_abandon"
    else:
        mode = "governed_bound"
    return {"assumed_route": "e1_e3", "assumed_dispatcher": "governed_capable",
            "reason_basis": "current_state_recomputed", "mode": mode, "reason": reason}


def bind_tasks(
    c: Classification, tasks: list["Task"], dispatcher: object
) -> dict[str, TaskGovernance] | str:
    """Build one template per selected task or return a whole-set refusal code."""
    if getattr(dispatcher, "supports_governed_delivery", False) is not True:
        return "governed_dispatcher_unsupported"
    manifest = c.manifest
    assert manifest is not None and c.admission_id is not None
    if manifest["render_version"] != RENDER_VERSION:
        return "governed_dispatcher_unsupported"
    versions = {row["assertion_id"]: row["criterion_version_id"] for row in manifest["criteria"]}
    result: dict[str, TaskGovernance] = {}
    for task in tasks:
        criteria = []
        for aid in task.targets:
            if aid not in versions or aid not in c.criteria_buffers:
                return "governed_content_unavailable"
            criteria.append((aid, versions[aid], c.criteria_buffers[aid]))
        result[task.id] = GovernedTemplate(c.admission_id, RENDER_VERSION, tuple(criteria))
    return result


# ---------------------------------------------------------------------------
# Strict input
# ---------------------------------------------------------------------------


def _valid(pattern: Any, value: object, max_len: int = ID_MAX_LENGTH) -> bool:
    return type(value) is str and len(value) <= max_len and pattern.fullmatch(value) is not None


def _require_ids(project_id: object, mission_id: object) -> None:
    if not _valid(PROJECT_ID, project_id) or not _valid(MISSION_ID, mission_id):
        refuse("governed_request_invalid")


def _require_request(value: object, schema: str, extra: Mapping[str, object]) -> str:
    if type(value) is not dict or set(value) != {"schema", "idempotency_key", *extra}:
        refuse("governed_request_invalid")
    if value["schema"] != schema or not _valid(IDEMPOTENCY_KEY, value["idempotency_key"]):
        refuse("governed_request_invalid")
    for key, expected in extra.items():
        if value[key] != expected:
            refuse("governed_request_invalid")
    return value["idempotency_key"]


@contextmanager
def lock_eligibility(store: "ProjectStore", project_id: str) -> Iterator[None]:
    from .project_lock import (
        ProjectLockBusyError,
        ProjectLockError,
        project_access_guard,
        project_lock_path,
    )

    try:
        lock_path = project_lock_path(store, project_id)
    except ProjectLockError:
        refuse("project_lock_error")
    if lock_path is None:
        from .controller import ToolError

        raise ToolError("not_found", "not found")
    try:
        with project_access_guard(store, project_id, blocking=False):
            yield
    except ProjectLockBusyError:
        refuse("project_busy")
    except ProjectLockError:
        refuse("project_lock_error")


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def _admission_refusal(c: Classification) -> str:
    if c.admission_status == "ABANDONED":
        return "governed_abandoned"
    if c.admission_status == "AMBIGUOUS":
        return "governed_admission_unresolved"
    if c.status_reason == "platform_unsupported":
        return "governed_platform_unsupported"
    if c.status_reason == "io_unavailable":
        return "governed_io_unavailable"
    return "governed_admission_unresolved"


def admission_receipt(manifest: dict[str, Any], *, replayed: bool) -> dict[str, Any]:
    return {
        "schema": "unrest.governed-admission-receipt.v1",
        "project_id": manifest["project_id"], "mission_id": manifest["mission_id"],
        "admission_id": manifest["admission_id"], "status": "COMMITTED", "replayed": replayed,
        "revision": 1, "render_version": RENDER_VERSION,
        "criteria": [{"assertion_id": row["assertion_id"],
                      "criterion_version_id": row["criterion_version_id"], "revision": 1}
                     for row in manifest["criteria"]],
        "timed_assessment_eligible": False, "committed_is_historical": True,
        "terminal_review": "not_covered", "not_claimed": list(NOT_CLAIMED),
    }


def output(store: "ProjectStore", key: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Output-bucket projection: guarded, bounded, never truncated."""
    try:
        data = canonical_bytes({key: payload})
        guard(data, (store.inventory,))
    except (GovernedRedactionConflict, ValueError, TypeError, UnicodeError):
        refuse("governed_output_unavailable")
    if len(data) > OUTPUT_LIMIT_ACTIVE[0]:
        refuse("governed_output_unavailable")
    return {key: payload}


PROJECT_RECORD_LIMIT = 1_048_576

# Mutable single-element holder so tests can lower the output ceiling.
OUTPUT_LIMIT_ACTIVE = [OUTPUT_LIMIT]


def m1_shape_screen(store: "ProjectStore", project_id: str, mid: str) -> None:
    """Conservative freshness *shape* screen; success proves no history claim."""
    from .models import ProjectRecord

    try:
        os.lstat(store.mission_runtime_dir(project_id, mid))
    except FileNotFoundError:
        pass
    except OSError:
        refuse("governed_io_unavailable")
    else:
        refuse("governed_mission_not_fresh")
    mission_dir = store.mission_dir(project_id, mid)
    try:
        with os.scandir(mission_dir) as entries:
            for entry in entries:
                if RESIDUE.fullmatch(entry.name) is not None and entry.is_file(
                    follow_symlinks=False
                ) and not entry.is_symlink():
                    continue
                if entry.name in ("contract", "governed") and entry.is_dir(
                    follow_symlinks=False
                ) and not entry.is_symlink():
                    continue
                refuse("governed_mission_not_fresh")
    except FileNotFoundError:
        pass
    except OSError:
        refuse("governed_io_unavailable")
    record_path = store.unrest_runtime_dir(project_id) / "project.json"
    try:
        fd = os.open(record_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        refuse("governed_mission_not_fresh")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            refuse("governed_mission_not_fresh")
        data = read_bounded_fd(fd, PROJECT_RECORD_LIMIT)
    except (OSError, GovernedRecordError):
        refuse("governed_mission_not_fresh")
    finally:
        os.close(fd)
    try:
        record = ProjectRecord.model_validate_json(data)
    except ValueError:
        refuse("governed_mission_not_fresh")
    if record.current_mission_id != mid or record.id != project_id:
        refuse("governed_mission_not_fresh")


def identity_admission_check(store: "ProjectStore", project_id: str, mid: str) -> None:
    """A4: only ELIGIBLE identity with a matching unconsumed reservation admits."""
    view = classify_identity(store, project_id)
    if view.state != "ELIGIBLE" or mid not in view.reserved or mid in view.consumed:
        refuse("governed_identity_unavailable")


@dataclass(frozen=True)
class _Buffers:
    criteria: list[tuple[str, bytes]]
    tasks: bytes
    task_state: bytes
    contract_state: bytes
    state: bytes
    manifest: bytes
    intent: bytes
    commit: bytes
    ids: dict[str, str]
    manifest_record: dict[str, Any]


def _build_buffers(
    store: "ProjectStore", project_id: str, mid: str, key: str,
    task_list: "TaskList", captured: list[tuple[str, bytes]],
) -> _Buffers:
    from .models import ContractStateEntry, ContractStateFile, MissionRunning, TaskStateFile

    tasks = store.render_json_bytes(task_list.model_dump(mode="json"))
    task_state = TaskStateFile()
    for task in task_list.tasks:
        task_state.set_status(task.id, "pending")
    contract = ContractStateFile()
    for aid, _ in sorted(captured):
        contract.items.setdefault(aid, ContractStateEntry())
    ids = id3(project_id, mid, secrets.token_hex(16))
    mapping = manifest_mapping(task_list)
    rows = []
    for aid, data in sorted(captured):
        owner, validators, gates = mapping[aid]
        rows.append({
            "assertion_id": aid, "criterion_version_id": secrets.token_hex(16), "revision": 1,
            "content_sha256": hashlib.sha256(data).hexdigest(), "work_owner_task_id": owner,
            "validate_task_ids": validators, "gate_task_ids": gates,
        })
    manifest = {
        "schema": "unrest.governed-admission-manifest.v1", **ids, "idempotency_key": key,
        "revision": 1, "criterion_identity_policy": "internal_digest_with_plaintext",
        "render_version": RENDER_VERSION, "canonicalization": "crlf-lf-rstrip-lf-v1",
        "post_image_members": list(POST_IMAGE_MEMBERS), "criteria": rows,
    }
    inventory = (store.inventory,)
    manifest_bytes = guard(canonical_bytes(manifest), inventory)
    intent = guard(canonical_bytes(build_intent(ids, (aid for aid, _ in sorted(captured)))),
                   inventory)
    commit = guard(canonical_bytes(build_commit(ids)), inventory)
    buffers = _Buffers(
        criteria=sorted(captured), tasks=tasks,
        task_state=store.render_json_bytes(task_state.model_dump(mode="json")),
        contract_state=store.render_json_bytes(contract.model_dump(mode="json")),
        state=store.render_json_bytes(MissionRunning(mission_id=mid).model_dump(mode="json")),
        manifest=manifest_bytes, intent=intent, commit=commit, ids=ids,
        manifest_record=manifest,
    )
    if len(manifest_bytes) > MANIFEST_LIMIT or len(intent) > INTENT_LIMIT:
        refuse("governed_limit_exceeded")
    for data in (buffers.tasks, buffers.task_state, buffers.contract_state, buffers.state):
        if len(data) > POST_IMAGE_LIMIT:
            refuse("governed_limit_exceeded")
    return buffers


def _io_code(exc: BaseException) -> str:
    if isinstance(exc, GovernedRedactionConflict):
        return "governed_metadata_redaction_conflict"
    if isinstance(exc, GovernedRecordError):
        if exc.reason == "artifact_identity_conflict":
            return "artifact_identity_conflict"
        if exc.reason == "limit_exceeded":
            return "governed_limit_exceeded"
        return "governed_io_unavailable"
    if isinstance(exc, FileExistsError):
        return "artifact_identity_conflict"
    return "governed_io_unavailable"


def _readback(dir_fd: int, name: str, expected: bytes, limit: int) -> None:
    if read_member(dir_fd, name, limit) != expected:
        raise GovernedRecordError("readback_mismatch")


def _publish_product(store: "ProjectStore", project_id: str, mid: str, b: _Buffers) -> None:
    from .storage import atomic_write_text

    bucket = store.bucket_root(project_id)
    runtime = store.mission_runtime_dir(project_id, mid)
    targets = (
        (runtime / "tasks.json", b.tasks),
        (runtime / "task-state.json", b.task_state),
        (runtime / "contract-state.json", b.contract_state),
        (store.unrest_runtime_dir(project_id) / "state.json", b.state),
    )
    for path, data in targets:
        atomic_write_text(path, data.decode("utf-8"), trusted_root=bucket, _redact=False)
    for path, data in targets:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if read_bounded_fd(fd, POST_IMAGE_LIMIT) != data:
                raise GovernedRecordError("readback_mismatch")
        finally:
            os.close(fd)


def _w_order(store: "ProjectStore", project_id: str, mid: str, b: _Buffers) -> None:
    anchor = store.unrest_dir(project_id)
    aid = b.ids["admission_id"]
    # Phase 1: governed staging; any failure is a refusal (A remains an orphan).
    try:
        m_fd = anchored_open(anchor, ("missions",))
        try:
            mkdir_at(m_fd, mid, reuse=True)
            mid_fd = anchored_open(anchor, ("missions", mid))
        finally:
            os.close(m_fd)
        try:
            g_fd = mkdir_open(mid_fd, "governed", reuse=True)
        finally:
            os.close(mid_fd)
        try:
            adm_fd = mkdir_open(g_fd, "admission", reuse=True)
        finally:
            os.close(g_fd)
        try:
            a_fd = mkdir_open(adm_fd, aid, reuse=False)
        finally:
            os.close(adm_fd)
        try:
            c_fd = mkdir_open(a_fd, "criteria", reuse=False)
            try:
                for assertion_id, data in b.criteria:
                    publish(c_fd, f"{assertion_id}.v1.md", data, 65_536)
                for assertion_id, data in b.criteria:
                    _readback(c_fd, f"{assertion_id}.v1.md", data, 65_536)
            finally:
                os.close(c_fd)
            p_fd = mkdir_open(a_fd, "post-images", reuse=False)
            post = {"tasks.json": b.tasks, "task-state.json": b.task_state,
                    "contract-state.json": b.contract_state, "state.json": b.state}
            try:
                for name in POST_IMAGE_MEMBERS:
                    publish(p_fd, name, post[name], POST_IMAGE_LIMIT)
                for name in POST_IMAGE_MEMBERS:
                    _readback(p_fd, name, post[name], POST_IMAGE_LIMIT)
            finally:
                os.close(p_fd)
            publish(a_fd, "manifest.json", b.manifest, MANIFEST_LIMIT)
            _readback(a_fd, "manifest.json", b.manifest, MANIFEST_LIMIT)
            publish(a_fd, "intent.json", b.intent, INTENT_LIMIT)
            _readback(a_fd, "intent.json", b.intent, INTENT_LIMIT)
        except BaseException:
            os.close(a_fd)
            raise
    except (OSError, GovernedRecordError, GovernedRedactionConflict) as exc:
        refuse(_io_code(exc))
    # Phase 2: intent is durable; any failure leaves AMBIGUOUS, never NONE.
    try:
        try:
            _publish_product(store, project_id, mid, b)
            publish(a_fd, "commit.json", b.commit, SMALL_RECORD_LIMIT)
            _readback(a_fd, "commit.json", b.commit, SMALL_RECORD_LIMIT)
        finally:
            os.close(a_fd)
    except (OSError, GovernedRecordError, GovernedRedactionConflict):
        refuse("governed_admission_unresolved")


def submit_governed_plan(
    store: "ProjectStore", project_id: str, mission_id: str, task_list: "TaskList",
    governed: object,
) -> dict[str, Any]:
    from .models import MissionPlanning
    from .patch_transaction import PatchTransactionError
    from .task_validation import validate_task_list_submission

    _require_ids(project_id, mission_id)
    key = _require_request(governed, "unrest.governed-admission-request.v1",
                           {"criterion_identity_policy": "internal_digest_with_plaintext"})
    with lock_eligibility(store, project_id):
        c = classify(store, project_id, mission_id, admission_only=True)
        if c.admission_status == "COMMITTED":
            assert c.manifest is not None and c.post_tasks is not None
            if key != c.manifest["idempotency_key"]:
                refuse("governed_already_admitted")
            staged = store.render_json_bytes(task_list.model_dump(mode="json"))
            if (
                mission_id != c.manifest["mission_id"]
                or c.manifest["criterion_identity_policy"] != "internal_digest_with_plaintext"
                or staged != c.post_tasks
            ):
                refuse("admission_retry_mismatch")
            return output(store, "governed_admission",
                          admission_receipt(c.manifest, replayed=True))
        if c.admission_status != "NONE":
            refuse(_admission_refusal(c))
        if not governed_fs_capable():
            refuse("governed_platform_unsupported")
        try:
            store.recover_patch_transactions(project_id)
        except PatchTransactionError as exc:
            from .controller import ToolError

            raise ToolError(exc.code, "project transaction unavailable") from exc
        state = store.load_state(project_id)
        if not isinstance(state, MissionPlanning) or state.mission_id != mission_id:
            refuse("wrong_state")
        identity_admission_check(store, project_id, mission_id)
        try:
            captured = capture_criteria(store, project_id, mission_id)
        except CaptureRefusal as exc:
            refuse(exc.code, exc.details)
        for aid, data in captured:
            text = data.decode("utf-8")
            if guard_text(text, store.inventory):
                refuse("criterion_contains_redactable")
        errors = validate_task_list_submission({aid for aid, _ in captured}, task_list)
        if errors:
            from .controller import ToolError

            raise ToolError("invalid_task_list", "task list validation failed", details=errors)
        if any(len(task.id) > ID_MAX_LENGTH for task in task_list.tasks) or any(
            len(aid) > ID_MAX_LENGTH for aid, _ in captured
        ):
            refuse("governed_limit_exceeded")
        m1_shape_screen(store, project_id, mission_id)
        buffers = _build_buffers_guarded(store, project_id, mission_id, key, task_list, captured)
        if len(c.admission_ids) >= ADMISSIONS_MAX:
            refuse("governed_limit_exceeded")
        _w_order(store, project_id, mission_id, buffers)
        return output(store, "governed_admission",
                      admission_receipt(buffers.manifest_record, replayed=False))


def guard_text(text: str, inventory: Mapping[str, str]) -> bool:
    """True when the inventory would redact part of ``text``."""
    from .capability_policy import redact_sensitive_value

    return bool(inventory) and redact_sensitive_value(text, inventory) != text


def _build_buffers_guarded(
    store: "ProjectStore", project_id: str, mid: str, key: str,
    task_list: "TaskList", captured: list[tuple[str, bytes]],
) -> _Buffers:
    try:
        return _build_buffers(store, project_id, mid, key, task_list, captured)
    except GovernedRedactionConflict:
        refuse("governed_metadata_redaction_conflict")


def allocate_next_mission(
    store: "ProjectStore", project_id: str, *, route: str
) -> str | None:
    """The single next-mission reservation point; ``None`` keeps the legacy count."""
    from .governed_records import IdentityError, mission_name, reserve_mission

    view = classify_identity(store, project_id)
    if view.state == "LEGACY":
        return None
    if view.state == "IDENTITY_UNAVAILABLE":
        refuse("mission_identity_unavailable")
    mid = mission_name(view.max_index + 1)
    try:
        reserve_mission(store, project_id, mid, route=route, existing=len(view.reserved))
    except IdentityError as exc:
        refuse(exc.code)
    except (OSError, GovernedRecordError, GovernedRedactionConflict):
        refuse("mission_identity_unavailable")
    return mid


def legacy_submit_needs_marker(store: "ProjectStore", project_id: str, mid: str) -> bool:
    """S-5 identity gate of legacy submit; read-only, before any submit effect.

    LEGACY (valid absence only) keeps the baseline submit without R. ANY
    IDENTITY_UNAVAILABLE, and INITIALIZING/ELIGIBLE without a reservation of ``mid``,
    refuse. True means option R must be published before the first submit write.
    """
    try:
        view = classify_identity(store, project_id)
    except (OSError, GovernedRecordError):
        refuse("mission_identity_unavailable")
    if view.state == "LEGACY":
        return False
    if view.state == "IDENTITY_UNAVAILABLE" or mid not in view.reserved:
        refuse("mission_identity_unavailable")
    return True


def mark_legacy_consumption(store: "ProjectStore", project_id: str, mid: str) -> None:
    """Option R: create-or-verify ``.consumed`` after read-only validation and before
    ``ensure_contract_dir``. Any failure or uncertain outcome refuses; a marker that
    reached the disk is retained and replays on retry."""
    from .governed_records import mark_mission_consumed

    try:
        mark_mission_consumed(store, project_id, mid)
    except (OSError, GovernedRecordError, GovernedRedactionConflict):
        refuse("mission_identity_unavailable")


# ---------------------------------------------------------------------------
# Abandon
# ---------------------------------------------------------------------------


def _abandon_phase(c: Classification) -> str:
    if c.admission_status == "COMMITTED":
        return "committed"
    if c.admission_status == "AMBIGUOUS":
        return c.status_reason
    return "precommit_orphan"


def abandon_receipt(record: dict[str, Any], *, replayed: bool) -> dict[str, Any]:
    return {
        "schema": "unrest.governed-abandon-receipt.v1", "project_id": record["project_id"],
        "mission_id": record["mission_id"], "abandon_id": record["abandon_id"],
        "status": "ABANDONED", "replayed": replayed,
        "admission_phase": record["admission_phase"], "not_claimed": list(NOT_CLAIMED),
    }


def abandon_governance(
    store: "ProjectStore", project_id: str, mission_id: str, request: object
) -> dict[str, Any]:
    _require_ids(project_id, mission_id)
    key = _require_request(request, "unrest.governed-abandon-request.v1", {})
    with lock_eligibility(store, project_id):
        c = classify(store, project_id, mission_id)
        status = c.admission_status
        if status == "ABANDONED":
            assert c.abandon is not None
            if c.abandon["idempotency_key"] != key:
                refuse("governed_already_abandoned")
            return output(store, "governed_abandon", abandon_receipt(c.abandon, replayed=True))
        if status == "NONE" and c.status_reason != "orphan_staging_present":
            refuse("governed_not_present")
        if status == "UNAVAILABLE":
            if c.status_reason == "platform_unsupported":
                refuse("governed_platform_unsupported")
            if c.status_reason == "io_unavailable":
                refuse("governed_io_unavailable")
            refuse("governed_content_unavailable")
        if status == "COMMITTED":
            if c.executions_status == "unavailable":
                refuse("governed_content_unavailable")
            if any(view.closed is None for view in c.executions.values()):
                refuse("governed_scope_open")
        committed = c.admission_id if status == "COMMITTED" else None
        record = {
            "schema": "unrest.governed-abandon.v1", "project_id": project_id,
            "mission_id": mission_id, "abandon_id": secrets.token_hex(16),
            "idempotency_key": key, "admission_phase": _abandon_phase(c),
            "inspected_admission_ids": sorted(c.admission_ids),
            "committed_admission_id": committed,
            "closed_execution_attempt_ids": sorted(c.executions) if committed else [],
        }
        try:
            data = guard(canonical_bytes(record), (store.inventory,))
            if len(data) > ABANDON_LIMIT:
                refuse("governed_limit_exceeded")
            g_fd = anchored_open(store.unrest_dir(project_id), ("missions", mission_id, "governed"))
            try:
                publish(g_fd, "abandoned.json", data, ABANDON_LIMIT, exclusive=True)
                _readback(g_fd, "abandoned.json", data, ABANDON_LIMIT)
            finally:
                os.close(g_fd)
        except (OSError, GovernedRecordError, GovernedRedactionConflict) as exc:
            refuse(_io_code(exc))
        return output(store, "governed_abandon", abandon_receipt(record, replayed=False))


# ---------------------------------------------------------------------------
# Inspector
# ---------------------------------------------------------------------------

SECTIONS = {"summary": None, "criteria": 64, "task_gate": 256, "executions": 8}
CURSOR_GRAMMAR = {"criteria": ASSERTION_ID_REGEX, "task_gate": TASK_ID_REGEX,
                  "executions": ATTEMPT_ID}
TRUST_BOUNDARY = {
    "older_binaries": "not_supported",
    "manual_edits_of_governed_records": "not_detected_in_general",
    "same_uid_tamper": "not_claimed",
    "unregistered_launch_detection": "not_claimed",
    "foreign_writers": "not_detected",
}
ROUTE_COVERAGE = {
    "terminal_review": "not_covered", "terminal_review_basis": "authoring_files",
    "async_admission": "not_supported", "run_project": "governed_bound_not_supported",
}


def _authoring_drift(store: "ProjectStore", project_id: str, mid: str, aid: str,
                     expected: bytes | None) -> str:
    try:
        fd = anchored_open(store.unrest_dir(project_id), ("missions", mid, "contract"))
    except GovernedRecordError as exc:
        return "missing" if exc.reason == "member_missing" else "unreadable"
    try:
        try:
            f = os.open(f"{aid}.md", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return "missing"
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR):
                return "non_regular"
            return "unreadable"
        try:
            if not stat.S_ISREG(os.fstat(f).st_mode):
                return "non_regular"
            try:
                raw = read_bounded_fd(f, 65_536)
            except GovernedRecordError:
                return "too_large"
            except OSError:
                return "unreadable"
        finally:
            os.close(f)
    finally:
        os.close(fd)
    try:
        current = canonicalize_criterion(raw)
    except CaptureRefusal as exc:
        if exc.code == "criterion_too_large":
            return "too_large"
        return "invalid_encoding"
    return "no_observed_drift" if current == expected else "changed"


def _criteria_rows(store: "ProjectStore", project_id: str, mid: str,
                   c: Classification) -> list[dict[str, Any]]:
    if c.manifest is None:
        return []
    return [{
        "assertion_id": row["assertion_id"], "criterion_version_id": row["criterion_version_id"],
        "artifact_integrity": "ok",
        "authoring_drift": _authoring_drift(
            store, project_id, mid, row["assertion_id"], c.criteria_buffers.get(row["assertion_id"])
        ),
    } for row in c.manifest["criteria"]]


def _bounded_json(path: Any) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        return read_bounded_fd(fd, POST_IMAGE_LIMIT)
    except (OSError, GovernedRecordError):
        return None
    finally:
        os.close(fd)


def _task_gate_rows(store: "ProjectStore", project_id: str, mid: str,
                    c: Classification) -> list[dict[str, Any]] | None:
    from .models import TaskList, TaskStateFile

    if not c.committed or c.manifest is None:
        return None
    runtime = store.mission_runtime_dir(project_id, mid)
    tasks_bytes = _bounded_json(runtime / "tasks.json")
    state_bytes = _bounded_json(runtime / "task-state.json")
    try:
        task_list = TaskList.model_validate_json(tasks_bytes or b"")
        task_state = (TaskStateFile.model_validate_json(state_bytes)
                      if state_bytes is not None else TaskStateFile())
    except ValueError:
        return []
    admitted = {row["assertion_id"] for row in c.manifest["criteria"]}
    rows = []
    for task in task_list.tasks:
        if task.type not in ("work", "validate") or task_state.status_of(task.id) != "pending":
            continue
        reason = None
        if c.executions_status == "unavailable":
            reason = "governed_content_unavailable"
        elif any(target not in admitted for target in task.targets):
            reason = "target_not_admitted"
        rows.append({"task_id": task.id, "reason": reason})
    return sorted(rows, key=lambda row: row["task_id"])


def _execution_rows(store: "ProjectStore", project_id: str, mid: str, c: Classification,
                    page_names: list[str]) -> list[dict[str, Any]]:
    rows = []
    for name in page_names:
        view = c.executions[name]
        if view.closed is None:
            scope = "open_or_unresolved"
        elif view.closed["closure"] == "owner_joined":
            scope = "closed_owner_joined"
        else:
            scope = "closed_not_launched"
        witness_ids = set(view.witnesses)
        if view.closed is not None:
            witness_ids |= set(view.closed["witness_ids"])
        witnesses = []
        for wid in sorted(witness_ids):
            stages = view.witnesses.get(wid)
            names = sorted(stages.stages) if stages is not None else []
            records = (read_witness_stages(store, project_id, mid, name, wid, names)
                       if names else {})
            unavailable = witness_unavailable_reason(names)
            if unavailable is None and any(record is None for record in records.values()):
                unavailable = "invalid_record"
            outcome = "unavailable" if unavailable else classify_witness(names)
            input_kind = None
            cvids: list[str] = []
            response_class = None
            for stage_name, record in records.items():
                if record is None:
                    continue
                input_kind = input_kind or record["input_kind"]
                if stage_name == "prepared":
                    cvids = sorted(row["criterion_version_id"] for row in record["criteria"])
                if stage_name == "response":
                    response_class = record["response_class"]
            witnesses.append({
                "witness_id": wid, "input_kind": input_kind, "criterion_version_ids": cvids,
                "observations": names, "submission_outcome": outcome,
                "response_class": response_class if outcome == "response_observed" else None,
            })
        rows.append({
            "attempt_id": name, "node_id": view.opened["node_id"], "scope": scope,
            "outcome": view.outcome["outcome"] if view.outcome is not None else None,
            "witnesses": witnesses,
        })
    return rows


def inspect_governed(
    store: "ProjectStore", project_id: str, mission_id: str, section: object, cursor: object
) -> dict[str, Any]:
    _require_ids(project_id, mission_id)
    if type(section) is not str or section not in SECTIONS:
        refuse("governed_request_invalid")
    if section == "summary":
        if cursor is not None:
            refuse("governed_request_invalid")
    elif cursor is not None and not _valid(CURSOR_GRAMMAR[section], cursor, 128):
        refuse("governed_request_invalid")
    before = membership_fingerprint(store, project_id, mission_id)
    c = classify(store, project_id, mission_id)
    if section == "summary":
        task_rows = _task_gate_rows(store, project_id, mission_id, c)
        payload: dict[str, Any] = {
            "schema": "unrest.governed-inspection.v2", "project_id": project_id,
            "mission_id": mission_id, "section": "summary",
            "admission_status": c.admission_status, "status_reason": c.status_reason,
            "executions_status": c.executions_status,
            "executions_reason": c.executions_reason,
            "dispatch_gate": dispatch_gate(c),
            "admission_id": c.admission_id,
            "abandon_id": c.abandon["abandon_id"] if c.abandon is not None else None,
            "orphan_admission_ids": sorted(c.orphan_ids),
            "temp_residue_count": c.residue_count,
            "counts": {"criteria": len(c.manifest["criteria"]) if c.manifest else 0,
                       "task_gate": None if task_rows is None else len(task_rows),
                       "executions": len(c.executions)},
            "committed_is_historical": True, "concurrent_owner": "unknown",
            "observation": "lock_free_single_recheck_v2", "route_coverage": ROUTE_COVERAGE,
            "trust_boundary": TRUST_BOUNDARY, "not_claimed": list(NOT_CLAIMED),
        }
        if membership_fingerprint(store, project_id, mission_id) != before:
            payload.update(admission_status="UNAVAILABLE", status_reason="concurrent_change",
                           dispatch_gate=_unavailable_gate())
        return output(store, "governed_inspection", payload)
    page_size = SECTIONS[section]
    assert page_size is not None
    keyed: list[tuple[str, Any]]
    if section == "criteria":
        manifest_rows = c.manifest["criteria"] if c.manifest else []
        keyed = [(row["assertion_id"], row) for row in manifest_rows]
    elif section == "task_gate":
        keyed = [(row["task_id"], row) for row in (
            _task_gate_rows(store, project_id, mission_id, c) or [])]
    else:
        names = sorted(c.executions) if c.executions_status == "ok" else []
        keyed = [(name, name) for name in names]
    keyed.sort(key=lambda item: item[0])
    after = cursor if isinstance(cursor, str) else None
    remaining = [item for item in keyed if after is None or item[0] > after]
    page = remaining[:page_size]
    next_cursor = page[-1][0] if len(remaining) > page_size else None
    if section == "criteria":
        selected = {key for key, _ in page}
        rows = [row for row in _criteria_rows(store, project_id, mission_id, c)
                if row["assertion_id"] in selected]
    elif section == "task_gate":
        rows = [row for _, row in page]
    else:
        rows = _execution_rows(store, project_id, mission_id, c, [key for key, _ in page])
    status, reason = c.admission_status, c.status_reason
    if membership_fingerprint(store, project_id, mission_id) != before:
        status, reason, rows, next_cursor, keyed = (
            "UNAVAILABLE", "concurrent_change", [], None, [])
    return output(store, "governed_inspection", {
        "schema": "unrest.governed-inspection-page.v1", "project_id": project_id,
        "mission_id": mission_id, "section": section, "admission_status": status,
        "status_reason": reason, "executions_status": c.executions_status,
        "page": {"cursor": cursor, "next_cursor": next_cursor, "page_size": page_size,
                 "total": len(keyed), "complete": next_cursor is None},
        "rows": rows, "observation": "lock_free_single_recheck_v2",
        "pages_are_snapshot": False, "not_claimed": list(NOT_CLAIMED),
    })


def _unavailable_gate() -> dict[str, Any]:
    return {"assumed_route": "e1_e3", "assumed_dispatcher": "governed_capable",
            "reason_basis": "current_state_recomputed", "mode": "refused",
            "reason": "governed_content_unavailable"}


__all__ = [
    "abandon_governance",
    "allocate_next_mission",
    "bind_tasks",
    "dispatch_gate",
    "gate_refusal",
    "inspect_governed",
    "legacy_mode",
    "submit_governed_plan",
]

