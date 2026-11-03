"""Durable, process-backed control for asynchronous Mission mutations.

This module owns admission and lifecycle custody, not Mission semantics.  A
worker calls one configured ``module:function`` executor; the integration layer
supplies the function that reaches the sole Mission mutation authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
import fcntl
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, BinaryIO, Iterator, Literal, NoReturn

from .canonical_identity import FoundationValidationError, IdentityRecord, construct_identity
from .foundation_store import CustodyActor, FoundationStore
from .mutation_journal import DurableMutationJournal, MutationJournalError
from .receipts import construct_receipt, load_receipt_catalog


# Only actual children spawned by this interpreter can be joined. Durable PID
# records convey lifecycle state, never parent wait ownership.
_local_workers: dict[tuple[str, str, int], subprocess.Popen[bytes]] = {}
_local_workers_lock = threading.Lock()


def _after_worker_fork() -> None:
    global _local_workers, _local_workers_lock
    _local_workers = {}
    _local_workers_lock = threading.Lock()


os.register_at_fork(after_in_child=_after_worker_fork)


RUN_OPERATIONS = frozenset(
    {
        "abort_project",
        "advance_project",
        "decide_attention",
        "end_mission",
        "start_project",
        "submit_plan",
    }
)
EXECUTOR_FAILURE_KEY = "_unrest_executor_failure_v1"
TERMINAL_RUN_STATES = frozenset({"attention", "cancelled", "failed", "succeeded"})
_ACTIVE_RUN_STATES = frozenset(
    {
        "cancel_requested",
        "draining",
        "effect_complete",
        "queued",
        "report_complete",
        "running",
    }
)
_DIGEST_PREFIX = "sha256:"
_TASK_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_TARGET_ID = re.compile(r"^[A-Z][A-Z0-9-]+$")

# Stop custody (ADR-0500). Records live below .unrest/runs/<token>/stop/<binding>/,
# where <binding> is the hex event digest of the single durable ``running`` event.
_STOP_SETTLEMENTS = frozenset(
    {
        "never_dispatched",
        "owner_completed",
        "owner_failed",
        "owner_reported",
        "owner_unproven",
        "unrequested_owner_cancel",
    }
)
_STOP_ACTORS = frozenset({"controller", "owner"})
_MARKED_CANCEL_KEYS = frozenset({"cancel_idempotency_digest", "reason_digest", "stop_custody"})
_LEGACY_CANCEL_KEYS = frozenset({"cancel_idempotency_digest", "reason_digest"})
_TERMINAL_REQUIRED_KEYS = frozenset({"receipt_digest", "receipt_id"})
_TERMINAL_OPTIONAL_KEYS = frozenset({"error", "stop_settlement", "terminal_source"})
_DELIVERY_OUTCOMES = frozenset({"accepted", "eperm", "esrch"})
# Exactly the four run receipt outcomes, mapped to the terminal state they record.
_RECEIPT_TERMINALS = {
    "partial": "attention",
    "cancelled": "cancelled",
    "failed": "failed",
    "succeeded": "succeeded",
}
_PENDING_RECEIPT_ERROR = {
    "error": {"code": "internal_error", "message": "run terminal recovered from pending receipt"}
}
_STOP_ATTEMPT = "attempt.json"
_STOP_DELIVERY = "delivered.json"
_STOP_TEMPORARY_PREFIX = ".stop-tmp-"
_STOP_TEMPORARY = re.compile(r"^\.stop-tmp-[A-Za-z0-9_]+$")
_HEX_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECORDED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
_ATTEMPT_KEYS = frozenset(
    {
        "binding",
        "identity_strength",
        "kind",
        "recorded_at",
        "request_event_digest",
        "run_id",
        "schema_version",
        "signal",
    }
)
_BINDING_KEYS = frozenset({"generation", "owner_id", "pgid", "pid", "running_event_digest"})
_DELIVERY_KEYS = frozenset(
    {"attempt_digest", "kind", "outcome", "recorded_at", "run_id", "schema_version"}
)


# Native field types of a stored request (ADR-0503 D1). Strings are type-only;
# their existing constraints (V2/V3/V4 of ADR-0502) are checked separately.
_REQUEST_STRING_FIELDS = (
    "control_identity_digest",
    "created_at",
    "issuer_identity_digest",
    "resource_key",
    "run_identity_digest",
)
_REQUEST_REQUIRED_KEYS = frozenset(
    {
        "arguments",
        "control_identity_digest",
        "created_at",
        "generation",
        "idempotency_key",
        "issuer_identity_digest",
        "operation",
        "project_id",
        "resource_key",
        "run_id",
        "run_identity_digest",
    }
)
_EVENT_REQUIRED_KEYS = frozenset(
    {
        "details",
        "event_digest",
        "observed_at",
        "previous_event_digest",
        "run_id",
        "sequence",
        "state",
    }
)


class RunState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    DRAINING = "draining"
    EFFECT_COMPLETE = "effect_complete"
    REPORT_COMPLETE = "report_complete"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    FAILED = "failed"
    ATTENTION = "attention"


_RUN_STATE_VALUES = frozenset(state.value for state in RunState)


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    operation: str
    state: str
    resource_key: str
    idempotency_key: str
    project_id: str | None
    created_at: str
    updated_at: str
    result: Mapping[str, Any] | None
    error: Mapping[str, Any] | None
    receipt_id: str | None
    active_attempts: tuple[Mapping[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "operation": self.operation,
            "state": self.state,
            "resource_key": self.resource_key,
            "idempotency_key": self.idempotency_key,
            "project_id": self.project_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": dict(self.result) if self.result is not None else None,
            "error": dict(self.error) if self.error is not None else None,
            "receipt_id": self.receipt_id,
            "active_attempts": [dict(item) for item in self.active_attempts],
        }


class RunControlError(RuntimeError):
    """Stable public failure which never includes rejected or provider data."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.public_message = message
        super().__init__(message)

    def as_envelope(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.public_message}}


class PendingReceiptConflict(RunControlError):
    """A committed receipt on the current prefix cannot be adopted unambiguously."""

    recovery_code = "pending_receipt_conflict"

    def __init__(self) -> None:
        super().__init__("integrity_error", "pending terminal receipt conflicts")


class StopCustodyInvalid(RunControlError):
    """Stop events or stop records are not exactly in the published schema."""

    recovery_code = "stop_custody_invalid"

    def __init__(self) -> None:
        super().__init__("integrity_error", "stop custody is invalid")


@dataclass(frozen=True)
class StopStatus:
    """Read-only stop accounting. No value proves drain, cleanup or product effect."""

    run_id: str
    request: str
    delivery: str
    identity_strength: str
    settlement: str
    terminal_source: str | None
    pending_terminal: str
    executor_result: str
    product_effect: str
    replay_clearance: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "request": self.request,
            "delivery": self.delivery,
            "identity_strength": self.identity_strength,
            "settlement": self.settlement,
            "terminal_source": self.terminal_source,
            "pending_terminal": self.pending_terminal,
            "executor_result": self.executor_result,
            "product_effect": self.product_effect,
            "replay_clearance": self.replay_clearance,
        }


@dataclass(frozen=True)
class _StopRecords:
    attempt: Mapping[str, Any] | None
    delivered: Mapping[str, Any] | None

    @property
    def death_required(self) -> bool:
        # A recorded EPERM consumed the attempt but proves nothing about death.
        return self.delivered is not None and self.delivered.get("outcome") == "eperm"


@dataclass(frozen=True)
class _Request:
    run_id: str
    operation: str
    arguments: Mapping[str, Any]
    idempotency_key: str
    resource_key: str
    project_id: str | None
    created_at: str
    run_identity_digest: str
    control_identity_digest: str
    issuer_identity_digest: str
    generation: int


@dataclass(frozen=True)
class _Event:
    sequence: int
    state: str
    observed_at: str
    event_digest: str
    previous_event_digest: str | None
    details: Mapping[str, Any]


@dataclass(frozen=True)
class _Claim:
    """One retained request: committed (``latest`` set) or an incomplete admission."""

    request: _Request
    key_token: str
    latest: str | None


@dataclass(frozen=True)
class _AdmissionView:
    """Effect-free classification of every retained claim (ADR-0502)."""

    claims: Mapping[str, _Claim]
    groups: Mapping[str, tuple[str, ...]]
    indexed: Mapping[str, str]
    quarantined: frozenset[str]
    held_resources: frozenset[str]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RunControlError("invalid_argument", "request contains unsupported JSON") from exc


def _sha256(value: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(value).hexdigest()


def _all_finite(value: Any) -> bool:
    """Whether a decoded JSON document holds only finite numbers (ADR-0503 D3).

    Iterative on purpose: a recursive walk would refuse nesting the decoder
    accepts. Runs after ``json.loads``, so an overwritten duplicate key is not seen.
    """
    pending = [value]
    try:
        while pending:
            item = pending.pop()
            if type(item) is float:
                if not math.isfinite(item):
                    return False
            elif type(item) is dict:
                pending.extend(item.values())
            elif type(item) is list:
                pending.extend(item)
    except RecursionError:
        return False
    return True


def _safe_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fail(code: str, message: str) -> NoReturn:
    raise RunControlError(code, message)


def _validate_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("invalid_argument", f"{name} must be a non-empty string")
    return value


def _validate_arguments(operation: str, arguments: Mapping[str, Any]) -> None:
    schemas: dict[str, tuple[frozenset[str], frozenset[str]]] = {
        "abort_project": (frozenset({"project_id", "reason"}), frozenset({"project_id", "reason"})),
        "advance_project": (frozenset({"project_id", "max_steps"}), frozenset({"project_id"})),
        "decide_attention": (frozenset({"project_id", "decisions"}), frozenset({"project_id", "decisions"})),
        "end_mission": (frozenset({"project_id", "deliverable_roots"}), frozenset({"project_id"})),
        "start_project": (
            frozenset({"brief", "workspace_dir", "worker_model", "worker_reasoning_effort"}),
            frozenset({"brief", "workspace_dir"}),
        ),
        "submit_plan": (frozenset({"project_id", "task_list"}), frozenset({"project_id", "task_list"})),
    }
    allowed, required = schemas[operation]
    if set(arguments) - allowed or required - set(arguments):
        _fail("invalid_argument", "arguments do not match the operation schema")
    if operation == "start_project":
        _validate_text(arguments.get("brief"), "brief")
        _validate_text(arguments.get("workspace_dir"), "workspace_dir")
        for optional in ("worker_model", "worker_reasoning_effort"):
            if optional in arguments and arguments[optional] is not None:
                _validate_text(arguments[optional], optional)
    else:
        _validate_text(arguments.get("project_id"), "project_id")
    if operation == "abort_project":
        _validate_text(arguments.get("reason"), "reason")
    if operation == "advance_project" and arguments.get("max_steps") is not None:
        steps = arguments["max_steps"]
        if isinstance(steps, bool) or not isinstance(steps, int) or steps < 1:
            _fail("invalid_argument", "max_steps must be a positive integer")
    if operation == "decide_attention":
        decisions = arguments.get("decisions")
        if not isinstance(decisions, list):
            _fail("invalid_argument", "decisions must be an array")
        for decision in decisions:
            _validate_decision(decision)
    if operation == "end_mission" and arguments.get("deliverable_roots") is not None:
        roots = arguments["deliverable_roots"]
        if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots):
            _fail("invalid_argument", "deliverable_roots must be an array of strings")
    if operation == "submit_plan":
        _validate_task_list(arguments.get("task_list"))
    _json_bytes(dict(arguments))


def _validate_task(value: Any) -> None:
    if not isinstance(value, Mapping):
        _fail("invalid_argument", "task must be an object")
    allowed = {"auto_merge", "body", "depends_on", "id", "skill", "targets", "type"}
    required = {"body", "id", "targets", "type"}
    if set(value) - allowed or required - set(value):
        _fail("invalid_argument", "task does not match the public schema")
    if not isinstance(value["id"], str) or _TASK_ID.fullmatch(value["id"]) is None:
        _fail("invalid_argument", "task id is invalid")
    if value["type"] not in {"gate", "validate", "work"} or not isinstance(value["body"], str):
        _fail("invalid_argument", "task does not match the public schema")
    targets = value["targets"]
    if not isinstance(targets, list) or not all(
        isinstance(item, str) and _TARGET_ID.fullmatch(item) is not None for item in targets
    ):
        _fail("invalid_argument", "task targets are invalid")
    dependencies = value.get("depends_on", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) and _TASK_ID.fullmatch(item) is not None for item in dependencies
    ):
        _fail("invalid_argument", "task dependencies are invalid")
    if "skill" in value and value["skill"] is not None and not isinstance(value["skill"], str):
        _fail("invalid_argument", "task skill is invalid")
    if "auto_merge" in value and not isinstance(value["auto_merge"], bool):
        _fail("invalid_argument", "task auto_merge is invalid")


def _validate_task_list(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) - {"tasks"}:
        _fail("invalid_argument", "task_list must be an object")
    tasks = value.get("tasks", [])
    if not isinstance(tasks, list):
        _fail("invalid_argument", "task_list tasks must be an array")
    for task in tasks:
        _validate_task(task)


def _validate_patch(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) - {"add", "add_items", "cancel", "supersede"}:
        _fail("invalid_argument", "decision patch is invalid")
    additions = value.get("add", [])
    if not isinstance(additions, list):
        _fail("invalid_argument", "decision patch is invalid")
    for task in additions:
        _validate_task(task)
    add_items = value.get("add_items", [])
    if not isinstance(add_items, list) or not all(
        isinstance(item, str) and _TARGET_ID.fullmatch(item) is not None for item in add_items
    ):
        _fail("invalid_argument", "decision patch is invalid")
    cancelled = value.get("cancel", [])
    if not isinstance(cancelled, list) or not all(isinstance(item, str) for item in cancelled):
        _fail("invalid_argument", "decision patch is invalid")
    superseded = value.get("supersede", {})
    if not isinstance(superseded, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in superseded.items()
    ):
        _fail("invalid_argument", "decision patch is invalid")


def _validate_decision(value: Any) -> None:
    if not isinstance(value, Mapping):
        _fail("invalid_argument", "decision must be an object")
    allowed = {"action", "item_id", "justification", "patch"}
    if set(value) - allowed or not {"action", "item_id"} <= set(value):
        _fail("invalid_argument", "decision does not match the public schema")
    _validate_text(value["item_id"], "decision item_id")
    action = value["action"]
    if action not in {"abort", "continue", "next_mission", "patch", "retry"}:
        _fail("invalid_argument", "decision action is invalid")
    if "justification" in value and not isinstance(value["justification"], str):
        _fail("invalid_argument", "decision justification is invalid")
    if action == "patch":
        _validate_patch(value.get("patch"))
    elif value.get("patch") is not None:
        _fail("invalid_argument", "non-patch decision cannot contain a patch")


def _resource_for(operation: str, arguments: Mapping[str, Any]) -> tuple[str, str | None]:
    if operation == "start_project":
        workspace = str(Path(str(arguments["workspace_dir"])).expanduser().resolve(strict=False))
        return f"workspace:{_safe_token(workspace)}", None
    project_id = str(arguments["project_id"])
    return f"project:{_safe_token(project_id)}", project_id


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_write(path: Path, content: bytes, *, immutable: bool) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.parent.lstat().st_mode):
        _fail("integrity_error", "run storage is not a directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".run-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if immutable:
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != content:
                    raise RunControlError("conflict", "immutable run record conflicts")
        else:
            os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[BinaryIO]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stream = path.open("a+b")
    os.chmod(path, 0o600)
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream
    finally:
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _pid_live(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _death_proven(pid: int) -> bool:
    # A STOP attempt is only published while getsid(pid) == pid. A session leader
    # cannot change session, so only ESRCH or a different session proves the bound
    # leader is gone (PID reuse by another leader remains an accepted limitation).
    try:
        session = os.getsid(pid)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return session != pid


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _parse_stop_record(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise StopCustodyInvalid() from exc
    if not isinstance(value, dict):
        raise StopCustodyInvalid()
    try:
        canonical = _json_bytes(value)
    except (RunControlError, TypeError, RecursionError) as exc:
        raise StopCustodyInvalid() from exc
    if canonical != raw:
        raise StopCustodyInvalid()
    return value


def _is_stop_prefix(events: tuple[_Event, ...]) -> bool:
    return any(event.state in {"cancel_requested", "draining"} for event in events)


def _first_marked_request(events: tuple[_Event, ...]) -> _Event | None:
    for event in events:
        if event.state == "cancel_requested" and "stop_custody" in event.details:
            return event
    return None


def _single_running(events: tuple[_Event, ...]) -> _Event | None:
    running = [event for event in events if event.state == "running"]
    if len(running) > 1:
        raise StopCustodyInvalid()
    return running[0] if running else None


def _run_custodian() -> CustodyActor:
    return CustodyActor(
        actor_id="provider_configuration:run-lifecycle-authority",
        authority_class="run_lifecycle_authority",
        decision_ref="decision:issue:run_receipt.v1",
    )


def _validate_project_envelope(result: Mapping[str, Any]) -> None:
    required = {"harnessRoot", "projectId", "projectRoot", "state"}
    allowed = {
        *required,
        "active_attempts",
        "dag",
        "frontier",
        "next_action",
        "supersession_lineage",
    }
    if set(result) - allowed or required - set(result):
        _fail("internal_error", "run executor returned an invalid result")
    if not all(isinstance(result[key], str) for key in ("harnessRoot", "projectId", "projectRoot")):
        _fail("internal_error", "run executor returned an invalid result")
    if "dag" in result and result["dag"] is not None and not isinstance(result["dag"], str):
        _fail("internal_error", "run executor returned an invalid result")
    state = result["state"]
    if not isinstance(state, Mapping) or state.get("state") not in {
        "aborted",
        "attention_needed",
        "done",
        "draft",
        "failed",
        "mission_planning",
        "mission_running",
    }:
        _fail("internal_error", "run executor returned an invalid result")


def load_executor(reference: str) -> Callable[[str, Mapping[str, Any], Any], Mapping[str, Any]]:
    """Resolve the deliberately small worker integration seam."""

    module_name, separator, attribute = reference.partition(":")
    if not separator or not module_name or not attribute:
        raise RunControlError("invalid_argument", "executor reference is invalid")
    try:
        candidate = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise RunControlError("provider_unavailable", "run executor is unavailable") from exc
    if not callable(candidate):
        raise RunControlError("provider_unavailable", "run executor is unavailable")
    return candidate


class RunControl:
    """Project-local durable run admission and lifecycle controller."""

    def __init__(
        self,
        project_root: str | Path,
        *,
        executor_ref: str,
        custody_root_id: str = "local:unrest-run-control",
        owner_id: str | None = None,
        python_executable: str | None = None,
        worker_environment: Mapping[str, str] | None = None,
        secret_set_version_id: str = "secret-set:run-control:v1",
        project_inspector: Callable[[str], Mapping[str, Any]] | None = None,
        steering_handler: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        recover: bool = True,
    ) -> None:
        self.project_root = Path(os.path.abspath(os.fspath(project_root)))
        if not self.project_root.is_dir():
            _fail("invalid_argument", "project root is not a directory")
        self.executor_ref = executor_ref
        load_executor(executor_ref)
        self.custody_root_id = custody_root_id
        self.owner_id = owner_id or f"server:{os.getpid()}:{os.urandom(6).hex()}"
        self.python_executable = python_executable or sys.executable
        self.worker_environment = dict(worker_environment or {})
        self.secret_set_version_id = secret_set_version_id
        self.project_inspector = project_inspector
        self.steering_handler = steering_handler
        self.durable_root = self.project_root / ".unrest" / "runs"
        self.runtime_root = self.project_root / ".unrest-runtime" / "runs"
        for path in (self.durable_root, self.runtime_root, self.runtime_root / "locks"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.foundation = FoundationStore(self.project_root, custody_root_id=custody_root_id)
        # Report of the latest recover() pass as sorted (run_id, code) pairs:
        # typed STOP-A1 conflicts, held/quarantined admissions and halted work
        # (ADR-0500, ADR-0502). No terminal outcome is invented for them.
        self.recovery_blocked: tuple[tuple[str, str], ...] = ()
        if recover:
            self.recover()

    def submit_run(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        idempotency_key: str,
    ) -> RunSummary:
        if operation not in RUN_OPERATIONS:
            _fail("invalid_argument", "operation is not asynchronously admissible")
        if not isinstance(arguments, Mapping):
            _fail("invalid_argument", "arguments must be an object")
        _validate_text(idempotency_key, "idempotency_key")
        _validate_arguments(operation, arguments)
        resource_key, project_id = _resource_for(operation, arguments)
        request_fingerprint = _sha256(
            _json_bytes(
                {
                    "arguments": dict(arguments),
                    "idempotency_key": idempotency_key,
                    "operation": operation,
                    "schema_version": 1,
                }
            )
        )
        run_token = request_fingerprint.removeprefix(_DIGEST_PREFIX)
        run_id = f"run:{run_token}"
        with _exclusive_lock(self.runtime_root / "admission.lock"):
            # ADR-0502: classify every retained claim before deciding; the
            # index is a projection and never short-cuts this preflight.
            view = self._admission_view()
            members = view.groups.get(_safe_token(idempotency_key), ())
            if len(members) > 1:
                _fail("admission_key_conflict", "idempotency key has conflicting admissions")
            if members:
                bound = view.claims[members[0]]
                if bound.latest is None:
                    if bound.request.run_id == run_id:
                        _fail("admission_incomplete", "run admission is incomplete")
                    _fail("conflict", "idempotency key is held by an incomplete admission")
                if bound.request.run_id != run_id:
                    _fail("conflict", "idempotency key was used for another request")
                # Read-only exact dedupe: the original receipt, without any
                # write, index repair, project inspection or launch.
                return self._admission_summary(run_id)
            if resource_key in view.held_resources:
                _fail("admission_resource_blocked", "resource is held by an unresolved admission")
            for claim in view.claims.values():
                if claim.latest in _ACTIVE_RUN_STATES and claim.request.resource_key == resource_key:
                    _fail("busy", "resource already has an active run")
            self._require_admissible_run_dir(run_id)
            created_at = _utc_now()
            issuer_identity, run_identity, control_identity = self._construct_identities(
                run_id, operation, idempotency_key, request_fingerprint
            )
            request = _Request(
                run_id=run_id,
                operation=operation,
                arguments=dict(arguments),
                idempotency_key=idempotency_key,
                resource_key=resource_key,
                project_id=project_id,
                created_at=created_at,
                run_identity_digest=run_identity.digest,
                control_identity_digest=control_identity.digest,
                issuer_identity_digest=issuer_identity.digest,
                generation=1,
            )
            # Stage outcomes (ADR-0502 Decision 7). The first queued event is the
            # commit fact: before its helper runs nothing is committed, once it
            # is entered the outcome is unknown, and only after it returns is a
            # failed index write a committed projection failure. Errors are
            # raised outside the handler so no OSError detail is chained.
            stage_failure: tuple[str, str] | None = None
            try:
                self.foundation.append_identity(issuer_identity)
                self.foundation.append_identity(run_identity)
                self.foundation.append_identity(control_identity)
                self._append_request(request)
            except OSError:
                stage_failure = ("admission_io_not_committed", "admission was not committed")
            if stage_failure is None:
                try:
                    self._append_event(run_id, "queued", {"owner_id": self.owner_id})
                except OSError:
                    stage_failure = ("admission_io_unknown", "admission outcome is unknown")
            if stage_failure is None:
                try:
                    self._append_idempotency(idempotency_key, run_id)
                except OSError:
                    stage_failure = (
                        "admission_committed_io_error",
                        "admission committed; projection write failed",
                    )
            if stage_failure is not None:
                _fail(*stage_failure)
            admitted = self._admission_summary(run_id)
            with _exclusive_lock(self._run_lock(run_id)):
                if self.inspect_run(run_id).state == "queued":
                    self._spawn(request)
        return admitted

    def inspect_run(self, run_id: str) -> RunSummary:
        request = self._load_request(run_id)
        events = self._load_events(run_id)
        if not events:
            self._reject_empty_stream(run_id)
        latest = events[-1]
        result: Mapping[str, Any] | None = None
        result_path = self._run_dir(run_id) / "result.json"
        if result_path.exists() and latest.state in {
            "effect_complete", "report_complete", "succeeded", "attention"
        }:
            loaded = self._read_json(result_path)
            if isinstance(loaded, Mapping):
                result = loaded
        error = latest.details.get("error")
        if not isinstance(error, Mapping):
            error = None
        receipt_id = latest.details.get("receipt_id")
        if not isinstance(receipt_id, str):
            receipt_id = self._terminal_receipt_id(events)
        active_attempts: tuple[Mapping[str, Any], ...] = ()
        if (
            request.operation in {"advance_project", "end_mission"}
            and latest.state not in TERMINAL_RUN_STATES
            and request.project_id is not None
            and self.project_inspector is not None
        ):
            inspected = self.project_inspector(request.project_id)
            rows = inspected.get("active_attempts", [])
            if not isinstance(rows, list) or not all(
                isinstance(item, Mapping) for item in rows
            ):
                _fail("integrity_error", "active attempt projection is invalid")
            active_attempts = tuple(dict(item) for item in rows)
        return RunSummary(
            run_id=request.run_id,
            operation=request.operation,
            state=latest.state,
            resource_key=request.resource_key,
            idempotency_key=request.idempotency_key,
            project_id=request.project_id,
            created_at=request.created_at,
            updated_at=latest.observed_at,
            result=result,
            error=dict(error) if error is not None else None,
            receipt_id=receipt_id,
            active_attempts=active_attempts,
        )

    def steer_attempt(
        self,
        run_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Route attached steering without copying its private body into run state."""
        incomplete = False
        try:
            summary = self.inspect_run(run_id)
        except RunControlError as exc:
            # The api adapter forwards this code unmapped; keep it stable.
            if exc.code != "admission_incomplete":
                raise
            incomplete = True
        if incomplete:
            _fail("invalid_transition", "run is not an active advance_project or end_mission")
        admitted = self._load_request(run_id)
        if (
            admitted.operation not in {"advance_project", "end_mission"}
            or summary.state in TERMINAL_RUN_STATES
        ):
            _fail(
                "invalid_transition",
                "run is not an active advance_project or end_mission",
            )
        if self.steering_handler is None:
            _fail("provider_unavailable", "attached steering is unavailable")
        if (
            request.get("project_id") != admitted.project_id
            or request.get("actor") != "orchestrator"
        ):
            _fail(
                "steering_binding_mismatch",
                "steering binding does not match the attached run",
            )
        try:
            return dict(self.steering_handler(request))
        except RunControlError:
            raise
        except Exception as exc:
            code = str(getattr(exc, "code", "invalid_argument"))
            if code not in {
                "nudge_limit_exceeded",
                "nudge_too_large",
                "not_at_semantic_checkpoint",
                "steering_action_replayed",
                "steering_binding_mismatch",
                "stale_checkpoint_binding",
            }:
                code = "invalid_argument"
            raise RunControlError(code, code.replace("_", " ")) from exc

    def _admission_summary(self, run_id: str) -> RunSummary:
        request = self._load_request(run_id)
        events = self._load_events(run_id)
        if not events or events[0].state != "queued":
            _fail("integrity_error", "run has no admission event")
        admission = events[0]
        return RunSummary(
            run_id=request.run_id,
            operation=request.operation,
            state="queued",
            resource_key=request.resource_key,
            idempotency_key=request.idempotency_key,
            project_id=request.project_id,
            created_at=request.created_at,
            updated_at=admission.observed_at,
            result=None,
            error=None,
            receipt_id=None,
            active_attempts=(),
        )

    def attach_run(
        self,
        run_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_interval: float = 0.02,
    ) -> RunSummary:
        started = time.monotonic()
        while True:
            summary = self.inspect_run(run_id)
            if summary.state in TERMINAL_RUN_STATES:
                request = self._load_request(run_id)
                key = (str(self.project_root.resolve()), run_id, request.generation)
                with _local_workers_lock:
                    worker = _local_workers.get(key)
                if worker is not None:
                    remaining = None if timeout_seconds is None else max(
                        0.0, timeout_seconds - (time.monotonic() - started)
                    )
                    try:
                        worker.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        _fail("timeout", "run worker did not exit")
                    with _local_workers_lock:
                        if _local_workers.get(key) is worker:
                            del _local_workers[key]
                return summary
            if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
                _fail("timeout", "run did not reach a terminal state")
            time.sleep(max(0.001, poll_interval))

    def cancel_run(self, run_id: str, reason: str, idempotency_key: str) -> RunSummary:
        # Pre-journal checks (no journal record is created for these failures).
        self._run_dir(run_id)
        _validate_text(reason, "reason")
        _validate_text(idempotency_key, "idempotency_key")
        self._load_request(run_id)
        if not self._load_events(run_id):
            _fail("not_found", "run was not found")
        request = {
            "idempotency_key": idempotency_key,
            "reason": reason,
            "run_id": run_id,
        }
        key_digest = _sha256(idempotency_key.encode("utf-8"))
        reason_digest = _sha256(reason.encode("utf-8"))

        # Effect and reconcile are one convergence: every signalling decision is
        # gated by durable stop records under the per-run lock, so re-running it
        # after any crash or under a new key cannot deliver a second signal.
        def converge(_: str) -> Mapping[str, Any]:
            with _exclusive_lock(self._run_lock(run_id)):
                self._converge_cancel_unlocked(run_id, key_digest, reason_digest)
            return self.inspect_run(run_id).as_dict()

        try:
            value = DurableMutationJournal(self.project_root).execute(
                operation="cancel_run",
                resource_key=run_id,
                idempotency_key=idempotency_key,
                request=request,
                effect=converge,
                reconcile=converge,
            )
        except MutationJournalError as exc:
            raise RunControlError(exc.code, exc.code.replace("_", " ")) from exc
        try:
            return RunSummary(
                run_id=str(value["run_id"]),
                operation=str(value["operation"]),
                state=str(value["state"]),
                resource_key=str(value["resource_key"]),
                idempotency_key=str(value["idempotency_key"]),
                project_id=str(value["project_id"]) if value["project_id"] is not None else None,
                created_at=str(value["created_at"]),
                updated_at=str(value["updated_at"]),
                result=dict(value["result"]) if isinstance(value["result"], Mapping) else None,
                error=dict(value["error"]) if isinstance(value["error"], Mapping) else None,
                receipt_id=str(value["receipt_id"]) if value["receipt_id"] is not None else None,
                active_attempts=tuple(
                    dict(item) for item in value.get("active_attempts", [])
                    if isinstance(item, Mapping)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RunControlError("integrity_error", "cancel replay record is invalid") from exc

    def _converge_cancel_unlocked(self, run_id: str, key_digest: str, reason_digest: str) -> None:
        events = self._load_events(run_id)
        if not events:
            _fail("integrity_error", "run has no admission event")
        # D6: a terminal run returns its summary before any stop validation.
        if events[-1].state in TERMINAL_RUN_STATES:
            return
        request = self._load_request(run_id)
        self._read_stop_records_unlocked(run_id, events)
        # W3: a receipt committed on this unchanged prefix completes that writer.
        if self._reconcile_pending_terminal_unlocked(run_id) == "adopted":
            return
        events = self._load_events(run_id)
        if events[-1].state == "draining":
            # D7 guard: no request is recorded and no signal is sent at draining.
            if _single_running(events) is not None and self._owner_proof_unlocked(request):
                return
            self._controller_settle_unlocked(run_id)
            return
        binding = _single_running(events)
        if binding is not None:
            # Checked before the request is recorded: a failure after the journal
            # claim leaves no new stop event, record, signal or settlement.
            details = binding.details
            pid = details.get("pid")
            if (
                type(pid) is not int
                or pid <= 1
                or pid == os.getpid()
                or type(details.get("pgid")) is not int
                or type(details.get("generation")) is not int
                or not isinstance(details.get("owner_id"), str)
            ):
                _fail("integrity_error", "run worker binding is invalid")
        if not any(event.state == "cancel_requested" for event in events):
            if events[-1].state not in {"queued", "running", "effect_complete", "report_complete"}:
                _fail("invalid_transition", "run lifecycle transition is invalid")
            self._append_event_unlocked(
                run_id,
                "cancel_requested",
                {
                    "cancel_idempotency_digest": key_digest,
                    "reason_digest": reason_digest,
                    "stop_custody": 1,
                },
            )
            events = self._load_events(run_id)
        marked = _first_marked_request(events)
        records = self._read_stop_records_unlocked(run_id, events)
        if binding is None:
            self._controller_settle_unlocked(run_id)
            return
        pid = int(binding.details["pid"])
        self._poll_local_worker(run_id)
        proof = self._owner_proof_unlocked(request)
        if marked is None or records.attempt is None:
            if not proof:
                self._controller_settle_unlocked(run_id)
            elif marked is not None:
                self._signal_once_unlocked(run_id, binding, marked, pid)
            # A legacy (unmarked) in-flight request never receives a signal.
            return
        delivered = records.delivered
        if delivered is None or delivered["outcome"] == "accepted":
            # Attempt without delivery is ambiguous: the signal may not have been
            # sent, and it is never resent.
            if not proof:
                self._controller_settle_unlocked(run_id)
            return
        self._controller_settle_unlocked(run_id)

    def _signal_once_unlocked(self, run_id: str, binding: _Event, marked: _Event, pid: int) -> None:
        token = binding.event_digest.removeprefix(_DIGEST_PREFIX)
        attempt = _json_bytes(
            {
                "binding": self._expected_binding(binding),
                "identity_strength": "pid_session_only",
                "kind": "stop_attempt",
                "recorded_at": _utc_now(),
                "request_event_digest": marked.event_digest,
                "run_id": run_id,
                "schema_version": 1,
                "signal": "SIGTERM",
            }
        )
        # Any publication error propagates before the syscall: no fall-through to kill.
        if not self._publish_stop_record_unlocked(run_id, token, _STOP_ATTEMPT, attempt):
            return
        outcome: str | None
        try:
            # The owner unwinds its managed children in parent-wait order; group
            # termination can kill those parents first, so no killpg here.
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            outcome = "esrch"
        except PermissionError:
            outcome = "eperm"
        except OSError:
            outcome = None
        else:
            outcome = "accepted"
        if outcome is None:
            return
        delivered = _json_bytes(
            {
                "attempt_digest": _sha256(attempt),
                "kind": "stop_delivery",
                "outcome": outcome,
                "recorded_at": _utc_now(),
                "run_id": run_id,
                "schema_version": 1,
            }
        )
        try:
            self._publish_stop_record_unlocked(run_id, token, _STOP_DELIVERY, delivered)
        except RunControlError:
            return
        if outcome in {"esrch", "eperm"}:
            self._controller_settle_unlocked(run_id)

    def recover(self) -> tuple[RunSummary, ...]:
        """One recovery pass (ADR-0500, ADR-0502).

        Phase A classifies every retained claim without effects; Phase B creates
        missing index projections; Phase C runs per-run actions. The admission
        lock is held throughout, so one snapshot decides the whole pass. An
        attributable repair or action I/O failure halts the remaining work of
        this pass only; a normal return with a non-empty report is partial.
        """
        recovered: list[RunSummary] = []
        entries: dict[tuple[str, int], str] = {}
        self.recovery_blocked = ()

        def report(run_id: str, rank: int, code: str) -> None:
            entries.setdefault((run_id, rank), code)
            # Published at once: an unexpected exception leaves what is known.
            self.recovery_blocked = tuple(
                (name, entries[name, order]) for name, order in sorted(entries)
            )

        with _local_workers_lock:
            for key, worker in list(_local_workers.items()):
                if key[0] == str(self.project_root.resolve()) and worker.poll() is not None:
                    del _local_workers[key]
        with _exclusive_lock(self.runtime_root / "admission.lock"):
            view = self._admission_view()
            for run_id, claim in view.claims.items():
                if run_id in view.quarantined:
                    report(run_id, 0, "admission_key_conflict")
                elif claim.latest is None:
                    report(run_id, 0, "admission_incomplete")
            halted = False
            remaining: list[str] = []
            repairs = [
                run_id
                for run_id, claim in view.claims.items()
                if claim.latest is not None
                and run_id not in view.quarantined
                and claim.key_token not in view.indexed
            ]
            for position, run_id in enumerate(repairs):
                code = self._repair_index(view.claims[run_id].request)
                if code is not None:
                    report(run_id, 1, code)
                    halted = True
                    remaining.extend(repairs[position + 1:])
                    break
            processed: set[str] = set()
            for run_id, claim in view.claims.items():
                if halted:
                    break
                if claim.latest is None:
                    continue
                processed.add(run_id)
                request = claim.request
                with _exclusive_lock(self._run_lock(run_id)):
                    summary = self.inspect_run(run_id)
                    if summary.state in TERMINAL_RUN_STATES:
                        continue
                    cursor = self._load_worker_cursor(run_id)
                    if cursor is not None and self._cursor_matches(request, cursor):
                        if _pid_live(int(cursor["pid"])):
                            recovered.append(summary)
                            continue
                    quarantined = run_id in view.quarantined
                    gated = quarantined or request.resource_key in view.held_resources
                    action_failed = False
                    try:
                        withheld = self._recover_run_unlocked(request, dispatch=not gated)
                        current = self.inspect_run(run_id)
                    except (PendingReceiptConflict, StopCustodyInvalid) as exc:
                        # Typed STOP-A1 conflicts are isolated and the pass goes on.
                        report(run_id, 1, exc.recovery_code)
                        continue
                    except OSError:
                        # Attributed to this run inside its lock; the outcome of
                        # the action is unknown and the rest of the pass halts.
                        action_failed = True
                    if action_failed:
                        report(run_id, 1, "recovery_io_unknown")
                        halted = True
                        continue
                    if withheld and not quarantined:
                        report(run_id, 1, "admission_resource_blocked")
                    recovered.append(current)
            if halted:
                remaining.extend(
                    run_id
                    for run_id, claim in view.claims.items()
                    if claim.latest is not None
                    and claim.latest not in TERMINAL_RUN_STATES
                    and run_id not in processed
                )
                for run_id in remaining:
                    report(run_id, 1, "recovery_halted")
        return tuple(recovered)

    def _repair_index(self, request: _Request) -> str | None:
        """Create a missing index projection with baseline bytes (recover only)."""
        code: str | None = None
        try:
            self._append_idempotency(request.idempotency_key, request.run_id)
        except RunControlError as exc:
            if exc.code != "conflict":
                raise
            code = "admission_key_conflict"
        except OSError:
            code = "admission_committed_io_error"
        return code

    def _recover_run_unlocked(self, request: _Request, *, dispatch: bool = True) -> bool:
        """Recover one run under its lock; True when a queued dispatch was withheld."""
        run_id = request.run_id
        # W4: a run that failed reattach first adopts a committed receipt.
        if self._reconcile_pending_terminal_unlocked(run_id) == "adopted":
            return False
        events = self._load_events(run_id)
        binding = _single_running(events)
        records = self._read_stop_records_unlocked(run_id, events)
        if binding is not None and records.death_required:
            pid = binding.details.get("pid")
            if type(pid) is not int or not _death_proven(pid):
                # EPERM hold: without independent death proof nothing is mutated.
                return False
        latest = events[-1]
        stop_prefix = _is_stop_prefix(events)
        unproven = "owner_unproven" if stop_prefix else None
        ownership_lost = {
            "error": {
                "code": "internal_error",
                "message": "worker ownership could not be recovered",
            }
        }
        if latest.state == "queued":
            if not dispatch:
                # Quarantine or a held resource denies only the new dispatch.
                return True
            self._spawn(request)
        elif latest.state == "cancel_requested":
            self._controller_settle_unlocked(run_id)
        elif latest.state == "draining":
            if latest.details.get("stop_actor") == "controller":
                self._controller_settle_unlocked(run_id)
            else:
                self._finalize_terminal_unlocked(
                    run_id, "attention", error=ownership_lost, settlement="owner_unproven"
                )
        elif latest.state == "report_complete":
            self._finalize_terminal_unlocked(run_id, "succeeded", settlement=unproven)
        elif latest.state == "effect_complete":
            self._append_event_unlocked(run_id, "report_complete", {"recovered": True})
            self._finalize_terminal_unlocked(run_id, "succeeded", settlement=unproven)
        else:
            self._finalize_terminal_unlocked(
                run_id, "attention", error=ownership_lost, settlement=unproven
            )
        return False

    def worker_start(self, run_id: str, *, pid: int, pgid: int, generation: int) -> bool:
        # Equality alone admits aliases such as True or 1.0; require the native int.
        if type(generation) is not int or generation <= 0:
            _fail("invalid_argument", "worker generation must be a positive integer")
        request = self._load_request(run_id)
        if generation != request.generation:
            _fail("stale", "worker generation does not match admission")
        with _exclusive_lock(self._run_lock(run_id)):
            state = self.inspect_run(run_id).state
            if state != "queued":
                return False
            self._write_worker_cursor(request, pid=pid, pgid=pgid)
            self._append_event_unlocked(
                run_id,
                "running",
                {
                    "generation": generation,
                    "owner_id": self.owner_id,
                    "pgid": pgid,
                    "pid": pid,
                },
            )
        return True

    def worker_draining(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            events = self._load_events(run_id)
            if events[-1].state in TERMINAL_RUN_STATES:
                return
            # Draining creates a stop prefix, so only the bound owner may write it.
            self._require_bound_owner(events)
            self._append_event_unlocked(run_id, "draining", {"stop_actor": "owner"})

    def worker_effect_complete(self, run_id: str, result: Mapping[str, Any]) -> None:
        if not isinstance(result, Mapping):
            _fail("internal_error", "run executor returned an invalid result")
        failure = result.get(EXECUTOR_FAILURE_KEY)
        if failure is not None:
            if set(result) != {EXECUTOR_FAILURE_KEY} or not isinstance(failure, Mapping):
                _fail("internal_error", "run executor returned an invalid result")
            public = failure.get("public_error")
            private = failure.get("private_tool_error")
            if (
                not isinstance(public, Mapping)
                or set(public) != {"error"}
                or not isinstance(public.get("error"), Mapping)
                or set(public["error"]) != {"code", "message"}
                or public["error"].get("code") not in {
                    "busy", "invalid_argument", "invalid_transition", "not_found"
                }
                or not isinstance(public["error"].get("message"), str)
                or not isinstance(private, Mapping)
                or set(private) != {"code", "details", "message"}
                or not isinstance(private.get("code"), str)
                or not isinstance(private.get("message"), str)
                or not isinstance(private.get("details"), list)
                or not all(isinstance(item, str) for item in private["details"])
            ):
                _fail("internal_error", "run executor returned an invalid result")
            with _exclusive_lock(self._run_lock(run_id)):
                events = self._load_events(run_id)
                if events[-1].state in TERMINAL_RUN_STATES:
                    return
                stop_prefix = _is_stop_prefix(events)
                if stop_prefix:
                    self._require_bound_owner(events)
                _atomic_private_write(
                    self._run_dir(run_id) / "private" / "tool-error.json",
                    _json_bytes(
                        {
                            "code": private["code"],
                            "details": list(private["details"]),
                            "message": private["message"],
                            "schema_version": 1,
                        }
                    ),
                    immutable=True,
                )
                self._finalize_terminal_unlocked(
                    run_id,
                    "failed",
                    error=public,
                    settlement="owner_failed" if stop_prefix else None,
                )
            return
        _validate_project_envelope(result)
        encoded = _json_bytes(dict(result))
        with _exclusive_lock(self._run_lock(run_id)):
            state = self.inspect_run(run_id).state
            if state in TERMINAL_RUN_STATES:
                return
            _atomic_private_write(self._run_dir(run_id) / "result.json", encoded, immutable=True)
            self._append_event_unlocked(
                run_id,
                "effect_complete",
                {"result_digest": _sha256(encoded)},
            )

    def worker_report_complete(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            if self.inspect_run(run_id).state in TERMINAL_RUN_STATES:
                return
            self._append_event_unlocked(run_id, "report_complete", {})

    def worker_succeeded(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            events = self._load_events(run_id)
            if events[-1].state not in TERMINAL_RUN_STATES:
                stop_prefix = _is_stop_prefix(events)
                if stop_prefix:
                    self._require_bound_owner(events)
                self._finalize_terminal_unlocked(
                    run_id,
                    "succeeded",
                    settlement="owner_completed" if stop_prefix else None,
                )
            self._remove_worker_cursor(run_id)

    def worker_cancelled(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            events = self._load_events(run_id)
            if events[-1].state not in TERMINAL_RUN_STATES:
                self._require_bound_owner(events)
                requested = any(event.state == "cancel_requested" for event in events)
                self._settle_cancel_without_worker_unlocked(
                    run_id,
                    settlement="owner_reported" if requested else "unrequested_owner_cancel",
                    actor="owner",
                )
            self._remove_worker_cursor(run_id)

    def worker_failed(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            events = self._load_events(run_id)
            if events[-1].state in TERMINAL_RUN_STATES:
                return
            stop_prefix = _is_stop_prefix(events)
            if stop_prefix:
                self._require_bound_owner(events)
            states = {event.state for event in events}
            terminal = "attention" if "running" in states else "failed"
            self._finalize_terminal_unlocked(
                run_id,
                terminal,
                error={
                    "error": {
                        "code": "internal_error",
                        "message": "run worker failed",
                    }
                },
                settlement="owner_failed" if stop_prefix else None,
            )
            self._remove_worker_cursor(run_id)

    @contextmanager
    def resource_lock(self, run_id: str) -> Iterator[None]:
        request = self._load_request(run_id)
        path = self.runtime_root / "locks" / f"{_safe_token(request.resource_key)}.lock"
        with _exclusive_lock(path):
            yield

    def request_payload(self, run_id: str) -> tuple[str, Mapping[str, Any]]:
        request = self._load_request(run_id)
        return request.operation, dict(request.arguments)

    def _construct_identities(
        self,
        run_id: str,
        operation: str,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> tuple[IdentityRecord, IdentityRecord, IdentityRecord]:
        token = run_id.removeprefix("run:")
        def derived(label: str) -> str:
            return _sha256(f"{label}\0{request_fingerprint}".encode("utf-8"))
        executor_configuration_digest = _sha256(
            _json_bytes(
                {
                    "environment_names": sorted(self.worker_environment),
                    "executor_ref": self.executor_ref,
                    "schema_version": 1,
                }
            )
        )
        issuer = construct_identity(
            "provider_configuration",
            {
                "provider_configuration_digest": executor_configuration_digest,
                "public_id": "provider_configuration:run-lifecycle-authority",
                "schema_version": 1,
                "secret_set_version_id": self.secret_set_version_id,
            },
        )
        run = construct_identity(
            "run",
            {
                "accepted_working_point_digest": derived("accepted"),
                "base_revision": hashlib.sha1(request_fingerprint.encode("ascii")).hexdigest(),
                "budget_envelope": {"amount": 1, "unit": "steps"},
                "candidate_digest": derived("candidate"),
                "capability_policy_digest": derived("policy"),
                "context_digest": derived("context"),
                "environment_digest": derived("environment"),
                "evaluator_digest": derived("evaluator"),
                "provider_configuration_digest": issuer.digest,
                "public_id": run_id,
                "route_profile_digest": derived("route"),
                "schema_version": 1,
                "secret_set_version_id": self.secret_set_version_id,
                "seed": int(token[:12], 16),
                "workload_digest": derived("workload"),
                "workspace_lease_id": f"lease:run-{token}",
            },
        )
        control = construct_identity(
            "control_operation",
            {
                "idempotency_key_digest": _sha256(idempotency_key.encode("utf-8")),
                "operation": operation,
                "public_id": f"control_operation:{token}",
                "run_digest": run.digest,
                "schema_version": 1,
            },
        )
        return issuer, run, control

    def _append_request(self, request: _Request) -> None:
        content = _json_bytes(
            {
                "arguments": dict(request.arguments),
                "control_identity_digest": request.control_identity_digest,
                "created_at": request.created_at,
                "generation": request.generation,
                "idempotency_key": request.idempotency_key,
                "issuer_identity_digest": request.issuer_identity_digest,
                "operation": request.operation,
                "project_id": request.project_id,
                "resource_key": request.resource_key,
                "run_id": request.run_id,
                "run_identity_digest": request.run_identity_digest,
                "schema_version": 1,
            }
        )
        path = self._run_dir(request.run_id) / "request.json"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_private_write(path, content, immutable=True)

    def _load_request(self, run_id: str) -> _Request:
        _validate_text(run_id, "run_id")
        path = self._run_dir(run_id) / "request.json"
        if not path.is_file():
            _fail("not_found", "run was not found")
        # The per-run path applies the same raw V1-V5 as admission (ADR-0503).
        return self._validated_request(run_id.removeprefix("run:"), self._read_record(path))

    @staticmethod
    def _read_record(path: Path) -> Any:
        """Decode one request/event record; decoder failures are corruption.

        ``_read_json`` stays the shared reader of result and cursor records; only
        request and event reads also contain the remaining decoder failures
        (integer digit limit, ``RecursionError``).
        """
        try:
            return RunControl._read_json(path)
        except (ValueError, RecursionError) as exc:
            raise RunControlError("integrity_error", "run record is invalid") from exc

    @staticmethod
    def _request_from_value(value: Mapping[str, Any]) -> _Request:
        """Exact native types of the remaining fields; no coercion (ADR-0503 D1)."""
        project_id = value.get("project_id")
        generation = value.get("generation")
        schema_version = value.get("schema_version")
        if (
            not _REQUEST_REQUIRED_KEYS <= value.keys()
            or any(type(value[name]) is not str for name in _REQUEST_STRING_FIELDS)
            or (project_id is not None and type(project_id) is not str)
            or type(generation) is not int
            or generation <= 0
            or ("schema_version" in value and type(schema_version) is not int)
            or not _all_finite(value)
        ):
            _fail("integrity_error", "run request is invalid")
        return _Request(
            run_id=value["run_id"],
            operation=value["operation"],
            arguments=dict(value["arguments"]),
            idempotency_key=value["idempotency_key"],
            resource_key=value["resource_key"],
            project_id=project_id,
            created_at=value["created_at"],
            run_identity_digest=value["run_identity_digest"],
            control_identity_digest=value["control_identity_digest"],
            issuer_identity_digest=value["issuer_identity_digest"],
            generation=generation,
        )

    def _validated_request(self, token: str, value: Any) -> _Request:
        """V1-V5 of ADR-0502 on the raw stored fields, then native types."""
        valid = _HEX_TOKEN.fullmatch(token) is not None and type(value) is dict
        if valid:
            operation = value.get("operation")
            key = value.get("idempotency_key")
            arguments = value.get("arguments")
            valid = (
                value.get("run_id") == f"run:{token}"
                and type(operation) is str
                and operation in RUN_OPERATIONS
                and type(key) is str
                and bool(key)
                and type(arguments) is dict
            )
        if valid:
            # The baseline fingerprint over the stored values: no normalization,
            # and fields outside it (created_at, resource_key) are not bound.
            try:
                fingerprint = hashlib.sha256(
                    _json_bytes(
                        {
                            "arguments": arguments,
                            "idempotency_key": key,
                            "operation": operation,
                            "schema_version": 1,
                        }
                    )
                ).hexdigest()
            except (RunControlError, RecursionError):
                fingerprint = ""
            valid = fingerprint == token
        if not valid:
            _fail("integrity_error", "run request is invalid")
        return self._request_from_value(value)

    def _admission_events(self, run_id: str) -> tuple[_Event, ...]:
        """Read a stream lock-free; confirm an apparent defect under the run lock.

        A directory listing may miss an event linked concurrently by a worker,
        so a suspicious stream is re-read once under its run lock (admission
        lock already held) before it is declared corrupt.
        """
        try:
            return self._load_events(run_id)
        except RunControlError:
            pass
        with _exclusive_lock(self._run_lock(run_id)):
            return self._load_events(run_id)

    @staticmethod
    def _entry_exists(path: Path) -> bool:
        failed = False
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            failed = True
        if failed:
            _fail("integrity_error", "run record is invalid")
        return True

    @staticmethod
    def _index_target(path: Path, key_token: str) -> str:
        """Run id of an exactly canonical index record (I1/I2), else corruption."""
        content: bytes | None = None
        try:
            if stat.S_ISREG(path.lstat().st_mode):
                content = path.read_bytes()
        except OSError:
            content = None
        target: Any = None
        if content is not None:
            try:
                value = json.loads(content)
            except (ValueError, UnicodeError, RecursionError):
                value = None
            if isinstance(value, dict):
                target = value.get("run_id")
        if not isinstance(target, str):
            _fail("integrity_error", "idempotency record is invalid")
        try:
            canonical = _json_bytes(
                {"key_digest": _DIGEST_PREFIX + key_token, "run_id": target, "schema_version": 1}
            )
        except (RunControlError, RecursionError) as exc:
            raise RunControlError("integrity_error", "idempotency record is invalid") from exc
        if content != canonical:
            _fail("integrity_error", "idempotency record is invalid")
        return target

    def _require_recognizable_incomplete(self, run_id: str, *, indexed: bool) -> None:
        """X1-X5: an empty stream with any later evidence is corruption."""
        directory = self._run_dir(run_id)
        evidence = (
            directory / "result.json",
            directory / "private",
            directory / "stop",
            self.runtime_root / f"{_safe_token(run_id)}.worker.json",
        )
        if indexed or any(self._entry_exists(path) for path in evidence):
            _fail("integrity_error", "run has no admission event")

    def _reject_empty_stream(self, run_id: str) -> NoReturn:
        """Per-run view of a request without events (no admission lock taken)."""
        token = run_id.removeprefix("run:")
        request = self._validated_request(
            token, self._read_record(self._run_dir(run_id) / "request.json")
        )
        key_token = _safe_token(request.idempotency_key)
        index = self.durable_root / "idempotency" / f"{key_token}.json"
        indexed = self._entry_exists(index) and self._index_target(index, key_token) == run_id
        self._require_recognizable_incomplete(run_id, indexed=indexed)
        _fail("admission_incomplete", "run admission is incomplete")

    def _admission_view(self) -> _AdmissionView:
        """Effect-free preflight over all retained claims (caller holds admission)."""
        claims: dict[str, _Claim] = {}
        for path in sorted(self.durable_root.glob("*/request.json")):
            request = self._validated_request(path.parent.name, self._read_record(path))
            events = self._admission_events(request.run_id)
            if events and events[0].state != "queued":
                _fail("integrity_error", "run has no admission event")
            claims[request.run_id] = _Claim(
                request=request,
                key_token=_safe_token(request.idempotency_key),
                latest=events[-1].state if events else None,
            )
        indexed: dict[str, str] = {}
        for path in sorted((self.durable_root / "idempotency").glob("*.json")):
            key_token = path.name.removesuffix(".json")
            if _HEX_TOKEN.fullmatch(key_token) is None:
                _fail("integrity_error", "idempotency record is invalid")
            target = self._index_target(path, key_token)
            claim = claims.get(target)
            if claim is None or claim.key_token != key_token:
                _fail("integrity_error", "idempotency record is invalid")
            indexed[key_token] = target
        indexed_runs = set(indexed.values())
        for run_id, claim in claims.items():
            if claim.latest is None:
                self._require_recognizable_incomplete(run_id, indexed=run_id in indexed_runs)
        grouped: dict[str, list[str]] = {}
        for run_id, claim in claims.items():
            grouped.setdefault(claim.key_token, []).append(run_id)
        quarantined = frozenset(
            run_id for members in grouped.values() if len(members) > 1 for run_id in members
        )
        held = frozenset(
            claim.request.resource_key
            for run_id, claim in claims.items()
            if claim.latest is None or run_id in quarantined
        )
        return _AdmissionView(
            claims=claims,
            groups={key: tuple(members) for key, members in grouped.items()},
            indexed=indexed,
            quarantined=quarantined,
            held_resources=held,
        )

    def _require_admissible_run_dir(self, run_id: str) -> None:
        """Admit only into an absent, empty or staging-only run directory.

        Leftover ``.run-*`` staging files of a pre-link request publication
        failure are preserved unchanged; anything else conflicts (ADR-0502 D9).
        """
        directory = self._run_dir(run_id)
        verdict: str | None = None
        try:
            mode = directory.lstat().st_mode
        except FileNotFoundError:
            return
        except OSError:
            verdict = "run record is invalid"
        else:
            if not stat.S_ISDIR(mode):
                verdict = "run record conflicts"
            else:
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if not entry.name.startswith(".run-") or not entry.is_file(
                                follow_symlinks=False
                            ):
                                verdict = "run record conflicts"
                                break
                except OSError:
                    verdict = "run record is invalid"
        if verdict is not None:
            _fail("integrity_error", verdict)

    def _run_dir(self, run_id: str) -> Path:
        if not isinstance(run_id, str) or not run_id.startswith("run:"):
            _fail("invalid_argument", "run_id is invalid")
        token = run_id.removeprefix("run:")
        if len(token) != 64 or any(character not in "0123456789abcdef" for character in token):
            _fail("invalid_argument", "run_id is invalid")
        return self.durable_root / token

    def _run_lock(self, run_id: str) -> Path:
        return self.runtime_root / f"{_safe_token(run_id)}.lock"

    def _append_event(self, run_id: str, state: str, details: Mapping[str, Any]) -> _Event:
        with _exclusive_lock(self._run_lock(run_id)):
            return self._append_event_unlocked(run_id, state, details)

    def _append_event_unlocked(self, run_id: str, state: str, details: Mapping[str, Any]) -> _Event:
        events = self._load_events(run_id)
        self._validate_transition(events[-1].state if events else None, state)
        sequence = len(events) + 1
        previous = events[-1].event_digest if events else None
        observed_at = _utc_now()
        body = {
            "details": dict(details),
            "observed_at": observed_at,
            "previous_event_digest": previous,
            "run_id": run_id,
            "schema_version": 1,
            "sequence": sequence,
            "state": state,
        }
        digest = _sha256(b"unrest.run-event.v1\0" + _json_bytes(body))
        record = {**body, "event_digest": digest}
        path = self._run_dir(run_id) / "events" / f"{sequence:020d}.json"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_private_write(path, _json_bytes(record), immutable=True)
        return _Event(sequence, state, observed_at, digest, previous, dict(details))

    @staticmethod
    def _validate_transition(previous: str | None, state: str) -> None:
        allowed: dict[str | None, frozenset[str]] = {
            None: frozenset({"queued"}),
            "queued": frozenset({"cancel_requested", "failed", "running"}),
            "running": frozenset(
                {"attention", "cancel_requested", "draining", "effect_complete", "failed"}
            ),
            "cancel_requested": frozenset(
                {"attention", "cancelled", "draining", "effect_complete", "failed"}
            ),
            "draining": frozenset({"attention", "cancelled", "effect_complete", "failed"}),
            "effect_complete": frozenset(
                {"attention", "cancel_requested", "failed", "report_complete"}
            ),
            "report_complete": frozenset(
                {"attention", "cancel_requested", "failed", "succeeded"}
            ),
        }
        if state not in allowed.get(previous, frozenset()):
            _fail("invalid_transition", "run lifecycle transition is invalid")

    def _load_events(self, run_id: str) -> tuple[_Event, ...]:
        """Replay a stored stream; the first defective file decides (ADR-0503 D2).

        Per file: decode, object, envelope native types and finite values, chain
        equalities and digest, then the first event is ``queued`` and every later
        state is a RunState reached by an edge of ``_validate_transition``.
        """
        events: list[_Event] = []
        predecessor: str | None = None
        for expected, path in enumerate(sorted((self._run_dir(run_id) / "events").glob("*.json")), 1):
            value = self._read_record(path)
            if (
                type(value) is not dict
                or not _EVENT_REQUIRED_KEYS <= value.keys()
                or type(value["run_id"]) is not str
                or type(value["sequence"]) is not int
                or (
                    value["previous_event_digest"] is not None
                    and type(value["previous_event_digest"]) is not str
                )
                or type(value["event_digest"]) is not str
                or type(value["state"]) is not str
                or type(value["observed_at"]) is not str
                or type(value["details"]) is not dict
                or ("schema_version" in value and type(value["schema_version"]) is not int)
                or not _all_finite(value)
            ):
                _fail("integrity_error", "run event is invalid")
            if (
                value["run_id"] != run_id
                or value["sequence"] != expected
                or value["previous_event_digest"] != predecessor
            ):
                _fail("integrity_error", "run event chain is invalid")
            body = dict(value)
            supplied = body.pop("event_digest")
            try:
                computed = _sha256(b"unrest.run-event.v1\0" + _json_bytes(body))
            except (RunControlError, RecursionError) as exc:
                raise RunControlError("integrity_error", "run event is invalid") from exc
            if supplied != computed:
                _fail("integrity_error", "run event chain is invalid")
            state = value["state"]
            if not events:
                if state != "queued":
                    _fail("integrity_error", "run has no admission event")
            else:
                if state not in _RUN_STATE_VALUES:
                    _fail("integrity_error", "run event is invalid")
                try:
                    self._validate_transition(events[-1].state, state)
                except RunControlError as exc:
                    if exc.code != "invalid_transition":
                        raise
                    raise RunControlError("integrity_error", "run event chain is invalid") from exc
            events.append(
                _Event(expected, state, value["observed_at"], supplied, predecessor, dict(value["details"]))
            )
            predecessor = supplied
        return tuple(events)

    def _append_idempotency(self, key: str, run_id: str) -> None:
        directory = self.durable_root / "idempotency"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_private_write(
            directory / f"{_safe_token(key)}.json",
            _json_bytes({"key_digest": _sha256(key.encode("utf-8")), "run_id": run_id, "schema_version": 1}),
            immutable=True,
        )

    def _spawn(self, request: _Request) -> None:
        command = [
            self.python_executable,
            "-m",
            "unrest_harness.run_worker",
            "--project-root",
            str(self.project_root),
            "--run-id",
            request.run_id,
            "--executor",
            self.executor_ref,
            "--custody-root-id",
            self.custody_root_id,
            "--generation",
            str(request.generation),
        ]
        try:
            package_source = str(Path(__file__).resolve().parent.parent)
            worker_environment = {
                "LANG": "C.UTF-8",
                "PATH": os.defpath,
                "PYTHONPATH": package_source,
                **self.worker_environment,
            }
            with _local_workers_lock:
                key = (str(self.project_root.resolve()), request.run_id, request.generation)
                existing = _local_workers.get(key)
                if existing is not None and existing.poll() is None:
                    return
                worker = subprocess.Popen(
                    command,
                    cwd=self.project_root,
                    env=worker_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                )
                _local_workers[key] = worker
        except OSError as exc:
            self._finalize_terminal_unlocked(
                request.run_id,
                "failed",
                error={"error": {"code": "internal_error", "message": "run worker could not start"}},
            )
            raise RunControlError("internal_error", "run worker could not start") from exc

    def _write_worker_cursor(self, request: _Request, *, pid: int, pgid: int) -> None:
        path = self.runtime_root / f"{_safe_token(request.run_id)}.worker.json"
        _atomic_private_write(
            path,
            _json_bytes(
                {
                    "control_identity_digest": request.control_identity_digest,
                    "generation": request.generation,
                    "owner_id": self.owner_id,
                    "pgid": pgid,
                    "pid": pid,
                    "run_id": request.run_id,
                    "schema_version": 1,
                    "updated_at": _utc_now(),
                }
            ),
            immutable=False,
        )

    def _load_worker_cursor(self, run_id: str) -> Mapping[str, Any] | None:
        path = self.runtime_root / f"{_safe_token(run_id)}.worker.json"
        if not path.exists():
            return None
        value = self._read_json(path)
        if not isinstance(value, Mapping):
            _fail("integrity_error", "worker cursor is invalid")
        return value

    def _cursor_matches(self, request: _Request, cursor: Mapping[str, Any]) -> bool:
        events = self._load_events(request.run_id)
        worker_events = [event for event in events if event.state == "running"]
        if not worker_events:
            return False
        durable = worker_events[-1].details
        matches = (
            cursor.get("run_id") == request.run_id
            and cursor.get("generation") == request.generation
            and cursor.get("control_identity_digest") == request.control_identity_digest
            and isinstance(cursor.get("pid"), int)
            and isinstance(cursor.get("pgid"), int)
            and cursor.get("pid") == durable.get("pid")
            and cursor.get("pgid") == durable.get("pgid")
            and cursor.get("generation") == durable.get("generation")
            and cursor.get("owner_id") == durable.get("owner_id")
        )
        if not matches:
            return False
        pid = int(cursor["pid"])
        pgid = int(cursor["pgid"])
        try:
            return pid == pgid and os.getpgid(pid) == pgid and os.getsid(pid) == pgid
        except OSError:
            return False

    def _remove_worker_cursor(self, run_id: str) -> None:
        (self.runtime_root / f"{_safe_token(run_id)}.worker.json").unlink(missing_ok=True)

    def _settle_cancel_without_worker_unlocked(
        self,
        run_id: str,
        *,
        settlement: str,
        actor: Literal["controller", "owner"],
    ) -> None:
        # W2: a committed receipt on this prefix wins over a synthesized draining.
        if self._reconcile_pending_terminal_unlocked(run_id) == "adopted":
            return
        events = self._load_events(run_id)
        if events[-1].state in TERMINAL_RUN_STATES:
            return
        states = {event.state for event in events}
        if states & {"effect_complete", "report_complete"}:
            self._finalize_terminal_unlocked(
                run_id,
                "attention",
                error={
                    "error": {
                        "code": "cancelled",
                        "message": "cancellation followed a completed effect",
                    }
                },
                settlement=settlement if _is_stop_prefix(events) else None,
            )
        else:
            if events[-1].state != "draining":
                self._append_event_unlocked(run_id, "draining", {"stop_actor": actor})
            self._finalize_terminal_unlocked(run_id, "cancelled", settlement=settlement)

    def _finalize_terminal_unlocked(
        self,
        run_id: str,
        state: str,
        *,
        error: Mapping[str, Any] | None = None,
        settlement: str | None = None,
    ) -> None:
        # Decisions use the event snapshot, never inspect_run/project_inspector,
        # because every caller already holds the per-run lock.
        events = self._load_events(run_id)
        if events[-1].state in TERMINAL_RUN_STATES:
            return
        # W1: adopt a receipt committed on this exact prefix before issuing our own.
        if self._reconcile_pending_terminal_unlocked(run_id) == "adopted":
            return
        # Validate before publishing a receipt (G14): a receipt for a transition
        # that cannot be recorded would later collide on receipt_id.
        self._validate_transition(events[-1].state, state)
        stop_prefix = _is_stop_prefix(events)
        if stop_prefix and settlement not in _STOP_SETTLEMENTS:
            _fail("internal_error", "stop terminal requires a settlement class")
        if not stop_prefix and settlement is not None:
            _fail("internal_error", "settlement class requires a stop prefix")
        request = self._load_request(run_id)
        outcome = {"attention": "partial", "cancelled": "cancelled", "failed": "failed", "succeeded": "succeeded"}[state]
        receipt = self._construct_run_receipt(request, outcome)
        self.foundation.append_receipt(receipt, custodian=_run_custodian())
        details: dict[str, Any] = {
            "receipt_digest": receipt.digest,
            "receipt_id": receipt.record["receipt_id"],
        }
        if error is not None:
            details["error"] = dict(error)
        if settlement is not None:
            details["stop_settlement"] = settlement
        self._append_event_unlocked(run_id, state, details)

    def _pending_receipt_unlocked(
        self,
        request: _Request,
        events: tuple[_Event, ...],
    ) -> tuple[str, Any] | None:
        """Return the single adoptable committed receipt on the current prefix.

        Only the four receipts this prefix can produce are probed. Absence is
        recognised only from ``not_found``; anything else is a conflict.
        """
        found: list[tuple[str, Any]] = []
        for outcome in _RECEIPT_TERMINALS:
            candidate = self._construct_run_receipt(request, outcome)
            try:
                self.foundation.load_receipt("run_receipt.v1", candidate.digest)
            except FoundationValidationError as exc:
                if exc.code == "not_found":
                    continue
                raise PendingReceiptConflict() from exc
            except OSError as exc:
                raise PendingReceiptConflict() from exc
            found.append((outcome, candidate))
        if not found:
            return None
        if len(found) != 1:
            raise PendingReceiptConflict()
        outcome, candidate = found[0]
        try:
            self._validate_transition(events[-1].state, _RECEIPT_TERMINALS[outcome])
        except RunControlError as exc:
            raise PendingReceiptConflict() from exc
        states = {event.state for event in events}
        if outcome == "succeeded" and not {"effect_complete", "report_complete"} <= states:
            raise PendingReceiptConflict()
        return outcome, candidate

    def _reconcile_pending_terminal_unlocked(self, run_id: str) -> Literal["none", "adopted"]:
        """W1-W4: adopt a receipt committed by a crashed terminal writer.

        The terminal run event stays the sole authoritative receipt reference;
        unreferenced receipts of superseded prefixes are tolerated evidence.
        """
        events = self._load_events(run_id)
        if not events or events[-1].state in TERMINAL_RUN_STATES:
            return "none"
        self._read_stop_records_unlocked(run_id, events)
        pending = self._pending_receipt_unlocked(self._load_request(run_id), events)
        if pending is None:
            return "none"
        outcome, receipt = pending
        try:
            # Re-append is byte-idempotent and repairs missing local custody.
            self.foundation.append_receipt(receipt, custodian=_run_custodian())
        except FoundationValidationError as exc:
            raise PendingReceiptConflict() from exc
        details: dict[str, Any] = {
            "receipt_digest": receipt.digest,
            "receipt_id": receipt.record["receipt_id"],
            "terminal_source": "pending_receipt",
        }
        if outcome in {"partial", "failed"}:
            details["error"] = dict(_PENDING_RECEIPT_ERROR)
        if _is_stop_prefix(events):
            details["stop_settlement"] = (
                "never_dispatched" if _single_running(events) is None else "owner_unproven"
            )
        self._append_event_unlocked(run_id, _RECEIPT_TERMINALS[outcome], details)
        return "adopted"

    def _require_bound_owner(self, events: tuple[_Event, ...]) -> None:
        running = [event for event in events if event.state == "running"]
        if len(running) != 1:
            _fail("integrity_error", "caller is not the bound run owner")
        details = running[0].details
        pid = details.get("pid")
        if type(pid) is not int or pid != os.getpid() or details.get("owner_id") != self.owner_id:
            _fail("integrity_error", "caller is not the bound run owner")

    def _owner_proof_unlocked(self, request: _Request) -> bool:
        # pid_session_only: retained solely for manual compatibility (ADR-0500 4);
        # vulnerable to PID reuse and check-to-signal races.
        cursor = self._load_worker_cursor(request.run_id)
        if cursor is None or not self._cursor_matches(request, cursor):
            return False
        return _pid_live(int(cursor["pid"]))

    def _poll_local_worker(self, run_id: str) -> None:
        # Non-blocking reap so an exited local child stops answering kill(pid, 0).
        root = str(self.project_root.resolve())
        with _local_workers_lock:
            for key, worker in list(_local_workers.items()):
                if key[0] == root and key[1] == run_id:
                    worker.poll()

    def _controller_settle_unlocked(self, run_id: str) -> bool:
        events = self._load_events(run_id)
        binding = _single_running(events)
        records = self._read_stop_records_unlocked(run_id, events)
        if binding is not None and records.death_required:
            pid = binding.details.get("pid")
            if type(pid) is not int or not _death_proven(pid):
                return False
        self._settle_cancel_without_worker_unlocked(
            run_id,
            settlement="never_dispatched" if binding is None else "owner_unproven",
            actor="controller",
        )
        return True

    def _stop_directory(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "stop"

    @staticmethod
    def _validate_stop_events(events: tuple[_Event, ...]) -> None:
        for event in events:
            details = event.details
            if event.state == "cancel_requested":
                keys = set(details)
                if keys == _MARKED_CANCEL_KEYS:
                    marker = details["stop_custody"]
                    if type(marker) is not int or marker != 1:
                        raise StopCustodyInvalid()
                elif keys != _LEGACY_CANCEL_KEYS:
                    raise StopCustodyInvalid()
                for name in ("cancel_idempotency_digest", "reason_digest"):
                    value = details[name]
                    if not isinstance(value, str) or _DIGEST_VALUE.fullmatch(value) is None:
                        raise StopCustodyInvalid()
            elif event.state == "draining":
                if details and (
                    set(details) != {"stop_actor"}
                    or not isinstance(details["stop_actor"], str)
                    or details["stop_actor"] not in _STOP_ACTORS
                ):
                    raise StopCustodyInvalid()
            elif event.state in TERMINAL_RUN_STATES:
                keys = set(details)
                if not _TERMINAL_REQUIRED_KEYS <= keys or keys - (
                    _TERMINAL_REQUIRED_KEYS | _TERMINAL_OPTIONAL_KEYS
                ):
                    raise StopCustodyInvalid()
                if "stop_settlement" in details and (
                    not isinstance(details["stop_settlement"], str)
                    or details["stop_settlement"] not in _STOP_SETTLEMENTS
                ):
                    raise StopCustodyInvalid()
                if "terminal_source" in details and details["terminal_source"] != "pending_receipt":
                    raise StopCustodyInvalid()

    @staticmethod
    def _expected_binding(binding: _Event) -> dict[str, Any]:
        details = binding.details
        return {
            "generation": details.get("generation"),
            "owner_id": details.get("owner_id"),
            "pgid": details.get("pgid"),
            "pid": details.get("pid"),
            "running_event_digest": binding.event_digest,
        }

    @staticmethod
    def _stop_record_bytes(path: Path) -> bytes | None:
        # Absence is recognised only from FileNotFoundError of lstat.
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StopCustodyInvalid() from exc
        if not stat.S_ISREG(mode):
            raise StopCustodyInvalid()
        try:
            return path.read_bytes()
        except OSError as exc:
            raise StopCustodyInvalid() from exc

    def _read_stop_records_unlocked(self, run_id: str, events: tuple[_Event, ...]) -> _StopRecords:
        """Fail-closed validation of stop events and the stop/ custody tree."""
        self._validate_stop_events(events)
        binding = _single_running(events)
        stop_directory = self._stop_directory(run_id)
        for component in (stop_directory.parent, stop_directory):
            try:
                mode = component.lstat().st_mode
            except FileNotFoundError:
                if component == stop_directory:
                    return _StopRecords(None, None)
                raise StopCustodyInvalid()
            except OSError as exc:
                raise StopCustodyInvalid() from exc
            if not stat.S_ISDIR(mode):
                raise StopCustodyInvalid()
        try:
            names = sorted(os.listdir(stop_directory))
        except OSError as exc:
            raise StopCustodyInvalid() from exc
        token = binding.event_digest.removeprefix(_DIGEST_PREFIX) if binding is not None else None
        if any(name != token for name in names):
            raise StopCustodyInvalid()
        if not names or binding is None or token is None or _HEX_TOKEN.fullmatch(token) is None:
            if names:
                raise StopCustodyInvalid()
            return _StopRecords(None, None)
        binding_directory = stop_directory / token
        try:
            if not stat.S_ISDIR(binding_directory.lstat().st_mode):
                raise StopCustodyInvalid()
            entries = sorted(os.listdir(binding_directory))
        except OSError as exc:
            raise StopCustodyInvalid() from exc
        for name in entries:
            if name in {_STOP_ATTEMPT, _STOP_DELIVERY}:
                continue
            if _STOP_TEMPORARY.fullmatch(name) is None:
                raise StopCustodyInvalid()
            try:
                temporary_mode = (binding_directory / name).lstat().st_mode
            except OSError as exc:
                raise StopCustodyInvalid() from exc
            if not stat.S_ISREG(temporary_mode):
                raise StopCustodyInvalid()
        attempt_raw = self._stop_record_bytes(binding_directory / _STOP_ATTEMPT)
        delivered_raw = self._stop_record_bytes(binding_directory / _STOP_DELIVERY)
        if attempt_raw is None:
            if delivered_raw is not None:
                raise StopCustodyInvalid()
            return _StopRecords(None, None)
        attempt = _parse_stop_record(attempt_raw)
        marked = _first_marked_request(events)
        recorded_binding = attempt.get("binding")
        if (
            set(attempt) != _ATTEMPT_KEYS
            or marked is None
            or type(attempt["schema_version"]) is not int
            or attempt["schema_version"] != 1
            or attempt["kind"] != "stop_attempt"
            or attempt["signal"] != "SIGTERM"
            or attempt["identity_strength"] != "pid_session_only"
            or attempt["run_id"] != run_id
            or attempt["request_event_digest"] != marked.event_digest
            or not isinstance(attempt["recorded_at"], str)
            or _RECORDED_AT.fullmatch(attempt["recorded_at"]) is None
            or not isinstance(recorded_binding, dict)
            or set(recorded_binding) != _BINDING_KEYS
            or any(
                type(recorded_binding[name]) is not int for name in ("generation", "pgid", "pid")
            )
            or not isinstance(recorded_binding["owner_id"], str)
            or _json_bytes(recorded_binding) != _json_bytes(self._expected_binding(binding))
        ):
            raise StopCustodyInvalid()
        if delivered_raw is None:
            return _StopRecords(attempt, None)
        delivered = _parse_stop_record(delivered_raw)
        if (
            set(delivered) != _DELIVERY_KEYS
            or type(delivered["schema_version"]) is not int
            or delivered["schema_version"] != 1
            or delivered["kind"] != "stop_delivery"
            or not isinstance(delivered["outcome"], str)
            or delivered["outcome"] not in _DELIVERY_OUTCOMES
            or delivered["run_id"] != run_id
            or delivered["attempt_digest"] != _sha256(attempt_raw)
            or not isinstance(delivered["recorded_at"], str)
            or _RECORDED_AT.fullmatch(delivered["recorded_at"]) is None
        ):
            raise StopCustodyInvalid()
        return _StopRecords(attempt, delivered)

    def _publish_stop_record_unlocked(
        self,
        run_id: str,
        binding_token: str,
        name: str,
        content: bytes,
    ) -> bool:
        """Create-only publication; True when this call linked the record.

        Under F1 (process crash only) the barrier is a returned ``link`` plus a
        verified read-back. No machine-crash or power-loss durability is claimed.
        A linked record exists even if the read-back below fails.
        """
        stop_directory = self._stop_directory(run_id)
        binding_directory = stop_directory / binding_token
        failure = RunControlError("internal_error", "stop record could not be published")
        try:
            for directory in (stop_directory, binding_directory):
                try:
                    directory.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                if not stat.S_ISDIR(directory.lstat().st_mode):
                    raise StopCustodyInvalid()
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=_STOP_TEMPORARY_PREFIX, dir=binding_directory
            )
        except OSError as exc:
            raise failure from exc
        temporary = Path(temporary_name)
        target = binding_directory / name
        try:
            try:
                os.fchmod(descriptor, 0o600)
                offset = 0
                while offset < len(content):
                    written = os.write(descriptor, content[offset:])
                    if written == 0:
                        raise OSError("short stop record write")
                    offset += written
                os.fsync(descriptor)
            except OSError as exc:
                raise failure from exc
            finally:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    raise failure from exc
            try:
                os.link(temporary, target)
                created = True
            except FileExistsError:
                created = False
            except OSError as exc:
                raise failure from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            published = target.lstat()
            stored = target.read_bytes()
        except OSError as exc:
            raise failure from exc
        if not stat.S_ISREG(published.st_mode) or (created and stored != content):
            raise StopCustodyInvalid()
        return created

    def inspect_stop(self, run_id: str) -> StopStatus:
        """Read-only stop accounting from one snapshot; never reaps or signals."""
        self._run_dir(run_id)
        request = self._load_request(run_id)
        with _exclusive_lock(self._run_lock(run_id)):
            events = self._load_events(run_id)
            if not events:
                _fail("not_found", "run was not found")
            records = self._read_stop_records_unlocked(run_id, events)
            latest = events[-1]
            terminal = latest.state in TERMINAL_RUN_STATES
            pending_terminal = "none"
            if not terminal:
                try:
                    pending = self._pending_receipt_unlocked(request, events)
                except PendingReceiptConflict:
                    pending_terminal = "conflict"
                else:
                    pending_terminal = "none" if pending is None else "adoptable"
            executor_result = self._executor_result_unlocked(run_id, events)
        marked = _first_marked_request(events)
        any_request = any(event.state == "cancel_requested" for event in events)
        stop_prefix = _is_stop_prefix(events)
        binding = _single_running(events)
        if marked is not None:
            request_status = "recorded"
        elif any_request:
            request_status = "legacy_recorded"
        else:
            # A request arriving at draining is deliberately not recorded (D7 guard).
            request_status = "late_not_recorded" if stop_prefix else "none"
        if marked is None:
            delivery = "legacy_unrecorded" if any_request else "not_applicable"
        elif records.attempt is None:
            delivery = "pending" if binding is not None and not terminal else "not_applicable"
        elif records.delivered is None:
            delivery = "ambiguous"
        else:
            delivery = str(records.delivered["outcome"])
        if terminal:
            recorded = latest.details.get("stop_settlement")
            if isinstance(recorded, str):
                settlement = recorded
            elif not stop_prefix:
                settlement = "not_applicable"
            elif marked is not None or any(
                event.state == "draining" and "stop_actor" in event.details for event in events
            ):
                # D6: a marked stop prefix must carry a class; a writer that does
                # not know STOP-A1 (mixed version) is reported, never guessed.
                raise StopCustodyInvalid()
            else:
                settlement = "legacy_unclassified"
            terminal_source: str | None = (
                "pending_receipt" if "terminal_source" in latest.details else "writer"
            )
        else:
            settlement = "pending" if stop_prefix else "not_applicable"
            terminal_source = None
        return StopStatus(
            run_id=run_id,
            request=request_status,
            delivery=delivery,
            identity_strength="pid_session_only" if marked is not None or not any_request else "legacy_unrecorded",
            settlement=settlement,
            terminal_source=terminal_source,
            pending_terminal=pending_terminal,
            executor_result=executor_result,
            product_effect="not_started" if binding is None else "unknown",
            replay_clearance="clear" if settlement == "never_dispatched" else "unresolved",
        )

    def _executor_result_unlocked(self, run_id: str, events: tuple[_Event, ...]) -> str:
        effects = [event for event in events if event.state == "effect_complete"]
        if not effects:
            return "none"
        path = self._run_dir(run_id) / "result.json"
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                _fail("integrity_error", "run result is invalid")
            encoded = path.read_bytes()
        except OSError as exc:
            raise RunControlError("integrity_error", "run result is invalid") from exc
        if effects[-1].details.get("result_digest") != _sha256(encoded):
            _fail("integrity_error", "run result is invalid")
        return "recorded"

    def _construct_run_receipt(self, request: _Request, outcome: str):
        family = load_receipt_catalog().families["run_receipt.v1"]
        dependencies = []
        for spec in family.dependencies:
            role = str(spec["role"])
            kind = str(spec["dependency_kind"])
            dependency_digest = (
                request.issuer_identity_digest
                if role == "provider_configuration_digest"
                else _sha256(f"{kind}\0{role}\0{request.run_identity_digest}".encode("utf-8"))
            )
            dependencies.append(
                {
                    "dependency_digest": dependency_digest,
                    "dependency_id": f"{kind}:{request.run_id.removeprefix('run:')}:{role}",
                    "dependency_kind": kind,
                    "dependency_type": "identity",
                    "must_be_fresh": True,
                    "role": role,
                }
            )
        dependencies.sort(
            key=lambda item: (
                item["dependency_type"], item["dependency_kind"], item["dependency_id"], item["role"]
            )
        )
        sequence = len(self._load_events(request.run_id)) + 1
        token = request.run_id.removeprefix("run:")
        return construct_receipt(
            {
                "append_only_disposition": "immutable",
                "artifact_refs": [],
                "chronology_is_authority": False,
                "consumers": list(family.consumers),
                "cost": {
                    "accounting_boundary": f"receipt:run_receipt.v1:{token}",
                    "completeness": "not_applicable",
                    "quantities": [],
                },
                "dependencies": dependencies,
                "deviations": [],
                "freshness_policy": {
                    "dependency_mode": "exact_typed_set",
                    "expiry": {"state": "absent"},
                    "policy_id": "freshness:run_receipt.v1",
                    "revocation_authority": family.revocation_authority,
                    "revocation_view": {"state": "absent"},
                    "unavailable_dependency": "unverifiable",
                },
                "integrity": {
                    "canonicalization": "canonical-json-v1",
                    "detached_signature": {"state": "absent"},
                    "digest_algorithm": "sha256",
                    "domain": "unrest.receipt.v1",
                },
                "issuer": {
                    "identity_digest": request.issuer_identity_digest,
                    "issuer_id": "provider_configuration:run-lifecycle-authority",
                    "issuer_kind": "provider_configuration",
                },
                "issuer_authority": {
                    "authority_class": family.issuer_authority,
                    "decision_ref": "decision:issue:run_receipt.v1",
                },
                "observed_at": self._load_events(request.run_id)[-1].observed_at,
                "outcome": outcome,
                "receipt_id": f"receipt:run_receipt.v1:{token}:{sequence}",
                "receipt_kind": family.id,
                "schema_version": 1,
                "sequence": sequence,
                "subject": {
                    "subject_digest": request.run_identity_digest,
                    "subject_id": request.run_id,
                    "subject_kind": "run",
                },
                "terminal_disposition": outcome,
            }
        )

    @staticmethod
    def _terminal_receipt_id(events: tuple[_Event, ...]) -> str | None:
        for event in reversed(events):
            receipt_id = event.details.get("receipt_id")
            if isinstance(receipt_id, str):
                return receipt_id
        return None

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                _fail("integrity_error", "run record is not a regular file")
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            _fail("not_found", "run record was not found")
        except (json.JSONDecodeError, UnicodeError, OSError) as exc:
            raise RunControlError("integrity_error", "run record is invalid") from exc


__all__ = [
    "RUN_OPERATIONS",
    "RunControl",
    "RunControlError",
    "RunState",
    "RunSummary",
    "StopStatus",
    "TERMINAL_RUN_STATES",
    "load_executor",
]
