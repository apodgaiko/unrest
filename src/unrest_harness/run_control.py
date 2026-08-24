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
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator, NoReturn

from .canonical_identity import IdentityRecord, construct_identity
from .foundation_store import CustodyActor, FoundationStore
from .mutation_journal import DurableMutationJournal, MutationJournalError
from .receipts import construct_receipt, load_receipt_catalog


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
        }


class RunControlError(RuntimeError):
    """Stable public failure which never includes rejected or provider data."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.public_message = message
        super().__init__(message)

    def as_envelope(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.public_message}}


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


def _validate_project_envelope(result: Mapping[str, Any]) -> None:
    required = {"harnessRoot", "projectId", "projectRoot", "state"}
    allowed = {*required, "dag"}
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
        self.durable_root = self.project_root / ".unrest" / "runs"
        self.runtime_root = self.project_root / ".unrest-runtime" / "runs"
        for path in (self.durable_root, self.runtime_root, self.runtime_root / "locks"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.foundation = FoundationStore(self.project_root, custody_root_id=custody_root_id)
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
            existing_id = self._idempotency_lookup(idempotency_key)
            if existing_id is not None:
                if existing_id != run_id:
                    _fail("conflict", "idempotency key was used for another request")
                return self._admission_summary(existing_id)
            for active in self._active_summaries():
                if active.resource_key == resource_key:
                    _fail("busy", "resource already has an active run")
            created_at = _utc_now()
            issuer_identity, run_identity, control_identity = self._construct_identities(
                run_id, operation, idempotency_key, request_fingerprint
            )
            self.foundation.append_identity(issuer_identity)
            self.foundation.append_identity(run_identity)
            self.foundation.append_identity(control_identity)
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
            self._append_request(request)
            self._append_event(run_id, "queued", {"owner_id": self.owner_id})
            self._append_idempotency(idempotency_key, run_id)
            admitted = self._admission_summary(run_id)
            with _exclusive_lock(self._run_lock(run_id)):
                if self.inspect_run(run_id).state == "queued":
                    self._spawn(request)
        return admitted

    def inspect_run(self, run_id: str) -> RunSummary:
        request = self._load_request(run_id)
        events = self._load_events(run_id)
        if not events:
            _fail("integrity_error", "run has no admission event")
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
        )

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
                return summary
            if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
                _fail("timeout", "run did not reach a terminal state")
            time.sleep(max(0.001, poll_interval))

    def cancel_run(self, run_id: str, reason: str, idempotency_key: str) -> RunSummary:
        _validate_text(reason, "reason")
        _validate_text(idempotency_key, "idempotency_key")
        request = {
            "idempotency_key": idempotency_key,
            "reason": reason,
            "run_id": run_id,
        }

        def effect(_: str) -> Mapping[str, Any]:
            with _exclusive_lock(self._run_lock(run_id)):
                summary = self.inspect_run(run_id)
                if summary.state in TERMINAL_RUN_STATES:
                    return summary.as_dict()
                events = self._load_events(run_id)
                if not any(event.state == "cancel_requested" for event in events):
                    self._append_event_unlocked(
                        run_id,
                        "cancel_requested",
                        {
                            "cancel_idempotency_digest": _sha256(idempotency_key.encode("utf-8")),
                            "reason_digest": _sha256(reason.encode("utf-8")),
                        },
                    )
                cursor = self._load_worker_cursor(run_id)
                if cursor is None or not _pid_live(int(cursor.get("pid", -1))):
                    self._settle_cancel_without_worker_unlocked(run_id)
                else:
                    try:
                        os.killpg(int(cursor["pgid"]), signal.SIGTERM)
                    except ProcessLookupError:
                        self._settle_cancel_without_worker_unlocked(run_id)
            return self.inspect_run(run_id).as_dict()

        try:
            value = DurableMutationJournal(self.project_root).execute(
                operation="cancel_run",
                resource_key=run_id,
                idempotency_key=idempotency_key,
                request=request,
                effect=effect,
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
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RunControlError("integrity_error", "cancel replay record is invalid") from exc

    def recover(self) -> tuple[RunSummary, ...]:
        recovered: list[RunSummary] = []
        with _exclusive_lock(self.runtime_root / "admission.lock"):
            for request in self._all_requests():
                with _exclusive_lock(self._run_lock(request.run_id)):
                    summary = self.inspect_run(request.run_id)
                    if summary.state in TERMINAL_RUN_STATES:
                        continue
                    cursor = self._load_worker_cursor(request.run_id)
                    if cursor is not None and self._cursor_matches(request, cursor):
                        if _pid_live(int(cursor["pid"])):
                            recovered.append(summary)
                            continue
                    events = self._load_events(request.run_id)
                    states = {event.state for event in events}
                    if summary.state == "queued":
                        self._spawn(request)
                    elif "report_complete" in states:
                        self._finalize_terminal_unlocked(request.run_id, "succeeded")
                    elif "effect_complete" in states:
                        self._append_event_unlocked(
                            request.run_id,
                            "report_complete",
                            {"recovered": True},
                        )
                        self._finalize_terminal_unlocked(request.run_id, "succeeded")
                    elif summary.state == "cancel_requested":
                        self._settle_cancel_without_worker_unlocked(request.run_id)
                    else:
                        self._finalize_terminal_unlocked(
                            request.run_id,
                            "attention",
                            error={
                                "error": {
                                    "code": "internal_error",
                                    "message": "worker ownership could not be recovered",
                                }
                            },
                        )
                    recovered.append(self.inspect_run(request.run_id))
        return tuple(recovered)

    def worker_start(self, run_id: str, *, pid: int, pgid: int, generation: int) -> bool:
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
            if self.inspect_run(run_id).state not in TERMINAL_RUN_STATES:
                self._append_event_unlocked(run_id, "draining", {})

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
                    "invalid_argument", "invalid_transition", "not_found"
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
                if self.inspect_run(run_id).state in TERMINAL_RUN_STATES:
                    return
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
                self._finalize_terminal_unlocked(run_id, "failed", error=public)
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
            self._finalize_terminal_unlocked(run_id, "succeeded")
            self._remove_worker_cursor(run_id)

    def worker_cancelled(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            self._settle_cancel_without_worker_unlocked(run_id)
            self._remove_worker_cursor(run_id)

    def worker_failed(self, run_id: str) -> None:
        with _exclusive_lock(self._run_lock(run_id)):
            if self.inspect_run(run_id).state in TERMINAL_RUN_STATES:
                return
            states = {event.state for event in self._load_events(run_id)}
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
        value = self._read_json(path)
        if not isinstance(value, Mapping) or value.get("run_id") != run_id:
            _fail("integrity_error", "run request is invalid")
        try:
            return _Request(
                run_id=str(value["run_id"]),
                operation=str(value["operation"]),
                arguments=dict(value["arguments"]),
                idempotency_key=str(value["idempotency_key"]),
                resource_key=str(value["resource_key"]),
                project_id=str(value["project_id"]) if value["project_id"] is not None else None,
                created_at=str(value["created_at"]),
                run_identity_digest=str(value["run_identity_digest"]),
                control_identity_digest=str(value["control_identity_digest"]),
                issuer_identity_digest=str(value["issuer_identity_digest"]),
                generation=int(value["generation"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RunControlError("integrity_error", "run request is invalid") from exc

    def _all_requests(self) -> tuple[_Request, ...]:
        requests: list[_Request] = []
        for path in sorted(self.durable_root.glob("*/request.json")):
            try:
                value = self._read_json(path)
                if isinstance(value, Mapping) and isinstance(value.get("run_id"), str):
                    requests.append(self._load_request(value["run_id"]))
            except RunControlError:
                raise
        return tuple(requests)

    def _active_summaries(self) -> tuple[RunSummary, ...]:
        return tuple(
            summary
            for summary in (self.inspect_run(request.run_id) for request in self._all_requests())
            if summary.state in _ACTIVE_RUN_STATES
        )

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
        events: list[_Event] = []
        predecessor: str | None = None
        for expected, path in enumerate(sorted((self._run_dir(run_id) / "events").glob("*.json")), 1):
            value = self._read_json(path)
            if not isinstance(value, Mapping):
                _fail("integrity_error", "run event is invalid")
            try:
                body = dict(value)
                supplied = str(body.pop("event_digest"))
                computed = _sha256(b"unrest.run-event.v1\0" + _json_bytes(body))
                if (
                    value.get("run_id") != run_id
                    or value.get("sequence") != expected
                    or value.get("previous_event_digest") != predecessor
                    or supplied != computed
                    or not isinstance(value.get("details"), Mapping)
                ):
                    _fail("integrity_error", "run event chain is invalid")
                event = _Event(
                    expected,
                    str(value["state"]),
                    str(value["observed_at"]),
                    supplied,
                    predecessor,
                    dict(value["details"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise RunControlError("integrity_error", "run event is invalid") from exc
            events.append(event)
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

    def _idempotency_lookup(self, key: str) -> str | None:
        path = self.durable_root / "idempotency" / f"{_safe_token(key)}.json"
        if not path.exists():
            return None
        value = self._read_json(path)
        if not isinstance(value, Mapping) or value.get("key_digest") != _sha256(key.encode("utf-8")):
            _fail("integrity_error", "idempotency record is invalid")
        run_id = value.get("run_id")
        if not isinstance(run_id, str):
            _fail("integrity_error", "idempotency record is invalid")
        return run_id

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
            subprocess.Popen(
                command,
                cwd=self.project_root,
                env=worker_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
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

    def _settle_cancel_without_worker_unlocked(self, run_id: str) -> None:
        states = {event.state for event in self._load_events(run_id)}
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
            )
        else:
            if self.inspect_run(run_id).state != "draining":
                self._append_event_unlocked(run_id, "draining", {})
            self._finalize_terminal_unlocked(run_id, "cancelled")

    def _finalize_terminal_unlocked(
        self,
        run_id: str,
        state: str,
        *,
        error: Mapping[str, Any] | None = None,
    ) -> None:
        current = self.inspect_run(run_id)
        if current.state in TERMINAL_RUN_STATES:
            return
        request = self._load_request(run_id)
        outcome = {"attention": "partial", "cancelled": "cancelled", "failed": "failed", "succeeded": "succeeded"}[state]
        receipt = self._construct_run_receipt(request, outcome)
        custodian = CustodyActor(
            actor_id="provider_configuration:run-lifecycle-authority",
            authority_class="run_lifecycle_authority",
            decision_ref="decision:issue:run_receipt.v1",
        )
        self.foundation.append_receipt(receipt, custodian=custodian)
        details: dict[str, Any] = {
            "receipt_digest": receipt.digest,
            "receipt_id": receipt.record["receipt_id"],
        }
        if error is not None:
            details["error"] = dict(error)
        self._append_event_unlocked(run_id, state, details)

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
    "TERMINAL_RUN_STATES",
    "load_executor",
]
