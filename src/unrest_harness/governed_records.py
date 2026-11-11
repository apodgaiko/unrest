"""Governed S1 durable records, strict reading, publication and classification.

The governed tree of one mission lives under
``<bucket>/.unrest/missions/<mid>/governed``.  Records are canonical ASCII
JSON, published write-once with ``os.link`` and read through bounded,
``O_NOFOLLOW`` descriptors.  Classification never writes and never repairs.
See ``docs/architecture/governed-s1.md`` and ADR-0507.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Literal, Mapping

from .capability_policy import redact_sensitive_value
from .models import ASSERTION_ID_REGEX, TASK_ID_REGEX

if TYPE_CHECKING:
    from .storage import ProjectStore


# ---------------------------------------------------------------------------
# Grammars and limits
# ---------------------------------------------------------------------------

HEX32 = re.compile(r"^[0-9a-f]{32}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MISSION_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
ATTEMPT_ID = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}Z(-[0-9]{4,8}){0,2}$"
)
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RESIDUE = re.compile(r"^\.tmp-[0-9a-f]{32}$")
ID_MAX_LENGTH = 128

CRITERION_LIMIT = 65_536
CRITERIA_MAX = 256
MANIFEST_LIMIT = 1_048_576
POST_IMAGE_LIMIT = 16 * 1_048_576
INTENT_LIMIT = 65_536
SMALL_RECORD_LIMIT = 4_096
PREPARED_LIMIT = 65_536
ABANDON_LIMIT = 262_144
STATE_LIMIT = 4_096
ADMISSIONS_MAX = 16
EXECUTIONS_MAX = 4_096
WITNESSES_MAX = 4
RESIDUE_MAX = 64
OUTPUT_LIMIT = 524_288

RENDER_VERSION = "criterion-render-v1"
POST_IMAGE_MEMBERS = ("contract-state.json", "state.json", "task-state.json", "tasks.json")
PRODUCT_PUBLICATION_ORDER = ("tasks.json", "task-state.json", "contract-state.json", "state.json")
STAGES = ("prepared", "not_submitted", "write_completed", "write_error", "response", "local_failure")
STAGE_LETTER = {
    "prepared": "P", "not_submitted": "N", "write_completed": "W",
    "write_error": "E", "response": "R", "local_failure": "L",
}
NOT_CLAIMED = (
    "assessment_eligibility", "effective_criterion_preservation", "every_launch_registered",
    "history_completeness", "model_consumption", "power_loss_durability", "process_cleanup",
    "remote_receipt", "same_uid_tamper_resistance", "timed_assessment", "wire_payload_equality",
    "writer_completeness",
)

_O_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(
    os, "O_CLOEXEC", 0
)
_O_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(
    os, "O_CLOEXEC", 0
)


def _compute_capability() -> bool:
    try:
        return (
            all(hasattr(os, n) for n in (
                "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK", "fsync", "link", "scandir"
            ))
            and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.unlink in os.supports_dir_fd
            and os.link in os.supports_dir_fd
            and os.link in os.supports_follow_symlinks
            and os.stat in os.supports_follow_symlinks
            and os.scandir in os.supports_fd
        )
    except AttributeError:
        return False


GOVERNED_FS_CAPABLE: bool = _compute_capability()


def governed_fs_capable() -> bool:
    """Read the module flag at call time so tests can force it unsupported."""
    return bool(globals()["GOVERNED_FS_CAPABLE"])


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GovernedRecordError(Exception):
    """A closed reason from the strict reader/publisher; never carries payload text."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class GovernedRedactionConflict(Exception):
    def __init__(self) -> None:
        super().__init__("governed_metadata_redaction_conflict")


# ---------------------------------------------------------------------------
# Canonical encoding and strict parsing
# ---------------------------------------------------------------------------


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii") + b"\n"


def _no_float(_: str) -> Any:
    raise ValueError("float")


def _no_constant(_: str) -> Any:
    raise ValueError("constant")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def strict_loads(data: bytes, *, canonical: bool = True) -> Any:
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_constant
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise GovernedRecordError("invalid_record") from None
    if canonical:
        try:
            if canonical_bytes(value) != data:
                raise GovernedRecordError("invalid_record")
        except (ValueError, TypeError, UnicodeEncodeError, RecursionError):
            raise GovernedRecordError("invalid_record") from None
    return value


# Validators -----------------------------------------------------------------

Validator = Callable[[Any], bool]


def v_re(pattern: re.Pattern[str], max_len: int = ID_MAX_LENGTH) -> Validator:
    return lambda v: type(v) is str and len(v) <= max_len and pattern.fullmatch(v) is not None


def v_lit(expected: object) -> Validator:
    return lambda v: type(v) is type(expected) and v == expected


def v_enum(*values: str) -> Validator:
    return lambda v: type(v) is str and v in values


def v_int(low: int, high: int) -> Validator:
    return lambda v: type(v) is int and low <= v <= high


def v_bool() -> Validator:
    return lambda v: type(v) is bool


def v_null_or(inner: Validator) -> Validator:
    return lambda v: v is None or inner(v)


def v_list(
    item: Validator, low: int, high: int, *, sorted_unique: bool = True
) -> Validator:
    def check(v: Any) -> bool:
        if type(v) is not list or not low <= len(v) <= high:
            return False
        if not all(item(x) for x in v):
            return False
        if sorted_unique:
            return all(v[i] < v[i + 1] for i in range(len(v) - 1))
        return True

    return check


def v_obj(spec: Mapping[str, Validator]) -> Validator:
    return lambda v: type(v) is dict and set(v) == set(spec) and all(
        spec[k](v[k]) for k in spec
    )


ASSERTION = v_re(ASSERTION_ID_REGEX)
TASK = v_re(TASK_ID_REGEX)
HEX = v_re(HEX32)
ATTEMPT = v_re(ATTEMPT_ID, 38)
ID3: dict[str, Validator] = {
    "project_id": v_re(PROJECT_ID), "mission_id": v_re(MISSION_ID), "admission_id": HEX,
}

MANIFEST_SPEC = {
    "schema": v_lit("unrest.governed-admission-manifest.v1"), **ID3,
    "idempotency_key": v_re(IDEMPOTENCY_KEY), "revision": v_lit(1),
    "criterion_identity_policy": v_lit("internal_digest_with_plaintext"),
    "render_version": v_lit(RENDER_VERSION), "canonicalization": v_lit("crlf-lf-rstrip-lf-v1"),
    "post_image_members": v_lit(list(POST_IMAGE_MEMBERS)),
    "criteria": v_list(v_obj({
        "assertion_id": ASSERTION, "criterion_version_id": HEX, "revision": v_lit(1),
        "content_sha256": v_re(SHA256_HEX, 64), "work_owner_task_id": TASK,
        "validate_task_ids": v_list(TASK, 0, 1 << 20), "gate_task_ids": v_list(TASK, 0, 1 << 20),
    }), 1, CRITERIA_MAX, sorted_unique=False),
}
INTENT_SPEC = {
    "schema": v_lit("unrest.governed-admission-intent.v1"), **ID3,
    "members": v_list(lambda v: type(v) is str and len(v) <= 160, 5, CRITERIA_MAX + 5),
}
COMMIT_SPEC = {
    "schema": v_lit("unrest.governed-admission-commit.v1"), **ID3,
    "product_publication_order": v_lit(list(PRODUCT_PUBLICATION_ORDER)),
    "readback": v_lit("exact_bytes_equal_v1"),
}
OPENED_SPEC = {
    "schema": v_lit("unrest.governed-execution-opened.v1"), **ID3,
    "attempt_id": ATTEMPT, "node_id": TASK,
}
CLOSED_SPEC = {
    "schema": v_lit("unrest.governed-execution-closed.v1"), **ID3,
    "attempt_id": ATTEMPT, "node_id": TASK, "closure": v_enum("owner_joined", "not_launched"),
    "witness_ids": v_list(HEX, 0, WITNESSES_MAX),
}
OUTCOME_SPEC = {
    "schema": v_lit("unrest.governed-execution-outcome.v1"), **ID3,
    "attempt_id": ATTEMPT, "node_id": TASK,
    "outcome": v_enum("completed", "failed", "synthetic", "cancelled"),
}
ABANDON_SPEC = {
    "schema": v_lit("unrest.governed-abandon.v1"), "project_id": v_re(PROJECT_ID),
    "mission_id": v_re(MISSION_ID), "abandon_id": HEX, "idempotency_key": v_re(IDEMPOTENCY_KEY),
    "admission_phase": v_enum(
        "precommit_orphan", "staging_without_intent", "intent_without_commit", "committed"
    ),
    "inspected_admission_ids": v_list(HEX, 1, ADMISSIONS_MAX),
    "committed_admission_id": v_null_or(HEX),
    "closed_execution_attempt_ids": v_list(ATTEMPT, 0, EXECUTIONS_MAX),
}
_WB: dict[str, Validator] = {
    **ID3, "attempt_id": ATTEMPT, "node_id": TASK, "witness_id": HEX,
    "input_kind": v_enum("initial", "continuation"),
}
STAGE_SPECS: dict[str, dict[str, Validator]] = {
    "prepared": {
        "schema": v_lit("unrest.governed-witness-prepared.v1"), **_WB,
        "jsonrpc_id": v_int(1, 2**53 - 1), "render_version": v_lit(RENDER_VERSION),
        "criteria": v_list(v_obj({"assertion_id": ASSERTION, "criterion_version_id": HEX}),
                           0, CRITERIA_MAX, sorted_unique=False),
    },
    "not_submitted": {
        "schema": v_lit("unrest.governed-witness-not-submitted.v1"), **_WB,
        "reason": v_lit("transport_closing_before_write"),
    },
    "write_completed": {"schema": v_lit("unrest.governed-witness-write-completed.v1"), **_WB},
    "write_error": {
        "schema": v_lit("unrest.governed-witness-write-error.v1"), **_WB,
        "error_class": v_enum("broken_pipe", "connection_reset", "os_error", "cancelled", "other"),
    },
    "response": {
        "schema": v_lit("unrest.governed-witness-response.v1"), **_WB,
        "response_class": v_enum("result", "error"),
    },
    "local_failure": {
        "schema": v_lit("unrest.governed-witness-local-failure.v1"), **_WB,
        "failure_class": v_enum("local_exception", "cancelled"),
    },
}


def validate_record(value: Any, spec: Mapping[str, Validator]) -> dict[str, Any]:
    if not v_obj(spec)(value):
        raise GovernedRecordError("invalid_record")
    return value


# ---------------------------------------------------------------------------
# Descriptor helpers
# ---------------------------------------------------------------------------


def read_bounded_fd(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 65_536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise GovernedRecordError("limit_exceeded")
    return data


def read_member(dir_fd: int, name: str, limit: int) -> bytes:
    try:
        fd = os.open(name, _O_READ, dir_fd=dir_fd)
    except FileNotFoundError:
        raise GovernedRecordError("member_missing") from None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR, errno.ENOTDIR):
            raise GovernedRecordError("unexpected_member") from None
        raise GovernedRecordError("io_unavailable") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise GovernedRecordError("unexpected_member")
        try:
            return read_bounded_fd(fd, limit)
        except OSError:
            raise GovernedRecordError("io_unavailable") from None
    finally:
        os.close(fd)


def read_record(dir_fd: int, name: str, limit: int, spec: Mapping[str, Validator]) -> dict[str, Any]:
    return validate_record(strict_loads(read_member(dir_fd, name, limit)), spec)


def open_dir_at(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, _O_DIR, dir_fd=parent_fd)
    except FileNotFoundError:
        raise GovernedRecordError("member_missing") from None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise GovernedRecordError("unexpected_member") from None
        raise GovernedRecordError("io_unavailable") from None


@dataclass(frozen=True)
class Member:
    name: str
    kind: Literal["dir", "file", "other"]


def scan_dir(dir_fd: int) -> tuple[dict[str, Member], int]:
    """Return members (excluding temp residue) and the residue count."""
    members: dict[str, Member] = {}
    residue = 0
    try:
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                if entry.is_symlink():
                    kind: Literal["dir", "file", "other"] = "other"
                elif entry.is_dir(follow_symlinks=False):
                    kind = "dir"
                elif entry.is_file(follow_symlinks=False):
                    kind = "file"
                else:
                    kind = "other"
                if RESIDUE.fullmatch(entry.name) is not None:
                    if kind != "file":
                        raise GovernedRecordError("unexpected_member")
                    residue += 1
                    continue
                members[entry.name] = Member(entry.name, kind)
    except GovernedRecordError:
        raise
    except OSError:
        raise GovernedRecordError("io_unavailable") from None
    if residue > RESIDUE_MAX:
        raise GovernedRecordError("limit_exceeded")
    return members, residue


def anchored_open(anchor: Path, components: Iterable[str]) -> int:
    """Open ``anchor`` (trusted, baseline-resolved) then each component no-follow."""
    try:
        fd = os.open(anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise GovernedRecordError("io_unavailable") from None
    try:
        for component in components:
            next_fd = open_dir_at(fd, component)
            os.close(fd)
            fd = next_fd
    except BaseException:
        os.close(fd)
        raise
    return fd


def guard(data: bytes, inventories: Iterable[Mapping[str, str] | None]) -> bytes:
    text = data.decode("ascii")
    for inventory in inventories:
        if inventory and redact_sensitive_value(text, inventory) != text:
            raise GovernedRedactionConflict()
    return data


def publish(
    dir_fd: int,
    name: str,
    data: bytes,
    limit: int,
    *,
    exclusive: bool = False,
) -> Literal["created", "reused"]:
    """Write-once publication via temp + ``os.link``; never replace."""
    if len(data) > limit:
        raise GovernedRecordError("limit_exceeded")
    if exclusive:
        # Callers hold the project lock; refusing on an existing name before the
        # temp keeps an exclusive refusal free of directory effects.
        try:
            os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(name)
    temp = f".tmp-{secrets.token_hex(16)}"
    fd = os.open(
        temp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=dir_fd,
    )
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            result: Literal["created", "reused"] = "created"
        except FileExistsError:
            if exclusive:
                raise
            try:
                existing = read_member(dir_fd, name, limit)
            except GovernedRecordError:
                raise GovernedRecordError("artifact_identity_conflict") from None
            if existing != data:
                raise GovernedRecordError("artifact_identity_conflict") from None
            result = "reused"
    finally:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except OSError:
            pass
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    return result


def mkdir_at(parent_fd: int, name: str, *, reuse: bool) -> None:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        if not reuse:
            raise GovernedRecordError("artifact_identity_conflict") from None
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise GovernedRecordError("artifact_identity_conflict") from None


def mkdir_open(parent_fd: int, name: str, *, reuse: bool) -> int:
    mkdir_at(parent_fd, name, reuse=reuse)
    return open_dir_at(parent_fd, name)


# ---------------------------------------------------------------------------
# Request governance modes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegacyNoAdmission:
    pass


@dataclass(frozen=True)
class LegacyAfterAbandon:
    abandon_id: str


@dataclass(frozen=True)
class GovernedTemplate:
    admission_id: str
    render_version: str
    criteria: tuple[tuple[str, str, bytes], ...]


class ExecutionScope:
    """One governed attempt's owner-protocol scope (in-process)."""

    def __init__(
        self,
        *,
        anchor: Path,
        project_id: str,
        mission_id: str,
        admission_id: str,
        attempt_id: str,
        node_id: str,
        inventory: Mapping[str, str],
    ) -> None:
        self.anchor = anchor
        self.project_id = project_id
        self.mission_id = mission_id
        self.admission_id = admission_id
        self.attempt_id = attempt_id
        self.node_id = node_id
        self.inventory = dict(inventory)
        self.lock = threading.Lock()
        self.fenced = False
        self.opened = False
        self.witness_ids: list[str] = []

    def components(self) -> tuple[str, ...]:
        return ("missions", self.mission_id, "governed", "executions", self.attempt_id)


@dataclass(frozen=True)
class GovernedBound:
    template: GovernedTemplate
    scope: ExecutionScope


TaskGovernance = LegacyNoAdmission | LegacyAfterAbandon | GovernedTemplate
RequestGovernance = LegacyNoAdmission | LegacyAfterAbandon | GovernedBound


# ---------------------------------------------------------------------------
# Record builders
# ---------------------------------------------------------------------------


def id3(project_id: str, mission_id: str, admission_id: str) -> dict[str, str]:
    return {"project_id": project_id, "mission_id": mission_id, "admission_id": admission_id}


def intent_members(assertion_ids: Iterable[str]) -> list[str]:
    members = [f"criteria/{aid}.v1.md" for aid in assertion_ids]
    members += ["manifest.json"] + [f"post-images/{name}" for name in POST_IMAGE_MEMBERS]
    return sorted(members)


def build_intent(ids: Mapping[str, str], assertion_ids: Iterable[str]) -> dict[str, Any]:
    return {"schema": "unrest.governed-admission-intent.v1", **ids,
            "members": intent_members(assertion_ids)}


def build_commit(ids: Mapping[str, str]) -> dict[str, Any]:
    return {"schema": "unrest.governed-admission-commit.v1", **ids,
            "product_publication_order": list(PRODUCT_PUBLICATION_ORDER),
            "readback": "exact_bytes_equal_v1"}


def scope_base(scope: ExecutionScope) -> dict[str, str]:
    return {**id3(scope.project_id, scope.mission_id, scope.admission_id),
            "attempt_id": scope.attempt_id, "node_id": scope.node_id}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass
class WitnessView:
    stages: frozenset[str]


@dataclass
class ExecutionView:
    attempt_id: str
    opened: dict[str, Any]
    closed: dict[str, Any] | None
    outcome: dict[str, Any] | None
    witnesses: dict[str, WitnessView]


@dataclass
class Classification:
    admission_status: str
    status_reason: str
    executions_status: str = "absent"
    executions_reason: str | None = None
    admission_id: str | None = None
    manifest: dict[str, Any] | None = None
    criteria_buffers: dict[str, bytes] = field(default_factory=dict)
    post_tasks: bytes | None = None
    orphan_ids: tuple[str, ...] = ()
    admission_ids: tuple[str, ...] = ()
    abandon: dict[str, Any] | None = None
    residue_count: int = 0
    executions: dict[str, ExecutionView] = field(default_factory=dict)
    execution_names: tuple[str, ...] = ()
    membership: tuple[Any, ...] = ()

    @property
    def committed(self) -> bool:
        return self.admission_status == "COMMITTED"


def _probe_absence(anchor: Path, mid: str) -> Classification | None:
    prefix = anchor
    for component in ("missions", mid, "governed"):
        prefix = prefix / component
        try:
            info = os.lstat(prefix)
        except FileNotFoundError:
            return Classification("NONE", "no_governed_tree")
        except NotADirectoryError:
            return Classification("UNAVAILABLE", "pre_governed_component_invalid")
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return Classification("UNAVAILABLE", "pre_governed_component_invalid")
            return Classification("UNAVAILABLE", "io_unavailable")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return Classification("UNAVAILABLE", "pre_governed_component_invalid")
    return None


def _read_product_state(store: "ProjectStore", project_id: str) -> Any:
    path = store.unrest_runtime_dir(project_id) / "state.json"
    try:
        fd = os.open(path, _O_READ)
    except FileNotFoundError:
        return None
    except OSError:
        raise GovernedRecordError("io_unavailable") from None
    try:
        try:
            data = read_bounded_fd(fd, STATE_LIMIT)
        except OSError:
            raise GovernedRecordError("io_unavailable") from None
    except GovernedRecordError as exc:
        if exc.reason == "limit_exceeded":
            return None
        raise
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _validate_manifest_mapping(manifest: dict[str, Any], tasks_bytes: bytes) -> None:
    from .models import TaskList

    try:
        task_list = TaskList.model_validate_json(tasks_bytes)
    except ValueError:
        raise GovernedRecordError("invalid_record") from None
    expected = manifest_mapping(task_list)
    for row in manifest["criteria"]:
        mapping = expected.get(row["assertion_id"])
        if mapping is None or mapping != (
            row["work_owner_task_id"], row["validate_task_ids"], row["gate_task_ids"]
        ):
            raise GovernedRecordError("invalid_record")


def manifest_mapping(task_list: Any) -> dict[str, tuple[str, list[str], list[str]]]:
    owners: dict[str, list[str]] = {}
    validators: dict[str, set[str]] = {}
    gates: dict[str, set[str]] = {}
    for task in task_list.tasks:
        for target in task.targets:
            if task.type == "work":
                owners.setdefault(target, []).append(task.id)
            elif task.type == "validate":
                validators.setdefault(target, set()).add(task.id)
            elif task.type == "gate":
                gates.setdefault(target, set()).add(task.id)
    return {
        aid: (ids[0], sorted(validators.get(aid, ())), sorted(gates.get(aid, ())))
        for aid, ids in owners.items()
        if len(ids) == 1
    }


def classify(
    store: "ProjectStore",
    project_id: str,
    mid: str,
    *,
    admission_only: bool = False,
) -> Classification:
    """Classify one mission's governed tree; no writes, no recovery.

    ``admission_only`` is the replay-only variant: ``G/executions`` is never
    opened, stat'ed or scanned (only its name in ``G`` is used) and
    ``abandoned.json`` is validated without execution binding.
    """
    anchor = store.unrest_dir(project_id)
    absent = _probe_absence(anchor, mid)
    if absent is not None:
        return absent
    if not governed_fs_capable():
        return Classification("UNAVAILABLE", "platform_unsupported")
    try:
        g_fd = anchored_open(anchor, ("missions", mid, "governed"))
    except GovernedRecordError as exc:
        reason = "io_unavailable" if exc.reason == "io_unavailable" else "pre_governed_component_invalid"
        return Classification("UNAVAILABLE", reason)
    try:
        return _classify_tree(store, project_id, mid, g_fd, admission_only)
    except GovernedRecordError as exc:
        return Classification("UNAVAILABLE", exc.reason)
    finally:
        os.close(g_fd)


def _classify_tree(
    store: "ProjectStore", project_id: str, mid: str, g_fd: int, admission_only: bool
) -> Classification:
    members, residue = scan_dir(g_fd)
    allowed = {"admission": "dir", "executions": "dir", "abandoned.json": "file"}
    for name, member in members.items():
        if allowed.get(name) != member.kind:
            raise GovernedRecordError("unexpected_member")
    has_exec = "executions" in members
    has_abandon = "abandoned.json" in members
    admission_names: dict[str, Member] = {}
    adm_fd: int | None = None
    adm_residue = 0
    if "admission" in members:
        adm_fd = open_dir_at(g_fd, "admission")
    try:
        if adm_fd is not None:
            admission_names, adm_residue = scan_dir(adm_fd)
        if not admission_names:
            if has_exec:
                raise GovernedRecordError("execution_without_admission")
            if has_abandon:
                raise GovernedRecordError("abandon_conflict")
            if residue == 0 and adm_residue == 0:
                return Classification("NONE", "empty_governed_residue")
            # Publication residue cannot precede an admission directory, so
            # residue without one is foreign content, never absence evidence.
            raise GovernedRecordError("unexpected_member")
        assert adm_fd is not None
        if len(admission_names) > ADMISSIONS_MAX:
            raise GovernedRecordError("limit_exceeded")
        for name, member in admission_names.items():
            if HEX32.fullmatch(name) is None or member.kind != "dir":
                raise GovernedRecordError("unexpected_member")
        result = _classify_admissions(store, project_id, mid, adm_fd, sorted(admission_names))
        result.residue_count += residue + adm_residue
    finally:
        if adm_fd is not None:
            os.close(adm_fd)
    committed_id = result.admission_id if result.admission_status == "COMMITTED" else None
    if has_exec and committed_id is None:
        raise GovernedRecordError("execution_without_admission")
    exec_names: tuple[str, ...] = ()
    exec_error: str | None = None
    if has_exec and not admission_only:
        try:
            exec_names, views, exec_residue = _scan_executions(g_fd, project_id, mid, committed_id)
            result.executions = views
            result.residue_count += exec_residue
        except GovernedRecordError as exc:
            exec_error = exc.reason
        result.execution_names = exec_names
    if has_abandon:
        abandon = read_record(g_fd, "abandoned.json", ABANDON_LIMIT, ABANDON_SPEC)
        if abandon["project_id"] != project_id or abandon["mission_id"] != mid:
            raise GovernedRecordError("identity_mismatch")
        _check_abandon_binding(abandon, result, has_exec, exec_error, admission_only)
        result.abandon = abandon
        result.admission_status, result.status_reason = "ABANDONED", "abandoned"
        if abandon["admission_phase"] != "committed":
            result.executions_status = "absent"
            return result
    if committed_id is not None or (result.abandon and result.abandon["committed_admission_id"]):
        if not has_exec:
            result.executions_status = "absent"
        elif admission_only:
            result.executions_status = "absent"
        elif exec_error is not None:
            result.executions_status, result.executions_reason = "unavailable", exec_error
        else:
            result.executions_status = "ok"
    return result


def _check_abandon_binding(
    abandon: dict[str, Any],
    result: Classification,
    has_exec: bool,
    exec_error: str | None,
    admission_only: bool,
) -> None:
    if abandon["inspected_admission_ids"] != sorted(result.admission_ids):
        raise GovernedRecordError("abandon_conflict")
    committed = result.admission_id if result.admission_status == "COMMITTED" else None
    if abandon["committed_admission_id"] != committed:
        raise GovernedRecordError("abandon_conflict")
    phase = abandon["admission_phase"]
    if result.admission_status == "COMMITTED":
        ok_phase = phase == "committed"
    elif result.admission_status == "AMBIGUOUS" and result.status_reason == "intent_without_commit":
        ok_phase = phase == "intent_without_commit"
    else:
        ok_phase = phase in ("precommit_orphan", "staging_without_intent")
    if not ok_phase:
        raise GovernedRecordError("abandon_conflict")
    if admission_only:
        return
    if exec_error is not None:
        return
    names = list(result.execution_names) if has_exec else []
    if abandon["closed_execution_attempt_ids"] != sorted(names):
        raise GovernedRecordError("abandon_conflict")
    for name in names:
        if result.executions[name].closed is None:
            raise GovernedRecordError("abandon_conflict")


def _classify_admissions(
    store: "ProjectStore", project_id: str, mid: str, adm_fd: int, names: list[str]
) -> Classification:
    with_intent: list[str] = []
    structures: dict[str, dict[str, Member]] = {}
    for name in names:
        a_fd = open_dir_at(adm_fd, name)
        try:
            members, _ = scan_dir(a_fd)
            allowed = {"criteria": "dir", "post-images": "dir", "manifest.json": "file",
                       "intent.json": "file", "commit.json": "file"}
            for member_name, member in members.items():
                if allowed.get(member_name) != member.kind:
                    raise GovernedRecordError("unexpected_member")
            if "commit.json" in members and "intent.json" not in members:
                raise GovernedRecordError("commit_without_intent")
            if "criteria" in members:
                c_fd = open_dir_at(a_fd, "criteria")
                try:
                    criteria, _ = scan_dir(c_fd)
                finally:
                    os.close(c_fd)
                if len(criteria) > CRITERIA_MAX:
                    raise GovernedRecordError("limit_exceeded")
                for cname, member in criteria.items():
                    if not cname.endswith(".v1.md") or member.kind != "file" or not ASSERTION(cname[:-6]):
                        raise GovernedRecordError("unexpected_member")
            if "post-images" in members:
                p_fd = open_dir_at(a_fd, "post-images")
                try:
                    posts, _ = scan_dir(p_fd)
                finally:
                    os.close(p_fd)
                for pname, member in posts.items():
                    if pname not in POST_IMAGE_MEMBERS or member.kind != "file":
                        raise GovernedRecordError("unexpected_member")
            structures[name] = members
            if "intent.json" in members:
                with_intent.append(name)
        finally:
            os.close(a_fd)
    if len(with_intent) >= 2:
        raise GovernedRecordError("multiple_admissions")
    if not with_intent:
        state = _read_product_state(store, project_id)
        orphans = tuple(names)
        if type(state) is dict and set(state) == {"state", "mission_id"} and state.get(
            "state"
        ) == "mission_planning" and state.get("mission_id") == mid:
            return Classification("NONE", "orphan_staging_present", orphan_ids=orphans,
                                  admission_ids=orphans)
        return Classification("AMBIGUOUS", "staging_without_intent", orphan_ids=orphans,
                              admission_ids=orphans)
    aid = with_intent[0]
    a_fd = open_dir_at(adm_fd, aid)
    try:
        ids = id3(project_id, mid, aid)
        intent = read_record(a_fd, "intent.json", INTENT_LIMIT, INTENT_SPEC)
        manifest = read_record(a_fd, "manifest.json", MANIFEST_LIMIT, MANIFEST_SPEC)
        for record in (intent, manifest):
            if any(record[k] != v for k, v in ids.items()):
                raise GovernedRecordError("identity_mismatch")
        criteria_rows = manifest["criteria"]
        aids = [row["assertion_id"] for row in criteria_rows]
        if aids != sorted(set(aids)) or len(
            {row["criterion_version_id"] for row in criteria_rows}
        ) != len(criteria_rows):
            raise GovernedRecordError("invalid_record")
        if intent["members"] != intent_members(aids):
            raise GovernedRecordError("invalid_record")
        buffers: dict[str, bytes] = {}
        c_fd = open_dir_at(a_fd, "criteria")
        try:
            criteria_names, _ = scan_dir(c_fd)
            if set(criteria_names) != {f"{a}.v1.md" for a in aids}:
                raise GovernedRecordError("member_missing")
            for row in criteria_rows:
                data = read_member(c_fd, f"{row['assertion_id']}.v1.md", CRITERION_LIMIT)
                if hashlib.sha256(data).hexdigest() != row["content_sha256"]:
                    raise GovernedRecordError("digest_mismatch")
                buffers[row["assertion_id"]] = data
        finally:
            os.close(c_fd)
        p_fd = open_dir_at(a_fd, "post-images")
        try:
            post_tasks = read_member(p_fd, "tasks.json", POST_IMAGE_LIMIT)
            for other in ("task-state.json", "state.json", "contract-state.json"):
                try:
                    fd = os.open(other, _O_READ, dir_fd=p_fd)
                except FileNotFoundError:
                    raise GovernedRecordError("member_missing") from None
                except OSError:
                    raise GovernedRecordError("unexpected_member") from None
                try:
                    info = os.fstat(fd)
                finally:
                    os.close(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise GovernedRecordError("unexpected_member")
                if info.st_size > POST_IMAGE_LIMIT:
                    raise GovernedRecordError("limit_exceeded")
        finally:
            os.close(p_fd)
        _validate_manifest_mapping(manifest, post_tasks)
        status, reason = "AMBIGUOUS", "intent_without_commit"
        if "commit.json" in structures[aid]:
            commit = read_record(a_fd, "commit.json", SMALL_RECORD_LIMIT, COMMIT_SPEC)
            if any(commit[k] != v for k, v in ids.items()):
                raise GovernedRecordError("identity_mismatch")
            status, reason = "COMMITTED", "committed"
    finally:
        os.close(a_fd)
    return Classification(
        status, reason, admission_id=aid, manifest=manifest, criteria_buffers=buffers,
        post_tasks=post_tasks, orphan_ids=tuple(n for n in names if n != aid),
        admission_ids=tuple(names),
    )


def _scan_executions(
    g_fd: int, project_id: str, mid: str, committed_id: str | None
) -> tuple[tuple[str, ...], dict[str, ExecutionView], int]:
    e_fd = open_dir_at(g_fd, "executions")
    views: dict[str, ExecutionView] = {}
    residue_total = 0
    try:
        names, residue_total = scan_dir(e_fd)
        if len(names) > EXECUTIONS_MAX:
            raise GovernedRecordError("limit_exceeded")
        for name, member in names.items():
            if not ATTEMPT(name) or member.kind != "dir":
                raise GovernedRecordError("unexpected_member")
        for name in sorted(names):
            x_fd = open_dir_at(e_fd, name)
            try:
                view, residue = _scan_execution(x_fd, project_id, mid, committed_id, name)
            finally:
                os.close(x_fd)
            residue_total += residue
            views[name] = view
    finally:
        os.close(e_fd)
    return tuple(sorted(views)), views, residue_total


def _scan_execution(
    x_fd: int, project_id: str, mid: str, committed_id: str | None, name: str
) -> tuple[ExecutionView, int]:
    members, residue = scan_dir(x_fd)
    allowed = {"opened.json": "file", "closed.json": "file", "outcome.json": "file",
               "submissions": "dir"}
    for member_name, member in members.items():
        if allowed.get(member_name) != member.kind:
            raise GovernedRecordError("unexpected_member")
    if "opened.json" not in members:
        if "closed.json" in members or "outcome.json" in members:
            raise GovernedRecordError("execution_binding_conflict")
        raise GovernedRecordError("member_missing")
    expected = {"project_id": project_id, "mission_id": mid, "admission_id": committed_id,
                "attempt_id": name}
    opened = read_record(x_fd, "opened.json", SMALL_RECORD_LIMIT, OPENED_SPEC)
    records: dict[str, dict[str, Any] | None] = {"closed.json": None, "outcome.json": None}
    for record_name, spec in (("closed.json", CLOSED_SPEC), ("outcome.json", OUTCOME_SPEC)):
        if record_name in members:
            records[record_name] = read_record(x_fd, record_name, SMALL_RECORD_LIMIT, spec)
    for record in (opened, records["closed.json"], records["outcome.json"]):
        if record is None:
            continue
        if any(record[k] != v for k, v in expected.items()) or record["node_id"] != opened["node_id"]:
            raise GovernedRecordError("identity_mismatch")
    witnesses: dict[str, WitnessView] = {}
    if "submissions" in members:
        s_fd = open_dir_at(x_fd, "submissions")
        try:
            subs, sub_residue = scan_dir(s_fd)
            residue += sub_residue
            if len(subs) > WITNESSES_MAX:
                raise GovernedRecordError("limit_exceeded")
            for wid, member in subs.items():
                if HEX32.fullmatch(wid) is None or member.kind != "dir":
                    raise GovernedRecordError("unexpected_member")
                w_fd = open_dir_at(s_fd, wid)
                try:
                    stages, w_residue = scan_dir(w_fd)
                finally:
                    os.close(w_fd)
                residue += w_residue
                names = set()
                for stage_name, member in stages.items():
                    if not stage_name.endswith(".json") or stage_name[:-5] not in STAGES or member.kind != "file":
                        raise GovernedRecordError("unexpected_member")
                    names.add(stage_name[:-5])
                witnesses[wid] = WitnessView(frozenset(names))
        finally:
            os.close(s_fd)
    closed = records["closed.json"]
    if closed is not None and not set(witnesses) <= set(closed["witness_ids"]):
        raise GovernedRecordError("execution_binding_conflict")
    return ExecutionView(name, opened, closed, records["outcome.json"], witnesses), residue


def membership_fingerprint(store: "ProjectStore", project_id: str, mid: str) -> tuple[Any, ...]:
    """Control-membership snapshot used by the inspector's single recheck."""
    root = store.unrest_dir(project_id) / "missions" / mid / "governed"
    try:
        top = tuple(sorted(os.listdir(root)))
    except FileNotFoundError:
        return ("absent",)
    except OSError:
        return ("io",)
    parts: list[Any] = [top]
    for sub in ("admission", "executions"):
        try:
            names = sorted(os.listdir(root / sub))
        except OSError:
            parts.append((sub, None))
            continue
        rows = []
        for name in names:
            path = root / sub / name
            if sub == "admission":
                rows.append((name, (path / "intent.json").exists(), (path / "commit.json").exists()))
            else:
                rows.append((name, (path / "opened.json").exists(), (path / "closed.json").exists()))
        parts.append((sub, tuple(rows)))
    return tuple(parts)


# ---------------------------------------------------------------------------
# Witness classification (ordered; C1)
# ---------------------------------------------------------------------------


def classify_witness(stages: Iterable[str]) -> str:
    letters = {STAGE_LETTER[s] for s in stages}
    if letters and "P" not in letters:
        return "unavailable"
    if "P" in letters and (
        ("N" in letters and letters & {"W", "E", "R", "L"})
        or {"W", "E"} <= letters
        or {"R", "L"} <= letters
    ):
        return "unavailable"
    if not letters:
        return "unknown"
    rest = frozenset(letters - {"P"})
    table = {
        frozenset(): "unknown", frozenset({"E"}): "unknown", frozenset({"L"}): "unknown",
        frozenset({"E", "L"}): "unknown", frozenset({"N"}): "not_submitted",
        frozenset({"R"}): "response_observed", frozenset({"W", "R"}): "response_observed",
        frozenset({"E", "R"}): "response_observed",
        frozenset({"W"}): "transport_write_completed",
        frozenset({"W", "L"}): "transport_write_completed",
    }
    return table[rest]


def witness_unavailable_reason(stages: Iterable[str]) -> str | None:
    letters = {STAGE_LETTER[s] for s in stages}
    if letters and "P" not in letters:
        return "stage_without_prepared"
    if classify_witness(stages) == "unavailable":
        return "conflicting_stages"
    return None


# ---------------------------------------------------------------------------
# Criterion capture and canonicalization
# ---------------------------------------------------------------------------


class CaptureRefusal(Exception):
    def __init__(self, code: str, details: list[Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


def canonicalize_criterion(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        raise CaptureRefusal("criterion_invalid_encoding")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise CaptureRefusal("criterion_invalid_encoding") from None
    if "\x00" in text:
        raise CaptureRefusal("criterion_invalid_encoding")
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise CaptureRefusal("criterion_invalid_encoding")
    text = text.rstrip()
    if text == "":
        raise CaptureRefusal("criterion_empty")
    canonical = (text + "\n").encode("utf-8")
    if len(canonical) > CRITERION_LIMIT:
        raise CaptureRefusal("criterion_too_large")
    return canonical


def capture_criteria(
    store: "ProjectStore", project_id: str, mid: str
) -> list[tuple[str, bytes]]:
    """Capture ``contract/*.md`` once per candidate; never create the directory."""
    import fnmatch

    from .task_validation import ValidationError

    contract = store.contract_dir(project_id, mid)
    anchor = store.unrest_dir(project_id)
    try:
        info = os.lstat(contract)
        missing = not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
    except FileNotFoundError:
        missing = True
    except OSError:
        raise CaptureRefusal("governed_io_unavailable") from None
    if missing:
        raise CaptureRefusal(
            "invalid_contract_dir", [ValidationError("contract_dir_missing", str(contract))]
        )
    try:
        d_fd = anchored_open(anchor, ("missions", mid, "contract"))
    except GovernedRecordError:
        raise CaptureRefusal(
            "invalid_contract_dir", [ValidationError("contract_dir_missing", str(contract))]
        ) from None
    try:
        try:
            names = sorted(n for n in os.listdir(d_fd) if fnmatch.fnmatchcase(n, "*.md"))
        except OSError:
            raise CaptureRefusal("governed_io_unavailable") from None
        candidates: list[tuple[str, str]] = []
        errors: list[Any] = []
        seen: set[str] = set()
        for name in names:
            stem = Path(name).stem
            if stem == "README":
                continue
            if not ASSERTION_ID_REGEX.fullmatch(stem):
                errors.append(ValidationError(
                    "invalid_assertion_filename",
                    f"{name} (stem '{stem}' does not match {ASSERTION_ID_REGEX.pattern})",
                ))
                continue
            if stem in seen:
                errors.append(ValidationError("duplicate_assertion_filename", stem))
                continue
            seen.add(stem)
            candidates.append((stem, name))
        if errors:
            raise CaptureRefusal("invalid_contract_dir", errors)
        if len(candidates) > CRITERIA_MAX:
            raise CaptureRefusal("criteria_set_too_large")
        captured: list[tuple[str, bytes]] = []
        for stem, name in candidates:
            try:
                fd = os.open(name, _O_READ, dir_fd=d_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR, errno.ENOTDIR):
                    raise CaptureRefusal("criterion_non_regular") from None
                raise CaptureRefusal("governed_io_unavailable") from None
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise CaptureRefusal("criterion_non_regular")
                try:
                    raw = read_bounded_fd(fd, CRITERION_LIMIT)
                except GovernedRecordError:
                    raise CaptureRefusal("criterion_too_large") from None
                except OSError:
                    raise CaptureRefusal("governed_io_unavailable") from None
            finally:
                os.close(fd)
            captured.append((stem, canonicalize_criterion(raw)))
        return captured
    finally:
        os.close(d_fd)


# ---------------------------------------------------------------------------
# Project identity (ADR-0507): ownership, reservations, consumption markers
# ---------------------------------------------------------------------------

IDENTITY_RECORD_LIMIT = 4_096
RESERVATIONS_MAX = 4_096
MISSION_NAME = re.compile(r"^mission-([0-9]{3,})\.(json|consumed)$")
IDENTITY_INIT_SPEC = {"schema": v_lit("unrest.governed-identity-init.v1"),
                      "project_id": v_re(PROJECT_ID)}
IDENTITY_READY_SPEC = {"schema": v_lit("unrest.governed-identity-ready.v1"),
                       "project_id": v_re(PROJECT_ID)}
RESERVATION_SPEC = {
    "schema": v_lit("unrest.governed-mission-reservation.v1"), "project_id": v_re(PROJECT_ID),
    "mission_id": v_re(MISSION_ID), "route": v_enum("start", "next_tx", "next_seal"),
}
CONSUMED_SPEC = {
    "schema": v_lit("unrest.governed-mission-consumed.v1"), "project_id": v_re(PROJECT_ID),
    "mission_id": v_re(MISSION_ID),
}

IdentityState = Literal["LEGACY", "INITIALIZING", "ELIGIBLE", "IDENTITY_UNAVAILABLE"]


class IdentityError(Exception):
    """Closed identity refusal; ``code`` is a tool-local error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class IdentityView:
    state: IdentityState
    reserved: frozenset[str] = frozenset()
    consumed: frozenset[str] = frozenset()
    max_index: int = 0


def mission_name(index: int) -> str:
    # Same canonical form as ProjectStore.generate_mission_id.
    return f"mission-{index:03d}"


def _identity_unavailable() -> IdentityView:
    return IdentityView("IDENTITY_UNAVAILABLE")


def classify_identity(store: "ProjectStore", project_id: str) -> IdentityView:
    """Four-way identity classification; never writes, never repairs.

    Only ``ENOENT`` of ``.unrest/identity`` (``os.lstat``) means LEGACY; every
    malformed or partial footprint is IDENTITY_UNAVAILABLE.
    """
    anchor = store.unrest_dir(project_id)
    try:
        info = os.lstat(anchor / "identity")
    except FileNotFoundError:
        return IdentityView("LEGACY")
    except OSError:
        return _identity_unavailable()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return _identity_unavailable()
    if not governed_fs_capable():
        return _identity_unavailable()
    try:
        i_fd = anchored_open(anchor, ("identity",))
    except GovernedRecordError:
        return _identity_unavailable()
    try:
        return _classify_identity_tree(project_id, i_fd)
    except GovernedRecordError:
        return _identity_unavailable()
    finally:
        os.close(i_fd)


def _classify_identity_tree(project_id: str, i_fd: int) -> IdentityView:
    members, _ = scan_dir(i_fd)
    allowed = {"init.json": "file", "ready.json": "file", "missions": "dir"}
    for name, member in members.items():
        if allowed.get(name) != member.kind:
            raise GovernedRecordError("unexpected_member")
    if "init.json" not in members:
        raise GovernedRecordError("member_missing")
    init = read_record(i_fd, "init.json", IDENTITY_RECORD_LIMIT, IDENTITY_INIT_SPEC)
    if init["project_id"] != project_id:
        raise GovernedRecordError("identity_mismatch")
    if "missions" not in members:
        raise GovernedRecordError("member_missing")
    m_fd = open_dir_at(i_fd, "missions")
    try:
        entries, _ = scan_dir(m_fd)
        reserved: dict[str, int] = {}
        consumed: set[str] = set()
        for name, member in entries.items():
            match = MISSION_NAME.fullmatch(name)
            if match is None or member.kind != "file":
                raise GovernedRecordError("unexpected_member")
            index = int(match.group(1))
            mid = mission_name(index)
            if index < 1 or f"{mid}.{match.group(2)}" != name:
                raise GovernedRecordError("unexpected_member")
            if match.group(2) == "json":
                reserved[mid] = index
            else:
                consumed.add(mid)
        if len(reserved) > RESERVATIONS_MAX:
            raise GovernedRecordError("limit_exceeded")
        if "mission-001" not in reserved or not consumed <= set(reserved):
            raise GovernedRecordError("member_missing")
        for mid in sorted(reserved):
            record = read_record(m_fd, f"{mid}.json", IDENTITY_RECORD_LIMIT, RESERVATION_SPEC)
            if record["project_id"] != project_id or record["mission_id"] != mid:
                raise GovernedRecordError("identity_mismatch")
        for mid in sorted(consumed):
            record = read_record(m_fd, f"{mid}.consumed", IDENTITY_RECORD_LIMIT, CONSUMED_SPEC)
            if record["project_id"] != project_id or record["mission_id"] != mid:
                raise GovernedRecordError("identity_mismatch")
    finally:
        os.close(m_fd)
    max_index = max(reserved.values())
    if "ready.json" not in members:
        return IdentityView("INITIALIZING", frozenset(reserved), frozenset(consumed), max_index)
    ready = read_record(i_fd, "ready.json", IDENTITY_RECORD_LIMIT, IDENTITY_READY_SPEC)
    if ready["project_id"] != project_id:
        raise GovernedRecordError("identity_mismatch")
    return IdentityView("ELIGIBLE", frozenset(reserved), frozenset(consumed), max_index)


def reservation_capacity_check(existing_reservations: int) -> None:
    """The single capacity gate every reservation producer calls before writing."""
    if existing_reservations >= RESERVATIONS_MAX:
        raise IdentityError("mission_identity_capacity_exhausted")


def _identity_publish(
    store: "ProjectStore", project_id: str, components: tuple[str, ...], name: str,
    record: dict[str, Any], *, exclusive: bool,
) -> Literal["created", "reused"]:
    data = guard(canonical_bytes(record), (store.inventory,))
    fd = anchored_open(store.unrest_dir(project_id), components)
    try:
        return publish(fd, name, data, IDENTITY_RECORD_LIMIT, exclusive=exclusive)
    finally:
        os.close(fd)


def initialize_identity(store: "ProjectStore", project_id: str) -> None:
    """K-c2: ``.unrest/identity/init.json`` and the empty ``missions/`` set."""
    unrest = store.unrest_dir(project_id)
    unrest.mkdir(exist_ok=True)
    fd = anchored_open(unrest, ())
    try:
        i_fd = mkdir_open(fd, "identity", reuse=False)
    finally:
        os.close(fd)
    try:
        mkdir_at(i_fd, "missions", reuse=False)
    finally:
        os.close(i_fd)
    _identity_publish(
        store, project_id, ("identity",), "init.json",
        {"schema": "unrest.governed-identity-init.v1", "project_id": project_id},
        exclusive=True,
    )


def reserve_mission(
    store: "ProjectStore", project_id: str, mission_id: str, *, route: str, existing: int
) -> None:
    reservation_capacity_check(existing)
    try:
        _identity_publish(
            store, project_id, ("identity", "missions"), f"{mission_id}.json",
            {"schema": "unrest.governed-mission-reservation.v1", "project_id": project_id,
             "mission_id": mission_id, "route": route},
            exclusive=True,
        )
    except FileExistsError:
        raise IdentityError("mission_id_reserved") from None


def publish_identity_ready(store: "ProjectStore", project_id: str) -> None:
    _identity_publish(
        store, project_id, ("identity",), "ready.json",
        {"schema": "unrest.governed-identity-ready.v1", "project_id": project_id},
        exclusive=True,
    )


def mark_mission_consumed(store: "ProjectStore", project_id: str, mission_id: str) -> None:
    """Option R: idempotent legacy-consumption marker (equal bytes reuse)."""
    _identity_publish(
        store, project_id, ("identity", "missions"), f"{mission_id}.consumed",
        {"schema": "unrest.governed-mission-consumed.v1", "project_id": project_id,
         "mission_id": mission_id},
        exclusive=False,
    )


# ---------------------------------------------------------------------------
# Execution scope and witness publication
# ---------------------------------------------------------------------------


class ScopeOpenError(Exception):
    pass


def open_scope(store: "ProjectStore", scope: ExecutionScope) -> None:
    """``mkdir X`` (no reuse), ``opened.json``, ``mkdir X/submissions``."""
    g_fd = anchored_open(scope.anchor, ("missions", scope.mission_id, "governed"))
    try:
        e_fd = mkdir_open(g_fd, "executions", reuse=True)
    finally:
        os.close(g_fd)
    try:
        x_fd = mkdir_open(e_fd, scope.attempt_id, reuse=False)
    finally:
        os.close(e_fd)
    try:
        data = guard(canonical_bytes({
            "schema": "unrest.governed-execution-opened.v1", **scope_base(scope)
        }), (store.inventory,))
        publish(x_fd, "opened.json", data, SMALL_RECORD_LIMIT, exclusive=True)
        scope.opened = True
        mkdir_at(x_fd, "submissions", reuse=False)
    finally:
        os.close(x_fd)


def count_executions(store: "ProjectStore", project_id: str, mid: str) -> int:
    """Number of ``X`` directories, re-counted under the owner before ``mkdir X``."""
    g_fd = anchored_open(store.unrest_dir(project_id), ("missions", mid, "governed"))
    try:
        try:
            e_fd = open_dir_at(g_fd, "executions")
        except GovernedRecordError as exc:
            if exc.reason == "member_missing":
                return 0
            raise
    finally:
        os.close(g_fd)
    try:
        members, _ = scan_dir(e_fd)
    finally:
        os.close(e_fd)
    return len(members)


def _scope_publish(scope: ExecutionScope, components: tuple[str, ...], name: str,
                   record: dict[str, Any], limit: int,
                   inventories: Iterable[Mapping[str, str] | None]) -> None:
    data = guard(canonical_bytes(record), inventories)
    fd = anchored_open(scope.anchor, scope.components() + components)
    try:
        publish(fd, name, data, limit, exclusive=True)
    finally:
        os.close(fd)


def close_scope(
    scope: ExecutionScope, *, effect_started: bool, outcome: str | None
) -> None:
    """Owner closure: fence, optional outcome, then ``closed.json``."""
    with scope.lock:
        scope.fenced = True
        witness_ids = sorted(scope.witness_ids)
    if outcome is not None:
        _scope_publish(scope, (), "outcome.json", {
            "schema": "unrest.governed-execution-outcome.v1", **scope_base(scope),
            "outcome": outcome,
        }, SMALL_RECORD_LIMIT, (scope.inventory,))
    _scope_publish(scope, (), "closed.json", {
        "schema": "unrest.governed-execution-closed.v1", **scope_base(scope),
        "closure": "owner_joined" if effect_started else "not_launched",
        "witness_ids": witness_ids,
    }, SMALL_RECORD_LIMIT, (scope.inventory,))


def register_witness(scope: ExecutionScope) -> str | None:
    """Under the scope lock: fence/cap check, ``mkdir W`` and append; ``None`` refuses."""
    with scope.lock:
        if scope.fenced or len(scope.witness_ids) >= WITNESSES_MAX:
            return None
        wid = secrets.token_hex(16)
        try:
            fd = anchored_open(scope.anchor, scope.components() + ("submissions",))
            try:
                mkdir_at(fd, wid, reuse=False)
            finally:
                os.close(fd)
        except (OSError, GovernedRecordError):
            return None
        scope.witness_ids.append(wid)
        return wid


def witness_record(
    scope: ExecutionScope, wid: str, stage: str, input_kind: str, **extra: Any
) -> dict[str, Any]:
    schema = {
        "prepared": "unrest.governed-witness-prepared.v1",
        "not_submitted": "unrest.governed-witness-not-submitted.v1",
        "write_completed": "unrest.governed-witness-write-completed.v1",
        "write_error": "unrest.governed-witness-write-error.v1",
        "response": "unrest.governed-witness-response.v1",
        "local_failure": "unrest.governed-witness-local-failure.v1",
    }[stage]
    record = {"schema": schema, **scope_base(scope), "witness_id": wid, "input_kind": input_kind,
              **extra}
    validate_record(record, STAGE_SPECS[stage])
    return record


def publish_witness_stage(
    scope: ExecutionScope, wid: str, stage: str, record: dict[str, Any],
    inventories: Iterable[Mapping[str, str] | None],
) -> None:
    limit = PREPARED_LIMIT if stage == "prepared" else SMALL_RECORD_LIMIT
    _scope_publish(scope, ("submissions", wid), f"{stage}.json", record, limit, inventories)


def read_witness_stages(
    store: "ProjectStore", project_id: str, mid: str, attempt_id: str, wid: str,
    names: Iterable[str],
) -> dict[str, dict[str, Any] | None]:
    """Inspector-only stage reads; a malformed stage yields ``None`` for it."""
    result: dict[str, dict[str, Any] | None] = {}
    fd = anchored_open(store.unrest_dir(project_id), (
        "missions", mid, "governed", "executions", attempt_id, "submissions", wid))
    try:
        for stage in names:
            limit = PREPARED_LIMIT if stage == "prepared" else SMALL_RECORD_LIMIT
            try:
                result[stage] = read_record(fd, f"{stage}.json", limit, STAGE_SPECS[stage])
            except GovernedRecordError:
                result[stage] = None
    finally:
        os.close(fd)
    return result


__all__ = [
    "CaptureRefusal",
    "Classification",
    "ExecutionScope",
    "GOVERNED_FS_CAPABLE",
    "GovernedBound",
    "GovernedRecordError",
    "GovernedRedactionConflict",
    "GovernedTemplate",
    "LegacyAfterAbandon",
    "LegacyNoAdmission",
    "RequestGovernance",
    "TaskGovernance",
    "canonical_bytes",
    "canonicalize_criterion",
    "capture_criteria",
    "classify",
    "classify_witness",
]
