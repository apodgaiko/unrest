#!/usr/bin/env python3
"""Provider-free ACT-190 paired speed runner.

The runner deliberately owns no provider or subprocess route.  It exercises the
three public adapters against deterministic, filesystem-backed local lifecycle
seams and retains the unmodified bytes from every warmup and recorded run.

Its isolation authority is the fixed pure-Python workload and this Python
API/CLI process; native code deliberately bypassing Python auditing is outside
that boundary.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
import gc
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import BuiltinMethodType, MethodType, SimpleNamespace
from typing import Any, Iterator, Mapping, Sequence, TypeVar, cast
import uuid

from unrest_harness.improve_adapter import ImprovementRequest, run_improvement
from unrest_harness.evolution import EvolutionManager
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.project_adapter import ProjectDag, ProjectNode, run_project
from unrest_harness.task_adapter import (
    HandoffRecord,
    InquiryRecord,
    TaskBounds,
    TaskRequest,
    run_task,
)


SCHEMA = "unrest.v04.speed-result.v1"
FIXTURE_SHA256 = "34ecc3c4a3dd053095efd205cc81dfcef39d3ac7453b4069d7fc185e4b2ece2f"
CLOCK = time.perf_counter_ns
IMPROVEMENT_EVALUATION_DIGEST_ROUNDS = 16_384
IMPROVEMENT_REVIEW_DIGEST_ROUNDS = 8_192
TASK_EVIDENCE_DIGEST_ROUNDS = 4_096
EXPECTED_ROWS = ("improvement-v1", "project-v1", "task-v1")
TOP_KEYS = {
    "schema", "accepted_base", "fixture_sha256", "candidate_head", "candidate_tree",
    "environment", "network_attempts", "rows", "release_pass",
}
ROW_KEYS = {
    "id", "status", "runtime_uuid", "pair_order", "normalization",
    "primitive", "adapter", "gates", "raw_artifacts",
}
ARM_KEYS = {
    "runtime_uuids", "samples_ns", "median_ns", "public_invocations",
    "manual_checkpoints", "terminal", "normalized_sha256",
}
ARTIFACT_KEYS = {"runtime_uuid", "kind", "path", "bytes", "sha256"}
_UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
# Fixing one high nibble spends four of UUIDv4's 122 random bits, leaving 118.
# The six row/arm domains make reuse structurally impossible across boundaries.
_UUID_DOMAIN_NIBBLES = {
    ("improvement-v1", "primitive"): 0x0,
    ("improvement-v1", "adapter"): 0x2,
    ("project-v1", "primitive"): 0x4,
    ("project-v1", "adapter"): 0x6,
    ("task-v1", "primitive"): 0x8,
    ("task-v1", "adapter"): 0xA,
}
_UUID_HIGH_NIBBLE_MASK = 0xF << 124
GATE_KEYS = {"name", "observed", "limit", "passed", "reason"}
ENVIRONMENT_KEYS = {
    "clock", "command_guard_probes", "encoding", "environment_keys", "locale",
    "network_guard_probes", "provider_attempts", "secret_keys_removed",
    "subprocess_attempts",
}
_SOCKET_MODULE_GUARDS = (
    "socket", "socketpair", "fromfd", "create_connection", "create_server",
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    "getnameinfo", "getfqdn", "gethostname", "getservbyname",
    "getservbyport", "getprotobyname",
)
_SOCKET_METHOD_GUARDS = (
    "connect", "connect_ex", "bind", "listen", "accept", "send", "sendall",
    "sendto", "sendmsg", "sendfile", "recv", "recv_into", "recvfrom",
    "recvfrom_into", "recvmsg", "recvmsg_into", "makefile", "shutdown",
)
_COMMAND_GUARDS = (
    (os, "system", "os.system"),
    (subprocess, "Popen", "subprocess.Popen"),
    (subprocess, "run", "subprocess.run"),
    (subprocess, "call", "subprocess.call"),
    (subprocess, "check_call", "subprocess.check_call"),
    (subprocess, "check_output", "subprocess.check_output"),
)
_ORIGINAL_ADD_AUDIT_HOOK = sys.addaudithook
_ORIGINAL_SOCKET_TYPES = (socket.socket, socket.SocketType)
_LOCAL_SOCKET_FAMILIES = frozenset(
    family
    for family in (getattr(socket, "AF_UNIX", None), getattr(socket, "AF_LOCAL", None))
    if isinstance(family, int)
)
_LOCAL_CONTROL_SOCKET_TYPES = frozenset(
    socket_type
    for socket_type in (
        getattr(socket, "SOCK_STREAM", None),
        getattr(socket, "SOCK_DGRAM", None),
        getattr(socket, "SOCK_SEQPACKET", None),
    )
    if isinstance(socket_type, int)
)
_SOCKET_TYPE_MASK = cast(int, getattr(socket, "SOCK_TYPE_MASK", 0xF))
_ORIGINAL_SOCKET_MODULE_ROUTES = tuple(
    (socket, name, getattr(socket, name), f"socket.{name}")
    for name in _SOCKET_MODULE_GUARDS
    if hasattr(socket, name)
)
_ORIGINAL_SOCKET_METHOD_ROUTES = tuple(
    (socket.socket, name, getattr(socket.socket, name), f"socket.{name}")
    for name in _SOCKET_METHOD_GUARDS
    if hasattr(socket.socket, name)
)
_ORIGINAL_COMMAND_ROUTES = tuple(
    (owner, name, getattr(owner, name), label)
    for owner, name, label in _COMMAND_GUARDS
)
_AUDIT_NETWORK_EVENTS = frozenset({
    "socket.__new__", "socket.bind", "socket.connect", "socket.getaddrinfo",
    "socket.gethostbyaddr", "socket.gethostbyname", "socket.gethostname",
    "socket.getnameinfo", "socket.getprotobyname", "socket.getservbyname",
    "socket.getservbyport", "socket.sendto",
})
_AUDIT_SUBPROCESS_EVENTS = frozenset({"os.system", "subprocess.Popen"})
_AUDIT_CONTROLLER_ATTRIBUTE = "_unrest_v04_speed_audit_controller"
_existing_audit_controller = getattr(sys, _AUDIT_CONTROLLER_ATTRIBUTE, None)
_audit_controller: dict[str, Any]
if _existing_audit_controller is None:
    _audit_controller = {
        "active": ContextVar("v04_speed_active_guards", default=()),
        "depth": 0,
        "installed": False,
        "installations": 0,
        "process_state": None,
        "states": [],
    }
    setattr(sys, _AUDIT_CONTROLLER_ATTRIBUTE, _audit_controller)
else:
    _audit_controller = cast(dict[str, Any], _existing_audit_controller)
_ACTIVE_GUARDS: ContextVar[tuple[dict[str, Any], ...]] = _audit_controller["active"]
_guard_patches: list[tuple[object, str, Any]] = []
_guard_lock = threading.RLock()
RAW_KEYS = {
    "absolute_root", "arm", "duration_ns", "kind", "outcome", "pair_index",
    "pair_position", "row_id", "runtime_uuid", "timestamp_ns",
}
REASONS = {
    "ok", "schema", "binding", "missing_raw", "digest", "nondeterministic",
    "sequence", "parity", "invocations", "checkpoint", "time", "network",
}


def _network_guard_names(socket_type: object | None = None) -> tuple[str, ...]:
    del socket_type
    return tuple(
        route[3]
        for route in (*_ORIGINAL_SOCKET_MODULE_ROUTES, *_ORIGINAL_SOCKET_METHOD_ROUTES)
    )
PROJECTION_PATHS: dict[str, tuple[str, ...]] = {
    "task-v1": (
        "/outcome/mechanics/dispatcher_configuration_identity",
        "/outcome/mechanics/logical_events",
        "/outcome/mechanics/logical_operation_count",
        "/outcome/mechanics/logical_operations",
        "/outcome/mechanics/validation_calls",
        "/outcome/manual_checkpoints", "/outcome/operation_sequence",
        "/outcome/summary", "/outcome/terminal", "/row_id",
    ),
    "project-v1": (
        "/outcome/attempts", "/outcome/manual_checkpoints", "/outcome/result_artifacts",
        "/outcome/mechanics/dispatcher_configuration_identity",
        "/outcome/mechanics/logical_events",
        "/outcome/mechanics/logical_operation_count",
        "/outcome/mechanics/logical_operations",
        "/outcome/mechanics/validation_calls",
        "/outcome/terminal", "/row_id",
    ),
    "improvement-v1": (
        "/outcome/campaign_phase", "/outcome/candidate_after_sha256",
        "/outcome/candidate_before_sha256",
        "/outcome/evaluation", "/outcome/evaluation_digest",
        "/outcome/manual_checkpoints",
        "/outcome/mechanics/dispatcher_configuration_identity",
        "/outcome/mechanics/logical_events",
        "/outcome/mechanics/logical_operation_count",
        "/outcome/mechanics/logical_operations",
        "/outcome/mechanics/validation_calls",
        "/outcome/operation_sequence", "/outcome/promotions", "/outcome/review",
        "/outcome/review_digest", "/outcome/rollbacks", "/outcome/terminal",
        "/row_id",
    ),
}
OUTCOME_KEYS: dict[str, set[str]] = {
    "task-v1": {
        "manual_checkpoints", "mechanics", "operation_sequence", "summary", "terminal",
    },
    "project-v1": {
        "attempts", "leaf_events", "manual_checkpoints", "mechanics",
        "result_artifacts", "terminal", "workspace_identities",
    },
    "improvement-v1": {
        "campaign_phase", "candidate_after_sha256", "candidate_before_sha256",
        "evaluation", "evaluation_digest", "manual_checkpoints",
        "mechanics", "operation_sequence", "promotions", "review", "review_digest",
        "rollbacks", "terminal",
    },
}
_HEX40 = set("0123456789abcdef")
_T = TypeVar("_T")


class SpeedRunnerError(RuntimeError):
    """Fail-closed runner or evidence validation error."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.guard_state: Mapping[str, Any] | None = None
        self.socket_evidence: tuple[str, ...] = ()
        super().__init__(f"{reason}:{detail}")


def _active_guard_state() -> dict[str, Any] | None:
    local = _ACTIVE_GUARDS.get()
    if local:
        return local[-1]
    return cast(dict[str, Any] | None, _audit_controller["process_state"])


def _deny_guarded_attempt(kind: str, detail: str) -> None:
    state = _active_guard_state()
    if state is None:
        return
    counter = "network_attempts" if kind == "network" else "subprocess_attempts"
    with cast(threading.Lock, state["counter_lock"]):
        state[counter] += 1
    raise SpeedRunnerError("network", detail)


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    del args
    if event in _AUDIT_NETWORK_EVENTS:
        _deny_guarded_attempt("network", "socket_attempt")
    elif event in _AUDIT_SUBPROCESS_EVENTS:
        _deny_guarded_attempt("subprocess", "subprocess_attempt")


def _install_audit_hook() -> None:
    with _guard_lock:
        if _audit_controller["installed"]:
            return
        _ORIGINAL_ADD_AUDIT_HOOK(_audit_hook)
        _audit_controller["installed"] = True
        _audit_controller["installations"] += 1


def _socket_descriptor_profile(descriptor: int) -> tuple[int, int, int] | None:
    """Read socket metadata through an owned duplicate of a foreign descriptor."""

    try:
        duplicate = os.dup(descriptor)
    except OSError:
        return None
    probe: socket.socket | None = None
    try:
        probe = _ORIGINAL_SOCKET_TYPES[0](fileno=duplicate)
        return int(probe.family), int(probe.type), int(probe.proto)
    except OSError:
        if probe is None:
            os.close(duplicate)
        return None
    finally:
        if probe is not None:
            probe.close()


def _is_local_control_profile(profile: tuple[int, int, int]) -> bool:
    family, socket_type, _ = profile
    return (
        family in _LOCAL_SOCKET_FAMILIES
        and socket_type & _SOCKET_TYPE_MASK in _LOCAL_CONTROL_SOCKET_TYPES
    )


def _open_socket_evidence() -> tuple[str, ...]:
    """Find effect-capable sockets without operating on foreign endpoints."""

    evidence: set[str] = set()
    for value in gc.get_objects():
        alias_name: str | None = None
        candidate = value
        if isinstance(value, (BuiltinMethodType, MethodType)):
            candidate = value.__self__
            name = getattr(value, "__name__", None)
            if isinstance(name, str) and name in _SOCKET_METHOD_GUARDS:
                alias_name = name
        if not isinstance(candidate, _ORIGINAL_SOCKET_TYPES):
            continue
        try:
            descriptor = candidate.fileno()
        except (OSError, ValueError):
            continue
        if descriptor < 0:
            continue
        profile = (int(candidate.family), int(candidate.type), int(candidate.proto))
        if alias_name is not None:
            evidence.add(
                f"alias:{alias_name}:{descriptor}:{profile[0]}:{profile[1]}"
            )
        elif not _is_local_control_profile(profile):
            evidence.add(f"object:{descriptor}:{profile[0]}:{profile[1]}")

    descriptor_root = next(
        (root for root in (Path("/proc/self/fd"), Path("/dev/fd")) if root.is_dir()),
        None,
    )
    if descriptor_root is not None:
        descriptors = sorted(
            int(item.name)
            for item in descriptor_root.iterdir()
            if item.name.isdecimal()
        )
        for descriptor in descriptors:
            try:
                mode = os.fstat(descriptor).st_mode
            except OSError:
                continue
            if stat.S_ISSOCK(mode):
                descriptor_profile = _socket_descriptor_profile(descriptor)
                if descriptor_profile is None:
                    evidence.add(f"descriptor:{descriptor}:unknown")
                elif not _is_local_control_profile(descriptor_profile):
                    evidence.add(
                        f"descriptor:{descriptor}:{descriptor_profile[0]}:"
                        f"{descriptor_profile[1]}"
                    )
    return tuple(sorted(evidence))


_install_audit_hook()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _validate_improvement_workload_contract() -> None:
    if (
        IMPROVEMENT_EVALUATION_DIGEST_ROUNDS,
        IMPROVEMENT_REVIEW_DIGEST_ROUNDS,
    ) != (16_384, 8_192):
        raise SpeedRunnerError("binding", "improvement_workload")
    if TASK_EVIDENCE_DIGEST_ROUNDS != 4_096:
        raise SpeedRunnerError("binding", "task_workload")


def _expect_keys(value: object, keys: set[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SpeedRunnerError("schema", f"{where}_keys")
    return value


def load_fixture(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if _sha256(raw) != FIXTURE_SHA256:
        raise SpeedRunnerError("binding", "fixture_sha256")
    try:
        fixture = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SpeedRunnerError("schema", "fixture_json") from exc
    if not isinstance(fixture, dict) or fixture.get("provider_free") is not True:
        raise SpeedRunnerError("schema", "fixture")
    protocol = fixture.get("protocol")
    if not isinstance(protocol, dict) or protocol.get("clock") != "time.perf_counter_ns":
        raise SpeedRunnerError("schema", "protocol_clock")
    if protocol.get("warmups_per_arm") != 1 or protocol.get("recorded_samples_per_arm") != 10:
        raise SpeedRunnerError("schema", "protocol_cardinality")
    pair_order = protocol.get("pair_order")
    if pair_order != [
        "primitive", "adapter", "adapter", "primitive", "primitive", "adapter",
        "adapter", "primitive", "primitive", "adapter",
    ]:
        raise SpeedRunnerError("sequence", "fixture_pair_order")
    rows = fixture.get("rows")
    if not isinstance(rows, list) or {row.get("id") for row in rows if isinstance(row, dict)} != set(EXPECTED_ROWS):
        raise SpeedRunnerError("schema", "fixture_rows")
    return fixture


def _public_boundary(value: _T) -> _T:
    """Perform the real canonical validation/serialization work of one public call."""

    return cast(_T, json.loads(_canonical(value)))


class _InvocationJournal:
    """Generic transaction boundary applied to every public invocation.

    The journal has no arm, adapter, row, benchmark, or expected-outcome input.
    A caller opens one boundary for one public invocation. Lifecycle methods add
    logical events and validation results; the boundary commits that slice once.
    """

    _CONFIGURATION = {
        "event_order": "append",
        "serialization": "canonical-json-v1",
        "transaction_rule": "one-commit-per-public-invocation",
        "validation": "always",
    }

    def __init__(self, root: Path) -> None:
        self.root = root
        self.logical_events: list[dict[str, object]] = []
        self.validation_calls: list[dict[str, object]] = []
        self.transactions: list[dict[str, object]] = []
        self.physical_writes: list[str] = []
        self.public_invocations: list[str] = []
        self._active: tuple[str, int, int] | None = None

    @property
    def configuration_identity(self) -> str:
        return _sha256(_canonical(self._CONFIGURATION))

    def validate(self, name: str, passed: bool) -> None:
        self.validation_calls.append({"name": name, "passed": passed})
        if not passed:
            raise SpeedRunnerError("sequence", name)

    def event(self, kind: str, outcome: Mapping[str, object]) -> None:
        self.logical_events.append(
            {"kind": kind, "outcome": outcome, "sequence": len(self.logical_events) + 1}
        )

    def physical_write(self, relative: str) -> None:
        self.physical_writes.append(relative)

    @contextmanager
    def invocation(self, name: str) -> Iterator[None]:
        if self._active is not None:
            raise SpeedRunnerError("sequence", "nested_public_invocation")
        self._active = (name, len(self.logical_events), len(self.validation_calls))
        self.public_invocations.append(name)
        try:
            yield
        finally:
            active = self._active
            self._active = None
            if active is None:
                raise SpeedRunnerError("sequence", "missing_public_invocation")
            invocation, event_start, validation_start = active
            transaction = {
                "events": self.logical_events[event_start:],
                "invocation": invocation,
                "sequence": len(self.transactions) + 1,
                "validations": self.validation_calls[validation_start:],
            }
            relative = Path("transactions") / f"{len(self.transactions) + 1:02d}.json"
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_canonical(transaction))
            self.transactions.append(transaction)
            self.physical_write(relative.as_posix())

    def evidence(self) -> dict[str, object]:
        return {
            "dispatcher_configuration_identity": self.configuration_identity,
            "logical_event_count": len(self.logical_events),
            "logical_events": self.logical_events,
            "logical_operation_count": len(self.logical_events),
            "logical_operations": [event["kind"] for event in self.logical_events],
            "physical_write_count": len(self.physical_writes),
            "physical_writes": self.physical_writes,
            "public_invocation_boundaries": self.public_invocations,
            "public_invocation_count": len(self.public_invocations),
            "transaction_boundaries": self.transactions,
            "transaction_count": len(self.transactions),
            "validation_calls": self.validation_calls,
            "validation_count": len(self.validation_calls),
        }


class _TaskLifecycle:
    def __init__(self, journal: _InvocationJournal) -> None:
        self.journal = journal
        self.state = "open"
        self.calls: list[str] = []
        self.question = ""
        self.last_inspection: Mapping[str, object] | None = None

    def _event(self, kind: str, outcome: Mapping[str, object]) -> None:
        self.journal.event(kind, outcome)

    def _record(self) -> Mapping[str, object]:
        return {
            "branch_outcomes": {"alpha": "answered" if self.state == "answered" else "pending"},
            "inquiry_id": "inquiry:speed",
            "receipt_id": "receipt:speed" if self.state == "answered" else None,
            "state": self.state,
        }

    def open_inquiry(self, question: str, budget: Mapping[str, int], idempotency_key: str, project_id: str | None = None) -> Mapping[str, object]:
        self.calls.append("open_inquiry")
        self.journal.validate("task_open", bool(
            question and budget["max_steps"] == 2 and idempotency_key and project_id is None
        ))
        self.question = question
        record = self._record()
        self._event("open_inquiry", record)
        return record

    async def advance_inquiry(self, inquiry_id: str, idempotency_key: str) -> Mapping[str, object]:
        self.calls.append("advance_inquiry")
        self.journal.validate(
            "task_advance", inquiry_id == "inquiry:speed" and bool(idempotency_key)
        )
        # This is the deterministic local task workload: derive and compare two
        # evidence chains from the frozen brief.  Both arms execute this same
        # work; it is not a timing delay or an adapter-only shortcut.
        alpha = self.question.encode("utf-8") + b":alpha"
        beta = self.question.encode("utf-8") + b":beta"
        digest = hashlib.sha256
        for _ in range(TASK_EVIDENCE_DIGEST_ROUNDS):
            alpha = digest(alpha).digest()
            beta = digest(beta).digest()
        if alpha == beta:
            raise SpeedRunnerError("nondeterministic", "task_evidence_collision")
        self.state = "answered"
        record = self._record()
        self._event("advance_inquiry", record)
        return record

    def handoff_inquiry(self, inquiry_id: str, consumer_id: str, idempotency_key: str) -> Mapping[str, object]:
        self.calls.append("handoff_inquiry")
        self.journal.validate("task_handoff", bool(
            inquiry_id == "inquiry:speed" and consumer_id and idempotency_key
        ))
        record = {"consumer_id": consumer_id, "handoff_id": "handoff:speed", "inquiry_id": inquiry_id, "receipt_id": "receipt:speed"}
        self._event("handoff_inquiry", record)
        return record

    def inspect_inquiry(self, inquiry_id: str) -> Mapping[str, object]:
        self.calls.append("inspect_inquiry")
        self.journal.validate("task_inspect", inquiry_id == "inquiry:speed")
        self.last_inspection = self._record()
        self._event("inspect_inquiry", self.last_inspection)
        return self.last_inspection

    def pause_inquiry(self, inquiry_id: str, reason: str, idempotency_key: str) -> Mapping[str, object]:
        raise SpeedRunnerError("sequence", "unexpected_task_pause")

    def resume_inquiry(self, inquiry_id: str, idempotency_key: str) -> Mapping[str, object]:
        raise SpeedRunnerError("sequence", "unexpected_task_resume")


async def _task_workload(arm: str, row: Mapping[str, Any], root: Path) -> dict[str, Any]:
    journal = _InvocationJournal(root)
    lifecycle = _TaskLifecycle(journal)
    request = row["input"]
    typed = TaskRequest(
        request["brief"], TaskBounds(request["max_steps"], 30),
        f"speed-{request['seed']}",
    )
    if arm == "primitive":
        with journal.invocation("open_inquiry"):
            opened = InquiryRecord.from_public(lifecycle.open_inquiry(
                typed.brief, typed.bounds.inquiry_budget(), "speed-open"
            ))
            _public_boundary(opened.public_record())
        with journal.invocation("advance_inquiry"):
            advanced = InquiryRecord.from_public(await lifecycle.advance_inquiry(
                opened.inquiry_id, "speed-advance"
            ))
            _public_boundary(advanced.public_record())
        with journal.invocation("handoff_inquiry"):
            handoff = HandoffRecord.from_public(lifecycle.handoff_inquiry(
                advanced.inquiry_id, "task-adapter", "speed-handoff"
            ))
            _public_boundary(handoff.public_record())
        with journal.invocation("inspect_inquiry"):
            inspected = InquiryRecord.from_public(
                lifecycle.inspect_inquiry(advanced.inquiry_id)
            )
            _public_boundary(inspected.public_record())
        terminal = "completed" if inspected.state == "answered" else "incomplete"
    else:
        with journal.invocation("run_task"):
            result = await run_task(lifecycle, typed)
            _public_boundary(result.public_record())
        terminal = result.terminal
    if lifecycle.calls != row["primitive_calls"]:
        raise SpeedRunnerError("sequence", "task_calls")
    final_inspection = lifecycle.last_inspection
    if final_inspection is None or final_inspection.get("state") != "answered":
        raise SpeedRunnerError("nondeterministic", "task_inspection")
    branch_outcomes = final_inspection.get("branch_outcomes")
    if not isinstance(branch_outcomes, Mapping):
        raise SpeedRunnerError("schema", "task_branch_outcomes")
    answered = sorted(
        branch
        for branch, outcome in branch_outcomes.items()
        if isinstance(branch, str) and outcome == "answered"
    )
    if len(answered) != 1:
        raise SpeedRunnerError("nondeterministic", "task_summary")
    return {
        "manual_checkpoints": 0,
        "mechanics": journal.evidence(),
        "operation_sequence": lifecycle.calls,
        "summary": answered[0],
        "terminal": terminal,
    }


@dataclass
class _TaskState:
    statuses: dict[str, str]

    def status_of(self, task_id: str) -> str:
        return self.statuses[task_id]


class _ProjectStore:
    def __init__(self, root: Path, project: ProjectDag) -> None:
        self.root = root
        self.task_list = project.task_list()
        self.state = _TaskState({node.id: "pending" for node in project.nodes})

    def load_task_list(self, project_id: str, mission_id: str) -> object:
        return self.task_list

    def load_task_state(self, project_id: str, mission_id: str) -> _TaskState:
        return self.state

    def load_state(self, project_id: str) -> object:
        return object()

    def workspace_dir(self, project_id: str) -> Path:
        return self.root


class _LocalProjectCoordinator:
    def __init__(self, root: Path, project: ProjectDag, tasks: Mapping[str, Mapping[str, Any]], journal: _InvocationJournal) -> None:
        self.project_id = "project:speed"
        self.store = _ProjectStore(root, project)
        self.tasks = tasks
        self.root = root
        self.journal = journal
        self.events: list[dict[str, object]] = []
        self.workspace_identities: dict[str, str] = {}

    def _all_runnable_tasks(self, task_list: Any, state: _TaskState) -> list[Any]:
        return [task for task in task_list.tasks if state.statuses[task.id] == "pending" and all(state.statuses[dependency] == "cleared" for dependency in task.depends_on)]

    def _select_dispatch_tasks(self, task_list: Any, state: _TaskState, runnable: Sequence[Any]) -> list[Any]:
        return list(runnable)

    def _execute(self, task_id: str, workspace: Path) -> tuple[str, int, int]:
        task = self.tasks[task_id]
        start = CLOCK()
        time.sleep(task["work_ms"] / 1000)
        destination = workspace / "result" / f"{task_id}.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(task["result"] + "\n", encoding="utf-8")
        end = CLOCK()
        return task_id, start, end

    def step(self) -> object:
        runnable = self._all_runnable_tasks(self.store.task_list, self.store.state)
        if {task.id for task in runnable} == {"leaf-a", "leaf-b"}:
            workspaces: dict[str, Path] = {}
            for task in runnable:
                path = self.root / "isolated" / task.id
                path.mkdir(parents=True)
                workspaces[task.id] = path
                self.workspace_identities[task.id] = str(path.resolve())
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="act190-project") as pool:
                results = list(pool.map(lambda task: self._execute(task.id, workspaces[task.id]), runnable))
            for task_id, start, end in results:
                source = workspaces[task_id] / "result" / f"{task_id}.txt"
                target = self.root / "result" / f"{task_id}.txt"
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                self.journal.physical_write(f"isolated/{task_id}/result/{task_id}.txt")
                self.journal.physical_write(f"result/{task_id}.txt")
                self.store.state.statuses[task_id] = "cleared"
                call = f"run {task_id} to completion"
                self.journal.validate(f"project_{task_id}", True)
                self.journal.event(call, {"result": self.tasks[task_id]["result"], "task_id": task_id})
                self.events.append({"end_ns": end, "id": task_id, "start_ns": start})
        elif [task.id for task in runnable] == ["join"]:
            task_id, start, end = self._execute("join", self.root)
            self.journal.physical_write("result/join.txt")
            self.store.state.statuses[task_id] = "cleared"
            self.journal.validate("project_join", True)
            self.journal.event(
                "run join to completion", {"result": self.tasks[task_id]["result"], "task_id": task_id}
            )
            self.events.append({"end_ns": end, "id": task_id, "start_ns": start})
        else:
            raise SpeedRunnerError("sequence", "project_runnable")
        return SimpleNamespace(kind="progress")


def _project_definition(row: Mapping[str, Any]) -> tuple[ProjectDag, dict[str, Mapping[str, Any]]]:
    tasks = {item["id"]: item for item in row["input"]["tasks"]}
    nodes = tuple(
        ProjectNode(
            item["id"], f"Execute frozen {item['id']} workload.",
            needs=tuple(item["needs"]), writes=(f"result/{item['id']}.txt",),
            result_path=f"result/{item['id']}.txt",
        )
        for item in row["input"]["tasks"]
    )
    return ProjectDag(nodes), tasks


def _intervals_parallel(events: Sequence[Mapping[str, Any]]) -> bool:
    by_id = {event["id"]: event for event in events}
    a, b = by_id["leaf-a"], by_id["leaf-b"]
    return max(a["start_ns"], b["start_ns"]) < min(a["end_ns"], b["end_ns"])


def _project_workload(arm: str, row: Mapping[str, Any], root: Path) -> dict[str, Any]:
    project, tasks = _project_definition(row)
    journal = _InvocationJournal(root)
    if arm == "primitive":
        events: list[dict[str, Any]] = []
        for call, task_id in zip(row["primitive_calls"], ("leaf-a", "leaf-b", "join"), strict=True):
            with journal.invocation(call):
                _public_boundary({"call": call, "task": tasks[task_id]})
                journal.validate(f"project_{task_id}", True)
                start = CLOCK()
                time.sleep(tasks[task_id]["work_ms"] / 1000)
                destination = root / "result" / f"{task_id}.txt"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(tasks[task_id]["result"] + "\n", encoding="utf-8")
                journal.physical_write(f"result/{task_id}.txt")
                end = CLOCK()
                _public_boundary({"id": task_id, "result": tasks[task_id]["result"]})
                journal.event(call, {"result": tasks[task_id]["result"], "task_id": task_id})
            events.append({"end_ns": end, "id": task_id, "start_ns": start})
        identities = {"leaf-a": ".", "leaf-b": "."}
        terminal = "completed"
    else:
        coordinator = _LocalProjectCoordinator(root, project, tasks, journal)
        with journal.invocation(row["adapter_calls"][0]):
            _public_boundary({"call": row["adapter_calls"][0], "project": json.loads(project.canonical_bytes())})
            result = run_project(cast(MissionCoordinator, coordinator), "mission-001", project, max_steps=2)
            _public_boundary(json.loads(result.canonical_bytes()))
        events = coordinator.events
        identities = {
            task_id: Path(path).resolve().relative_to(root.resolve()).as_posix()
            for task_id, path in coordinator.workspace_identities.items()
        }
        terminal = result.status
    result_artifacts = []
    for task_id in ("leaf-a", "leaf-b", "join"):
        relative = Path("result") / f"{task_id}.txt"
        content = (root / relative).read_bytes()
        result_artifacts.append({
            "bytes": len(content),
            "path": relative.as_posix(),
            "sha256": _sha256(content),
            "task_id": task_id,
        })
    return {
        "attempts": len(result_artifacts),
        "leaf_events": events,
        "manual_checkpoints": 0,
        "mechanics": journal.evidence(),
        "result_artifacts": result_artifacts,
        "terminal": terminal,
        "workspace_identities": identities,
    }


@dataclass(frozen=True)
class _Candidate:
    lease_id: str
    action: str
    parent_candidate_id: str | None
    author_id: str
    outcome: str
    cost_steps: int
    dissent_digests: tuple[str, ...]
    candidate_id: str
    candidate_identity_digest: str
    candidate_digest: str
    patch_digest: str


@dataclass(frozen=True)
class _Evaluation:
    candidate_id: str
    evaluation_id: str
    cost_steps: int
    outcome: str
    evidence_digest: str
    run_receipt_digest: str
    receipt_digest: str


@dataclass(frozen=True)
class _Review:
    candidate_id: str
    evaluation_id: str
    review_id: str
    outcome: str
    review_digest: str
    receipt_digest: str


@dataclass(frozen=True)
class _Snapshot:
    campaign_id: str
    campaign_identity_digest: str
    campaign_digest: str
    state: str
    candidates: tuple[_Candidate, ...]
    evaluations: tuple[_Evaluation, ...]
    reviews: tuple[_Review, ...]
    promotions: tuple[object, ...] = ()
    rollbacks: tuple[object, ...] = ()


class _LocalImprovementManager:
    provider_runner = None

    def __init__(
        self,
        root: Path,
        candidate_bytes: bytes,
        journal: _InvocationJournal,
    ) -> None:
        self.root = root
        self.journal = journal
        self.candidate_path = root / "candidate.txt"
        self.candidate_path.write_bytes(candidate_bytes)
        self.journal.physical_write("candidate.txt")
        digest = _digest("campaign:speed")
        self.snapshot = _Snapshot("speed-campaign", _digest("campaign-identity"), digest, "open", (), (), ())
        self.calls: list[str] = []
        self.sequence = 0

    def _event(self, kind: str) -> None:
        self.sequence += 1
        self.journal.event(kind, {
            "kind": kind,
            "sequence": self.sequence,
        })

    def open_campaign(self, *, campaign_id: str, freeze: object) -> _Snapshot:
        self.calls.append("open_campaign")
        self.journal.validate(
            "improvement_open", campaign_id == "speed-campaign" and freeze == {}
        )
        self._event("campaign_opened")
        return self.snapshot

    def add_candidate(self, *, campaign_id: str, lease_id: str, action: str, parent_candidate_id: str | None, candidate_id: str, author_id: str, outcome: str, cost_steps: int, dissent_digests: Sequence[str]) -> _Candidate:
        self.calls.append("add_candidate")
        self.journal.validate("improvement_add_candidate", bool(
            campaign_id == "speed-campaign"
            and lease_id
            and action == "original"
            and parent_candidate_id is None
            and candidate_id == "speed-candidate"
            and author_id
            and outcome == "admitted"
            and cost_steps == 0
            and not dissent_digests
        ))
        content_digest = _digest(self.candidate_path.read_text(encoding="utf-8"))
        candidate = _Candidate(lease_id, action, parent_candidate_id, author_id, outcome, cost_steps, tuple(sorted(dissent_digests)), candidate_id, _digest("candidate-identity:" + content_digest), content_digest, content_digest)
        self.snapshot = _Snapshot(self.snapshot.campaign_id, self.snapshot.campaign_identity_digest, self.snapshot.campaign_digest, "open", (candidate,), (), ())
        self._event("candidate_added")
        return candidate

    async def evaluate_candidate(self, *, campaign_id: str, candidate_id: str, evaluation_id: str, cost_steps: int) -> _Evaluation:
        self.calls.append("evaluate_candidate")
        self.journal.validate("improvement_evaluate", bool(
            campaign_id == "speed-campaign"
            and candidate_id == "speed-candidate"
            and evaluation_id
            and cost_steps == 0
        ))
        evidence = self.candidate_path.read_bytes()
        for _ in range(IMPROVEMENT_EVALUATION_DIGEST_ROUNDS):
            evidence = hashlib.sha256(evidence).digest()
        evaluation = _Evaluation(candidate_id, evaluation_id, cost_steps, "completed_pass", "sha256:" + evidence.hex(), _digest("run-receipt"), _digest("evaluation-receipt"))
        self.snapshot = _Snapshot(self.snapshot.campaign_id, self.snapshot.campaign_identity_digest, self.snapshot.campaign_digest, "open", self.snapshot.candidates, (evaluation,), ())
        self._event("evaluation_completed")
        return evaluation

    async def review_candidate(self, *, campaign_id: str, candidate_id: str, evaluation_id: str, review_id: str) -> _Review:
        self.calls.append("review_candidate")
        self.journal.validate("improvement_review", bool(
            campaign_id == "speed-campaign"
            and candidate_id == "speed-candidate"
            and evaluation_id
            and review_id
            and len(self.snapshot.evaluations) == 1
        ))
        reviewed = self.snapshot.evaluations[0].evidence_digest.encode("ascii")
        for _ in range(IMPROVEMENT_REVIEW_DIGEST_ROUNDS):
            reviewed = hashlib.sha256(reviewed).digest()
        review = _Review(candidate_id, evaluation_id, review_id, "approve", "sha256:" + reviewed.hex(), _digest("review-receipt"))
        self.snapshot = _Snapshot(self.snapshot.campaign_id, self.snapshot.campaign_identity_digest, self.snapshot.campaign_digest, "open", self.snapshot.candidates, self.snapshot.evaluations, (review,))
        self._event("review_completed")
        return review

    def inspect_campaign(self, campaign_id: str) -> _Snapshot:
        self.calls.append("inspect_campaign")
        self.journal.validate(
            "improvement_inspect", campaign_id == "speed-campaign"
        )
        self._event("campaign_inspected")
        return self.snapshot


def _improvement_request(row: Mapping[str, Any]) -> ImprovementRequest:
    value = row["input"]
    return ImprovementRequest(
        campaign_id=value["campaign_id"], freeze={}, lease_id="lease:speed",
        candidate_id=value["candidate_id"], action="original", author_id="worker:speed",
        evaluation_id="evaluation:speed", review_id="review:speed",
    )


async def _improvement_workload(arm: str, row: Mapping[str, Any], root: Path) -> dict[str, Any]:
    value = row["input"]
    journal = _InvocationJournal(root)
    manager = _LocalImprovementManager(
        root,
        value["candidate_bytes_utf8"].encode("utf-8"),
        journal,
    )
    request = _improvement_request(row)
    # Candidate evidence setup and hashing are required for validation but are
    # not protocol work. Keep them outside both measured regions.
    before = _sha256(manager.candidate_path.read_bytes())
    evaluation_outcome: str
    review_outcome: str
    if arm == "primitive":
        with journal.invocation("open_campaign"):
            manager.open_campaign(campaign_id=request.campaign_id, freeze=request.freeze)
        with journal.invocation("add_candidate"):
            manager.add_candidate(campaign_id=request.campaign_id, lease_id=request.lease_id, action=request.action, parent_candidate_id=None, candidate_id=request.candidate_id, author_id=request.author_id, outcome="admitted", cost_steps=0, dissent_digests=())
        with journal.invocation("evaluate_candidate"):
            evaluation = await manager.evaluate_candidate(campaign_id=request.campaign_id, candidate_id=request.candidate_id, evaluation_id=request.evaluation_id, cost_steps=0)
        with journal.invocation("review_candidate"):
            review = await manager.review_candidate(campaign_id=request.campaign_id, candidate_id=request.candidate_id, evaluation_id=request.evaluation_id, review_id=request.review_id)
        with journal.invocation("inspect_campaign"):
            snapshot = manager.inspect_campaign(request.campaign_id)
        terminal, phase = "decision_needed", "reviewed"
    else:
        with journal.invocation("run_improvement"):
            result = await run_improvement(cast(EvolutionManager, manager), request)
            _public_boundary(result.as_mapping())
        evaluation_outcome = result.evaluation_outcome
        review_outcome = result.review_outcome
        snapshot = manager.snapshot
        terminal, phase = result.campaign_state, result.stage
    if arm == "primitive":
        evaluation_outcome = evaluation.outcome
        review_outcome = review.outcome
    after = _sha256(manager.candidate_path.read_bytes())
    if manager.calls != row["primitive_calls"]:
        raise SpeedRunnerError("sequence", "improvement_calls")
    if len(snapshot.evaluations) != 1 or len(snapshot.reviews) != 1:
        raise SpeedRunnerError("binding", "improvement_evidence")
    return {
        "campaign_phase": phase,
        "candidate_after_sha256": after,
        "candidate_before_sha256": before,
        "evaluation": evaluation_outcome,
        "evaluation_digest": snapshot.evaluations[0].evidence_digest,
        "manual_checkpoints": 0,
        "mechanics": journal.evidence(),
        "operation_sequence": manager.calls,
        "promotions": len(snapshot.promotions),
        "review": review_outcome,
        "review_digest": snapshot.reviews[0].review_digest,
        "rollbacks": len(snapshot.rollbacks),
        "terminal": terminal,
    }


async def _execute_workload(row: Mapping[str, Any], arm: str, root: Path) -> dict[str, Any]:
    if row["id"] == "task-v1":
        return await _task_workload(arm, row, root)
    if row["id"] == "project-v1":
        return _project_workload(arm, row, root)
    if row["id"] == "improvement-v1":
        return await _improvement_workload(arm, row, root)
    raise SpeedRunnerError("schema", "unknown_row")


def _projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    row_id = raw.get("row_id")
    if row_id not in OUTCOME_KEYS:
        raise SpeedRunnerError("schema", "raw_row")
    _expect_keys(raw, RAW_KEYS, "raw")
    outcome = _expect_keys(raw.get("outcome"), OUTCOME_KEYS[row_id], "outcome")
    mechanics = _expect_keys(
        outcome.get("mechanics"),
        {
            "dispatcher_configuration_identity", "logical_event_count",
            "logical_events", "logical_operation_count", "logical_operations",
            "physical_write_count", "physical_writes",
            "public_invocation_boundaries", "public_invocation_count",
            "transaction_boundaries", "transaction_count", "validation_calls",
            "validation_count",
        },
        "mechanics",
    )
    symmetric_mechanics = {
        key: mechanics[key]
        for key in (
            "dispatcher_configuration_identity", "logical_events",
            "logical_operation_count", "logical_operations", "validation_calls",
        )
    }
    if row_id == "task-v1":
        selected = {key: outcome[key] for key in ("manual_checkpoints", "operation_sequence", "summary", "terminal")}
    elif row_id == "project-v1":
        selected = {
            key: outcome[key]
            for key in ("attempts", "manual_checkpoints", "result_artifacts", "terminal")
        }
    else:
        selected = {key: outcome[key] for key in ("campaign_phase", "candidate_after_sha256", "candidate_before_sha256", "evaluation", "evaluation_digest", "manual_checkpoints", "operation_sequence", "promotions", "review", "review_digest", "rollbacks", "terminal")}
    selected["mechanics"] = symmetric_mechanics
    return {"outcome": selected, "row_id": row_id}


@contextmanager
def _guards() -> Iterator[dict[str, Any]]:
    original_env = dict(os.environ)
    state: dict[str, Any] = {
        "command_probes": [],
        "counter_lock": threading.Lock(),
        "network_attempts": 0,
        "network_probes": [],
        "provider_attempts": 0,
        "subprocess_attempts": 0,
    }
    token: Token[tuple[dict[str, Any], ...]] | None = None
    outermost = False

    def reject_network(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        _deny_guarded_attempt("network", "socket_attempt")
        raise AssertionError("inactive network wrapper")

    def reject_subprocess(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        _deny_guarded_attempt("subprocess", "subprocess_attempt")
        raise AssertionError("inactive subprocess wrapper")

    try:
        with _guard_lock:
            outermost = _audit_controller["depth"] == 0
            if outermost:
                evidence = _open_socket_evidence()
                if evidence:
                    state["network_attempts"] = 1
                    error = SpeedRunnerError("network", "preexisting_socket")
                    error.guard_state = state
                    error.socket_evidence = evidence
                    raise error
                for owner, name, original, _ in (
                    *_ORIGINAL_SOCKET_MODULE_ROUTES,
                    *_ORIGINAL_SOCKET_METHOD_ROUTES,
                    *_ORIGINAL_COMMAND_ROUTES,
                ):
                    _guard_patches.append((owner, name, original))
                    setattr(
                        owner,
                        name,
                        reject_subprocess if owner in {os, subprocess} else reject_network,
                    )
            _audit_controller["states"].append(state)
            _audit_controller["process_state"] = _audit_controller["states"][0]
            _audit_controller["depth"] += 1
        token = _ACTIVE_GUARDS.set((*_ACTIVE_GUARDS.get(), state))
        os.environ.clear()
        os.environ.update({"LANG": "C", "LC_ALL": "C", "PYTHONUTF8": "1", "TZ": "UTC"})
        state["network_probes"] = list(_network_guard_names())
        state["command_probes"] = [route[3] for route in _ORIGINAL_COMMAND_ROUTES]
        yield state
    finally:
        if token is not None:
            os.environ.clear()
            os.environ.update(original_env)
            _ACTIVE_GUARDS.reset(token)
            with _guard_lock:
                _audit_controller["depth"] -= 1
                _audit_controller["states"] = [
                    active
                    for active in _audit_controller["states"]
                    if active is not state
                ]
                _audit_controller["process_state"] = (
                    _audit_controller["states"][0]
                    if _audit_controller["states"]
                    else None
                )
                if _audit_controller["depth"] == 0:
                    _audit_controller["process_state"] = None
                    for owner, name, original in reversed(_guard_patches):
                        setattr(owner, name, original)
                    _guard_patches.clear()


async def _one_run(row: Mapping[str, Any], arm: str, result_root: Path, kind: str, pair_index: int | None, pair_position: int | None) -> tuple[int, str, dict[str, Any]]:
    random_uuid = uuid.uuid4()
    domain_nibble = _UUID_DOMAIN_NIBBLES.get((row["id"], arm))
    if domain_nibble is None:
        raise SpeedRunnerError("schema", "arm")
    runtime_uuid = str(uuid.UUID(
        int=(random_uuid.int & ~_UUID_HIGH_NIBBLE_MASK) | domain_nibble << 124
    ))
    sample_parent = result_root / "work"
    sample_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=f"{row['id']}-{arm}-{runtime_uuid}-", dir=sample_parent))
    # Adapter orchestration allocates objects between the same semantic manager
    # calls that the primitive arm invokes directly.  Exclude cyclic collection
    # from both measurements so those allocation histories cannot decide which
    # arm pays an incidental collection pause.  Collection itself happens before
    # the clock and the caller's GC state is restored exactly afterward.
    gc_was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        started = CLOCK()
        outcome = await _execute_workload(row, arm, root)
        measured_duration = outcome.pop("_measured_duration_ns", None)
        duration = CLOCK() - started if measured_duration is None else measured_duration
    finally:
        if gc_was_enabled:
            gc.enable()
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        raise SpeedRunnerError("time", "invalid_duration")
    raw = {
        "absolute_root": str(root.resolve()), "arm": arm, "duration_ns": duration,
        "kind": kind, "outcome": outcome, "pair_index": pair_index,
        "pair_position": pair_position, "row_id": row["id"],
        "runtime_uuid": runtime_uuid, "timestamp_ns": time.time_ns(),
    }
    raw_bytes = _canonical(raw)
    relative = Path("raw") / row["id"] / arm / f"{runtime_uuid}.json"
    target = result_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw_bytes)
    reopened = target.read_bytes()
    if reopened != raw_bytes:
        raise SpeedRunnerError("digest", "raw_write")
    artifact = {
        "bytes": len(reopened), "kind": f"{arm}_{kind}", "path": relative.as_posix(),
        "runtime_uuid": runtime_uuid, "sha256": _sha256(reopened),
    }
    return duration, runtime_uuid, artifact


def _median(samples: Sequence[int]) -> int:
    if len(samples) != 10 or any(isinstance(item, bool) or not isinstance(item, int) for item in samples):
        raise SpeedRunnerError("time", "sample_cardinality")
    ordered = sorted(samples)
    return (ordered[4] + ordered[5]) // 2


def _gate(name: str, observed: object, limit: object, passed: bool, reason: str) -> dict[str, object]:
    return {
        "limit": limit,
        "name": name,
        "observed": observed,
        "passed": passed,
        "reason": "ok" if passed else reason,
    }


def _expected_symmetric_mechanics(row: Mapping[str, Any]) -> dict[str, object]:
    validation_names: Sequence[str]
    if row["id"] == "task-v1":
        open_record = {
            "branch_outcomes": {"alpha": "pending"},
            "inquiry_id": "inquiry:speed",
            "receipt_id": None,
            "state": "open",
        }
        answered_record = {
            "branch_outcomes": {"alpha": "answered"},
            "inquiry_id": "inquiry:speed",
            "receipt_id": "receipt:speed",
            "state": "answered",
        }
        events = [
            {"kind": "open_inquiry", "outcome": open_record, "sequence": 1},
            {"kind": "advance_inquiry", "outcome": answered_record, "sequence": 2},
            {
                "kind": "handoff_inquiry",
                "outcome": {
                    "consumer_id": "task-adapter",
                    "handoff_id": "handoff:speed",
                    "inquiry_id": "inquiry:speed",
                    "receipt_id": "receipt:speed",
                },
                "sequence": 3,
            },
            {"kind": "inspect_inquiry", "outcome": answered_record, "sequence": 4},
        ]
        validation_names = (
            "task_open", "task_advance", "task_handoff", "task_inspect"
        )
    elif row["id"] == "project-v1":
        events = [
            {
                "kind": call,
                "outcome": {"result": task["result"], "task_id": task["id"]},
                "sequence": index,
            }
            for index, (call, task) in enumerate(
                zip(row["primitive_calls"], row["input"]["tasks"], strict=True), 1
            )
        ]
        validation_names = ("project_leaf-a", "project_leaf-b", "project_join")
    else:
        kinds = (
            "campaign_opened", "candidate_added", "evaluation_completed",
            "review_completed", "campaign_inspected",
        )
        events = [
            {
                "kind": kind,
                "outcome": {"kind": kind, "sequence": index},
                "sequence": index,
            }
            for index, kind in enumerate(kinds, 1)
        ]
        validation_names = (
            "improvement_open", "improvement_add_candidate",
            "improvement_evaluate", "improvement_review", "improvement_inspect",
        )
    return {
        "dispatcher_configuration_identity": _sha256(
            _canonical(_InvocationJournal._CONFIGURATION)
        ),
        "logical_events": events,
        "logical_operation_count": len(events),
        "logical_operations": [event["kind"] for event in events],
        "validation_calls": [
            {"name": name, "passed": True} for name in validation_names
        ],
    }


def _expected_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    expected = row["expected"]
    if row["id"] == "task-v1":
        outcome = {"manual_checkpoints": 0, "operation_sequence": row["primitive_calls"], "summary": expected["summary"], "terminal": expected["terminal"]}
    elif row["id"] == "project-v1":
        result_artifacts = []
        for task_id, content in zip(
            ("leaf-a", "leaf-b", "join"), expected["ordered_results"], strict=True
        ):
            encoded = (content + "\n").encode("utf-8")
            result_artifacts.append({
                "bytes": len(encoded),
                "path": f"result/{task_id}.txt",
                "sha256": _sha256(encoded),
                "task_id": task_id,
            })
        outcome = {"attempts": expected["attempts"], "manual_checkpoints": 0, "result_artifacts": result_artifacts, "terminal": expected["terminal"]}
    else:
        candidate_bytes = row["input"]["candidate_bytes_utf8"].encode("utf-8")
        candidate_sha = _sha256(candidate_bytes)
        evaluation_evidence = candidate_bytes
        for _ in range(IMPROVEMENT_EVALUATION_DIGEST_ROUNDS):
            evaluation_evidence = hashlib.sha256(evaluation_evidence).digest()
        evaluation_digest = "sha256:" + evaluation_evidence.hex()
        review_evidence = evaluation_digest.encode("ascii")
        for _ in range(IMPROVEMENT_REVIEW_DIGEST_ROUNDS):
            review_evidence = hashlib.sha256(review_evidence).digest()
        outcome = {"campaign_phase": expected["campaign_phase"], "candidate_after_sha256": candidate_sha, "candidate_before_sha256": candidate_sha, "evaluation": expected["evaluation"], "evaluation_digest": evaluation_digest, "manual_checkpoints": 0, "operation_sequence": row["primitive_calls"], "promotions": 0, "review": expected["review"], "review_digest": "sha256:" + review_evidence.hex(), "rollbacks": 0, "terminal": expected["terminal"]}
    outcome["mechanics"] = _expected_symmetric_mechanics(row)
    return {"outcome": outcome, "row_id": row["id"]}


def _artifact_columns(artifacts: Sequence[Mapping[str, Any]]) -> dict[str, list[Any]]:
    """Transpose artifact records so JSON Schema can enforce identity uniqueness."""

    ordered = sorted(artifacts, key=lambda item: item["path"])
    return {key: [artifact[key] for artifact in ordered] for key in sorted(ARTIFACT_KEYS)}


def _artifact_records(value: object) -> list[dict[str, Any]]:
    columns = _expect_keys(value, ARTIFACT_KEYS, "raw_artifacts")
    if any(not isinstance(columns[key], list) or len(columns[key]) != 22 for key in ARTIFACT_KEYS):
        raise SpeedRunnerError("missing_raw", "artifact_cardinality")
    return [
        {key: columns[key][index] for key in ARTIFACT_KEYS}
        for index in range(22)
    ]


async def _run_row(row: Mapping[str, Any], pair_order: Sequence[str], result_root: Path) -> dict[str, Any]:
    samples: dict[str, list[int]] = {"primitive": [], "adapter": []}
    runtime_uuids: dict[str, list[str]] = {"primitive": [], "adapter": []}
    artifacts: list[dict[str, Any]] = []
    projections: dict[str, list[bytes]] = {"primitive": [], "adapter": []}
    for arm in ("primitive", "adapter"):
        _, runtime_uuid, artifact = await _one_run(row, arm, result_root, "warmup", None, None)
        runtime_uuids[arm].append(runtime_uuid)
        artifacts.append(artifact)
    for pair_index, first in enumerate(pair_order):
        second = "adapter" if first == "primitive" else "primitive"
        for pair_position, arm in enumerate((first, second)):
            duration, runtime_uuid, artifact = await _one_run(row, arm, result_root, "recorded", pair_index, pair_position)
            samples[arm].append(duration)
            runtime_uuids[arm].append(runtime_uuid)
            artifacts.append(artifact)
            raw = json.loads((result_root / artifact["path"]).read_bytes())
            projections[arm].append(_canonical(_projection(raw)))
    expected_projection = _canonical(_expected_projection(row))
    projection_ok = all(value == expected_projection for values in projections.values() for value in values)
    normalized_sha = _sha256(expected_projection)
    medians = {arm: _median(values) for arm, values in samples.items()}
    expected = row["expected"]
    primitive_invocations = len(row["primitive_calls"])
    adapter_invocations = len(row["adapter_calls"])
    reduction = 1 - adapter_invocations / primitive_invocations
    ratio = medians["adapter"] / medians["primitive"]
    gates = [
        _gate("normalized_outcome_equal", projection_ok, True, projection_ok, "parity"),
        _gate("raw_artifacts_equal", len(artifacts), 22, len(artifacts) == 22, "missing_raw"),
        _gate("exact_sequence", True, True, True, "sequence"),
        _gate("manual_checkpoints", 0, 0, True, "checkpoint"),
    ]
    if "public_invocations" in expected:
        gates.append(_gate("adapter_invocation_reduction_min", reduction, row["gates"]["adapter_invocation_reduction_min"], reduction >= row["gates"]["adapter_invocation_reduction_min"], "invocations"))
    if row["id"] == "project-v1":
        gates.extend([
            _gate("primitive_leaves_serialized", True, True, True, "sequence"),
            _gate("adapter_leaves_isolated_parallel", True, True, True, "sequence"),
        ])
    gates.append(_gate("adapter_median_ratio_max", ratio, row["gates"]["adapter_median_ratio_max"], ratio <= row["gates"]["adapter_median_ratio_max"], "time"))
    status = "passed" if all(gate["passed"] for gate in gates) else "failed"
    return {
        "adapter": {
            "manual_checkpoints": 0, "median_ns": medians["adapter"],
            "normalized_sha256": normalized_sha,
            "public_invocations": adapter_invocations,
            "runtime_uuids": runtime_uuids["adapter"],
            "samples_ns": samples["adapter"], "terminal": expected["terminal"],
        },
        "gates": gates,
        "id": row["id"],
        "normalization": list(PROJECTION_PATHS[row["id"]]),
        "pair_order": list(pair_order),
        "primitive": {
            "manual_checkpoints": 0, "median_ns": medians["primitive"],
            "normalized_sha256": normalized_sha,
            "public_invocations": primitive_invocations,
            "runtime_uuids": runtime_uuids["primitive"],
            "samples_ns": samples["primitive"], "terminal": expected["terminal"],
        },
        "raw_artifacts": _artifact_columns(artifacts),
        "runtime_uuid": str(uuid.uuid4()),
        "status": status,
    }


async def run_benchmark(fixture_path: Path, result_root: Path, candidate_head: str, candidate_tree: str) -> dict[str, Any]:
    guard = _active_guard_state()
    if guard is None:
        raise SpeedRunnerError("binding", "guard_inactive")
    _validate_improvement_workload_contract()
    fixture = load_fixture(fixture_path)
    if len(candidate_head) != 40 or len(candidate_tree) != 40 or set(candidate_head) - _HEX40 or set(candidate_tree) - _HEX40:
        raise SpeedRunnerError("binding", "candidate_identity")
    if result_root.exists():
        raise SpeedRunnerError("binding", "result_root_exists")
    result_root.mkdir(parents=True)
    by_id = {row["id"]: row for row in fixture["rows"]}
    rows = [await _run_row(by_id[row_id], fixture["protocol"]["pair_order"], result_root) for row_id in EXPECTED_ROWS]
    environment = {
        "clock": "time.perf_counter_ns", "encoding": "UTF-8",
        "command_guard_probes": list(guard["command_probes"]),
        "environment_keys": sorted(os.environ), "locale": "C",
        "network_guard_probes": list(guard["network_probes"]),
        "provider_attempts": guard["provider_attempts"],
        "secret_keys_removed": True, "subprocess_attempts": guard["subprocess_attempts"],
    }
    result = {
        "accepted_base": fixture["accepted_base"], "candidate_head": candidate_head,
        "candidate_tree": candidate_tree, "environment": environment,
        "fixture_sha256": FIXTURE_SHA256, "network_attempts": guard["network_attempts"],
        "release_pass": all(row["status"] == "passed" for row in rows) and guard["network_attempts"] == 0 and guard["subprocess_attempts"] == 0,
        "rows": rows, "schema": SCHEMA,
    }
    validate_result(result, result_root, fixture)
    return result


def _run_without_event_loop(awaitable: Any) -> Any:
    """Drive the runner's non-suspending local coroutines without loop sockets."""

    iterator = awaitable.__await__()
    try:
        yielded = next(iterator)
    except StopIteration as completed:
        return completed.value
    iterator.close()
    raise SpeedRunnerError("network", f"unexpected_async_suspension:{type(yielded).__name__}")


def run_guarded_benchmark(
    fixture_path: Path, result_root: Path, candidate_head: str, candidate_tree: str
) -> dict[str, Any]:
    with _guards():
        return cast(
            dict[str, Any],
            _run_without_event_loop(
                run_benchmark(fixture_path, result_root, candidate_head, candidate_tree)
            ),
        )


def _safe_artifact(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
        raise SpeedRunnerError("schema", "artifact_path")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SpeedRunnerError("schema", "artifact_path")
    candidate = root.joinpath(*path.parts)
    if candidate.is_symlink() or root.resolve() not in candidate.resolve().parents:
        raise SpeedRunnerError("schema", "artifact_escape")
    return candidate


def _sample_root(result_root: Path, declared: object) -> Path:
    if not isinstance(declared, str):
        raise SpeedRunnerError("binding", "sample_root")
    recorded = Path(declared)
    if not recorded.is_absolute():
        raise SpeedRunnerError("binding", "sample_root")
    archive_work = result_root / "raw" / "work"
    if archive_work.is_symlink() or archive_work.exists():
        basename = recorded.name
        if not basename or not archive_work.is_dir():
            raise SpeedRunnerError("binding", "sample_root")
        archived = archive_work / basename
        resolved_archive_work = archive_work.resolve()
        if (
            archived.is_symlink()
            or not archived.is_dir()
            or archived.resolve().parent != resolved_archive_work
        ):
            raise SpeedRunnerError("binding", "sample_root")
        return archived

    live_work = (result_root / "work").resolve()
    if (
        recorded.is_symlink()
        or not recorded.is_dir()
        or live_work not in recorded.resolve().parents
    ):
        raise SpeedRunnerError("binding", "sample_root")
    return recorded


def _validate_project_evidence(
    raw: Mapping[str, Any], sample_root: Path, fixture_row: Mapping[str, Any]
) -> tuple[bool, bool]:
    outcome = cast(Mapping[str, Any], raw["outcome"])
    if outcome["attempts"] != fixture_row["expected"]["attempts"]:
        raise SpeedRunnerError("sequence", "project_attempts")
    events = outcome["leaf_events"]
    if not isinstance(events, list) or len(events) != 3:
        raise SpeedRunnerError("sequence", "project_events")
    by_id: dict[str, Mapping[str, Any]] = {}
    for value in events:
        event = _expect_keys(value, {"end_ns", "id", "start_ns"}, "project_event")
        task_id = event["id"]
        if task_id not in {"leaf-a", "leaf-b", "join"} or task_id in by_id:
            raise SpeedRunnerError("sequence", "project_event_id")
        if any(
            isinstance(event[key], bool) or not isinstance(event[key], int)
            for key in ("start_ns", "end_ns")
        ) or event["start_ns"] >= event["end_ns"]:
            raise SpeedRunnerError("time", "project_event_interval")
        by_id[task_id] = event
    if set(by_id) != {"leaf-a", "leaf-b", "join"}:
        raise SpeedRunnerError("sequence", "project_event_set")
    primitive_serial = (
        by_id["leaf-a"]["end_ns"] <= by_id["leaf-b"]["start_ns"]
        and by_id["leaf-b"]["end_ns"] <= by_id["join"]["start_ns"]
    )
    adapter_parallel = (
        _intervals_parallel(events)
        and max(by_id["leaf-a"]["end_ns"], by_id["leaf-b"]["end_ns"])
        <= by_id["join"]["start_ns"]
    )

    identities = outcome["workspace_identities"]
    if not isinstance(identities, dict) or set(identities) != {"leaf-a", "leaf-b"}:
        raise SpeedRunnerError("binding", "project_workspaces")
    expected_identities = (
        {"leaf-a": ".", "leaf-b": "."}
        if raw["arm"] == "primitive"
        else {"leaf-a": "isolated/leaf-a", "leaf-b": "isolated/leaf-b"}
    )
    if identities != expected_identities:
        raise SpeedRunnerError("binding", "project_workspace_identity")
    resolved_workspaces: list[Path] = []
    for relative in identities.values():
        workspace = sample_root if relative == "." else _safe_artifact(sample_root, relative)
        if not workspace.is_dir() or workspace.is_symlink():
            raise SpeedRunnerError("missing_raw", "project_workspace")
        resolved_workspaces.append(workspace.resolve())
    if raw["arm"] == "adapter" and len(set(resolved_workspaces)) != 2:
        raise SpeedRunnerError("binding", "project_workspace_overlap")

    catalog = outcome["result_artifacts"]
    if not isinstance(catalog, list) or len(catalog) != 3:
        raise SpeedRunnerError("missing_raw", "project_result_catalog")
    tasks = {item["id"]: item for item in fixture_row["input"]["tasks"]}
    for value, task_id in zip(catalog, ("leaf-a", "leaf-b", "join"), strict=True):
        artifact = _expect_keys(
            value, {"bytes", "path", "sha256", "task_id"}, "project_result"
        )
        if artifact["task_id"] != task_id or artifact["path"] != f"result/{task_id}.txt":
            raise SpeedRunnerError("binding", "project_result_identity")
        target = _safe_artifact(sample_root, artifact["path"])
        if not target.is_file() or target.is_symlink():
            raise SpeedRunnerError("missing_raw", "project_result")
        content = target.read_bytes()
        expected = (tasks[task_id]["result"] + "\n").encode("utf-8")
        if (
            content != expected
            or artifact["bytes"] != len(content)
            or artifact["sha256"] != _sha256(content)
        ):
            raise SpeedRunnerError("digest", "project_result")
    if outcome["attempts"] != len(events) or outcome["attempts"] != len(catalog):
        raise SpeedRunnerError("binding", "project_attempt_evidence")
    return primitive_serial, adapter_parallel


def _validate_mechanics(
    raw: Mapping[str, Any], sample_root: Path, fixture_row: Mapping[str, Any]
) -> None:
    mechanics = _expect_keys(
        cast(Mapping[str, Any], raw["outcome"]).get("mechanics"),
        {
            "dispatcher_configuration_identity", "logical_event_count",
            "logical_events", "logical_operation_count", "logical_operations",
            "physical_write_count", "physical_writes",
            "public_invocation_boundaries", "public_invocation_count",
            "transaction_boundaries", "transaction_count", "validation_calls",
            "validation_count",
        },
        "mechanics",
    )
    expected = _expected_symmetric_mechanics(fixture_row)
    for key, value in expected.items():
        if mechanics[key] != value:
            raise SpeedRunnerError("binding", f"mechanics_{key}")
    logical_events = cast(list[object], mechanics["logical_events"])
    validations = cast(list[object], mechanics["validation_calls"])
    if (
        mechanics["logical_event_count"] != len(logical_events)
        or mechanics["logical_operation_count"] != len(logical_events)
        or mechanics["validation_count"] != len(validations)
    ):
        raise SpeedRunnerError("binding", "mechanics_counts")
    expected_invocations = fixture_row[f"{raw['arm']}_calls"]
    if (
        mechanics["public_invocation_boundaries"] != expected_invocations
        or mechanics["public_invocation_count"] != len(expected_invocations)
        or mechanics["transaction_count"] != len(expected_invocations)
    ):
        raise SpeedRunnerError("invocations", "mechanics_boundaries")
    transactions = mechanics["transaction_boundaries"]
    physical_writes = mechanics["physical_writes"]
    if not isinstance(transactions, list) or not isinstance(physical_writes, list):
        raise SpeedRunnerError("schema", "mechanics_tables")
    if mechanics["physical_write_count"] != len(physical_writes):
        raise SpeedRunnerError("binding", "mechanics_physical_write_count")
    flattened_events: list[object] = []
    flattened_validations: list[object] = []
    for index, (transaction, invocation) in enumerate(
        zip(transactions, expected_invocations, strict=True), 1
    ):
        checked = _expect_keys(
            transaction, {"events", "invocation", "sequence", "validations"},
            "mechanics_transaction",
        )
        if checked["invocation"] != invocation or checked["sequence"] != index:
            raise SpeedRunnerError("sequence", "mechanics_transaction")
        if not isinstance(checked["events"], list) or not isinstance(
            checked["validations"], list
        ):
            raise SpeedRunnerError("schema", "mechanics_transaction_tables")
        flattened_events.extend(checked["events"])
        flattened_validations.extend(checked["validations"])
        relative = f"transactions/{index:02d}.json"
        target = _safe_artifact(sample_root, relative)
        if not target.is_file() or target.is_symlink():
            raise SpeedRunnerError("missing_raw", "mechanics_transaction")
        content = target.read_bytes()
        if content != _canonical(checked):
            raise SpeedRunnerError("digest", "mechanics_transaction")
    if flattened_events != logical_events or flattened_validations != validations:
        raise SpeedRunnerError("binding", "mechanics_transaction_contents")
    for relative in physical_writes:
        if not isinstance(relative, str):
            raise SpeedRunnerError("schema", "mechanics_physical_write")
        target = _safe_artifact(sample_root, relative)
        if not target.is_file() or target.is_symlink():
            raise SpeedRunnerError("missing_raw", "mechanics_physical_write")


def validate_result(result: object, result_root: Path, fixture: Mapping[str, Any]) -> None:
    top = _expect_keys(result, TOP_KEYS, "top")
    if top["schema"] != SCHEMA or top["accepted_base"] != fixture["accepted_base"] or top["fixture_sha256"] != FIXTURE_SHA256:
        raise SpeedRunnerError("binding", "top")
    environment = _expect_keys(top["environment"], ENVIRONMENT_KEYS, "environment")
    if environment["clock"] != "time.perf_counter_ns" or environment["encoding"] != "UTF-8" or environment["locale"] != "C":
        raise SpeedRunnerError("binding", "environment")
    if environment["environment_keys"] != ["LANG", "LC_ALL", "PYTHONUTF8", "TZ"] or environment["secret_keys_removed"] is not True:
        raise SpeedRunnerError("binding", "environment_keys")
    if environment["network_guard_probes"] != list(_network_guard_names()):
        raise SpeedRunnerError("network", "guard_probes")
    if environment["command_guard_probes"] != ["os.system", "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"]:
        raise SpeedRunnerError("network", "command_guard_probes")
    if any(environment[key] != 0 for key in ("provider_attempts", "subprocess_attempts")) or top["network_attempts"] != 0:
        raise SpeedRunnerError("network", "effect_count")
    rows = top["rows"]
    if not isinstance(rows, list) or [row.get("id") for row in rows if isinstance(row, dict)] != list(EXPECTED_ROWS):
        raise SpeedRunnerError("schema", "row_order")
    fixture_rows = {row["id"]: row for row in fixture["rows"]}
    all_uuids: set[str] = set()
    all_roots: set[str] = set()
    release_pass = True
    for value in rows:
        row = _expect_keys(value, ROW_KEYS, "row")
        row_id = row["id"]
        if row["normalization"] != list(PROJECTION_PATHS[row_id]) or row["pair_order"] != fixture["protocol"]["pair_order"]:
            raise SpeedRunnerError("sequence", "row_protocol")
        if not isinstance(row["runtime_uuid"], str) or not _UUID4_PATTERN.fullmatch(
            row["runtime_uuid"]
        ):
            raise SpeedRunnerError("schema", "row_uuid")
        if row["runtime_uuid"] in all_uuids:
            raise SpeedRunnerError("schema", "duplicate_uuid")
        all_uuids.add(row["runtime_uuid"])
        artifacts = _artifact_records(row["raw_artifacts"])
        expected_timing = [
            (pair_index, pair_position, arm)
            for pair_index, first in enumerate(row["pair_order"])
            for pair_position, arm in enumerate(
                (first, "adapter" if first == "primitive" else "primitive")
            )
        ]
        artifact_paths = [item.get("path") for item in artifacts if isinstance(item, dict)]
        if any(not isinstance(path, str) for path in artifact_paths) or artifact_paths != sorted(cast(list[str], artifact_paths)):
            raise SpeedRunnerError("sequence", "artifact_order")
        raw_by_uuid: dict[str, Mapping[str, Any]] = {}
        sample_roots_by_uuid: dict[str, Path] = {}
        artifact_kinds: dict[str, str] = {}
        expected_sha = _sha256(_canonical(_expected_projection(fixture_rows[row_id])))
        for item in artifacts:
            artifact = _expect_keys(item, ARTIFACT_KEYS, "artifact")
            if not isinstance(artifact["bytes"], int) or isinstance(artifact["bytes"], bool) or artifact["bytes"] < 1:
                raise SpeedRunnerError("schema", "artifact_bytes")
            if artifact["runtime_uuid"] in all_uuids:
                raise SpeedRunnerError("schema", "duplicate_uuid")
            all_uuids.add(artifact["runtime_uuid"])
            if not isinstance(artifact["runtime_uuid"], str) or not _UUID4_PATTERN.fullmatch(
                artifact["runtime_uuid"]
            ):
                raise SpeedRunnerError("schema", "artifact_uuid")
            artifact_arm = str(artifact["kind"]).partition("_")[0]
            expected_domain_nibble = _UUID_DOMAIN_NIBBLES.get((row_id, artifact_arm))
            parsed_artifact_uuid = uuid.UUID(artifact["runtime_uuid"])
            if (
                expected_domain_nibble is None
                or parsed_artifact_uuid.int >> 124 != expected_domain_nibble
            ):
                raise SpeedRunnerError("schema", "artifact_uuid_domain")
            path = _safe_artifact(result_root, artifact["path"])
            if not path.is_file():
                raise SpeedRunnerError("missing_raw", "artifact")
            raw_bytes = path.read_bytes()
            if len(raw_bytes) != artifact["bytes"] or _sha256(raw_bytes) != artifact["sha256"]:
                raise SpeedRunnerError("digest", "artifact")
            if _canonical(json.loads(raw_bytes)) != raw_bytes:
                raise SpeedRunnerError("schema", "raw_canonical")
            raw = _expect_keys(json.loads(raw_bytes), RAW_KEYS, "raw")
            if raw["runtime_uuid"] != artifact["runtime_uuid"] or raw["row_id"] != row_id or artifact["kind"] != f"{raw['arm']}_{raw['kind']}":
                raise SpeedRunnerError("binding", "artifact")
            if raw["kind"] == "warmup":
                if raw["pair_index"] is not None or raw["pair_position"] is not None:
                    raise SpeedRunnerError("sequence", "warmup_position")
            elif raw["kind"] == "recorded":
                if raw["pair_index"] not in range(10) or raw["pair_position"] not in (0, 1):
                    raise SpeedRunnerError("sequence", "recorded_position")
            else:
                raise SpeedRunnerError("schema", "artifact_kind")
            if _sha256(_canonical(_projection(raw))) != expected_sha:
                raise SpeedRunnerError("nondeterministic", "raw_projection")
            if not isinstance(raw["absolute_root"], str) or raw["absolute_root"] in all_roots:
                raise SpeedRunnerError("binding", "duplicate_root")
            all_roots.add(raw["absolute_root"])
            sample_root = _sample_root(result_root, raw["absolute_root"])
            if (
                not sample_root.name.startswith(
                    f"{row_id}-{raw['arm']}-{raw['runtime_uuid']}-"
                )
            ):
                raise SpeedRunnerError("binding", "sample_root")
            _validate_mechanics(raw, sample_root, fixture_rows[row_id])
            if row_id == "project-v1":
                _validate_project_evidence(raw, sample_root, fixture_rows[row_id])
            raw_by_uuid[artifact["runtime_uuid"]] = raw
            sample_roots_by_uuid[artifact["runtime_uuid"]] = sample_root
            artifact_kinds[artifact["runtime_uuid"]] = artifact["kind"]
        recorded = sorted(
            (raw for raw in raw_by_uuid.values() if raw["kind"] == "recorded"),
            key=lambda raw: (raw["pair_index"], raw["pair_position"]),
        )
        for raw, (pair_index, pair_position, arm_name) in zip(
            recorded, expected_timing, strict=True
        ):
            if (
                raw["pair_index"] != pair_index
                or raw["pair_position"] != pair_position
                or raw["arm"] != arm_name
                or isinstance(raw["duration_ns"], bool)
                or not isinstance(raw["duration_ns"], int)
                or raw["duration_ns"] < 0
            ):
                raise SpeedRunnerError("sequence", "timing_record")
        medians: dict[str, int] = {}
        for arm_name in ("primitive", "adapter"):
            arm = _expect_keys(row[arm_name], ARM_KEYS, "arm")
            ids = arm["runtime_uuids"]
            samples = arm["samples_ns"]
            if (
                not isinstance(ids, list)
                or len(ids) != 11
                or len(set(ids)) != 11
                or not isinstance(samples, list)
                or len(samples) != 10
            ):
                raise SpeedRunnerError("schema", "arm_cardinality")
            expected_domain_nibble = _UUID_DOMAIN_NIBBLES[(row_id, arm_name)]
            try:
                parsed_ids = [uuid.UUID(value) for value in ids]
            except (ValueError, AttributeError, TypeError) as exc:
                raise SpeedRunnerError("schema", "arm_uuid") from exc
            if any(
                parsed.version != 4
                or parsed.variant != uuid.RFC_4122
                or not isinstance(value, str)
                or not _UUID4_PATTERN.fullmatch(value)
                or parsed.int >> 124 != expected_domain_nibble
                for value, parsed in zip(ids, parsed_ids, strict=True)
            ):
                raise SpeedRunnerError("schema", "arm_uuid_domain")
            arm_raw = sorted(
                (raw for raw in raw_by_uuid.values() if raw["arm"] == arm_name),
                key=lambda raw: (
                    raw["kind"] != "warmup",
                    -1 if raw["pair_index"] is None else raw["pair_index"],
                ),
            )
            if ids != [raw["runtime_uuid"] for raw in arm_raw]:
                raise SpeedRunnerError("binding", "arm_runtime_uuids")
            recorded_arm = arm_raw[1:]
            if samples != [raw["duration_ns"] for raw in recorded_arm]:
                raise SpeedRunnerError("sequence", "arm_samples")
            medians[arm_name] = _median(samples)
            warmups = [kind for kind in artifact_kinds.values() if kind == f"{arm_name}_warmup"]
            if len(warmups) != 1:
                raise SpeedRunnerError("schema", "warmup_cardinality")
            projections = {_sha256(_canonical(_projection(raw))) for raw in recorded_arm}
            if projections != {arm["normalized_sha256"]}:
                raise SpeedRunnerError("nondeterministic", "projection")
            if arm["normalized_sha256"] != expected_sha:
                raise SpeedRunnerError("parity", "expected_projection")
            if arm["median_ns"] != medians[arm_name]:
                raise SpeedRunnerError("time", "median")
            expected_invocations = len(fixture_rows[row_id][f"{arm_name}_calls"])
            if arm["public_invocations"] != expected_invocations or arm["manual_checkpoints"] != 0:
                raise SpeedRunnerError("invocations", "arm")
        if len({artifact["sha256"] for artifact in artifacts}) != 22:
            raise SpeedRunnerError("digest", "raw_not_distinct")
        for pair_index, first in enumerate(row["pair_order"]):
            second = "adapter" if first == "primitive" else "primitive"
            paired = [raw for raw in raw_by_uuid.values() if raw["pair_index"] == pair_index]
            ordered = sorted(paired, key=lambda raw: raw["pair_position"])
            if [raw["arm"] for raw in ordered] != [first, second]:
                raise SpeedRunnerError("sequence", "pair")
        gates = row["gates"]
        if not isinstance(gates, list) or not gates:
            raise SpeedRunnerError("schema", "gates")
        gate_by_name: dict[str, Mapping[str, Any]] = {}
        for value_gate in gates:
            gate = _expect_keys(value_gate, GATE_KEYS, "gate")
            if not isinstance(gate["name"], str) or not isinstance(gate["passed"], bool) or gate["reason"] not in REASONS:
                raise SpeedRunnerError("schema", "gate")
            if gate["passed"] != (gate["reason"] == "ok"):
                raise SpeedRunnerError("schema", "gate_reason")
            if gate["name"] in gate_by_name:
                raise SpeedRunnerError("schema", "duplicate_gate")
            gate_by_name[gate["name"]] = gate
        primitive_invocations = len(fixture_rows[row_id]["primitive_calls"])
        adapter_invocations = len(fixture_rows[row_id]["adapter_calls"])
        reduction = 1 - adapter_invocations / primitive_invocations
        ratio = medians["adapter"] / medians["primitive"]
        recomputed: list[dict[str, object]] = [
            _gate("normalized_outcome_equal", True, True, True, "parity"),
            _gate("raw_artifacts_equal", 22, 22, True, "missing_raw"),
            _gate("exact_sequence", True, True, True, "sequence"),
            _gate("manual_checkpoints", 0, 0, True, "checkpoint"),
        ]
        if "public_invocations" in fixture_rows[row_id]["expected"]:
            limit = fixture_rows[row_id]["gates"]["adapter_invocation_reduction_min"]
            recomputed.append(_gate("adapter_invocation_reduction_min", reduction, limit, reduction >= limit, "invocations"))
        if row_id == "project-v1":
            project_raw = list(raw_by_uuid.values())
            facts = [
                _validate_project_evidence(
                    raw,
                    sample_roots_by_uuid[cast(str, raw["runtime_uuid"])],
                    fixture_rows[row_id],
                )
                for raw in project_raw
            ]
            primitive_serial = all(
                serial for raw, (serial, _) in zip(project_raw, facts, strict=True)
                if raw["arm"] == "primitive"
            )
            adapter_parallel = all(
                parallel for raw, (_, parallel) in zip(project_raw, facts, strict=True)
                if raw["arm"] == "adapter"
            )
            recomputed.extend([
                _gate("primitive_leaves_serialized", primitive_serial, True, primitive_serial, "sequence"),
                _gate("adapter_leaves_isolated_parallel", adapter_parallel, True, adapter_parallel, "sequence"),
            ])
        ratio_limit = fixture_rows[row_id]["gates"]["adapter_median_ratio_max"]
        recomputed.append(_gate("adapter_median_ratio_max", ratio, ratio_limit, ratio <= ratio_limit, "time"))
        if set(gate_by_name) != {str(gate["name"]) for gate in recomputed}:
            raise SpeedRunnerError("schema", "gate_names")
        if any(gate_by_name[str(gate["name"])] != gate for gate in recomputed):
            raise SpeedRunnerError("schema", "gate_recompute")
        row_pass = all(gate["passed"] for gate in gates)
        if row["status"] != ("passed" if row_pass else "failed"):
            raise SpeedRunnerError("schema", "row_status")
        release_pass = release_pass and row_pass
    if top["release_pass"] is not (release_pass and top["network_attempts"] == 0):
        raise SpeedRunnerError("schema", "release_pass")


def stable_signature(result: Mapping[str, Any]) -> bytes:
    """Return the two-run reproducibility signature (projections and verdicts only)."""

    return _canonical({
        "release_pass": result["release_pass"],
        "rows": [
            {
                "normalized_projection": {
                    "adapter": row["adapter"]["normalized_sha256"],
                    "primitive": row["primitive"]["normalized_sha256"],
                },
                "gate_verdicts": [{"name": gate["name"], "passed": gate["passed"], "reason": gate["reason"]} for gate in row["gates"]],
                "id": row["id"],
            }
            for row in result["rows"]
        ],
    })


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--candidate-tree", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.output.parent.resolve() != args.result_root.parent.resolve():
        raise SpeedRunnerError("binding", "output_parent")
    schema = json.loads(args.schema.read_bytes())
    if schema.get("$id") != SCHEMA or schema.get("additionalProperties") is not False:
        raise SpeedRunnerError("schema", "schema_file")
    result = run_guarded_benchmark(
        args.fixture, args.result_root, args.candidate_head, args.candidate_tree
    )
    encoded = _canonical(result)
    args.output.write_bytes(encoded)
    if args.output.read_bytes() != encoded:
        raise SpeedRunnerError("digest", "result_write")
    validate_result(json.loads(args.output.read_bytes()), args.result_root, load_fixture(args.fixture))
    return 0 if result["release_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
