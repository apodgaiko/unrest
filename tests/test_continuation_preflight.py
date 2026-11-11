"""VAL-PF-01..25 for the experimental continuation preflight (ADR-0505).

Expected outputs are written from the normative contract, never derived from the
production projection. G1/G2 are exact byte goldens.
"""
from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import IO, Any

import click
import pytest
from click.testing import CliRunner

import unrest_harness.continuation_preflight as cp
import unrest_harness.runtime_observability as ro
from unrest_harness import cli as cli_module
from unrest_harness.cli import cli
from unrest_harness.config import HARNESS_CONFIG_ENV_VARS, HarnessConfig
from unrest_harness.continuation_state import DEFERRED_PAIRS, HINTS, REASON_CODES, STATES
from unrest_harness.controller import ProjectController
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.run_control import RunControl

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/unrest_harness/continuation_preflight.py"
CLI_PATH = ROOT / "src/unrest_harness/cli.py"
CLOCK = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fixtures (contract §11.0-§11.2). Paths are relative to <F> = tmp_path.resolve().
# ---------------------------------------------------------------------------

R = "home/projects/p1/.unrest-runtime"
M = f"{R}/missions/mission-001"
PJ = f"{R}/project.json"
ST = f"{R}/state.json"
AT = f"{R}/attention.json"
TK = f"{M}/tasks.json"
TS = f"{M}/task-state.json"
CS = f"{M}/contract-state.json"
A10 = f"{M}/attempts/2026-11-04T10-00-00Z__working.json"
A09 = f"{M}/attempts/2026-11-04T09-00-00Z__working.json"

G1_TASKS = (
    b'{"tasks":[{"id":"working","type":"work","body":"PRIVATE_BODY","skill":"s",'
    b'"targets":["VAL-B","VAL-A","VAL-A"],"depends_on":["ready","ghost","ready"]},'
    b'{"id":"ready","type":"validate","body":"","skill":"s","targets":[]},'
    b'{"id":"other","type":"work","body":"","skill":"s","targets":[],"depends_on":[]}]}'
)
G1_ATTENTION = (
    b'{"items":[{"id":"PRIVATE_ID_A1","report":"PRIVATE_REPORT_A1","kind":"node_attention",'
    b'"mission_id":"mission-001","node_id":"working","attempt_id":"2026-11-04T10-00-00Z"},'
    b'{"id":"PRIVATE_ID_A2","report":"PRIVATE_REPORT_A2","kind":"node_failed",'
    b'"mission_id":"mission-001","node_id":"other","attempt_id":"2026-11-04T09-00-00Z"},'
    b'{"id":"PRIVATE_ID_A3","report":"PRIVATE_REPORT_A3","kind":"terminal_review",'
    b'"mission_id":"mission-001","terminal_review_id":"tr1"},'
    b'{"id":"PRIVATE_ID_A4","report":"PRIVATE_REPORT_A4","kind":"node_attention",'
    b'"mission_id":"mission-000","node_id":"working","attempt_id":"2026-11-04T08-00-00Z"}]}'
)
G1_FILES: dict[str, bytes] = {
    PJ: (
        b'{"id":"p1","workspace_dir":"/fixture/ws","created_at":"2026-11-04T00:00:00Z",'
        b'"current_mission_id":"mission-001"}'
    ),
    ST: b'{"state":"mission_running","mission_id":"mission-001"}',
    AT: G1_ATTENTION,
    f"{R}/mutation.lock": b"",
    TK: G1_TASKS,
    TS: (
        b'{"tasks":{"working":{"status":"running","last_attempt":"2026-11-04T10-00-00Z"},'
        b'"ready":{"status":"cleared"}}}'
    ),
    CS: b'{"items":{"VAL-A":{"status":"passed"},"VAL-B":{}}}',
    A10: b"PRIVATE_ATTEMPT",
    f"{M}/terminal-reviews/tr1.json": b"PRIVATE_TERMINAL_REVIEW",
    f"{M}/terminal-review-config.json": b"PRIVATE_TR_CONFIG",
    f"{M}/supervision/x.json": b"PRIVATE_SUPERVISION",
    f"{M}/patch-transactions/tx1/marker.json": b"PRIVATE_PATCH_TX",
    f"{M}/provider-reviews/k.json": b"PRIVATE_PROVIDER_REVIEW",
    f"{R}/missions/mission-000/tasks.json": b"PRIVATE_OTHER_MISSION",
    "home/projects/p1/.unrest/x.json": b"PRIVATE_PROJECT_DURABLE",
    "home/.unrest/x.json": b"PRIVATE_HOME_DURABLE",
    "home/.unrest-runtime/runs/r.json": b"PRIVATE_RUN",
}
G2_FILES: dict[str, bytes] = {
    PJ: (
        b'{"id":"p1","workspace_dir":"/fixture/ws","created_at":"2026-11-04T00:00:00Z",'
        b'"current_mission_id":"none"}'
    ),
    f"{R}/missions/none/tasks.json": (
        b'{"tasks":[{"id":"T1","type":"gate","body":"","skill":null,"targets":["GATE-1"]}]}'
    ),
    "home/projects/p1/.unrest/x.json": b"PRIVATE_PROJECT_DURABLE",
}
G1_ARGS = ("--project", "p1", "--mission", "mission-001", "--task", "working")
G2_ARGS = ("--project", "p1", "--mission", "none", "--task", "T1")

G1_STDOUT = (
    '{"schema":"unrest.continuation-preflight","schema_version":1,"surface":"experimental_prefli'
    'ght","read_at":"2026-11-04T12:00:00.000000Z","read_at_meaning":"read_time_only","subject":{'
    '"project_id":"p1","mission_id":"mission-001","task_id":"working","selection_basis":"state_m'
    'ission"},"observations":{"mission_record_state":{"presence":"present","value":"mission_runn'
    'ing","source":{"root":"project_bucket","path":".unrest-runtime/state.json","capture":"bytes'
    '"}},"task_type":{"presence":"present","value":"work","source":{"root":"project_bucket","pat'
    'h":".unrest-runtime/missions/mission-001/tasks.json","capture":"bytes"}},"task_status":{"pr'
    'esence":"present","value":"running","source":{"root":"project_bucket","path":".unrest-runti'
    'me/missions/mission-001/task-state.json","capture":"bytes"}},"task_last_attempt":{"presence'
    '":"present","value":"2026-11-04T10-00-00Z","source":{"root":"project_bucket","path":".unres'
    't-runtime/missions/mission-001/task-state.json","capture":"bytes"}},"attempt_record":{"look'
    'up":"bytes_captured","source":{"root":"project_bucket","path":".unrest-runtime/missions/mis'
    'sion-001/attempts/2026-11-04T10-00-00Z__working.json","capture":"bytes"}},"dependencies":{"'
    'presence":"present","association_source":{"root":"project_bucket","path":".unrest-runtime/m'
    'issions/mission-001/tasks.json","capture":"bytes"},"status_source":{"root":"project_bucket",'
    '"path":".unrest-runtime/missions/mission-001/task-state.json","capture":"bytes"},"items":[{'
    '"task_id":"ghost","plan_membership":"not_in_plan","status":{"presence":"entry_absent","valu'
    'e":null}},{"task_id":"ready","plan_membership":"in_plan","status":{"presence":"present","va'
    'lue":"cleared"}}]},"targets":{"presence":"present","relation":"association","association_so'
    'urce":{"root":"project_bucket","path":".unrest-runtime/missions/mission-001/tasks.json","ca'
    'pture":"bytes"},"status_source":{"root":"project_bucket","path":".unrest-runtime/missions/m'
    'ission-001/contract-state.json","capture":"bytes"},"items":[{"assertion_id":"VAL-A","status'
    '":{"presence":"present","value":"passed"}},{"assertion_id":"VAL-B","status":{"presence":"fi'
    'eld_absent","value":null}}]},"attention":{"presence":"present","join":"mission_id_and_node_'
    'id","counts":{"gate_checkpoint":0,"gate_failed":0,"node_attention":1,"node_failed":0,"termi'
    'nal_review":0},"excluded_sources":["state_attention_items"],"join_excluded_kinds":["termina'
    'l_review"],"source":{"root":"project_bucket","path":".unrest-runtime/attention.json","captu'
    're":"bytes"}}},"coverage":[{"family":"attempt_bodies","status":"partial"},{"family":"clock_'
    'lineage","status":"no_source"},{"family":"control_requests","status":"unsupported_reader"},{'
    '"family":"deadline_profile","status":"no_source"},{"family":"external_waits","status":"no_s'
    'ource"},{"family":"patch_transactions","status":"not_captured"},{"family":"progress_history"'
    ',"status":"no_source"},{"family":"project_durable_records","status":"not_captured"},{"famil'
    'y":"project_runtime_cursors","status":"captured"},{"family":"provider_review_guards","statu'
    's":"unsupported_reader"},{"family":"readiness","status":"not_evaluated"},{"family":"run_con'
    'trol_records","status":"unsupported_reader"},{"family":"supervision_snapshots","status":"no'
    't_captured"},{"family":"terminal_reviews","status":"metadata_only"}],"stability":{"method":'
    '"stat_identity_before_after","scope":"captured_project_runtime_files","attempts_used":1,"li'
    'mitations":["coverage_list_non_exhaustive","same_stat_rewrite_undetected","uncaptured_famil'
    'ies_unchecked"]},"assessment":{"status":"unavailable","reasons":["clock_lineage_unavailable'
    '","deadline_profile_unavailable","durable_records_unavailable","progress_history_unavailabl'
    'e","readiness_not_evaluated","run_control_records_unavailable","supervision_snapshots_unava'
    'ilable"]}}\n'
)
G1_SHA256 = "1578bac63f7fe22dacc820c922d2edafe9a5ef4e22f98f4d51882dc4bcc57f43"
G2_STDOUT = (
    '{"schema":"unrest.continuation-preflight","schema_version":1,"surface":"experimental_prefli'
    'ght","read_at":"2026-11-04T12:00:00.000000Z","read_at_meaning":"read_time_only","subject":{'
    '"project_id":"p1","mission_id":"none","task_id":"T1","selection_basis":"project_cursor"},"o'
    'bservations":{"mission_record_state":{"presence":"file_absent","value":null,"source":{"root'
    '":"project_bucket","path":".unrest-runtime/state.json","capture":"absent"}},"task_type":{"p'
    'resence":"present","value":"gate","source":{"root":"project_bucket","path":".unrest-runtime'
    '/missions/none/tasks.json","capture":"bytes"}},"task_status":{"presence":"file_absent","val'
    'ue":null,"source":{"root":"project_bucket","path":".unrest-runtime/missions/none/task-state'
    '.json","capture":"absent"}},"task_last_attempt":{"presence":"file_absent","value":null,"sou'
    'rce":{"root":"project_bucket","path":".unrest-runtime/missions/none/task-state.json","captu'
    're":"absent"}},"attempt_record":{"lookup":"unavailable","source":null},"dependencies":{"pre'
    'sence":"field_absent","association_source":{"root":"project_bucket","path":".unrest-runtime'
    '/missions/none/tasks.json","capture":"bytes"},"status_source":{"root":"project_bucket","pat'
    'h":".unrest-runtime/missions/none/task-state.json","capture":"absent"},"items":null},"targe'
    'ts":{"presence":"present","relation":"association","association_source":{"root":"project_b'
    'ucket","path":".unrest-runtime/missions/none/tasks.json","capture":"bytes"},"status_source"'
    ':{"root":"project_bucket","path":".unrest-runtime/missions/none/contract-state.json","captu'
    're":"absent"},"items":[{"assertion_id":"GATE-1","status":{"presence":"file_absent","value":'
    'null}}]},"attention":{"presence":"file_absent","join":"mission_id_and_node_id","counts":nul'
    'l,"excluded_sources":["state_attention_items"],"join_excluded_kinds":["terminal_review"],"s'
    'ource":{"root":"project_bucket","path":".unrest-runtime/attention.json","capture":"absent"}'
    '}},"coverage":[{"family":"attempt_bodies","status":"partial"},{"family":"clock_lineage","st'
    'atus":"no_source"},{"family":"control_requests","status":"unsupported_reader"},{"family":"d'
    'eadline_profile","status":"no_source"},{"family":"external_waits","status":"no_source"},{"f'
    'amily":"patch_transactions","status":"not_captured"},{"family":"progress_history","status":'
    '"no_source"},{"family":"project_durable_records","status":"not_captured"},{"family":"projec'
    't_runtime_cursors","status":"captured"},{"family":"provider_review_guards","status":"unsupp'
    'orted_reader"},{"family":"readiness","status":"not_evaluated"},{"family":"run_control_recor'
    'ds","status":"unsupported_reader"},{"family":"supervision_snapshots","status":"not_captured'
    '"},{"family":"terminal_reviews","status":"metadata_only"}],"stability":{"method":"stat_iden'
    'tity_before_after","scope":"captured_project_runtime_files","attempts_used":1,"limitations"'
    ':["coverage_list_non_exhaustive","same_stat_rewrite_undetected","uncaptured_families_unchec'
    'ked"]},"assessment":{"status":"unavailable","reasons":["clock_lineage_unavailable","deadlin'
    'e_profile_unavailable","durable_records_unavailable","progress_history_unavailable","readin'
    'ess_not_evaluated","run_control_records_unavailable","supervision_snapshots_unavailable"]}}'
    "\n"
)
G2_SHA256 = "b073e677f38513bc3439ff0753ba7d3f65505fec6619822cff9ed819f7b5c242"

COVERAGE_LITERAL = [
    {"family": "attempt_bodies", "status": "partial"},
    {"family": "clock_lineage", "status": "no_source"},
    {"family": "control_requests", "status": "unsupported_reader"},
    {"family": "deadline_profile", "status": "no_source"},
    {"family": "external_waits", "status": "no_source"},
    {"family": "patch_transactions", "status": "not_captured"},
    {"family": "progress_history", "status": "no_source"},
    {"family": "project_durable_records", "status": "not_captured"},
    {"family": "project_runtime_cursors", "status": "captured"},
    {"family": "provider_review_guards", "status": "unsupported_reader"},
    {"family": "readiness", "status": "not_evaluated"},
    {"family": "run_control_records", "status": "unsupported_reader"},
    {"family": "supervision_snapshots", "status": "not_captured"},
    {"family": "terminal_reviews", "status": "metadata_only"},
]
ASSESSMENT_LITERAL = {
    "status": "unavailable",
    "reasons": [
        "clock_lineage_unavailable",
        "deadline_profile_unavailable",
        "durable_records_unavailable",
        "progress_history_unavailable",
        "readiness_not_evaluated",
        "run_control_records_unavailable",
        "supervision_snapshots_unavailable",
    ],
}
ERROR_CODES_LITERAL = frozenset(
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
HELP_TEXT = """Print an experimental read-only preflight report for one explicit task.

Reads only captured project runtime cursors and never evaluates continuation
state: assessment is always unavailable in schema version 1. Capture is
limited to 4 MiB per file, 16 MiB total, 4,096 selected files or entries,
depth 6, and three snapshot attempts, for the whole selected mission. Limit
violations report unsafe_cursor."""


def _materialize(base: Path, files: dict[str, bytes]) -> None:
    for relative, data in sorted(files.items()):
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


@pytest.fixture
def froot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path.resolve()
    for variable in HARNESS_CONFIG_ENV_VARS:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("UNREST_HOME", str(base / "home"))
    return base


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cp, "_read_clock", lambda: CLOCK)


@dataclass
class Run:
    exit_code: int
    stdout: bytes
    stderr: bytes

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.stdout)
        assert isinstance(value, dict)
        return value


def _invoke(*args: str) -> Run:
    result = CliRunner().invoke(cli, ["continuation-preflight", *args])
    return Run(result.exit_code, result.stdout_bytes, result.stderr_bytes or b"")


def _assert_error(run: Run, code: str) -> None:
    assert run.exit_code == 1
    assert run.stdout == b""
    assert run.stderr == f"Error: {code}\n".encode()


def _assert_no_private(run: Run) -> None:
    assert b"PRIVATE" not in run.stdout
    assert b"PRIVATE" not in run.stderr


# ---------------------------------------------------------------------------
# Expected payload helpers (written from contract §6, not from production code).
# ---------------------------------------------------------------------------

K_TS = ".unrest-runtime/missions/mission-001/task-state.json"
K_TK = ".unrest-runtime/missions/mission-001/tasks.json"
K_CS = ".unrest-runtime/missions/mission-001/contract-state.json"


def _src(path: str, capture: str) -> dict[str, str]:
    return {"root": "project_bucket", "path": path, "capture": capture}


def _cell(presence: str, value: object = None) -> dict[str, object]:
    return {"presence": presence, "value": value}


def _g1() -> dict[str, Any]:
    payload = json.loads(G1_STDOUT)
    assert isinstance(payload, dict)
    return payload


def _set_scalar(payload: dict[str, Any], key: str, presence: str, value: object = None,
                capture: str | None = None) -> None:
    fact = payload["observations"][key]
    fact["presence"] = presence
    fact["value"] = value
    if capture is not None:
        fact["source"]["capture"] = capture


def _set_attempt(payload: dict[str, Any], lookup: str, path: str | None = None,
                 capture: str | None = None) -> None:
    source = None if path is None else _src(path, str(capture))
    payload["observations"]["attempt_record"] = {"lookup": lookup, "source": source}


def _set_dependency_statuses(payload: dict[str, Any], presence: str) -> None:
    for item in payload["observations"]["dependencies"]["items"]:
        item["status"] = _cell(presence)


def _attempt_key(reference: str) -> str:
    return f".unrest-runtime/missions/mission-001/attempts/{reference}__working.json"


def _tasks_with_working(**changes: object) -> bytes:
    plan = json.loads(G1_TASKS)
    working = plan["tasks"][0]
    for key, value in changes.items():
        if value is _DROP:
            working.pop(key)
        else:
            working[key] = value
    return json.dumps(plan, separators=(",", ":")).encode()


_DROP = object()


def _task_state(working: object) -> bytes:
    return json.dumps(
        {"tasks": {"working": working, "ready": {"status": "cleared"}}},
        separators=(",", ":"),
    ).encode()


# ---------------------------------------------------------------------------
# Scenario table: matrix m1-m23 (§11.3, Amendments 1-2), selector X1-X9 (PF-08)
# and per-run open-read sets O(run) (§14.1), written from the fixture.
# ---------------------------------------------------------------------------

O_G1 = frozenset({PJ, ST, AT, TK, TS, CS, A10})
O_G1_NO_ATTEMPT = O_G1 - {A10}


@dataclass
class Scenario:
    name: str
    files: dict[str, bytes]
    args: tuple[str, ...]
    outcome: str
    selected: str | None
    opened: frozenset[str]
    expected: dict[str, Any] | None = None
    absent_strings: tuple[bytes, ...] = ()
    extra: dict[str, object] = field(default_factory=dict)


def _variant(changes: dict[str, bytes | None]) -> dict[str, bytes]:
    files = dict(G1_FILES)
    for key, value in changes.items():
        if value is None:
            files.pop(key, None)
        else:
            files[key] = value
    return files


def _m_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []

    def add(name: str, changes: dict[str, bytes | None], outcome: str, opened: frozenset[str],
            edit: Callable[[dict[str, Any]], None] | None = None,
            args: tuple[str, ...] = G1_ARGS, absent: tuple[bytes, ...] = ()) -> None:
        expected = None
        if outcome == "report":
            expected = _g1()
            if edit is not None:
                edit(expected)
        scenarios.append(
            Scenario(name, _variant(changes), args, outcome, "mission-001", opened, expected,
                     absent)
        )

    def m1(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_status", "file_absent", capture="absent")
        _set_scalar(e, "task_last_attempt", "file_absent", capture="absent")
        _set_attempt(e, "unavailable")
        e["observations"]["dependencies"]["status_source"] = _src(K_TS, "absent")
        _set_dependency_statuses(e, "file_absent")

    add("m1", {TS: None}, "report", O_G1 - {TS, A10}, m1)

    def m2(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_status", "collection_absent")
        _set_scalar(e, "task_last_attempt", "collection_absent")
        _set_attempt(e, "unavailable")
        _set_dependency_statuses(e, "collection_absent")

    add("m2", {TS: b"{}"}, "report", O_G1_NO_ATTEMPT, m2)

    def m3(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_status", "entry_absent")
        _set_scalar(e, "task_last_attempt", "entry_absent")
        _set_attempt(e, "unavailable")
        _set_dependency_statuses(e, "entry_absent")

    add("m3", {TS: b'{"tasks":{}}'}, "report", O_G1_NO_ATTEMPT, m3)

    def m4(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_status", "field_absent")
        _set_scalar(e, "task_last_attempt", "field_absent")
        _set_attempt(e, "unavailable")

    add("m4", {TS: _task_state({})}, "report", O_G1_NO_ATTEMPT, m4)

    def m5(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_status", "present", "pending")
        _set_scalar(e, "task_last_attempt", "field_absent")
        _set_attempt(e, "unavailable")

    add("m5", {TS: _task_state({"status": "pending"})}, "report", O_G1_NO_ATTEMPT, m5)

    def m6(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_last_attempt", "explicit_null")
        _set_attempt(e, "not_applicable")

    add("m6", {TS: _task_state({"status": "running", "last_attempt": None})}, "report", O_G1,
        m6)

    def m7(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_last_attempt", "malformed_reference")
        _set_attempt(e, "unavailable")

    for suffix, reference in (("garbage", "garbage"), ("feb30", "2024-02-30T00-00-00Z")):
        add(f"m7-{suffix}", {TS: _task_state({"status": "running", "last_attempt": reference})},
            "report", O_G1, m7, absent=(reference.encode(),))

    def m8(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_last_attempt", "present", "2026-11-04T11-00-00Z")
        _set_attempt(e, "absent", _attempt_key("2026-11-04T11-00-00Z"), "absent")

    add("m8", {TS: _task_state({"status": "running", "last_attempt": "2026-11-04T11-00-00Z"})},
        "report", O_G1, m8)

    def m9(e: dict[str, Any]) -> None:
        _set_scalar(e, "task_last_attempt", "present", "2026-11-04T09-00-00Z")
        _set_attempt(e, "metadata_only", _attempt_key("2026-11-04T09-00-00Z"), "metadata_only")

    add("m9", {A09: b"PRIVATE_ATTEMPT_OLD",
               TS: _task_state({"status": "running", "last_attempt": "2026-11-04T09-00-00Z"})},
        "report", O_G1, m9)

    add("m10-status-null", {TS: _task_state({"status": None})}, "malformed_cursor",
        O_G1_NO_ATTEMPT)
    add("m10-depends-null", {TK: _tasks_with_working(depends_on=None)}, "malformed_cursor",
        O_G1_NO_ATTEMPT)
    add("m10-tasks-null", {TK: b'{"tasks":null}'}, "malformed_cursor", O_G1_NO_ATTEMPT)

    def m11(e: dict[str, Any]) -> None:
        dependencies = e["observations"]["dependencies"]
        dependencies["presence"] = "field_absent"
        dependencies["items"] = None

    add("m11", {TK: _tasks_with_working(depends_on=_DROP)}, "report", O_G1, m11)

    def m12(e: dict[str, Any]) -> None:
        e["observations"]["dependencies"]["items"] = []

    add("m12", {TK: _tasks_with_working(depends_on=[])}, "report", O_G1, m12)

    def target_statuses(presence: str) -> Callable[[dict[str, Any]], None]:
        def edit(e: dict[str, Any]) -> None:
            for item in e["observations"]["targets"]["items"]:
                item["status"] = _cell(presence)

        return edit

    add("m13", {CS: b"{}"}, "report", O_G1, target_statuses("collection_absent"))
    add("m14", {CS: b'{"items":{}}'}, "report", O_G1, target_statuses("entry_absent"))

    def m15(e: dict[str, Any]) -> None:
        e["observations"]["attention"]["presence"] = "collection_absent"
        e["observations"]["attention"]["counts"] = None

    add("m15", {AT: b"{}"}, "report", O_G1, m15)

    def m16(e: dict[str, Any]) -> None:
        e["observations"]["attention"]["counts"]["node_attention"] = 0

    add("m16", {AT: b'{"items":[]}'}, "report", O_G1, m16)
    add("m17", {ST: b"{}"}, "malformed_cursor", O_G1)
    add("m18-newline", {TK: _tasks_with_working(targets=["VAL-1\n"])}, "malformed_cursor", O_G1,
        absent=(b"VAL-1",))
    add("m18-bad", {TK: _tasks_with_working(targets=["bad"])}, "malformed_cursor", O_G1,
        absent=(b"bad",))
    add("m19", {TK: b"{}"}, "subject_plan_absent", O_G1_NO_ATTEMPT)
    # Amendment-2 witness 1: P10 subset check precedes subject lookup.
    add("m20", {TK: b'{"tasks":[]}'}, "malformed_cursor", O_G1_NO_ATTEMPT)
    # Amendment-2 witness 3: no task-state, empty plan.
    add("m20-no-task-state", {TK: b'{"tasks":[]}', TS: None}, "subject_task_absent",
        O_G1 - {TS, A10})
    # Amendment-2 witness 2: unchanged G1 with a valid task ID outside the plan.
    add("task-nosuch", {}, "subject_task_absent", O_G1,
        args=("--project", "p1", "--mission", "mission-001", "--task", "nosuch"))
    working = json.loads(G1_TASKS)["tasks"][0]
    twice = json.loads(G1_TASKS)
    twice["tasks"].append(working)
    add("m21", {TK: json.dumps(twice, separators=(",", ":")).encode()}, "malformed_cursor",
        O_G1)
    add("m22", {TK: _tasks_with_working(targets=[]),
                CS: b'{"items":{"VAL-A":{"status":null}}}'}, "malformed_cursor", O_G1)
    add("m23", {TK: _tasks_with_working(targets=[]), CS: b'{"items":'}, "malformed_cursor",
        O_G1)
    return scenarios


def _project_json(cursor: object) -> bytes:
    return json.dumps(
        {
            "id": "p1",
            "workspace_dir": "/fixture/ws",
            "created_at": "2026-11-04T00:00:00Z",
            "current_mission_id": cursor,
        },
        separators=(",", ":"),
    ).encode()


def _x_scenarios() -> list[Scenario]:
    mission_002 = ("--project", "p1", "--mission", "mission-002", "--task", "working")
    x3 = _g1()
    x3["subject"]["selection_basis"] = "project_cursor"
    x3["observations"]["mission_record_state"]["value"] = "done"
    x4 = _g1()
    x4["subject"]["selection_basis"] = "project_cursor"
    x4["observations"]["mission_record_state"]["value"] = "attention_needed"
    return [
        Scenario("X1-m001", _variant({PJ: _project_json("mission-002")}), G1_ARGS,
                 "subject_mission_cursor_mismatch", "mission-001", O_G1),
        Scenario("X1-m002", _variant({PJ: _project_json("mission-002")}), mission_002,
                 "subject_mission_cursor_mismatch", "mission-001", O_G1),
        Scenario("X2", _variant({PJ: _project_json(None)}), G1_ARGS,
                 "subject_mission_cursor_mismatch", "mission-001", O_G1),
        Scenario("X3", _variant({ST: b'{"state":"done"}'}), G1_ARGS, "report", "mission-001",
                 O_G1, x3),
        Scenario("X4", _variant({ST: b'{"state":"attention_needed","items":[]}'}), G1_ARGS,
                 "report", "mission-001", O_G1, x4),
        Scenario("X5", _variant({PJ: _project_json("bad id")}), G1_ARGS, "malformed_cursor",
                 "mission-001", O_G1, absent_strings=(b"bad id",)),
        Scenario("X6a", _variant({ST: b'{"state":"mission_planning","mission_id":"mission-001"}',
                                  TK: None}), G1_ARGS, "subject_plan_absent", "mission-001",
                 O_G1 - {TK, A10}),
        Scenario("X6b", _variant({TK: None}), G1_ARGS, "malformed_cursor", "mission-001",
                 O_G1 - {TK, A10}),
        Scenario("X7", dict(G1_FILES), mission_002, "subject_mission_not_selected",
                 "mission-001", O_G1),
        Scenario("X8", _variant({ST: None, PJ: _project_json(None)}), G1_ARGS,
                 "subject_mission_not_selected", None, frozenset({PJ, AT})),
    ]


M_SCENARIOS = _m_scenarios()
X_SCENARIOS = _x_scenarios()
G_SCENARIOS = [
    Scenario("G1", dict(G1_FILES), G1_ARGS, "report", "mission-001", O_G1, _g1()),
    Scenario("G2", dict(G2_FILES), G2_ARGS, "report", "none",
             frozenset({PJ, f"{R}/missions/none/tasks.json"}), json.loads(G2_STDOUT)),
]
ALL_SCENARIOS = G_SCENARIOS + X_SCENARIOS + M_SCENARIOS


def _check_scenario(run: Run, scenario: Scenario) -> None:
    _assert_no_private(run)
    for text in scenario.absent_strings:
        assert text not in run.stdout
        assert text not in run.stderr
    if scenario.outcome == "report":
        assert run.exit_code == 0, run.stderr
        assert run.stderr == b""
        assert run.stdout.endswith(b"\n") and run.stdout.count(b"\n") == 1
        assert run.payload == scenario.expected
        _assert_schema(run.payload)
    else:
        _assert_error(run, scenario.outcome)


# ---------------------------------------------------------------------------
# Schema shape (§11): exact key order everywhere.
# ---------------------------------------------------------------------------

SOURCE_KEYS = ["root", "path", "capture"]


def _assert_source(value: Any) -> None:
    assert list(value) == SOURCE_KEYS
    assert value["root"] == "project_bucket"
    assert value["path"].startswith(".unrest-runtime/")
    assert value["capture"] in {"bytes", "metadata_only", "absent"}


def _assert_schema(payload: dict[str, Any]) -> None:
    assert list(payload) == [
        "schema", "schema_version", "surface", "read_at", "read_at_meaning", "subject",
        "observations", "coverage", "stability", "assessment",
    ]
    assert payload["schema"] == "unrest.continuation-preflight"
    assert payload["schema_version"] == 1
    assert payload["surface"] == "experimental_preflight"
    assert payload["read_at_meaning"] == "read_time_only"
    assert list(payload["subject"]) == ["project_id", "mission_id", "task_id", "selection_basis"]
    assert payload["subject"]["selection_basis"] in {"state_mission", "project_cursor"}
    observations = payload["observations"]
    assert list(observations) == [
        "mission_record_state", "task_type", "task_status", "task_last_attempt",
        "attempt_record", "dependencies", "targets", "attention",
    ]
    for key in ("mission_record_state", "task_type", "task_status", "task_last_attempt"):
        assert list(observations[key]) == ["presence", "value", "source"]
        _assert_source(observations[key]["source"])
    attempt = observations["attempt_record"]
    assert list(attempt) == ["lookup", "source"]
    assert attempt["lookup"] in {
        "bytes_captured", "metadata_only", "absent", "not_applicable", "unavailable"
    }
    if attempt["source"] is not None:
        _assert_source(attempt["source"])
    dependencies = observations["dependencies"]
    assert list(dependencies) == ["presence", "association_source", "status_source", "items"]
    _assert_source(dependencies["association_source"])
    _assert_source(dependencies["status_source"])
    for item in dependencies["items"] or []:
        assert list(item) == ["task_id", "plan_membership", "status"]
        assert item["plan_membership"] in {"in_plan", "not_in_plan"}
        assert list(item["status"]) == ["presence", "value"]
    targets = observations["targets"]
    assert list(targets) == [
        "presence", "relation", "association_source", "status_source", "items"
    ]
    assert targets["relation"] == "association"
    _assert_source(targets["association_source"])
    _assert_source(targets["status_source"])
    for item in targets["items"]:
        assert list(item) == ["assertion_id", "status"]
        assert list(item["status"]) == ["presence", "value"]
    attention = observations["attention"]
    assert list(attention) == [
        "presence", "join", "counts", "excluded_sources", "join_excluded_kinds", "source"
    ]
    if attention["counts"] is not None:
        assert list(attention["counts"]) == [
            "gate_checkpoint", "gate_failed", "node_attention", "node_failed", "terminal_review"
        ]
    _assert_source(attention["source"])
    assert payload["coverage"] == COVERAGE_LITERAL
    assert list(payload["stability"]) == ["method", "scope", "attempts_used", "limitations"]
    assert payload["assessment"] == ASSESSMENT_LITERAL


# ---------------------------------------------------------------------------
# PF-17(a), PF-06, PF-09..PF-11, PF-13: goldens.
# ---------------------------------------------------------------------------


def test_pf17a_golden_g1_exact_bytes(froot: Path) -> None:
    assert len(G1_STDOUT.encode()) == 3745
    assert hashlib.sha256(G1_STDOUT.encode()).hexdigest() == G1_SHA256
    _materialize(froot, G1_FILES)
    run = _invoke(*G1_ARGS)
    assert run.exit_code == 0
    assert run.stderr == b""
    assert run.stdout == G1_STDOUT.encode()
    assert hashlib.sha256(run.stdout).hexdigest() == G1_SHA256
    _assert_no_private(run)


def test_pf17a_golden_g2_exact_bytes(froot: Path) -> None:
    assert len(G2_STDOUT.encode()) == 3185
    assert hashlib.sha256(G2_STDOUT.encode()).hexdigest() == G2_SHA256
    _materialize(froot, G2_FILES)
    run = _invoke(*G2_ARGS)
    assert run.exit_code == 0
    assert run.stderr == b""
    assert run.stdout == G2_STDOUT.encode()
    _assert_no_private(run)


def test_pf03_pf06_pf09_g1_subject_dependencies_and_provenance(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    run = _invoke(*G1_ARGS)
    payload = run.payload
    _assert_schema(payload)
    observations = payload["observations"]
    assert payload["subject"] == {
        "project_id": "p1",
        "mission_id": "mission-001",
        "task_id": "working",
        "selection_basis": "state_mission",
    }
    # PF-03: one subject; other plan tasks surface only as dependency IDs.
    assert b'"other"' not in run.stdout
    assert b"mission-000" not in run.stdout
    # PF-06: both sources, not_in_plan retained, set semantics, bytewise order.
    dependencies = observations["dependencies"]
    assert [item["task_id"] for item in dependencies["items"]] == ["ghost", "ready"]
    assert dependencies["items"][0]["plan_membership"] == "not_in_plan"
    assert dependencies["association_source"] == _src(K_TK, "bytes")
    assert dependencies["status_source"] == _src(K_TS, "bytes")
    # PF-07 shape on G1: dedup and order.
    assert [item["assertion_id"] for item in observations["targets"]["items"]] == [
        "VAL-A", "VAL-B"
    ]
    assert observations["targets"]["status_source"] == _src(K_CS, "bytes")
    # PF-09: relative provenance everywhere, no absolute path.
    assert str(froot).encode() not in run.stdout


def test_pf10_pf11_coverage_and_assessment_constant(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    g1 = _invoke(*G1_ARGS).payload
    assert g1["coverage"] == COVERAGE_LITERAL
    assert g1["assessment"] == ASSESSMENT_LITERAL
    assert g1["stability"]["limitations"] == [
        "coverage_list_non_exhaustive",
        "same_stat_rewrite_undetected",
        "uncaptured_families_unchecked",
    ]
    assert [list(item.items()) for item in COVERAGE_LITERAL] == [
        [("family", family), ("status", status)] for family, status in cp.COVERAGE
    ]
    assert list(cp.ASSESSMENT_REASONS) == ASSESSMENT_LITERAL["reasons"]


def test_pf10_coverage_without_optional_families(froot: Path) -> None:
    _materialize(froot, G2_FILES)
    payload = _invoke(*G2_ARGS).payload
    assert payload["coverage"] == COVERAGE_LITERAL


def _core_lexicon() -> set[str]:
    words: set[str] = set(STATES) | set(REASON_CODES) | {"no_classifiable_condition"}
    words |= set(HINTS) | set(DEFERRED_PAIRS) | set(DEFERRED_PAIRS.values())
    words |= {"assessed", "indeterminate", "deferred"}
    return words


@pytest.mark.parametrize("name", ["G1", "G2", "X3"])
def test_pf13_decision_slots_and_core_word_ids(froot: Path, name: str) -> None:
    scenario = next(item for item in ALL_SCENARIOS if item.name == name)
    _materialize(froot, scenario.files)
    run = _invoke(*scenario.args)
    assert run.exit_code == 0
    payload = run.payload
    _assert_schema(payload)
    lexicon = _core_lexicon()
    assert payload["assessment"]["status"] not in lexicon
    assert not set(payload["assessment"]["reasons"]) & lexicon
    if name == "G1":
        assert payload["subject"]["task_id"] == "working"
        assert "ready" in [item["task_id"] for item in payload["observations"]["dependencies"][
            "items"]]
    if name == "G2":
        assert payload["subject"]["mission_id"] == "none"


# ---------------------------------------------------------------------------
# PF-01, PF-02: argument and usage errors.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "code", "echo"),
    (
        (("--project", "p 1", "--mission", "mission-001", "--task", "working"),
         "invalid_project_id", "p 1"),
        (("--project", "p1", "--mission", "1x", "--task", "working"), "invalid_mission_id",
         "1x"),
        (("--project", "p1", "--mission", "mission-001", "--task", "a" * 129),
         "invalid_task_id", "a" * 129),
        (("--project", "p1", "--mission", "mission-001", "--task", "T1\n"), "invalid_task_id",
         "T1\n"),
    ),
)
def test_pf01_invalid_identifiers(froot: Path, args: tuple[str, ...], code: str,
                                  echo: str) -> None:
    _materialize(froot, G1_FILES)
    run = _invoke(*args)
    _assert_error(run, code)
    assert echo.encode() not in run.stderr


@pytest.mark.parametrize(
    "args",
    (
        ("--mission", "mission-001", "--task", "working"),
        ("--project", "p1", "--task", "working"),
        ("--project", "p1", "--mission", "mission-001"),
        (*G1_ARGS, "--unknown"),
    ),
)
def test_pf02_click_usage_errors_exit_two(froot: Path, args: tuple[str, ...]) -> None:
    _materialize(froot, G1_FILES)
    run = _invoke(*args)
    assert run.exit_code == 2
    assert run.stdout == b""
    assert b"Error: internal_error" not in run.stderr


# ---------------------------------------------------------------------------
# PF-04, PF-05, PF-07, PF-08, PF-19: scenario outcomes (in-process).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", M_SCENARIOS, ids=lambda item: item.name)
def test_pf04_pf05_pf07_presence_matrix(froot: Path, scenario: Scenario) -> None:
    _materialize(froot, scenario.files)
    _check_scenario(_invoke(*scenario.args), scenario)


@pytest.mark.parametrize("scenario", X_SCENARIOS, ids=lambda item: item.name)
def test_pf08_selector(froot: Path, scenario: Scenario) -> None:
    _materialize(froot, scenario.files)
    _check_scenario(_invoke(*scenario.args), scenario)


def _real_capture(froot: Path) -> tuple[Any, ...]:
    return tuple(ro._capture_inputs(froot / "home/projects/p1"))


def test_pf08_x9_capture_disagreement_refuses(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    captured = _real_capture(froot)
    foreign = ro._CapturedFile(
        relative_path=".unrest-runtime/missions/other/tasks.json",
        content_sha256="",
        device=0,
        inode=0,
        size=2,
        mtime_ns=0,
        data=b"{}",
    )
    seam = tuple(sorted((*captured, foreign), key=lambda item: item.relative_path))
    monkeypatch.setattr(cp, "_capture_inputs", lambda root: seam)
    _assert_error(_invoke(*G1_ARGS), "malformed_cursor")


@pytest.mark.parametrize("name", ["G1", "m6", "m7-garbage", "X3"])
def test_pf19_exit_zero_for_any_report(froot: Path, name: str) -> None:
    scenario = next(item for item in ALL_SCENARIOS if item.name == name)
    _materialize(froot, scenario.files)
    assert _invoke(*scenario.args).exit_code == 0


def test_pf19_failed_task_status_is_still_a_report(froot: Path) -> None:
    _materialize(froot, _variant({TS: _task_state({"status": "failed"})}))
    run = _invoke(*G1_ARGS)
    assert run.exit_code == 0
    assert run.payload["observations"]["task_status"]["value"] == "failed"


# ---------------------------------------------------------------------------
# PF-14a / PF-14b: instrumented route and read audit (in-process).
# ---------------------------------------------------------------------------

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


@dataclass
class _Journal:
    root: Path
    forbidden: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    metadata: set[str] = field(default_factory=set)
    listing: set[str] = field(default_factory=set)
    opened: set[str] = field(default_factory=set)

    def normalize(self, value: object) -> str | None:
        if isinstance(value, int) or not isinstance(value, (str, bytes, os.PathLike)):
            return None
        text = os.fsdecode(os.fspath(value))
        if not os.path.isabs(text):
            text = os.path.join(os.getcwd(), text)
        return os.path.normpath(text)

    def relative(self, path: str) -> str | None:
        parts = PurePosixPath(path).parts
        root_parts = PurePosixPath(str(self.root)).parts
        if parts[: len(root_parts)] != root_parts:
            return None
        return "/".join(parts[len(root_parts):])

    def record(self, kind: str, operation: str, value: object,
               kwargs: dict[str, Any]) -> None:
        if kwargs.get("dir_fd") is not None:
            self.unknown.append(f"{operation}:dir_fd")
            return
        path = self.normalize(value)
        if path is None:
            self.unknown.append(f"{operation}:{type(value).__name__}")
            return
        relative = self.relative(path)
        if relative is None:
            return
        getattr(self, kind).add(relative)


@contextmanager
def _instrumented(root: Path) -> Iterator[_Journal]:
    journal = _Journal(root)
    originals = {
        name: getattr(os, name)
        for name in ("stat", "lstat", "readlink", "scandir", "listdir", "open")
    }
    original_open = builtins.open
    original_io_open = io.open

    def guard(name: str) -> Callable[..., Any]:
        def refuse(*args: Any, **kwargs: Any) -> Any:
            journal.forbidden.append(name)
            raise PermissionError(f"preflight route guard: {name}")

        return refuse

    def metadata(name: str) -> Callable[..., Any]:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            journal.record("metadata", name, path, kwargs)
            return originals[name](path, *args, **kwargs)

        return wrapper

    def listing(name: str) -> Callable[..., Any]:
        def wrapper(path: Any = ".", *args: Any, **kwargs: Any) -> Any:
            journal.record("listing", name, path, kwargs)
            return originals[name](path, *args, **kwargs)

        return wrapper

    def os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> Any:
        if flags & _WRITE_FLAGS:
            journal.forbidden.append("os.open:write")
            raise PermissionError("preflight route guard: os.open write")
        journal.record("opened", "os.open", path, kwargs)
        return originals["open"](path, flags, *args, **kwargs)

    def builtin_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if mode not in {"r", "rb", "rt"}:
            journal.forbidden.append("open:write")
            raise PermissionError("preflight route guard: open write")
        journal.record("opened", "open", file, {})
        return original_open(file, mode, *args, **kwargs)

    def io_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        # pathlib.Path.open/read_*/write_* reach io.open, not builtins.open.
        if mode not in {"r", "rb", "rt"}:
            journal.forbidden.append("io.open:write")
            raise PermissionError("preflight route guard: io.open write")
        journal.record("opened", "io.open", file, {})
        return original_io_open(file, mode, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        for name in ("stat", "lstat", "readlink"):
            patch.setattr(os, name, metadata(name))
        for name in ("scandir", "listdir"):
            patch.setattr(os, name, listing(name))
        patch.setattr(os, "open", os_open)
        patch.setattr(builtins, "open", builtin_open)
        patch.setattr(io, "open", io_open)
        for name in ("fork", "posix_spawn", "mkdir", "makedirs", "rename", "replace", "unlink",
                     "remove", "rmdir", "symlink", "link", "utime", "chmod"):
            patch.setattr(os, name, guard(f"os.{name}"))
        patch.setattr(subprocess.Popen, "__init__", guard("subprocess.Popen"))
        patch.setattr(RunControl, "__init__", guard("RunControl"))
        patch.setattr(ProjectController, "__init__", guard("ProjectController"))
        patch.setattr(MissionCoordinator, "__init__", guard("MissionCoordinator"))
        yield journal


def _tree(root: Path) -> dict[str, tuple[int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, str]] = {}
    for directory, names, files in os.walk(root):
        for name in sorted(names + files):
            path = Path(directory) / name
            info = path.lstat()
            digest = ""
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[str(path.relative_to(root))] = (
                info.st_mode, info.st_size, info.st_mtime_ns, digest
            )
    return snapshot


def _assert_clean_journal(journal: _Journal) -> None:
    assert journal.forbidden == []
    assert journal.unknown == []


def _instrumented_invoke(root: Path, *args: str) -> tuple[Run, _Journal]:
    before = _tree(root)
    runner = CliRunner()
    with _instrumented(root) as journal:
        result = runner.invoke(cli, ["continuation-preflight", *args])
    assert _tree(root) == before
    _assert_clean_journal(journal)
    return Run(result.exit_code, result.stdout_bytes, result.stderr_bytes or b""), journal


def _ancestors_or_self(path: str) -> set[str]:
    parts = PurePosixPath(path).parts
    return {"/".join(parts[:index]) for index in range(0, len(parts) + 1)}


def _assert_read_audit(journal: _Journal, scenario: Scenario, files: dict[str, bytes]) -> None:
    runtime = R
    deny: list[str] = [
        "home/projects/p1/.unrest",
        "home/.unrest",
        "home/.unrest-runtime",
    ]
    allowed_metadata = _ancestors_or_self("home") | _ancestors_or_self("home/projects")
    allowed_metadata |= {"home/projects/p1", runtime, PJ, ST, AT}
    runtime_entries = {
        "/".join(PurePosixPath(path).parts[:5])
        for path in files
        if path.startswith(runtime + "/")
    }
    allowed_metadata |= runtime_entries
    allowed_listing = {runtime}
    selected = scenario.selected
    if selected is not None:
        mission = f"{runtime}/missions/{selected}"
        for name in ("tasks.json", "task-state.json", "contract-state.json"):
            allowed_metadata.add(f"{mission}/{name}")
        for directory in ("attempts", "terminal-reviews"):
            allowed_metadata.add(f"{mission}/{directory}")
            allowed_listing.add(f"{mission}/{directory}")
            allowed_metadata |= {
                path for path in files if path.startswith(f"{mission}/{directory}/")
                and path.count("/") == mission.count("/") + 2
            }
        deny += [
            f"{mission}/supervision",
            f"{mission}/patch-transactions",
            f"{mission}/provider-reviews",
            f"{mission}/terminal-review-config.json",
        ]
    events = journal.metadata | journal.listing | journal.opened
    for event in events:
        parts = PurePosixPath(event).parts
        for denied in deny:
            denied_parts = PurePosixPath(denied).parts
            assert parts[: len(denied_parts)] != denied_parts, event
        if len(parts) > 5 and parts[:4] == ("home", "projects", "p1", ".unrest-runtime") and \
                parts[4] == "missions":
            assert selected is not None and parts[5] == selected, event
    assert journal.metadata <= allowed_metadata, sorted(journal.metadata - allowed_metadata)
    assert journal.listing <= allowed_listing, sorted(journal.listing - allowed_listing)
    assert journal.opened == scenario.opened, sorted(journal.opened ^ scenario.opened)
    lock = f"{runtime}/mutation.lock"
    assert lock not in journal.opened and lock not in journal.listing


@pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=lambda item: item.name)
def test_pf14_routes_and_read_audit(froot: Path, scenario: Scenario) -> None:
    _materialize(froot, scenario.files)
    run, journal = _instrumented_invoke(froot, *scenario.args)
    _check_scenario(run, scenario)
    _assert_read_audit(journal, scenario, scenario.files)


@pytest.mark.parametrize(
    ("name", "code"),
    (
        ("missing-home", "project_not_found"),
        ("missing-projects", "project_not_found"),
        ("missing-project", "project_not_found"),
        ("missing-runtime", "snapshot_changed"),
        ("symlink-state", "unsafe_cursor"),
    ),
)
def test_pf14a_failure_routes_have_no_forbidden_effects(
    froot: Path, monkeypatch: pytest.MonkeyPatch, name: str, code: str
) -> None:
    if name == "missing-home":
        monkeypatch.setenv("UNREST_HOME", str(froot / "absent-home"))
    elif name == "missing-projects":
        (froot / "home").mkdir()
    elif name == "missing-project":
        (froot / "home/projects").mkdir(parents=True)
    elif name == "missing-runtime":
        (froot / "home/projects/p1").mkdir(parents=True)
    else:
        _materialize(froot, _variant({ST: None}))
        (froot / ST).symlink_to(froot / AT)
    run, _journal = _instrumented_invoke(froot, *G1_ARGS)
    _assert_error(run, code)


# ---------------------------------------------------------------------------
# N-1 negative controls (Amendment-4). Fixture-only test actions inside the
# instrumentation; they demonstrate detection and are not product mutations.
# ---------------------------------------------------------------------------

SUPERVISION = f"{M}/supervision/x.json"
TR_CONFIG = f"{M}/terminal-review-config.json"


@contextmanager
def _legacy_instrumented_without_io_open(root: Path) -> Iterator[_Journal]:
    """NC-0 only: byte-for-byte copy of the PF-14 instrumentation before Amendment-4."""

    journal = _Journal(root)
    originals = {
        name: getattr(os, name)
        for name in ("stat", "lstat", "readlink", "scandir", "listdir", "open")
    }
    original_open = builtins.open

    def guard(name: str) -> Callable[..., Any]:
        def refuse(*args: Any, **kwargs: Any) -> Any:
            journal.forbidden.append(name)
            raise PermissionError(f"preflight route guard: {name}")

        return refuse

    def metadata(name: str) -> Callable[..., Any]:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            journal.record("metadata", name, path, kwargs)
            return originals[name](path, *args, **kwargs)

        return wrapper

    def listing(name: str) -> Callable[..., Any]:
        def wrapper(path: Any = ".", *args: Any, **kwargs: Any) -> Any:
            journal.record("listing", name, path, kwargs)
            return originals[name](path, *args, **kwargs)

        return wrapper

    def os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> Any:
        if flags & _WRITE_FLAGS:
            journal.forbidden.append("os.open:write")
            raise PermissionError("preflight route guard: os.open write")
        journal.record("opened", "os.open", path, kwargs)
        return originals["open"](path, flags, *args, **kwargs)

    def builtin_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if mode not in {"r", "rb", "rt"}:
            journal.forbidden.append("open:write")
            raise PermissionError("preflight route guard: open write")
        journal.record("opened", "open", file, {})
        return original_open(file, mode, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        for name in ("stat", "lstat", "readlink"):
            patch.setattr(os, name, metadata(name))
        for name in ("scandir", "listdir"):
            patch.setattr(os, name, listing(name))
        patch.setattr(os, "open", os_open)
        patch.setattr(builtins, "open", builtin_open)
        for name in ("fork", "posix_spawn", "mkdir", "makedirs", "rename", "replace", "unlink",
                     "remove", "rmdir", "symlink", "link", "utime", "chmod"):
            patch.setattr(os, name, guard(f"os.{name}"))
        patch.setattr(subprocess.Popen, "__init__", guard("subprocess.Popen"))
        patch.setattr(RunControl, "__init__", guard("RunControl"))
        patch.setattr(ProjectController, "__init__", guard("ProjectController"))
        patch.setattr(MissionCoordinator, "__init__", guard("MissionCoordinator"))
        yield journal


def _g1_scenario() -> Scenario:
    return next(item for item in ALL_SCENARIOS if item.name == "G1")


def test_nc0_legacy_instrumentation_misses_pathlib_read(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    target = froot / SUPERVISION
    with _legacy_instrumented_without_io_open(froot) as journal:
        data = target.read_bytes()
    assert data == b"PRIVATE_SUPERVISION"
    # Reproduces N-1: the pre-Amendment-4 audit cannot see a pathlib read.
    assert SUPERVISION not in journal.opened
    assert journal.opened == set()


def test_nc1_pathlib_read_bytes_is_detected_and_denied(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    target = froot / SUPERVISION
    with _instrumented(froot) as journal:
        data = target.read_bytes()
    assert data == b"PRIVATE_SUPERVISION"
    assert SUPERVISION in journal.opened
    with pytest.raises(AssertionError, match="supervision"):
        _assert_read_audit(journal, _g1_scenario(), G1_FILES)


def test_nc2_path_open_is_detected_and_denied(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    target = froot / TR_CONFIG
    handle: IO[bytes] | None = None
    try:
        with _instrumented(froot) as journal:
            handle = target.open("rb")
    finally:
        if handle is not None:
            handle.close()
    assert TR_CONFIG in journal.opened
    with pytest.raises(AssertionError, match="terminal-review-config"):
        _assert_read_audit(journal, _g1_scenario(), G1_FILES)


def test_nc3_pathlib_write_is_refused_without_creating_a_file(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    target = froot / "nc3.tmp"
    before = _tree(froot)
    with _instrumented(froot) as journal:
        with pytest.raises(PermissionError):
            target.write_bytes(b"x")
    assert journal.forbidden == ["io.open:write"]
    assert not target.exists()
    assert _tree(froot) == before
    with pytest.raises(AssertionError):
        _assert_clean_journal(journal)


def test_nc4_integer_descriptor_is_unknown_and_fails_the_audit(froot: Path) -> None:
    _materialize(froot, G1_FILES)
    descriptor = os.open(froot / AT, os.O_RDONLY)
    handle: IO[bytes] | None = None
    try:
        with _instrumented(froot) as journal:
            handle = os.fdopen(descriptor, "rb", closefd=False)
    finally:
        if handle is not None:
            handle.close()
        os.close(descriptor)
    assert journal.unknown == ["io.open:int"]
    with pytest.raises(AssertionError):
        _assert_clean_journal(journal)


# ---------------------------------------------------------------------------
# PF-15 / PF-25(b): stability through the module-global capture seam.
# ---------------------------------------------------------------------------


def _bumped(captured: tuple[Any, ...], amount: int) -> tuple[Any, ...]:
    first = captured[0].model_copy(update={"mtime_ns": captured[0].mtime_ns + amount})
    return (first, *captured[1:])


@dataclass
class _Counter:
    calls: int = 0


def _counted_clock(monkeypatch: pytest.MonkeyPatch) -> _Counter:
    counter = _Counter()

    def clock() -> datetime:
        counter.calls += 1
        return CLOCK

    monkeypatch.setattr(cp, "_read_clock", clock)
    return counter


def test_pf15a_pf25b_one_changed_generation_retries_once(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    real = _real_capture(froot)
    calls = _Counter()

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        return _bumped(real, 1) if calls.calls == 2 else real

    monkeypatch.setattr(cp, "_capture_inputs", seam)
    clock = _counted_clock(monkeypatch)
    run = _invoke(*G1_ARGS)
    assert run.exit_code == 0
    assert run.payload["stability"]["attempts_used"] == 2
    assert calls.calls == 4
    assert clock.calls == 1


def test_pf15b_always_changing_generation_refuses(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    real = _real_capture(froot)
    calls = _Counter()

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        return _bumped(real, calls.calls)

    monkeypatch.setattr(cp, "_capture_inputs", seam)
    _assert_error(_invoke(*G1_ARGS), "snapshot_changed")
    assert calls.calls == 6


def test_pf15c_transient_content_error_is_reconfirmed(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    real = _real_capture(froot)
    without_subject = tuple(
        item.model_copy(update={"data": b'{"tasks":[]}'}) if item.relative_path == K_TK
        else item.model_copy(update={"data": b'{"tasks":{}}'}) if item.relative_path == K_TS
        else item
        for item in real
    )
    calls = _Counter()

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        if calls.calls == 1:
            return without_subject
        if calls.calls == 2:
            return _bumped(real, 7)
        return real

    monkeypatch.setattr(cp, "_capture_inputs", seam)
    run = _invoke(*G1_ARGS)
    assert run.exit_code == 0, run.stderr
    assert run.stdout == G1_STDOUT.replace('"attempts_used":1', '"attempts_used":2').encode()
    assert calls.calls == 4


def test_pf15d_stable_content_error_after_one_confirmation(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    calls = _Counter()
    original = cp._capture_inputs

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        return original(root)

    monkeypatch.setattr(cp, "_capture_inputs", seam)
    _assert_error(
        _invoke("--project", "p1", "--mission", "mission-001", "--task", "nosuch"),
        "subject_task_absent",
    )
    assert calls.calls == 2


def test_pf15e_uncaptured_family_change_is_not_detected(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    original = cp._capture_inputs
    calls = _Counter()

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        result = original(root)
        if calls.calls == 1:
            (froot / M / "supervision/x.json").write_bytes(b"PRIVATE_SUPERVISION_CHANGED")
        return result

    monkeypatch.setattr(cp, "_capture_inputs", seam)
    run = _invoke(*G1_ARGS)
    assert run.stdout == G1_STDOUT.encode()
    assert "uncaptured_families_unchecked" in run.payload["stability"]["limitations"]
    assert calls.calls == 2


# ---------------------------------------------------------------------------
# PF-16: privacy and the two-phase boundary.
# ---------------------------------------------------------------------------


def test_pf16b_unexpected_exception_is_internal_error(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)

    def explode(*args: object, **kwargs: object) -> dict[str, object]:
        raise RuntimeError("PRIVATE_SENTINEL /abs")

    monkeypatch.setattr(cp, "_project", explode)
    run = _invoke(*G1_ARGS)
    _assert_error(run, "internal_error")
    _assert_no_private(run)


def test_pf16c_keyboard_interrupt_is_not_converted(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)

    def interrupt(*args: object, **kwargs: object) -> dict[str, object]:
        raise KeyboardInterrupt

    monkeypatch.setattr(cp, "_project", interrupt)
    callback = cli_module.continuation_preflight_cmd.callback
    assert callback is not None
    with pytest.raises(KeyboardInterrupt):
        callback(project_id="p1", mission_id="mission-001", task_id="working")
    run = _invoke(*G1_ARGS)
    assert b"internal_error" not in run.stderr
    assert run.stdout == b""


def test_pf16d_deep_json_is_internal_error(froot: Path) -> None:
    _materialize(froot, _variant({AT: b"[" * 100000 + b"]" * 100000}))
    run = _invoke(*G1_ARGS)
    _assert_error(run, "internal_error")


def test_pf16e1_phase_one_import_failure(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    monkeypatch.setitem(sys.modules, "unrest_harness.continuation_preflight", None)
    run = _invoke(*G1_ARGS)
    _assert_error(run, "internal_error")


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (click.ClickException("PRIVATE_SENTINEL"), "internal_error"),
        (click.ClickException("malformed_cursor"), "malformed_cursor"),
        (cp.PreflightError("not_a_code"), "internal_error"),
    ),
)
def test_pf16e2_closed_passthrough(
    froot: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, code: str
) -> None:
    _materialize(froot, G1_FILES)

    def fail(*args: object, **kwargs: object) -> dict[str, object]:
        raise error

    monkeypatch.setattr(cp, "build_preflight", fail)
    run = _invoke(*G1_ARGS)
    _assert_error(run, code)
    _assert_no_private(run)


def test_pf16_error_codes_closed() -> None:
    assert cp.ERROR_CODES == ERROR_CODES_LITERAL
    assert len(cp.ERROR_CODES) == 14


# ---------------------------------------------------------------------------
# PF-22: configuration matrix equivalent to observe-project.
# ---------------------------------------------------------------------------

CONFIG_CASES: tuple[tuple[str, str, str], ...] = (
    ("home-long", "UNREST_HOME", "/" + "a" * 4096),
    ("home-control", "UNREST_HOME", "/tmp/a\x01b"),
    ("projects-long", "UNREST_PROJECTS_DIR", "/" + "a" * 4096),
    ("projects-control", "UNREST_PROJECTS_DIR", "/tmp/a\x01b"),
    ("parallel-abc", "UNREST_MAX_PARALLEL_NODES", "abc"),
    ("parallel-zero", "UNREST_MAX_PARALLEL_NODES", "0"),
    ("parallel-negative", "UNREST_MAX_PARALLEL_NODES", "-1"),
    ("model-blank", "UNREST_WORKER_MODEL", "   "),
    ("model-long", "UNREST_WORKER_MODEL", "m" * 257),
    ("model-control", "UNREST_WORKER_MODEL", "m\x01"),
    ("approval-recovery", "UNREST_APPROVAL_RECOVERY", "2"),
    ("worker-provider", "UNREST_WORKER_PROVIDER", "no-such-provider"),
    ("home-file", "UNREST_HOME", "<file>"),
    ("projects-file", "UNREST_PROJECTS_DIR", "<file>"),
    ("capability-seam", "", ""),
)


@pytest.mark.parametrize(("name", "variable", "value"), CONFIG_CASES,
                         ids=[case[0] for case in CONFIG_CASES])
def test_pf22_configuration_matrix(
    froot: Path, monkeypatch: pytest.MonkeyPatch, name: str, variable: str, value: str
) -> None:
    _materialize(froot, G1_FILES)
    if value == "<file>":
        target = froot / f"{name}.file"
        target.write_bytes(b"")
        value = str(target)
    if variable:
        monkeypatch.setenv(variable, value)
    else:
        def refuse(self: HarnessConfig) -> None:
            raise RuntimeError("PRIVATE_SENTINEL")

        monkeypatch.setattr(HarnessConfig, "validate_capability_support", refuse)
    observe = CliRunner().invoke(cli, ["observe-project", "p1", "--format", "json"])
    assert observe.exit_code == 1
    assert observe.stdout_bytes == b""
    assert observe.stderr_bytes == b"Error: invalid_configuration\n"
    _assert_error(_invoke(*G1_ARGS), "invalid_configuration")


# ---------------------------------------------------------------------------
# PF-25: clock and projection purity.
# ---------------------------------------------------------------------------


def test_pf25a_naive_clock_refuses_before_capture(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    calls = _Counter()

    def seam(root: Path) -> tuple[Any, ...]:
        calls.calls += 1
        return ()

    monkeypatch.setattr(cp, "_read_clock", lambda: datetime(2026, 11, 4, 12, 0, 0))
    monkeypatch.setattr(cp, "_capture_inputs", seam)
    _assert_error(_invoke(*G1_ARGS), "internal_error")
    assert calls.calls == 0


def test_pf25c_aware_clock_is_rendered_in_utc(
    froot: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _materialize(froot, G1_FILES)
    monkeypatch.setattr(
        cp,
        "_read_clock",
        lambda: datetime(2026, 11, 4, 16, 0, 0, tzinfo=timezone(timedelta(hours=4))),
    )
    run = _invoke(*G1_ARGS)
    assert run.payload["read_at"] == "2026-11-04T12:00:00.000000Z"
    assert run.stdout == G1_STDOUT.encode()


def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_pf25d_projection_is_pure() -> None:
    functions = _functions(_module_tree())
    reachable: set[str] = set()
    pending = ["_project"]
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in functions:
                    pending.append(node.func.id)
    assert "_project" in reachable
    for name in reachable:
        for node in ast.walk(functions[name]):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                assert func.id not in {
                    "_read_clock", "_capture_inputs", "_validated_project_root", "open"
                }, (name, func.id)
            if isinstance(func, ast.Attribute):
                base = func.value
                assert not (isinstance(base, ast.Name) and base.id == "os"), name
                assert not (
                    isinstance(base, ast.Name) and base.id == "datetime" and func.attr == "now"
                ), name


# ---------------------------------------------------------------------------
# PF-12b, PF-12c, PF-17b, PF-18: static structure.
# ---------------------------------------------------------------------------

RUNTIME_IMPORTS = {
    "__future__:annotations",
    "datetime:UTC",
    "datetime:datetime",
    "json:",
    "typing:TYPE_CHECKING",
    "typing:Final",
    "typing:NamedTuple",
    ".models:ProjectRecord",
    ".models:MissionRunning",
    ".models:MissionPlanning",
    ".models:TaskList",
    ".models:TaskStateFile",
    ".models:ContractStateFile",
    ".models:AttentionFile",
    ".models:TASK_ID_REGEX",
    ".models:ASSERTION_ID_REGEX",
    ".runtime_observability:_capture_inputs",
    ".runtime_observability:_identity_generation",
    ".runtime_observability:_source_map",
    ".runtime_observability:_parse_json_model",
    ".runtime_observability:_parse_state",
    ".runtime_observability:_parse_spawn_ts",
    ".runtime_observability:_validated_project_root",
    ".runtime_observability:RuntimeObservationError",
    ".runtime_observability:CAPTURE_ATTEMPTS",
    ".runtime_observability:PROJECT_ID_PATTERN",
    ".runtime_observability:MISSION_ID_PATTERN",
}
TYPE_CHECKING_IMPORTS = {
    "collections.abc:Mapping",
    ".storage:ProjectStore",
    ".runtime_observability:_CapturedFile",
}


def _import_names(node: ast.Import | ast.ImportFrom) -> set[str]:
    if isinstance(node, ast.Import):
        return {f"{alias.name}:" for alias in node.names}
    module = "." * node.level + (node.module or "")
    return {f"{module}:{alias.name}" for alias in node.names}


def _is_type_checking(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    )


def test_pf12b_import_lists_are_closed() -> None:
    tree = _module_tree()
    first = tree.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        first = tree.body[1]
    assert isinstance(first, ast.ImportFrom) and first.module == "__future__"
    assert [alias.name for alias in first.names] == ["annotations"]
    type_checking_nodes: set[int] = set()
    type_checking: set[str] = set()
    for node in ast.walk(tree):
        if _is_type_checking(node):
            assert isinstance(node, ast.If)
            for child in node.body:
                for inner in ast.walk(child):
                    if isinstance(inner, (ast.Import, ast.ImportFrom)):
                        type_checking_nodes.add(id(inner))
                        type_checking |= _import_names(inner)
    runtime: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and id(node) not in type_checking_nodes:
            runtime |= _import_names(node)
    assert runtime == RUNTIME_IMPORTS
    assert {name for name in runtime if name.startswith(".runtime_observability:")} == {
        name for name in RUNTIME_IMPORTS if name.startswith(".runtime_observability:")
    }
    assert type_checking <= TYPE_CHECKING_IMPORTS
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                assert func.id not in {"__import__", "open", "exec", "eval"}
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                assert func.value.id != "importlib"


FORBIDDEN_IO_ATTRIBUTES = frozenset(
    {
        "open", "read_bytes", "read_text", "write_bytes", "write_text", "iterdir", "glob",
        "rglob", "walk", "scandir", "listdir", "stat", "lstat", "readlink", "resolve", "exists",
        "is_file", "is_dir", "is_symlink", "touch", "mkdir", "unlink", "rmdir", "rename",
        "symlink_to", "hardlink_to", "chmod", "samefile", "expanduser", "absolute", "owner",
        "group",
    }
)
FORBIDDEN_IO_NAMES = frozenset(
    {
        "io", "_io", "os", "posix", "nt", "pathlib", "Path", "PurePath", "shutil", "tempfile",
        "glob", "fnmatch", "mmap", "socket", "subprocess", "importlib",
    }
)


def _forbidden_io_calls(tree: ast.Module) -> list[str]:
    """Syntactic regression fence for file I/O in the preflight module.

    It flags attribute calls with file-system method names and any use of
    I/O-capable module or class names. It is not proof that no indirect,
    aliased or C-level I/O exists; the closed import list (PF-12b) and the
    runtime audit (PF-14) remain the other layers. ``str.replace`` stays legal.
    """

    violations: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in FORBIDDEN_IO_ATTRIBUTES
        ):
            violations.append(f"{node.lineno}:call:{node.func.attr}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_IO_NAMES:
            violations.append(f"{node.lineno}:name:{node.id}")
    return sorted(violations)


def test_pf12b_forbidden_io_fence_on_module() -> None:
    assert _forbidden_io_calls(_module_tree()) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("def f(p):\n    return p.read_bytes()\n", "2:call:read_bytes"),
        ("import io\nio.open('x')\n", "2:name:io"),
        ("from pathlib import Path\nPath('x').iterdir()\n", "2:call:iterdir"),
        ("import os\nos.fdopen(3)\n", "2:name:os"),
        ("def f(p):\n    with p.open('rb') as h:\n        return h\n", "2:call:open"),
        ("def f(p):\n    return p.parent.write_text('x')\n", "2:call:write_text"),
    ),
)
def test_nc5_forbidden_io_fence_flags_synthetic_io(source: str, expected: str) -> None:
    assert expected in _forbidden_io_calls(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    (
        "x = 'a'.replace('b', 'c')\n",
        "x = '2026-11-04T12:00:00+00:00'.replace('+00:00', 'Z')\n",
        "x = {'a': 1}.get('a')\n",
    ),
)
def test_nc6_forbidden_io_fence_allows_non_io_calls(source: str) -> None:
    assert _forbidden_io_calls(ast.parse(source)) == []


def test_pf12c_no_core_module_substrings() -> None:
    for path in (MODULE_PATH, CLI_PATH):
        text = path.read_text(encoding="utf-8")
        for needle in ("continuation_state", "continuation_reservations", "continuation_types"):
            assert needle not in text, (path.name, needle)


def test_pf17b_renderer_structure() -> None:
    function = _functions(_module_tree())["render_preflight"]
    dumps = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "dumps"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
    ]
    assert len(dumps) == 1
    keywords = {keyword.arg: keyword.value for keyword in dumps[0].keywords}
    assert set(keywords) == {"separators", "ensure_ascii", "allow_nan"}
    assert ast.literal_eval(keywords["separators"]) == (",", ":")
    assert ast.literal_eval(keywords["ensure_ascii"]) is True
    assert ast.literal_eval(keywords["allow_nan"]) is False
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    assert len(returns) == 1
    value = returns[0].value
    assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
    assert value.left is dumps[0]
    assert isinstance(value.right, ast.Constant) and value.right.value == "\n"


def test_pf18_spawn_timestamp_only_checked_for_presence() -> None:
    tree = _module_tree()
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_parse_spawn_ts"
    ]
    assert calls
    for call in calls:
        parent = parents[id(call)]
        assert isinstance(parent, ast.Compare)
        assert parent.left is call
        assert len(parent.ops) == 1 and isinstance(parent.ops[0], ast.IsNot)
        comparator = parent.comparators[0]
        assert isinstance(comparator, ast.Constant) and comparator.value is None


# ---------------------------------------------------------------------------
# PF-20(a,c), PF-21, PF-23, PF-24: compatibility pins.
# ---------------------------------------------------------------------------

CLI_SEGMENTS = {
    "_observation_format": "effde318299d05037b16a0fd20241faeac7ec2de1b7c2e615a48fd383fcd11ad",
    "_stale_threshold": "87252b9fd96bc9fc3aa6ddcaf23fe8badb459117e94b214bd51f1e254b2d412a",
    "_observation_store": "0065222e5c12d9654f412c8c7cae928fac5a3642a2ca54a872268c53558c5632",
    "_ObservationCommand": "6711e69277ff24e0172405a7a4cf0ead990d6352db80a088a65d83cc874417d9",
    "observe_project_cmd": "51bd0bdb6d4dd24aa83ebc67f0990d10d8fb16061d56b234b17f9e2e2533c233",
}


def test_pf20a_cli_source_segments_unchanged() -> None:
    source = CLI_PATH.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    found: dict[str, str] = {}
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in CLI_SEGMENTS:
            start = min([item.lineno for item in node.decorator_list] + [node.lineno])
            assert node.end_lineno is not None
            segment = "".join(lines[start - 1 : node.end_lineno]).encode("utf-8")
            found[node.name] = hashlib.sha256(segment).hexdigest()
    assert found == CLI_SEGMENTS


FILE_BASELINE = {
    "src/unrest_harness/runtime_observability.py":
        "53dd39fbd39f1fe23ddfeb469e93e8cf79090e4b55c602588ef46ab009ed5048",
    "src/unrest_harness/models.py":
        "08706c0e70ba3ee24d5481c01658c3607f20e6419f31c931731770bfbd095a78",
    "src/unrest_harness/storage.py":
        "5defe671daac92308f4fc0463be1d9ea61ab87164f6af43c17e864c497fa5bf6",
    "src/unrest_harness/config.py":
        "09835fde9cd71844bcff7ce3e4f4427e959a60e0883ba7241b632dd8f04b5ea2",
    "src/unrest_harness/providers.py":
        "1c6b04d982a0653e3317447ff63731cbc7064126c32b10d14caef813f9d5440f",
    "src/unrest_harness/capability_policy.py":
        "0aaa3eca3a1b891bcf7458832aeed92768489826fda23320ab000ce3d1df3c30",
    "src/unrest_harness/server.py":
        "6c9df14211b1aec796395e5534129eeb2cfab9f83639eecaf580e4d9d647bffa",
    "src/unrest_harness/controller.py":
        "5a72d2671606770750a8b9039296005eb174092529bff037033aab65109d7168",
    "src/unrest_harness/coordinator.py":
        "17a7f92940d15972b509ca8143668f1bfc4aa4da19bc01e3863b0706c5c8ce52",
    "src/unrest_harness/run_control.py":
        "a4a010d6560ebffb9f1a842ca5fad6ab5d999f75d653eac12bc4762da7d9c122",
    "src/unrest_harness/supervision.py":
        "8a6983b504b95748da57305e6bb76f136fd3ad8d752b0657fc0d22669e689d23",
    "src/unrest_harness/continuation_state.py":
        "c3049e9dd57773eee6a608a2b0b5dfdf5a8fd446ec31c9c68d343c2589eaa661",
    "src/unrest_harness/continuation_types.py":
        "af2efdfebbfa8208c986ded2bea681b0bffb4259b41b51b6c11f6e382b87e92b",
    "src/unrest_harness/continuation_reservations.py":
        "5ca0c85f5b0e6d79558e111f7b876d44217a3810f0eed42776ebedecce40e354",
    "docs/v03/v0.3.1/public-surface.v1.json":
        "2d500d39a401837162625254d954cb3431760a10b78661f3156ec08bc956c4ad",
    "src/unrest_harness/bundled/foundation/public-surface.v1.json":
        "df5a5f15a9c4840849b9ead85d52d12b8af52a5607ee30cf7bff4d44300fe051",
    "docs/decisions/ADR-0504-continuation-state.md":
        "15801f560180f15699a3180f3a95120bbd44ee14c2cfb6a9bd7cdc49b3e4ef3a",
    "uv.lock": "d7dcea4ddefcfbe87a58f83edee8be33dd612cb92f6b9dcdc5e11de5982b56d7",
    "pyproject.toml": "4df92555d1d341a1c04f1b0bac682e4221c31f91674f017e2e14ed0eedd4415f",
    "tests/test_runtime_observability.py":
        "bc4977de515c9f3a3b3ccab626a245525deccd9a6449fce8ad02253d220af305",
    "tests/test_cli.py": "5976e28915db5c021ad80aaa7a772402ea3732120e63eece0104d84ac7e241a8",
    "tests/test_continuation_state.py":
        "b95bf0704c1af13ca4428d176a99a40c9915732fc883259b1f0938687e8c925c",
    "tests/test_continuation_reservations.py":
        "6a7ef81c77c70458cdc89431dffee5f585d2c13d61f4efb483a87bacbcfb5268",
    "tests/test_continuation_types.py":
        "27b23bbb29495342442a45aaef4c53b2ec52c4709b30ea5a012dfb1e4c603174",
    "tests/test_foundation_integration.py":
        "bcbddfff3ffabd8b4374be17fa22b35872bd347d2daa8ca9ee3132f007caa8ef",
    "tests/test_run_control.py":
        "13ad6766039059c212f53d615e7521e67fce69bfd0e329c4ae63ea28a7b88fcf",
    "tests/test_mutation_journal.py":
        "dbaec57f5937ce7583c1de5819ee87b55dd30f45d8e4a3cc0c2d8d9b1607ea49",
    "tests/test_server.py": "a9ce122c8928dad545be1502f43f8e6d33e2f1a0d836f81bff599462bb697a44",
    "tests/test_run_stop_custody.py":
        "f4dd95cd2d8b066246a35a5e02686abcda1b9db4239152c1f9a77d259f8e5c4a",
    "tests/test_run_receipt_golden.py":
        "1c5d9b44cb4806e104cfef71f0de4dc41f9b10f120f23a5d3f0d1d4de96b142d",
    "tests/test_run_admission_recovery.py":
        "7428ed7475b139453d3a3d682ff8c1fd4c0eb2815013ba4f8fa1c6fc7f671c2d",
    "tests/test_run_record_strictness.py":
        "dd9b349ce1d8337347688155b5649271000e8ef6d38e3381b584855dc2c174aa",
}


def test_pf21_pf20c_file_baseline_unchanged() -> None:
    actual = {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in FILE_BASELINE
    }
    assert actual == FILE_BASELINE


SIGNATURES = {
    "_capture_inputs": "(project_root: 'Path') -> 'tuple[_CapturedFile, ...]'",
    "_identity_generation": (
        "(files: 'tuple[_CapturedFile, ...]') -> 'tuple[tuple[str, int, int, int, int], ...]'"
    ),
    "_source_map": "(files: 'tuple[_CapturedFile, ...]') -> 'dict[str, _CapturedFile]'",
    "_parse_json_model": (
        "(sources: 'dict[str, _CapturedFile]', key: 'str', model: 'type[BaseModel]', *, "
        "default: 'BaseModel | None' = None) -> 'BaseModel'"
    ),
    "_parse_state": "(sources: 'dict[str, _CapturedFile]') -> 'ProjectState | None'",
    "_parse_spawn_ts": "(value: 'str | None') -> 'datetime | None'",
    "_validated_project_root": "(store: 'ProjectStore', project_id: 'str') -> 'Path'",
}


def test_pf23_symbol_pins_and_capture_golden(froot: Path) -> None:
    for name, expected in SIGNATURES.items():
        assert str(inspect.signature(getattr(ro, name))) == expected, name
    assert issubclass(ro.RuntimeObservationError, RuntimeError)
    assert str(inspect.signature(ro.RuntimeObservationError.__init__)) == (
        "(self, code: 'ObservationFailureCode') -> 'None'"
    )
    assert ro.CAPTURE_ATTEMPTS == 3
    assert ro.PROJECT_ID_PATTERN.pattern == r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
    assert ro.MISSION_ID_PATTERN.pattern == r"^[A-Za-z][A-Za-z0-9_-]{0,127}$"
    for name in ("_capture_inputs", "_identity_generation", "_source_map", "_parse_json_model",
                 "_parse_state", "_parse_spawn_ts", "_validated_project_root",
                 "RuntimeObservationError", "CAPTURE_ATTEMPTS", "PROJECT_ID_PATTERN",
                 "MISSION_ID_PATTERN"):
        assert getattr(cp, name) is getattr(ro, name), name
    _materialize(froot, G1_FILES)
    captured = _real_capture(froot)
    assert {(item.relative_path, item.data is not None) for item in captured} == {
        (".unrest-runtime/attention.json", True),
        (".unrest-runtime/missions/mission-001/attempts/2026-11-04T10-00-00Z__working.json",
         True),
        (".unrest-runtime/missions/mission-001/contract-state.json", True),
        (".unrest-runtime/missions/mission-001/task-state.json", True),
        (".unrest-runtime/missions/mission-001/tasks.json", True),
        (".unrest-runtime/missions/mission-001/terminal-reviews/tr1.json", False),
        (".unrest-runtime/project.json", True),
        (".unrest-runtime/state.json", True),
    }


def test_pf24_help_text_matches_capture_limits() -> None:
    command = cli_module.continuation_preflight_cmd
    assert command.callback is not None
    assert inspect.cleandoc(command.callback.__doc__ or "") == HELP_TEXT
    mib = 1024 * 1024
    assert f"{ro.MAX_CAPTURE_FILE_BYTES // mib} MiB per file" in HELP_TEXT
    assert ro.MAX_CAPTURE_FILE_BYTES % mib == 0
    assert f"{ro.MAX_CAPTURE_TOTAL_BYTES // mib} MiB total" in HELP_TEXT
    assert ro.MAX_CAPTURE_TOTAL_BYTES % mib == 0
    assert f"{ro.MAX_CAPTURE_FILES:,} selected files" in HELP_TEXT
    assert f"depth {ro.MAX_CAPTURE_DEPTH}," in HELP_TEXT
    assert {3: "three"}[ro.CAPTURE_ATTEMPTS] + " snapshot attempts" in HELP_TEXT
    assert [param.name for param in command.params] == ["project_id", "mission_id", "task_id"]
    assert all(getattr(param, "required", False) for param in command.params)


def test_pf24_help_does_not_need_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process support for N1; the fresh-interpreter proof is PF-20b."""

    monkeypatch.setitem(sys.modules, "unrest_harness.continuation_preflight", None)
    result = CliRunner().invoke(cli, ["continuation-preflight", "--help"])
    assert result.exit_code == 0
    assert "experimental read-only preflight report" in result.stdout
    root_help = CliRunner().invoke(cli, ["--help"])
    assert root_help.exit_code == 0
    assert "continuation-preflight" in root_help.stdout


# ---------------------------------------------------------------------------
# PF-12a, PF-20b: pristine fresh-interpreter import boundary. These launch a
# child interpreter and require separate launch authorization.
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES = tuple(
    f"unrest_harness.{name}"
    for name in (
        "continuation_state", "continuation_types", "continuation_reservations", "coordinator",
        "controller", "run_control", "run_worker", "runtime_executor", "supervision",
        "foundation_store", "foundation_tools", "server", "acp_runner", "dispatcher",
        "project_lock", "patch_transaction", "workspaces", "provider_review",
        "provider_sessions",
    )
)
PRISTINE_SCRIPT = r'''
import importlib.abc
import json
import sys

args = json.loads(sys.argv[1])
forbidden = set(json.loads(sys.argv[2]))
requested = []
class Recorder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("unrest_harness."):
            requested.append(fullname)
        return None
sys.meta_path.insert(0, Recorder())
assert not forbidden & set(sys.modules)
exit_code = None
try:
    from unrest_harness.cli import cli
    cli.main(args=args, prog_name="unrest", standalone_mode=False)
    exit_code = 0
except SystemExit as exc:
    exit_code = exc.code
except BaseException as exc:
    exit_code = type(exc).__name__
loaded = sorted(name for name in sys.modules if name.startswith("unrest_harness."))
print(json.dumps({"requested": sorted(set(requested)), "loaded": loaded, "exit": exit_code}))
'''


def _pristine(base: Path, args: list[str]) -> dict[str, Any]:
    environment = {
        key: value for key, value in os.environ.items() if key not in HARNESS_CONFIG_ENV_VARS
    }
    environment["UNREST_HOME"] = str(base / "home")
    result = subprocess.run(
        [sys.executable, "-c", PRISTINE_SCRIPT, json.dumps(args),
         json.dumps(FORBIDDEN_MODULES)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout.splitlines()[-1])
    assert isinstance(value, dict)
    return value


def test_pf12a_pristine_import_boundary(tmp_path: Path) -> None:
    runs: list[tuple[str, dict[str, bytes], list[str]]] = [
        ("g1", G1_FILES, ["continuation-preflight", *G1_ARGS]),
        ("g2", G2_FILES, ["continuation-preflight", *G2_ARGS]),
        ("x1", _variant({PJ: _project_json("mission-002")}),
         ["continuation-preflight", *G1_ARGS]),
        ("m18", _variant({TK: _tasks_with_working(targets=["bad"])}),
         ["continuation-preflight", *G1_ARGS]),
        ("help", {}, ["continuation-preflight", "--help"]),
    ]
    for name, files, args in runs:
        base = tmp_path.resolve() / name
        base.mkdir()
        _materialize(base, files)
        observation = _pristine(base, args)
        touched = set(observation["requested"]) | set(observation["loaded"])
        assert not touched & set(FORBIDDEN_MODULES), (name, touched & set(FORBIDDEN_MODULES))


def test_pf20b_pristine_lazy_module_loading(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    _materialize(base, G1_FILES)
    module = "unrest_harness.continuation_preflight"
    for args in (["--help"], ["list-projects"], ["observe-project", "--help"],
                 ["continuation-preflight", "--help"]):
        assert module not in _pristine(base, args)["loaded"], args
    assert module in _pristine(base, ["continuation-preflight", *G1_ARGS])["loaded"]
