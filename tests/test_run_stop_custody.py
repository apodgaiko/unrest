"""STOP-A1: bounded manual cancellation and pending terminal receipts (ADR-0500).

Every case is in-process. ``_spawn`` never starts a child, and ``os.kill``,
``os.getpgid`` and ``os.getsid`` are replaced by a fake process table, so no
real signal is sent. Owner calls patch ``os.getpid`` to the bound worker PID.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
from typing import Any

import pytest

import unrest_harness.mutation_journal as journal_module
from unrest_harness.mutation_journal import DurableMutationJournal
import unrest_harness.run_control as runs
from unrest_harness.foundation_store import FoundationStore
from unrest_harness.run_control import RunControl, RunControlError


OWNER_PID = 4242
# The complete signal log of a run that was signalled once: exactly one SIGTERM
# to the bound owner and nothing else (no SIGKILL, no other target).
ONE_TERM = [(OWNER_PID, signal.SIGTERM)]
EXECUTOR = "json:dumps"
RESULT = {
    "dag": None,
    "harnessRoot": "/nonexistent/.unrest",
    "projectId": "stop-project",
    "projectRoot": "/nonexistent",
    "state": {"state": "done"},
}
FAILURE = {
    runs.EXECUTOR_FAILURE_KEY: {
        "public_error": {"error": {"code": "invalid_argument", "message": "bad"}},
        "private_tool_error": {"code": "x", "details": [], "message": "private"},
    }
}


class Crash(Exception):
    """Simulated process crash at an injected cut."""


@dataclass
class FakeProcesses:
    live: set[int] = field(default_factory=set)
    sessions: dict[int, int] = field(default_factory=dict)
    signals: list[tuple[int, int]] = field(default_factory=list)
    term_error: BaseException | None = None
    getsid_error: BaseException | None = None
    on_term: Callable[[int], None] | None = None

    def kill(self, pid: int, sig: int) -> None:
        if sig == 0:
            if pid in self.live:
                return
            raise ProcessLookupError(pid)
        self.signals.append((pid, sig))
        if self.on_term is not None:
            self.on_term(pid)
        if self.term_error is not None:
            raise self.term_error

    def getpgid(self, pid: int) -> int:
        if pid in self.live:
            return self.sessions.get(pid, pid)
        raise ProcessLookupError(pid)

    def getsid(self, pid: int) -> int:
        if self.getsid_error is not None:
            raise self.getsid_error
        if pid in self.live:
            return self.sessions.get(pid, pid)
        raise ProcessLookupError(pid)


class Env:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeProcesses) -> None:
        self.root = root
        self.mp = monkeypatch
        self.fake = fake
        self.spawned: list[str] = []

    def control(self, owner_id: str = "server:test", **kwargs: Any) -> RunControl:
        kwargs.setdefault("recover", False)
        return RunControl(self.root, executor_ref=EXECUTOR, owner_id=owner_id, **kwargs)

    def submit(self, control: RunControl, label: str = "a") -> str:
        workspace = self.root / f"workspace-{label}"
        workspace.mkdir(exist_ok=True)
        return control.submit_run(
            "start_project", {"brief": label, "workspace_dir": str(workspace)}, f"idem:{label}"
        ).run_id

    def start_owner(self, run_id: str, pid: int = OWNER_PID) -> RunControl:
        owner = self.control(owner_id=f"worker:{pid}:1")
        self.fake.live.add(pid)
        assert owner.worker_start(run_id, pid=pid, pgid=pid, generation=1)
        return owner

    @contextmanager
    def as_pid(self, pid: int = OWNER_PID) -> Iterator[None]:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runs.os, "getpid", lambda: pid)
            yield

    def run_dir(self, run_id: str) -> Path:
        return self.root / ".unrest" / "runs" / run_id.removeprefix("run:")

    def events(self, run_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(path.read_text())
            for path in sorted((self.run_dir(run_id) / "events").glob("*.json"))
        ]

    def states(self, run_id: str) -> list[str]:
        return [event["state"] for event in self.events(run_id)]

    def last(self, run_id: str) -> dict[str, Any]:
        return self.events(run_id)[-1]

    def binding_dir(self, run_id: str) -> Path:
        running = [event for event in self.events(run_id) if event["state"] == "running"]
        assert len(running) == 1
        return self.run_dir(run_id) / "stop" / running[0]["event_digest"].removeprefix("sha256:")

    def cursor(self, run_id: str) -> Path:
        return self.root / ".unrest-runtime" / "runs" / (
            hashlib.sha256(run_id.encode()).hexdigest() + ".worker.json"
        )

    def receipt_ids(self) -> Counter[str]:
        counts: Counter[str] = Counter()
        directory = self.root / ".unrest" / "foundation" / "receipts" / "run_receipt.v1"
        for path in directory.glob("*.json"):
            counts[json.loads(path.read_bytes())["receipt_id"]] += 1
        return counts

    def assert_unique_receipts(self) -> None:
        assert all(count == 1 for count in self.receipt_ids().values()), self.receipt_ids()

    def snapshot(self) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for path in sorted((self.root / ".unrest").rglob("*")):
            if "public-mutations" in path.parts or not path.is_file() or path.is_symlink():
                continue
            result[str(path.relative_to(self.root))] = path.read_bytes()
        return result

    def plant_receipt(self, control: RunControl, run_id: str, outcome: str) -> Any:
        receipt = control._construct_run_receipt(control._load_request(run_id), outcome)
        control.foundation.append_receipt(receipt, custodian=runs._run_custodian())
        return receipt

    def journal_faults(self, cut: str, *, foreign: bool = False) -> None:
        """Arrange that the next journal reaching ``cut`` crashes once."""
        fired = {"done": False}

        def fault(point: str) -> None:
            if point == cut and not fired["done"]:
                fired["done"] = True
                raise Crash(point)

        self.mp.setattr(
            runs, "DurableMutationJournal", lambda root: DurableMutationJournal(root, fault=fault)
        )
        if foreign:
            self.mp.setattr(journal_module, "_pid_is_alive", lambda pid: False)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    fake = FakeProcesses()
    monkeypatch.setattr(runs.os, "kill", fake.kill)
    monkeypatch.setattr(runs.os, "getpgid", fake.getpgid)
    monkeypatch.setattr(runs.os, "getsid", fake.getsid)

    def forbidden_killpg(*args: object) -> None:
        pytest.fail("STOP-A1 never signals a process group")

    monkeypatch.setattr(runs.os, "killpg", forbidden_killpg)
    environment = Env(tmp_path, monkeypatch, fake)
    monkeypatch.setattr(
        RunControl, "_spawn", lambda self, request: environment.spawned.append(request.run_id)
    )
    yield environment
    # Whatever a case asserts, STOP-A1 may only ever deliver SIGTERM.
    assert all(sig == signal.SIGTERM for _, sig in fake.signals), fake.signals


def _running(env: Env, label: str = "a") -> tuple[RunControl, RunControl, str]:
    control = env.control()
    run_id = env.submit(control, label)
    owner = env.start_owner(run_id)
    return control, owner, run_id


def _crash_append(env: Env, state: str) -> None:
    original = RunControl._append_event_unlocked
    fired = {"done": False}

    def crashing(self: RunControl, run_id: str, new_state: str, details: Any) -> Any:
        if new_state == state and not fired["done"]:
            fired["done"] = True
            raise Crash(state)
        return original(self, run_id, new_state, details)

    env.mp.setattr(RunControl, "_append_event_unlocked", crashing)


def _crash_after_append(env: Env, state: str) -> None:
    original = RunControl._append_event_unlocked
    fired = {"done": False}

    def crashing(self: RunControl, run_id: str, new_state: str, details: Any) -> Any:
        event = original(self, run_id, new_state, details)
        if new_state == state and not fired["done"]:
            fired["done"] = True
            raise Crash(state)
        return event

    env.mp.setattr(RunControl, "_append_event_unlocked", crashing)


def _public_mutation_files(env: Env) -> list[Path]:
    return sorted((env.root / ".unrest" / "foundation" / "public-mutations").glob("*"))


# ---------------------------------------------------------------- A01 / R6-pre


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("bad_run_id", "invalid_argument"),
        ("empty_reason", "invalid_argument"),
        ("empty_key", "invalid_argument"),
        ("unknown_run", "not_found"),
        ("request_without_events", "not_found"),
        ("corrupt_event", "integrity_error"),
    ],
)
def test_a01_prejournal_failures_create_no_journal_record(env: Env, case: str, code: str) -> None:
    control = env.control()
    run_id = env.submit(control)
    reason, key = "stop", "cancel:a01"
    if case == "bad_run_id":
        run_id = "run:not-hex"
    elif case == "empty_reason":
        reason = ""
    elif case == "empty_key":
        key = ""
    elif case == "unknown_run":
        run_id = "run:" + "f" * 64
    elif case == "request_without_events":
        for path in (env.run_dir(run_id) / "events").glob("*.json"):
            path.unlink()
    else:
        first = sorted((env.run_dir(run_id) / "events").glob("*.json"))[0]
        first.write_text('{"state":"queued"}\n')
    before = _public_mutation_files(env)
    for instance in (control, env.control(owner_id="server:second")):
        with pytest.raises(RunControlError) as caught:
            instance.cancel_run(run_id, reason, key)
        assert caught.value.code == code
    assert _public_mutation_files(env) == before == []
    assert env.fake.signals == []


# ---------------------------------------------------------------- A02 / A03


def test_a02_request_and_attempt_are_durable_before_the_single_term(env: Env) -> None:
    control, _, run_id = _running(env)
    observed: list[tuple[bool, bool]] = []

    def at_kill(pid: int) -> None:
        marked = [
            event for event in env.events(run_id)
            if event["state"] == "cancel_requested" and event["details"].get("stop_custody") == 1
        ]
        observed.append((len(marked) == 1, (env.binding_dir(run_id) / "attempt.json").is_file()))

    env.fake.on_term = at_kill
    summary = control.cancel_run(run_id, "stop", "cancel:a02")
    assert summary.state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert observed == [(True, True)]
    other = env.root / "workspace-a"
    with pytest.raises(RunControlError) as competing:
        control.submit_run("start_project", {"brief": "x", "workspace_dir": str(other)}, "idem:x")
    assert competing.value.code == "busy"
    status = control.inspect_stop(run_id)
    assert (status.request, status.delivery, status.settlement) == ("recorded", "accepted", "pending")
    assert status.identity_strength == "pid_session_only"


def test_a03_never_dispatched_is_the_only_clear_replay(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    summary = control.cancel_run(run_id, "stop", "cancel:a03")
    assert summary.state == "cancelled"
    assert env.fake.signals == []
    assert env.last(run_id)["details"]["stop_settlement"] == "never_dispatched"
    assert env.states(run_id) == ["queued", "cancel_requested", "draining", "cancelled"]
    assert env.events(run_id)[2]["details"] == {"stop_actor": "controller"}
    assert control.worker_start(run_id, pid=OWNER_PID, pgid=OWNER_PID, generation=1) is False
    status = control.inspect_stop(run_id)
    assert status.replay_clearance == "clear"
    assert (status.delivery, status.product_effect) == ("not_applicable", "not_started")
    assert status.terminal_source == "writer"


# ---------------------------------------------------------------- A04 owner


def test_a04_owner_reported_after_single_term_and_non_owner_is_refused(env: Env) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:a04")
    assert env.fake.signals == ONE_TERM
    stranger = env.control(owner_id="worker:9999:1")
    before = env.snapshot()
    for call in (stranger.worker_draining, stranger.worker_cancelled, stranger.worker_failed):
        with pytest.raises(RunControlError) as refused:
            call(run_id)
        assert refused.value.code == "integrity_error"
    with env.as_pid(OWNER_PID), pytest.raises(RunControlError) as wrong_owner_id:
        stranger.worker_cancelled(run_id)
    assert wrong_owner_id.value.code == "integrity_error"
    assert env.snapshot() == before
    assert env.cursor(run_id).exists()
    with env.as_pid():
        owner.worker_draining(run_id)
        owner.worker_cancelled(run_id)
    last = env.last(run_id)
    assert last["state"] == "cancelled"
    assert last["details"]["stop_settlement"] == "owner_reported"
    assert env.events(run_id)[-2]["details"] == {"stop_actor": "owner"}
    status = control.inspect_stop(run_id)
    assert (status.settlement, status.replay_clearance) == ("owner_reported", "unresolved")
    assert status.delivery == "accepted"
    assert env.fake.signals == ONE_TERM
    env.assert_unique_receipts()


@pytest.mark.parametrize("caller", ["foreign_pid", "foreign_owner_id"])
@pytest.mark.parametrize("writer", ["effect_failure", "succeeded"])
def test_a04_non_owner_failure_effect_and_success_on_stop_prefix_are_refused(
    env: Env, writer: str, caller: str
) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:a04-e1")
    assert env.fake.signals == ONE_TERM
    if writer == "succeeded":
        # The owner finished its effect after the request; success is legal here.
        owner.worker_effect_complete(run_id, RESULT)
        owner.worker_report_complete(run_id)
        assert env.states(run_id)[-3:] == ["cancel_requested", "effect_complete", "report_complete"]
    else:
        assert env.states(run_id)[-1] == "cancel_requested"
    tool_error = env.run_dir(run_id) / "private" / "tool-error.json"
    before = env.snapshot()

    def call(instance: RunControl) -> None:
        if writer == "effect_failure":
            instance.worker_effect_complete(run_id, FAILURE)
        else:
            instance.worker_succeeded(run_id)

    with pytest.raises(RunControlError) as refused:
        if caller == "foreign_pid":
            # The bound owner id from another process (os.getpid is not the bound PID).
            call(owner)
        else:
            with env.as_pid(OWNER_PID):
                call(env.control(owner_id="worker:9999:1"))
    assert refused.value.code == "integrity_error"
    assert env.snapshot() == before
    assert not tool_error.exists()
    assert env.cursor(run_id).exists()
    assert env.receipt_ids() == Counter()
    assert env.fake.signals == ONE_TERM
    # Positive control: the bound owner on the same prefix is accepted.
    with env.as_pid():
        call(owner)
    last = env.last(run_id)
    if writer == "effect_failure":
        assert last["state"] == "failed"
        assert last["details"]["stop_settlement"] == "owner_failed"
        assert tool_error.is_file()
    else:
        assert last["state"] == "succeeded"
        assert last["details"]["stop_settlement"] == "owner_completed"
    env.assert_unique_receipts()


def test_a04_pending_receipt_is_not_adopted_by_a_non_owner(env: Env) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:a04p")
    with env.as_pid():
        owner.worker_draining(run_id)
    pending = env.plant_receipt(control, run_id, "cancelled")
    stranger = env.control(owner_id="worker:9999:1")
    before = env.snapshot()
    with pytest.raises(RunControlError) as refused:
        stranger.worker_cancelled(run_id)
    assert refused.value.code == "integrity_error"
    assert env.snapshot() == before
    assert control.inspect_stop(run_id).pending_terminal == "adoptable"
    with env.as_pid():
        owner.worker_cancelled(run_id)
    last = env.last(run_id)
    assert last["details"]["receipt_digest"] == pending.digest
    assert last["details"]["terminal_source"] == "pending_receipt"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    env.assert_unique_receipts()


# ---------------------------------------------------------------- A05 / A06


def test_a05a_esrch_settles_owner_unproven(env: Env) -> None:
    control, _, run_id = _running(env)
    env.fake.term_error = ProcessLookupError(OWNER_PID)
    summary = control.cancel_run(run_id, "stop", "cancel:a05a")
    assert summary.state == "cancelled"
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_unproven"
    assert control.inspect_stop(run_id).delivery == "esrch"
    assert env.fake.signals == ONE_TERM


@pytest.mark.parametrize("proof", ["live_owner", "cursor_removed", "cursor_mismatch"])
@pytest.mark.parametrize("death", ["esrch", "other_session"])
def test_a05b_eperm_requires_independent_death_proof(
    env: Env, proof: str, death: str
) -> None:
    control, _, run_id = _running(env)
    env.fake.term_error = PermissionError(OWNER_PID)
    assert control.cancel_run(run_id, "stop", "cancel:eperm-1").state == "cancel_requested"
    env.fake.term_error = None
    assert control.inspect_stop(run_id).delivery == "eperm"
    if proof == "cursor_removed":
        env.cursor(run_id).unlink()
    elif proof == "cursor_mismatch":
        env.mp.setattr(RunControl, "_cursor_matches", lambda self, request, cursor: False)
    env.fake.getsid_error = None
    for key in ("cancel:eperm-2", "cancel:eperm-3"):
        assert control.cancel_run(run_id, "stop", key).state == "cancel_requested"
    env.fake.getsid_error = PermissionError(OWNER_PID)
    assert control.cancel_run(run_id, "stop", "cancel:eperm-4").state == "cancel_requested"
    env.fake.getsid_error = None
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ()
    assert env.last(run_id)["state"] == "cancel_requested"
    status = control.inspect_stop(run_id)
    assert (status.settlement, status.replay_clearance) == ("pending", "unresolved")
    assert env.fake.signals == ONE_TERM
    if death == "esrch":
        env.fake.live.discard(OWNER_PID)
    else:
        env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    summary = control.cancel_run(run_id, "stop", "cancel:eperm-5")
    assert summary.state == "cancelled"
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_unproven"
    assert env.fake.signals == ONE_TERM


@pytest.mark.parametrize("draining", ["owner", "legacy"])
def test_a05b_eperm_hold_covers_draining_recover_and_converge(env: Env, draining: str) -> None:
    control, owner, run_id = _running(env)
    env.fake.term_error = PermissionError(OWNER_PID)
    control.cancel_run(run_id, "stop", "cancel:eperm-d")
    env.fake.term_error = None
    if draining == "owner":
        with env.as_pid():
            owner.worker_draining(run_id)
    else:
        control._append_event(run_id, "draining", {})
    env.cursor(run_id).unlink()
    before = env.snapshot()
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ()
    assert control.cancel_run(run_id, "stop", "cancel:eperm-d2").state == "draining"
    assert env.snapshot() == before
    env.fake.live.discard(OWNER_PID)
    env.control(owner_id="server:recover-2", recover=True)
    last = env.last(run_id)
    assert last["state"] == "attention"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert last["details"]["error"]["error"]["message"] == "worker ownership could not be recovered"
    assert env.fake.signals == ONE_TERM


def test_a06_missing_cursor_settles_without_signal(env: Env) -> None:
    control, _, run_id = _running(env)
    env.cursor(run_id).unlink()
    assert control.cancel_run(run_id, "stop", "cancel:a06").state == "cancelled"
    assert env.fake.signals == []
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_unproven"
    assert control.inspect_stop(run_id).delivery == "not_applicable"


# ---------------------------------------------------------------- A07 crash matrix


def _marked_requests(env: Env, run_id: str) -> int:
    return sum(
        1 for event in env.events(run_id)
        if event["state"] == "cancel_requested" and "stop_custody" in event["details"]
    )


@contextmanager
def _crash_call(env: Env, foreign: bool) -> Iterator[None]:
    if foreign:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runs.os, "getpid", lambda: 777_777)
            with pytest.raises(Crash):
                yield
    else:
        with pytest.raises(Crash):
            yield


@pytest.mark.parametrize("foreign", [False, True], ids=["same-process", "foreign-process"])
@pytest.mark.parametrize("cut", ["prepared", "staged", "applying"])
def test_a07_c1_c3_crash_before_request_converges_once(env: Env, foreign: bool, cut: str) -> None:
    control, _, run_id = _running(env)
    if cut == "applying":
        # The journal claim is held; the effect dies before the request is written.
        _crash_append(env, "cancel_requested")
    else:
        env.journal_faults(cut)
    if foreign:
        env.mp.setattr(journal_module, "_pid_is_alive", lambda pid: False)
    with _crash_call(env, foreign):
        control.cancel_run(run_id, "stop", "cancel:c1")
    assert "cancel_requested" not in env.states(run_id)
    assert env.fake.signals == []
    assert control.cancel_run(run_id, "stop", "cancel:c1").state == "cancel_requested"
    assert control.cancel_run(run_id, "stop", "cancel:c1-other").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert _marked_requests(env, run_id) == 1


@pytest.mark.parametrize("foreign", [False, True], ids=["same-process", "foreign-process"])
def test_a07_c4_request_without_attempt_signals_on_next_cancel_only(env: Env, foreign: bool) -> None:
    control, _, run_id = _running(env)
    if foreign:
        env.mp.setattr(journal_module, "_pid_is_alive", lambda pid: False)
    _crash_after_append(env, "cancel_requested")
    with _crash_call(env, foreign):
        control.cancel_run(run_id, "stop", "cancel:c4")
    assert env.states(run_id).count("cancel_requested") == 1
    assert not (env.run_dir(run_id) / "stop").exists()
    env.control(owner_id="server:recover", recover=True)
    assert env.fake.signals == []
    assert control.cancel_run(run_id, "stop", "cancel:c4").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert _marked_requests(env, run_id) == 1
    assert control.inspect_stop(run_id).delivery == "accepted"


class _Faults:
    """Inject one failure into stop-record publication (C5a)."""

    def __init__(self, env: Env, point: str, name: str = "attempt.json") -> None:
        self.env = env
        self.point = point
        self.name = name
        self.fired = False

    def install(self) -> None:
        mp = self.env.mp
        if self.point == "mkdir":
            original_mkdir = Path.mkdir

            def mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
                if path.name == "stop" and not self.fired:
                    self.fired = True
                    raise OSError("injected mkdir failure")
                original_mkdir(path, *args, **kwargs)

            mp.setattr(Path, "mkdir", mkdir)
        elif self.point == "mkstemp":
            original_mkstemp = runs.tempfile.mkstemp

            def mkstemp(*args: Any, **kwargs: Any) -> Any:
                if kwargs.get("prefix") == ".stop-tmp-" and not self.fired:
                    self.fired = True
                    raise OSError("injected mkstemp failure")
                return original_mkstemp(*args, **kwargs)

            mp.setattr(runs.tempfile, "mkstemp", mkstemp)
        elif self.point == "write":
            original_mkstemp = runs.tempfile.mkstemp

            def readonly_mkstemp(*args: Any, **kwargs: Any) -> Any:
                descriptor, name = original_mkstemp(*args, **kwargs)
                if kwargs.get("prefix") == ".stop-tmp-" and not self.fired:
                    self.fired = True
                    os.close(descriptor)
                    descriptor = os.open(name, os.O_RDONLY)
                return descriptor, name

            mp.setattr(runs.tempfile, "mkstemp", readonly_mkstemp)
        elif self.point == "link":
            original_link = os.link

            def link(source: Any, target: Any, *args: Any, **kwargs: Any) -> None:
                if Path(target).name == self.name and not self.fired:
                    self.fired = True
                    raise OSError("injected link failure")
                original_link(source, target, *args, **kwargs)

            mp.setattr(runs.os, "link", link)
        elif self.point in {"lstat", "read"}:
            # Arm only after the record is linked: the failure hits the
            # publisher's read-back of an already published record.
            armed = {"value": False}
            original_link = os.link

            def arming_link(source: Any, target: Any, *args: Any, **kwargs: Any) -> None:
                original_link(source, target, *args, **kwargs)
                if Path(target).name == self.name:
                    armed["value"] = True

            mp.setattr(runs.os, "link", arming_link)
            method = "lstat" if self.point == "lstat" else "read_bytes"
            original = getattr(Path, method)

            def failing(path: Path, *args: Any, **kwargs: Any) -> Any:
                if path.name == self.name and armed["value"] and not self.fired:
                    self.fired = True
                    raise OSError("injected post-link failure")
                return original(path, *args, **kwargs)

            mp.setattr(Path, method, failing)
        else:  # pragma: no cover - parameter guard
            raise AssertionError(self.point)


@pytest.mark.parametrize("point", ["mkdir", "mkstemp", "write", "link"])
def test_a07_c5a_unpublished_attempt_failure_never_signals_then_retries(env: Env, point: str) -> None:
    control, _, run_id = _running(env)
    _Faults(env, point).install()
    with pytest.raises(RunControlError) as failed:
        control.cancel_run(run_id, "stop", "cancel:c5a")
    assert failed.value.code == "internal_error"
    assert env.fake.signals == []
    binding = env.binding_dir(run_id)
    assert not (binding / "attempt.json").exists()
    if point == "write":
        assert [path.name.startswith(".stop-tmp-") for path in binding.iterdir()] in ([], [True])
    assert control.inspect_stop(run_id).delivery == "pending"
    assert control.cancel_run(run_id, "stop", "cancel:c5a").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert control.cancel_run(run_id, "stop", "cancel:c5a-new").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert _marked_requests(env, run_id) == 1


@pytest.mark.parametrize("point", ["lstat", "read"])
def test_a07_c5a_published_attempt_with_failed_readback_is_ambiguous(env: Env, point: str) -> None:
    control, _, run_id = _running(env)
    _Faults(env, point).install()
    with pytest.raises(RunControlError):
        control.cancel_run(run_id, "stop", "cancel:c5p")
    assert env.fake.signals == []
    assert (env.binding_dir(run_id) / "attempt.json").is_file()
    for key in ("cancel:c5p", "cancel:c5p-new"):
        assert control.cancel_run(run_id, "stop", key).state == "cancel_requested"
    assert env.fake.signals == []
    assert control.inspect_stop(run_id).delivery == "ambiguous"


@pytest.mark.parametrize("foreign", [False, True], ids=["same-process", "foreign-process"])
def test_a07_c5b_crash_after_kill_before_delivery_is_ambiguous(env: Env, foreign: bool) -> None:
    control, _, run_id = _running(env)
    if foreign:
        env.mp.setattr(journal_module, "_pid_is_alive", lambda pid: False)
    env.fake.term_error = Crash("after kill")
    with _crash_call(env, foreign):
        control.cancel_run(run_id, "stop", "cancel:c5b")
    env.fake.term_error = None
    assert env.fake.signals == ONE_TERM
    for key in ("cancel:c5b", "cancel:c5b-new"):
        assert control.cancel_run(run_id, "stop", key).state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert control.inspect_stop(run_id).delivery == "ambiguous"
    env.cursor(run_id).unlink()
    assert control.cancel_run(run_id, "stop", "cancel:c5b-settle").state == "cancelled"
    assert env.fake.signals == ONE_TERM


def test_a07_c5c_delivery_publication_failure_is_ambiguous(env: Env) -> None:
    control, _, run_id = _running(env)
    _Faults(env, "link", name="delivered.json").install()
    assert control.cancel_run(run_id, "stop", "cancel:c5c").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert not (env.binding_dir(run_id) / "delivered.json").exists()
    assert control.cancel_run(run_id, "stop", "cancel:c5c-new").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert control.inspect_stop(run_id).delivery == "ambiguous"


@pytest.mark.parametrize("foreign", [False, True], ids=["same-process", "foreign-process"])
@pytest.mark.parametrize("cut", ["effect_applied", "effect_complete"])
def test_a07_c6_c7_after_delivery_never_resignals(env: Env, foreign: bool, cut: str) -> None:
    control, _, run_id = _running(env)
    env.journal_faults(cut, foreign=foreign)
    with _crash_call(env, foreign):
        control.cancel_run(run_id, "stop", "cancel:c6")
    assert env.fake.signals == ONE_TERM
    replay = control.cancel_run(run_id, "stop", "cancel:c6")
    assert replay.state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    env.cursor(run_id).unlink()
    if cut == "effect_complete":
        # C7: the journal already holds the terminal effect snapshot.
        assert control.cancel_run(run_id, "stop", "cancel:c6") == replay
    assert control.cancel_run(run_id, "stop", "cancel:c6-settle").state == "cancelled"
    assert env.fake.signals == ONE_TERM
    assert _marked_requests(env, run_id) == 1


@pytest.mark.parametrize("finisher", ["converge", "recover"])
def test_a07_c8_controller_draining_before_receipt_settles_deterministically(
    env: Env, finisher: str
) -> None:
    control, _, run_id = _running(env)
    env.cursor(run_id).unlink()
    original = FoundationStore.append_receipt
    fired = {"done": False}

    def crashing(self: FoundationStore, *args: Any, **kwargs: Any) -> Any:
        if not fired["done"]:
            fired["done"] = True
            raise Crash("before receipt")
        return original(self, *args, **kwargs)

    env.mp.setattr(FoundationStore, "append_receipt", crashing)
    with pytest.raises(Crash):
        control.cancel_run(run_id, "stop", "cancel:c8")
    assert env.states(run_id)[-1] == "draining"
    assert env.last(run_id)["details"] == {"stop_actor": "controller"}
    if finisher == "converge":
        control.cancel_run(run_id, "stop", "cancel:c8")
    else:
        env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == "cancelled"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert env.fake.signals == []
    env.assert_unique_receipts()


@pytest.mark.parametrize("entry", ["W1-owner-finalize", "W2-owner-settle", "W3-cancel", "W4-recover"])
def test_a07_c9_committed_receipt_without_terminal_is_adopted(env: Env, entry: str) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:c9")
    with env.as_pid():
        owner.worker_draining(run_id)
    _crash_append(env, "cancelled")
    with env.as_pid(), pytest.raises(Crash):
        owner.worker_cancelled(run_id)
    assert env.states(run_id)[-1] == "draining"
    pending = [rid for rid in env.receipt_ids()]
    assert len(pending) == 1
    if entry == "W1-owner-finalize":
        with env.as_pid():
            owner.worker_failed(run_id)
    elif entry == "W2-owner-settle":
        with env.as_pid():
            owner.worker_cancelled(run_id)
    elif entry == "W3-cancel":
        control.cancel_run(run_id, "stop", "cancel:c9-new")
    else:
        env.cursor(run_id).unlink()
        env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == "cancelled"
    assert last["details"]["terminal_source"] == "pending_receipt"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert "error" not in last["details"]
    assert list(env.receipt_ids()) == pending
    env.assert_unique_receipts()
    assert env.fake.signals == ONE_TERM
    assert control.inspect_stop(run_id).terminal_source == "pending_receipt"


@pytest.mark.parametrize("crashed", ["worker_failed", "effect_failure"])
def test_a07_c9_w2_receipt_on_cancel_requested_is_adopted_without_synthesized_draining(
    env: Env, crashed: str
) -> None:
    """W2 proper: the committed prefix ends at ``cancel_requested``.

    Without W2 the settle path would append ``draining{owner}`` first, which
    moves the prefix so that W1 no longer sees the committed receipt.
    """
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:c9w2")
    assert env.fake.signals == ONE_TERM
    terminal = "attention" if crashed == "worker_failed" else "failed"
    _crash_append(env, terminal)
    with env.as_pid(), pytest.raises(Crash):
        if crashed == "worker_failed":
            owner.worker_failed(run_id)
        else:
            owner.worker_effect_complete(run_id, FAILURE)
    assert env.states(run_id) == ["queued", "running", "cancel_requested"]
    pending = list(env.receipt_ids())
    assert len(pending) == 1
    env.mp.setattr(RunControl, "_append_event_unlocked", _ORIGINAL_APPEND)
    with env.as_pid():
        owner.worker_cancelled(run_id)
    assert env.states(run_id) == ["queued", "running", "cancel_requested", terminal]
    last = env.last(run_id)
    assert last["details"]["terminal_source"] == "pending_receipt"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert last["details"]["error"] == runs._PENDING_RECEIPT_ERROR
    assert list(env.receipt_ids()) == pending
    assert last["details"]["receipt_id"] == pending[0]
    env.assert_unique_receipts()
    assert not env.cursor(run_id).exists()
    assert env.fake.signals == ONE_TERM
    assert control.inspect_stop(run_id).terminal_source == "pending_receipt"


# ---------------------------------------------------------------- A08 (G1)


def test_a08_applying_key_converges_after_run_became_terminal(env: Env) -> None:
    control, owner, run_id = _running(env)
    _crash_append(env, "cancel_requested")
    with pytest.raises(Crash):
        control.cancel_run(run_id, "stop", "cancel:g1")
    owner.worker_effect_complete(run_id, RESULT)
    owner.worker_report_complete(run_id)
    owner.worker_succeeded(run_id)
    assert control.cancel_run(run_id, "stop", "cancel:g1").state == "succeeded"
    assert env.fake.signals == []


def test_a08_applying_key_converges_after_a_foreign_request(env: Env) -> None:
    control, _, run_id = _running(env)
    original = RunControl._append_event_unlocked
    fired = {"done": False}

    def failing(self: RunControl, run: str, state: str, details: Any) -> Any:
        if state == "cancel_requested" and not fired["done"]:
            fired["done"] = True
            raise OSError("any effect exception")
        return original(self, run, state, details)

    env.mp.setattr(RunControl, "_append_event_unlocked", failing)
    with pytest.raises(OSError):
        control.cancel_run(run_id, "stop", "cancel:g1-a")
    control.cancel_run(run_id, "other", "cancel:g1-b")
    assert env.fake.signals == ONE_TERM
    assert control.cancel_run(run_id, "stop", "cancel:g1-a").state == "cancel_requested"
    assert env.fake.signals == ONE_TERM
    assert _marked_requests(env, run_id) == 1


# ---------------------------------------------------------------- A09 idempotency


def test_a09_idempotency_table(env: Env) -> None:
    control, owner, run_id = _running(env)
    first = control.cancel_run(run_id, "stop", "cancel:k")
    assert control.cancel_run(run_id, "stop", "cancel:k") == first
    with pytest.raises(RunControlError) as conflict:
        control.cancel_run(run_id, "other reason", "cancel:k")
    assert conflict.value.code == "conflict"
    for key in ("cancel:k2", "cancel:k3"):
        control.cancel_run(run_id, "stop", key)
    assert env.fake.signals == ONE_TERM
    second_control = env.control()
    other_run = env.submit(second_control, "b")
    assert control.cancel_run(other_run, "stop", "cancel:k").state == "cancelled"
    with env.as_pid():
        owner.worker_draining(run_id)
    events = len(env.events(run_id))
    assert control.cancel_run(run_id, "stop", "cancel:k4").state == "draining"
    assert len(env.events(run_id)) == events
    with env.as_pid():
        owner.worker_cancelled(run_id)
    terminal = control.cancel_run(run_id, "stop", "cancel:k5")
    assert terminal.state == "cancelled"
    assert env.fake.signals == ONE_TERM


# ---------------------------------------------------------------- A10 recover


def test_a10_g10_cancel_requested_after_effect_recovers_to_attention(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    control.cancel_run(run_id, "stop", "cancel:g10")
    assert env.states(run_id)[-1] == "cancel_requested"
    env.cursor(run_id).unlink()
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ()
    last = env.last(run_id)
    assert last["state"] == "attention"
    assert last["details"]["error"]["error"]["message"] == "cancellation followed a completed effect"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    env.assert_unique_receipts()


def test_a10_g10b_owner_draining_after_effect_recovers_to_attention(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    control.cancel_run(run_id, "stop", "cancel:g10b")
    with env.as_pid():
        owner.worker_draining(run_id)
    env.cursor(run_id).unlink()
    env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == "attention"
    assert last["details"]["error"]["error"]["message"] == "worker ownership could not be recovered"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert "report_complete" not in env.states(run_id)


@pytest.mark.parametrize(
    ("actor", "state", "message"),
    [
        ("controller", "cancelled", None),
        ("owner", "attention", "worker ownership could not be recovered"),
        ("legacy", "attention", "worker ownership could not be recovered"),
    ],
)
def test_a10_draining_branches_by_stop_actor(
    env: Env, actor: str, state: str, message: str | None
) -> None:
    control, _, run_id = _running(env)
    control._append_event(run_id, "draining", {} if actor == "legacy" else {"stop_actor": actor})
    env.cursor(run_id).unlink()
    env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == state
    assert last["details"]["stop_settlement"] == "owner_unproven"
    if message is not None:
        assert last["details"]["error"]["error"]["message"] == message


def test_a10_without_stop_prefix_recovery_is_unchanged(env: Env) -> None:
    control = env.control()
    queued = env.submit(control, "queued")
    running = env.submit(control, "running")
    env.start_owner(running)
    env.cursor(running).unlink()
    effect = env.submit(control, "effect")
    owner = env.start_owner(effect, pid=OWNER_PID + 1)
    owner.worker_effect_complete(effect, RESULT)
    env.cursor(effect).unlink()
    env.spawned.clear()
    env.control(owner_id="server:recover", recover=True)
    assert env.spawned == [queued]
    assert env.states(running)[-1] == "attention"
    assert env.states(effect)[-2:] == ["report_complete", "succeeded"]
    for run_id in (running, effect):
        assert "stop_settlement" not in env.last(run_id)["details"]
        assert "terminal_source" not in env.last(run_id)["details"]


# ---------------------------------------------------------------- A11 legacy


def test_a11_legacy_in_flight_request_is_never_signalled(env: Env) -> None:
    control, _, run_id = _running(env)
    control._append_event(
        run_id,
        "cancel_requested",
        {"cancel_idempotency_digest": "sha256:" + "0" * 64, "reason_digest": "sha256:" + "1" * 64},
    )
    events = len(env.events(run_id))
    assert control.cancel_run(run_id, "stop", "cancel:legacy").state == "cancel_requested"
    assert env.fake.signals == []
    assert len(env.events(run_id)) == events
    status = control.inspect_stop(run_id)
    assert (status.request, status.delivery, status.identity_strength) == (
        "legacy_recorded", "legacy_unrecorded", "legacy_unrecorded"
    )
    env.cursor(run_id).unlink()
    assert control.cancel_run(run_id, "stop", "cancel:legacy-2").state == "cancelled"
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_unproven"
    assert env.fake.signals == []
    successor = control.submit_run(
        "start_project", {"brief": "next", "workspace_dir": str(env.root / "workspace-a")}, "idem:next"
    )
    assert successor.state == "queued"


@pytest.mark.parametrize("with_request", [True, False])
def test_a11_legacy_terminal_is_unclassified_and_untouched(env: Env, with_request: bool) -> None:
    control, _, run_id = _running(env)
    if with_request:
        control._append_event(
            run_id,
            "cancel_requested",
            {"cancel_idempotency_digest": "sha256:" + "0" * 64, "reason_digest": "sha256:" + "1" * 64},
        )
    control._append_event(run_id, "draining", {})
    control._append_event(
        run_id,
        "cancelled",
        {"receipt_digest": "sha256:" + "2" * 64, "receipt_id": "receipt:run_receipt.v1:legacy:1"},
    )
    before = env.snapshot()
    status = control.inspect_stop(run_id)
    assert (status.settlement, status.replay_clearance) == ("legacy_unclassified", "unresolved")
    assert control.cancel_run(run_id, "stop", "cancel:legacy-terminal").state == "cancelled"
    env.control(owner_id="server:recover", recover=True)
    assert env.snapshot() == before
    assert env.fake.signals == []


def test_a11_legacy_journal_record_replays_byte_for_byte(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    legacy_result = control.inspect_run(run_id).as_dict()
    request = {"idempotency_key": "cancel:old", "reason": "stop", "run_id": run_id}
    DurableMutationJournal(env.root).execute(
        operation="cancel_run",
        resource_key=run_id,
        idempotency_key="cancel:old",
        request=request,
        effect=lambda _: legacy_result,
        reconcile=lambda _: None,
    )
    records = sorted((env.root / ".unrest/foundation/public-mutations").glob("*.json"))
    before = {path: path.read_bytes() for path in records}
    replay = control.cancel_run(run_id, "stop", "cancel:old")
    assert replay.as_dict() == legacy_result
    assert {path: path.read_bytes() for path in records} == before
    assert env.states(run_id) == ["queued"]
    assert list(replay.as_dict()) == [
        "run_id", "operation", "state", "resource_key", "idempotency_key", "project_id",
        "created_at", "updated_at", "result", "error", "receipt_id", "active_attempts",
    ]


# ---------------------------------------------------------------- A12 constraints


def test_a12_no_nested_lock_inspection_or_project_inspector_under_run_lock(env: Env) -> None:
    held: list[str] = []
    strict = {"on": False}
    original_lock = runs._exclusive_lock

    def is_run_lock(name: str) -> bool:
        return not name.endswith("admission.lock") and "/locks/" not in name

    @contextmanager
    def tracking(path: Path) -> Iterator[Any]:
        name = str(path)
        if name in held:
            pytest.fail(f"nested acquisition of {path.name}")
        if strict["on"] and any(is_run_lock(item) for item in held):
            pytest.fail(f"{path.name} acquired under a run lock")
        with original_lock(path) as stream:
            held.append(name)
            try:
                yield stream
            finally:
                held.remove(name)

    def under_run_lock() -> bool:
        return strict["on"] and any(is_run_lock(item) for item in held)

    def inspector(project_id: str) -> dict[str, Any]:
        if under_run_lock():
            raise AssertionError("project_inspector under run lock")
        return {"active_attempts": []}

    original_inspect = RunControl.inspect_run

    def guarded_inspect(self: RunControl, run_id: str) -> Any:
        if under_run_lock():
            pytest.fail("inspect_run under run lock in a stop path")
        return original_inspect(self, run_id)

    env.mp.setattr(runs, "_exclusive_lock", tracking)
    env.mp.setattr(RunControl, "inspect_run", guarded_inspect)
    control = env.control(project_inspector=inspector)
    owner = env.control(owner_id=f"worker:{OWNER_PID}:1", project_inspector=inspector)
    run_id = control.submit_run("advance_project", {"project_id": "p", "max_steps": 1}, "idem:adv").run_id
    env.fake.live.add(OWNER_PID)
    assert owner.worker_start(run_id, pid=OWNER_PID, pgid=OWNER_PID, generation=1)

    class _Worker:
        polls = 0

        def poll(self) -> None:
            _Worker.polls += 1

        def wait(self, *args: Any, **kwargs: Any) -> None:
            pytest.fail("cancel waits for a worker")

    key = (str(env.root.resolve()), run_id, 1)
    runs._local_workers[key] = _Worker()  # type: ignore[assignment]
    strict["on"] = True
    try:
        assert control.cancel_run(run_id, "stop", "cancel:a12").state == "cancel_requested"
        assert control.inspect_stop(run_id).delivery == "accepted"
        with env.as_pid():
            owner.worker_draining(run_id)
            owner.worker_cancelled(run_id)
        second = env.control(owner_id="server:other", project_inspector=inspector)
        assert second.cancel_run(run_id, "stop", "cancel:a12-terminal").state == "cancelled"
    finally:
        strict["on"] = False
        runs._local_workers.pop(key, None)
    assert _Worker.polls >= 1
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_reported"
    assert env.fake.signals == ONE_TERM
    queued = control.submit_run("advance_project", {"project_id": "q", "max_steps": 1}, "idem:adv2").run_id
    strict["on"] = True
    try:
        assert control.cancel_run(queued, "stop", "cancel:a12-q").state == "cancelled"
    finally:
        strict["on"] = False


def test_a12_self_signal_and_invalid_binding_pid_fail_closed(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    me = os.getpid()
    owner = env.control(owner_id=f"worker:{me}:1")
    env.fake.live.add(me)
    assert owner.worker_start(run_id, pid=me, pgid=me, generation=1)
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "stop", "cancel:self")
    assert caught.value.code == "integrity_error"
    assert env.fake.signals == []
    assert env.snapshot() == before
    assert env.states(run_id) == ["queued", "running"]
    assert not (env.run_dir(run_id) / "stop").exists()
    bad = env.submit(control, "bool-pid")
    owner_bad = env.control(owner_id="worker:bool:1")
    assert owner_bad.worker_start(bad, pid=True, pgid=True, generation=1)  # type: ignore[arg-type]
    with pytest.raises(RunControlError) as invalid:
        control.cancel_run(bad, "stop", "cancel:bool")
    assert invalid.value.code == "integrity_error"
    assert env.fake.signals == []
    assert env.states(bad) == ["queued", "running"]


def test_a12_corrupt_stop_custody_is_local_to_its_run(env: Env) -> None:
    control, _, run_x = _running(env, "x")
    control.cancel_run(run_x, "stop", "cancel:x")
    (env.binding_dir(run_x) / "attempt.json").write_bytes(b"{}\n")
    with pytest.raises(RunControlError) as caught:
        control.inspect_stop(run_x)
    assert caught.value.code == "integrity_error"
    assert control.inspect_run(run_x).state == "cancel_requested"
    run_y = env.submit(control, "y")
    assert control.inspect_run(run_y).state == "queued"
    assert control.cancel_run(run_y, "stop", "cancel:y").state == "cancelled"


def test_a12_stop_vocabulary_is_confined_to_run_control() -> None:
    package = Path(runs.__file__).parent
    hits = sorted(
        path.name
        for path in package.rglob("*.py")
        if any(
            token in path.read_text(encoding="utf-8")
            for token in ("stop/", "stop_settlement", "stop_actor", "terminal_source")
        )
    )
    assert hits == ["run_control.py"]


# ---------------------------------------------------------------- A13 (G11)


@pytest.mark.parametrize("owner_proof", ["cursor_removed", "getsid_esrch"])
def test_a13_existing_attempt_with_owner_proof_false_settles_without_signal(
    env: Env, owner_proof: str
) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:g11")
    control.cancel_run(run_id, "stop", "cancel:g11-live")
    assert env.fake.signals == ONE_TERM
    if owner_proof == "cursor_removed":
        env.cursor(run_id).unlink()
    else:
        env.fake.live.discard(OWNER_PID)
    assert control.cancel_run(run_id, "stop", "cancel:g11-settle").state == "cancelled"
    assert env.fake.signals == ONE_TERM
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_unproven"
    successor = control.submit_run(
        "start_project", {"brief": "next", "workspace_dir": str(env.root / "workspace-a")}, "idem:g11"
    )
    assert successor.state == "queued"


# ---------------------------------------------------------------- A14 schemas


def _rewrite_json(path: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    value = json.loads(path.read_bytes())
    mutate(value)
    path.write_bytes(runs._json_bytes(value))


def _corrupt(env: Env, run_id: str, case: str) -> None:
    binding = env.binding_dir(run_id)
    attempt = binding / "attempt.json"
    delivered = binding / "delivered.json"
    stop = binding.parent
    if case == "noncanonical":
        attempt.write_bytes(attempt.read_bytes().replace(b",", b", ", 1))
    elif case == "duplicate_key":
        attempt.write_bytes(attempt.read_bytes().replace(b'{"binding"', b'{"kind":"stop_attempt","binding"', 1))
    elif case == "bool_version":
        _rewrite_json(attempt, lambda value: value.update(schema_version=True))
    elif case == "extra_field":
        _rewrite_json(attempt, lambda value: value.update(extra=1))
    elif case == "missing_field":
        _rewrite_json(attempt, lambda value: value.pop("signal"))
    elif case == "unknown_version":
        _rewrite_json(attempt, lambda value: value.update(schema_version=2))
    elif case == "binding_mismatch":
        _rewrite_json(attempt, lambda value: value["binding"].update(pid=OWNER_PID + 7))
    elif case == "binding_owner_list":
        _rewrite_json(attempt, lambda value: value["binding"].update(owner_id=["foreign"]))
    elif case == "request_mismatch":
        _rewrite_json(attempt, lambda value: value.update(request_event_digest="sha256:" + "9" * 64))
    elif case == "attempt_digest_mismatch":
        _rewrite_json(delivered, lambda value: value.update(attempt_digest="sha256:" + "9" * 64))
    elif case == "unknown_outcome":
        _rewrite_json(delivered, lambda value: value.update(outcome="maybe"))
    elif case == "list_outcome":
        _rewrite_json(delivered, lambda value: value.update(outcome=["eperm"]))
    elif case == "object_outcome":
        _rewrite_json(delivered, lambda value: value.update(outcome={"value": "eperm"}))
    elif case == "deep_json":
        delivered.write_bytes(b'{"nested":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}")
    elif case == "delivered_without_attempt":
        attempt.unlink()
    elif case == "symlink_record":
        moved = env.run_dir(run_id) / "moved-attempt"
        attempt.rename(moved)
        attempt.symlink_to(moved)
    elif case == "directory_record":
        delivered.unlink()
        attempt.unlink()
        attempt.mkdir()
    elif case == "unknown_name":
        (binding / "notes.txt").write_text("x")
    elif case == "foreign_temp_prefix":
        (binding / ".run-abc123").write_text("x")
    elif case == "temp_directory":
        (binding / ".stop-tmp-abc").mkdir()
    elif case == "foreign_binding":
        (stop / ("e" * 64)).mkdir()
    elif case == "stop_is_file":
        renamed = stop.with_name("stop-moved")
        stop.rename(renamed)
        stop.write_text("x")
    elif case == "stop_is_symlink":
        renamed = stop.with_name("stop-moved")
        stop.rename(renamed)
        stop.symlink_to(renamed.name)
    else:  # pragma: no cover - parameter guard
        raise AssertionError(case)


SCHEMA_CASES = [
    "noncanonical", "duplicate_key", "bool_version", "extra_field", "missing_field",
    "unknown_version", "binding_mismatch", "binding_owner_list", "request_mismatch", "attempt_digest_mismatch",
    "unknown_outcome", "list_outcome", "object_outcome", "deep_json", "delivered_without_attempt", "symlink_record", "directory_record",
    "unknown_name", "foreign_temp_prefix", "temp_directory", "foreign_binding",
    "stop_is_file", "stop_is_symlink",
]


@pytest.mark.parametrize("case", SCHEMA_CASES)
def test_a14_invalid_stop_custody_fails_closed(env: Env, case: str) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:a14")
    _corrupt(env, run_id, case)
    env.cursor(run_id).unlink()
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "stop", "cancel:a14-new")
    assert caught.value.code == "integrity_error"
    with pytest.raises(RunControlError) as inspected:
        control.inspect_stop(run_id)
    assert inspected.value.code == "integrity_error"
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ((run_id, "stop_custody_invalid"),)
    assert env.snapshot() == before
    assert env.fake.signals == ONE_TERM


@pytest.mark.parametrize(
    ("state", "details"),
    [
        ("cancel_requested", {"cancel_idempotency_digest": "sha256:" + "0" * 64, "reason_digest": "sha256:" + "1" * 64, "stop_custody": True}),
        ("cancel_requested", {"cancel_idempotency_digest": "sha256:" + "0" * 64, "reason_digest": "sha256:" + "1" * 64, "stop_custody": 2}),
        ("cancel_requested", {"cancel_idempotency_digest": "sha256:" + "0" * 64, "reason_digest": "sha256:" + "1" * 64, "extra": 1}),
        ("draining", {"stop_actor": "robot"}),
        ("draining", {"stop_actor": []}),
        ("draining", {"stop_actor": {}}),
    ],
)
def test_a14_invalid_stop_events_fail_closed(env: Env, state: str, details: dict[str, Any]) -> None:
    control, _, run_id = _running(env)
    control._append_event(run_id, state, details)
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "stop", "cancel:bad-event")
    assert caught.value.code == "integrity_error"
    with pytest.raises(RunControlError) as inspected:
        control.inspect_stop(run_id)
    assert inspected.value.code == "integrity_error"
    env.cursor(run_id).unlink()
    assert env.control(recover=True).recovery_blocked == ((run_id, "stop_custody_invalid"),)
    assert env.fake.signals == []


@pytest.mark.parametrize("details", [{"stop_settlement": "drained"}, {"stop_settlement": []}, {"stop_settlement": {}}, {"terminal_source": "guess"}, {"surprise": 1}])
def test_a14_invalid_terminal_details_fail_inspection(env: Env, details: dict[str, Any]) -> None:
    control = env.control()
    run_id = env.submit(control)
    control._append_event(
        run_id,
        "failed",
        {"receipt_digest": "sha256:" + "2" * 64, "receipt_id": "receipt:x", **details},
    )
    with pytest.raises(RunControlError) as caught:
        control.inspect_stop(run_id)
    assert caught.value.code == "integrity_error"
    assert control.cancel_run(run_id, "stop", "cancel:terminal").state == "failed"


def test_a14_stop_temporaries_are_ignored_not_removed(env: Env) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:tmp")
    leftover = env.binding_dir(run_id) / ".stop-tmp-abc_123"
    leftover.write_bytes(b"partial")
    control.cancel_run(run_id, "stop", "cancel:tmp-2")
    assert control.inspect_stop(run_id).delivery == "accepted"
    assert leftover.read_bytes() == b"partial"
    assert env.fake.signals == ONE_TERM


def test_a14_record_schemas_are_exact(env: Env) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:schema")
    binding = env.binding_dir(run_id)
    assert sorted(path.name for path in binding.iterdir()) == ["attempt.json", "delivered.json"]
    assert sorted(path.name for path in binding.parent.iterdir()) == [binding.name]
    attempt_bytes = (binding / "attempt.json").read_bytes()
    attempt = json.loads(attempt_bytes)
    running = [event for event in env.events(run_id) if event["state"] == "running"][0]
    marked = [event for event in env.events(run_id) if event["state"] == "cancel_requested"][0]
    assert attempt == {
        "binding": {
            "generation": 1,
            "owner_id": f"worker:{OWNER_PID}:1",
            "pgid": OWNER_PID,
            "pid": OWNER_PID,
            "running_event_digest": running["event_digest"],
        },
        "identity_strength": "pid_session_only",
        "kind": "stop_attempt",
        "recorded_at": attempt["recorded_at"],
        "request_event_digest": marked["event_digest"],
        "run_id": run_id,
        "schema_version": 1,
        "signal": "SIGTERM",
    }
    delivered = json.loads((binding / "delivered.json").read_bytes())
    assert delivered == {
        "attempt_digest": "sha256:" + hashlib.sha256(attempt_bytes).hexdigest(),
        "kind": "stop_delivery",
        "outcome": "accepted",
        "recorded_at": delivered["recorded_at"],
        "run_id": run_id,
        "schema_version": 1,
    }
    assert marked["details"]["stop_custody"] == 1
    assert b"body" not in attempt_bytes and b"body" not in (binding / "delivered.json").read_bytes()


@pytest.mark.parametrize("method", ["lstat", "read_bytes"])
def test_a19_persistent_record_access_failure_is_integrity_error(env: Env, method: str) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:a19")
    original = getattr(Path, method)

    def failing(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path.name == "attempt.json":
            raise PermissionError("injected")
        return original(path, *args, **kwargs)

    env.mp.setattr(Path, method, failing)
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "stop", "cancel:a19-new")
    assert caught.value.code == "integrity_error"
    assert env.fake.signals == ONE_TERM


# ---------------------------------------------------------------- A15 / A17 / A18


def test_a15_owner_terminal_paths_carry_their_class(env: Env) -> None:
    control, owner, failed_run = _running(env, "failed")
    control.cancel_run(failed_run, "stop", "cancel:failed")
    with env.as_pid():
        owner.worker_failed(failed_run)
    assert env.last(failed_run)["state"] == "attention"
    assert env.last(failed_run)["details"]["stop_settlement"] == "owner_failed"

    control, owner, effect_failure = _running(env, "effect-failure")
    env.fake.live.add(OWNER_PID)
    control.cancel_run(effect_failure, "stop", "cancel:effect-failure")
    with env.as_pid():
        owner.worker_effect_complete(effect_failure, FAILURE)
    assert env.last(effect_failure)["state"] == "failed"
    assert env.last(effect_failure)["details"]["stop_settlement"] == "owner_failed"
    assert (env.run_dir(effect_failure) / "private" / "tool-error.json").is_file()

    control, owner, completed = _running(env, "completed")
    control.cancel_run(completed, "stop", "cancel:completed")
    owner.worker_effect_complete(completed, RESULT)
    owner.worker_report_complete(completed)
    with env.as_pid():
        owner.worker_succeeded(completed)
    assert env.last(completed)["state"] == "succeeded"
    assert env.last(completed)["details"]["stop_settlement"] == "owner_completed"
    status = control.inspect_stop(completed)
    assert (status.settlement, status.replay_clearance, status.executor_result) == (
        "owner_completed", "unresolved", "recorded"
    )

    control, owner, effect_cancel = _running(env, "effect-cancel")
    owner.worker_effect_complete(effect_cancel, RESULT)
    control.cancel_run(effect_cancel, "stop", "cancel:effect-cancel")
    with env.as_pid():
        owner.worker_cancelled(effect_cancel)
    assert env.last(effect_cancel)["state"] == "attention"
    assert env.last(effect_cancel)["details"]["stop_settlement"] == "owner_reported"
    env.assert_unique_receipts()


def test_a15_stop_terminal_without_class_is_internal_error_without_receipt(env: Env) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:noclass")
    receipts = env.receipt_ids()
    with runs._exclusive_lock(control._run_lock(run_id)), pytest.raises(RunControlError) as caught:
        control._finalize_terminal_unlocked(run_id, "attention")
    assert caught.value.code == "internal_error"
    plain = env.submit(control, "plain")
    with runs._exclusive_lock(control._run_lock(plain)), pytest.raises(RunControlError) as stray:
        control._finalize_terminal_unlocked(plain, "failed", settlement="owner_failed")
    assert stray.value.code == "internal_error"
    assert env.receipt_ids() == receipts


def test_a15_every_terminal_writer_call_site_is_classified() -> None:
    tree = ast.parse(Path(runs.__file__).read_text(encoding="utf-8"))
    sites: list[tuple[str, bool]] = []
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_finalize_terminal_unlocked"
            ):
                sites.append(
                    (function.name, any(item.arg == "settlement" for item in node.keywords))
                )
    # The nine b307cc6 terminal call sites, plus recover's draining branch, now
    # separate from the running branch. Only _spawn (a queued run, never a stop
    # prefix) omits the class; _finalize rejects a missing class on a stop prefix.
    assert len(sites) == 10
    assert sorted(name for name, classified in sites if not classified) == ["_spawn"]


def test_a17_unrequested_owner_cancel_and_late_request(env: Env) -> None:
    control, owner, run_id = _running(env)
    with env.as_pid():
        owner.worker_draining(run_id)
    assert control.cancel_run(run_id, "stop", "cancel:late").state == "draining"
    assert env.fake.signals == []
    assert "cancel_requested" not in env.states(run_id)
    with env.as_pid():
        owner.worker_cancelled(run_id)
    assert env.last(run_id)["details"]["stop_settlement"] == "unrequested_owner_cancel"
    status = control.inspect_stop(run_id)
    assert (status.request, status.settlement, status.replay_clearance) == (
        "late_not_recorded", "unrequested_owner_cancel", "unresolved"
    )


def test_a18_executor_result_and_product_effect_fields(env: Env) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:g9")
    with env.as_pid():
        owner.worker_draining(run_id)
        owner.worker_cancelled(run_id)
    status = control.inspect_stop(run_id)
    assert (status.executor_result, status.product_effect) == ("none", "unknown")
    control, owner, effect = _running(env, "effect")
    owner.worker_effect_complete(effect, RESULT)
    status = control.inspect_stop(effect)
    assert (status.executor_result, status.product_effect, status.settlement) == (
        "recorded", "unknown", "not_applicable"
    )
    assert (status.request, status.delivery, status.terminal_source) == ("none", "not_applicable", None)


# ---------------------------------------------------------------- A20 draining guard


def test_a20_request_at_owner_draining_is_not_recorded_or_signalled(env: Env) -> None:
    control, owner, run_id = _running(env)
    with env.as_pid():
        owner.worker_draining(run_id)
    before = env.snapshot()
    for key in ("cancel:a20", "cancel:a20-2"):
        assert control.cancel_run(run_id, "stop", key).state == "draining"
    assert env.snapshot() == before
    assert env.fake.signals == []
    with env.as_pid():
        owner.worker_cancelled(run_id)
    status = control.inspect_stop(run_id)
    assert (status.request, status.settlement) == ("late_not_recorded", "unrequested_owner_cancel")


# ---------------------------------------------------------------- A22 two controllers


def test_a22_two_controllers_two_keys_one_attempt(env: Env) -> None:
    first, _, run_id = _running(env)
    second = env.control(owner_id="server:second")
    original = RunControl._publish_stop_record_unlocked
    fired = {"done": False}

    def crash_after_attempt(self: RunControl, run: str, token: str, name: str, content: bytes) -> bool:
        created = original(self, run, token, name, content)
        if name == "attempt.json" and not fired["done"]:
            fired["done"] = True
            raise Crash("after attempt publication")
        return created

    env.mp.setattr(RunControl, "_publish_stop_record_unlocked", crash_after_attempt)
    with pytest.raises(Crash):
        first.cancel_run(run_id, "stop", "cancel:first")
    assert second.cancel_run(run_id, "stop", "cancel:second").state == "cancel_requested"
    assert first.cancel_run(run_id, "stop", "cancel:first").state == "cancel_requested"
    assert env.fake.signals == []
    assert len(list(env.binding_dir(run_id).glob("attempt.json"))) == 1

    third, _, other = _running(env, "b")
    fourth = env.control(owner_id="server:fourth")
    third.cancel_run(other, "stop", "cancel:third")
    fourth.cancel_run(other, "stop", "cancel:fourth")
    assert env.fake.signals == ONE_TERM


def _run_lock_is_held(control: RunControl, run_id: str) -> bool:
    """Probe the actual per-run lock from a fresh open file description."""
    path = control._run_lock(run_id)
    assert path.is_file()
    with path.open("a+b") as probe:
        try:
            fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
        return False


@pytest.mark.parametrize("signaller", ["first", "second"])
def test_a22_attempt_publication_and_signal_happen_under_the_run_lock(
    env: Env, signaller: str
) -> None:
    """Deterministic §5 check without threads: the run lock is held at every
    signalling step, so a second controller cannot interleave check and kill."""
    first, _, run_id = _running(env)
    second = env.control(owner_id="server:second")
    if signaller == "second":
        # The first controller crashes after recording the request, before any attempt.
        _crash_after_append(env, "cancel_requested")
        with pytest.raises(Crash):
            first.cancel_run(run_id, "stop", "cancel:first")
        env.mp.setattr(RunControl, "_append_event_unlocked", _ORIGINAL_APPEND)
        assert not (env.run_dir(run_id) / "stop").exists()
    assert not _run_lock_is_held(first, run_id)
    held: list[tuple[str, bool]] = []
    original = RunControl._publish_stop_record_unlocked

    def probing(self: RunControl, run: str, token: str, name: str, content: bytes) -> bool:
        held.append((f"before:{name}", _run_lock_is_held(first, run)))
        created = original(self, run, token, name, content)
        held.append((f"after:{name}", _run_lock_is_held(first, run)))
        return created

    env.mp.setattr(RunControl, "_publish_stop_record_unlocked", probing)
    env.fake.on_term = lambda pid: held.append(("kill", _run_lock_is_held(first, run_id)))
    actor = first if signaller == "first" else second
    assert actor.cancel_run(run_id, "stop", f"cancel:{signaller}").state == "cancel_requested"
    assert held == [
        ("before:attempt.json", True),
        ("after:attempt.json", True),
        ("kill", True),
        ("before:delivered.json", True),
        ("after:delivered.json", True),
    ]
    assert env.fake.signals == ONE_TERM
    # The probe is not vacuous: once the call returns the lock is free again.
    assert not _run_lock_is_held(second, run_id)


# ---------------------------------------------------------------- R1 OI-1


def test_r1_owner_draining_crash_before_receipt_recovers_attention(env: Env) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:r1")
    with env.as_pid():
        owner.worker_draining(run_id)
    env.cursor(run_id).unlink()
    env.fake.live.discard(OWNER_PID)
    env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == "attention"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    env.assert_unique_receipts()


def test_r1_owner_draining_crash_after_receipt_adopts_owner_outcome(env: Env) -> None:
    control, owner, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:r1b")
    with env.as_pid():
        owner.worker_draining(run_id)
    _crash_append(env, "cancelled")
    with env.as_pid(), pytest.raises(Crash):
        owner.worker_cancelled(run_id)
    pending = list(env.receipt_ids())
    env.cursor(run_id).unlink()
    env.fake.live.discard(OWNER_PID)
    env.control(owner_id="server:recover", recover=True)
    last = env.last(run_id)
    assert last["state"] == "cancelled"
    assert last["details"]["terminal_source"] == "pending_receipt"
    assert last["details"]["stop_settlement"] == "owner_unproven"
    assert list(env.receipt_ids()) == pending
    env.assert_unique_receipts()


# ---------------------------------------------------------------- R2 OI-2


def _controller_crash_after_receipt(env: Env, control: RunControl, run_id: str, key: str) -> None:
    _crash_append(env, "cancelled")
    with pytest.raises(Crash):
        control.cancel_run(run_id, "stop", key)
    assert env.last(run_id)["details"] == {"stop_actor": "controller"}
    env.mp.setattr(RunControl, "_append_event_unlocked", _ORIGINAL_APPEND)


_ORIGINAL_APPEND = RunControl._append_event_unlocked


def test_r2a_live_owner_success_supersedes_controller_pending_receipt(env: Env) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1  # owner proof false although live
    _controller_crash_after_receipt(env, control, run_id, "cancel:r2a")
    stale = set(env.receipt_ids())
    owner.worker_effect_complete(run_id, RESULT)
    owner.worker_report_complete(run_id)
    with env.as_pid():
        owner.worker_succeeded(run_id)
    last = env.last(run_id)
    assert last["state"] == "succeeded"
    assert last["details"]["stop_settlement"] == "owner_completed"
    assert "terminal_source" not in last["details"]
    assert (env.run_dir(run_id) / "result.json").is_file()
    assert last["details"]["receipt_id"] not in stale
    env.assert_unique_receipts()


def test_r2b_failure_branch_keeps_tool_error_and_adopts(env: Env) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    _controller_crash_after_receipt(env, control, run_id, "cancel:r2b")
    pending = list(env.receipt_ids())
    with env.as_pid():
        owner.worker_effect_complete(run_id, FAILURE)
    assert (env.run_dir(run_id) / "private" / "tool-error.json").is_file()
    last = env.last(run_id)
    assert last["state"] == "cancelled"
    assert last["details"]["terminal_source"] == "pending_receipt"
    assert list(env.receipt_ids()) == pending


@pytest.mark.parametrize("writer", ["worker_failed", "worker_cancelled"])
def test_r2c_owner_terminal_on_unchanged_prefix_adopts(env: Env, writer: str) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    _controller_crash_after_receipt(env, control, run_id, "cancel:r2c")
    pending = list(env.receipt_ids())
    with env.as_pid():
        getattr(owner, writer)(run_id)
    assert env.last(run_id)["details"]["terminal_source"] == "pending_receipt"
    assert list(env.receipt_ids()) == pending


def test_r2d_controller_crash_before_receipt_then_owner_completes(env: Env) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    original = FoundationStore.append_receipt
    fired = {"done": False}

    def crashing(self: FoundationStore, *args: Any, **kwargs: Any) -> Any:
        if not fired["done"]:
            fired["done"] = True
            raise Crash("before receipt")
        return original(self, *args, **kwargs)

    env.mp.setattr(FoundationStore, "append_receipt", crashing)
    with pytest.raises(Crash):
        control.cancel_run(run_id, "stop", "cancel:r2d")
    owner.worker_effect_complete(run_id, RESULT)
    owner.worker_report_complete(run_id)
    with env.as_pid():
        owner.worker_succeeded(run_id)
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_completed"
    env.assert_unique_receipts()


def test_r2e_repeated_cancel_adopts_then_late_effect_is_terminal_noop(env: Env) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    _controller_crash_after_receipt(env, control, run_id, "cancel:r2e")
    assert control.cancel_run(run_id, "stop", "cancel:r2e-again").state == "cancelled"
    assert env.last(run_id)["details"]["terminal_source"] == "pending_receipt"
    owner.worker_effect_complete(run_id, RESULT)
    assert not (env.run_dir(run_id) / "result.json").exists()
    assert env.fake.signals == []


def test_r2e_owner_effect_before_repeat_is_not_adopted(env: Env) -> None:
    control, owner, run_id = _running(env)
    env.fake.sessions[OWNER_PID] = OWNER_PID + 1
    _controller_crash_after_receipt(env, control, run_id, "cancel:r2e2")
    owner.worker_effect_complete(run_id, RESULT)
    env.fake.sessions[OWNER_PID] = OWNER_PID  # owner proof true again
    assert control.cancel_run(run_id, "stop", "cancel:r2e2-again").state == "effect_complete"
    assert "terminal_source" not in env.last(run_id)["details"]
    assert env.fake.signals == ONE_TERM
    owner.worker_report_complete(run_id)
    with env.as_pid():
        owner.worker_succeeded(run_id)
    assert env.last(run_id)["details"]["stop_settlement"] == "owner_completed"
    env.assert_unique_receipts()


# ---------------------------------------------------------------- R3 / R4 non-stop


def test_r3_pending_partial_at_effect_complete_is_adopted_by_recover(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    receipt = env.plant_receipt(control, run_id, "partial")
    env.cursor(run_id).unlink()
    env.control(owner_id="server:recover", recover=True)
    assert env.states(run_id)[-2:] == ["effect_complete", "attention"]
    last = env.last(run_id)
    assert last["details"]["receipt_digest"] == receipt.digest
    assert last["details"]["error"] == runs._PENDING_RECEIPT_ERROR
    assert "stop_settlement" not in last["details"]


def test_r3_pending_failed_at_queued_is_adopted_without_spawn(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    env.plant_receipt(control, run_id, "failed")
    env.spawned.clear()
    env.control(owner_id="server:recover", recover=True)
    assert env.spawned == []
    assert env.states(run_id) == ["queued", "failed"]
    assert env.last(run_id)["details"]["terminal_source"] == "pending_receipt"


def test_r3_pending_succeeded_at_report_complete_is_adopted_by_cancel(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    owner.worker_report_complete(run_id)
    env.plant_receipt(control, run_id, "succeeded")
    assert control.cancel_run(run_id, "stop", "cancel:r3").state == "succeeded"
    assert "cancel_requested" not in env.states(run_id)
    assert "error" not in env.last(run_id)["details"]
    assert env.fake.signals == []


def test_r4_receipt_without_custody_is_repaired_on_adoption(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    receipt = control._construct_run_receipt(control._load_request(run_id), "failed")
    path = control.foundation.receipt_root / "run_receipt.v1" / (
        receipt.digest.removeprefix("sha256:") + ".json"
    )
    control.foundation._append_exact(path, receipt.canonical_bytes)
    assert not control.foundation.has_local_custody(receipt.digest)
    env.control(owner_id="server:recover", recover=True)
    assert control.foundation.has_local_custody(receipt.digest)
    assert control.foundation.verify_custody_chain()
    assert env.last(run_id)["details"]["receipt_digest"] == receipt.digest


# ---------------------------------------------------------------- R5 (G14)


def test_r5_invalid_transition_publishes_no_receipt(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    owner.worker_report_complete(run_id)
    control.cancel_run(run_id, "stop", "cancel:g14")
    assert env.states(run_id)[-1] == "cancel_requested"
    with env.as_pid(), pytest.raises(RunControlError) as caught:
        owner.worker_succeeded(run_id)
    assert caught.value.code == "invalid_transition"
    assert sum(env.receipt_ids().values()) == 0
    with env.as_pid():
        owner.worker_failed(run_id)
    receipts = env.receipt_ids()
    assert sum(receipts.values()) == 1
    env.assert_unique_receipts()
    directory = env.root / ".unrest/foundation/receipts/run_receipt.v1"
    assert [json.loads(path.read_bytes())["outcome"] for path in directory.glob("*.json")] == ["partial"]


# ---------------------------------------------------------------- R6 conflicts


@pytest.mark.parametrize("conflict", ["two_candidates", "verify_failure", "not_regular", "lstat_error"])
def test_r6_pending_receipt_conflict_is_isolated(env: Env, conflict: str) -> None:
    control, _, run_x = _running(env, "x")
    env.cursor(run_x).unlink()
    if conflict == "two_candidates":
        env.plant_receipt(control, run_x, "failed")
        env.plant_receipt(control, run_x, "partial")
    else:
        receipt = control._construct_run_receipt(control._load_request(run_x), "partial")
        path = control.foundation.receipt_root / "run_receipt.v1" / (
            receipt.digest.removeprefix("sha256:") + ".json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        if conflict == "verify_failure":
            path.write_bytes(receipt.canonical_bytes.replace(b"partial", b"failed!", 1))
        elif conflict == "not_regular":
            path.mkdir()
        else:
            original_lstat = Path.lstat

            def failing(candidate: Path, *args: Any, **kwargs: Any) -> Any:
                if candidate.name == path.name:
                    raise PermissionError("injected")
                return original_lstat(candidate, *args, **kwargs)

            env.mp.setattr(Path, "lstat", failing)
    run_y = env.submit(control, "y")
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_x, "stop", "cancel:r6")
    assert caught.value.code == "integrity_error"
    assert env.snapshot() == before
    assert control.inspect_stop(run_x).pending_terminal == "conflict"
    env.spawned.clear()
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ((run_x, "pending_receipt_conflict"),)
    assert env.spawned == [run_y]
    assert env.states(run_x)[-1] == "running"
    assert env.fake.signals == []


# ---------------------------------------------------------------- mixed version


def test_mixed_version_worker_terminal_on_marked_prefix_is_reported_not_guessed(env: Env) -> None:
    control, _, run_id = _running(env)
    control.cancel_run(run_id, "stop", "cancel:mixed")
    # An old worker ignores STOP-A1 and writes an unclassified terminal.
    control._append_event(run_id, "draining", {})
    control._append_event(
        run_id,
        "cancelled",
        {"receipt_digest": "sha256:" + "2" * 64, "receipt_id": "receipt:run_receipt.v1:old:1"},
    )
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        control.inspect_stop(run_id)
    assert caught.value.code == "integrity_error"
    assert control.cancel_run(run_id, "stop", "cancel:mixed-2").state == "cancelled"
    restarted = env.control(owner_id="server:recover", recover=True)
    assert restarted.recovery_blocked == ()
    assert env.snapshot() == before
    assert env.fake.signals == ONE_TERM


def test_s2_owner_cancel_after_effect_without_stop_prefix(env: Env) -> None:
    control, owner, run_id = _running(env)
    owner.worker_effect_complete(run_id, RESULT)
    with env.as_pid():
        owner.worker_cancelled(run_id)
    assert control.inspect_run(run_id).state == "attention"
    assert "stop_settlement" not in env.last(run_id)["details"]
    assert env.fake.signals == []


@pytest.mark.parametrize("close_number", [1, 2])
def test_s3_stop_descriptor_close_error_is_contained(env: Env, close_number: int) -> None:
    control, _, run_id = _running(env)
    real_close = runs.os.close
    calls = 0

    def failing_close(fd: int) -> None:
        nonlocal calls
        in_stop_publish = sys._getframe(1).f_code.co_name == "_publish_stop_record_unlocked"
        real_close(fd)
        if not in_stop_publish:
            return
        calls += 1
        if calls == close_number:
            raise OSError("injected close error")

    with env.mp.context() as patch:
        patch.setattr(runs.os, "close", failing_close)
        if close_number == 1:
            with pytest.raises(RunControlError) as caught:
                control.cancel_run(run_id, "stop", "cancel:close")
            assert caught.value.code == "internal_error"
            assert env.fake.signals == []
        else:
            assert control.cancel_run(run_id, "stop", "cancel:close").state == "cancel_requested"
    expected_delivery = "ambiguous" if close_number == 2 else "accepted"
    if close_number == 2:
        assert control.inspect_stop(run_id).delivery == expected_delivery
    control.cancel_run(run_id, "stop", "cancel:close-retry")
    assert control.inspect_stop(run_id).delivery == expected_delivery
    assert env.fake.signals == ONE_TERM
