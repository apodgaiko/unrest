"""ADM-R (ADR-0502): admission commit fact, scoped isolation and partial recovery.

Every case is in-process and hermetic. ``RunControl._spawn`` records an intent;
``subprocess.Popen``, fork/exec/spawn primitives and every real signal raise and
are recorded, so an unexpected launch fails the case even when it is caught.
Storage faults are injected with ``monkeypatch`` only. Fixture trees are built
with the unchanged baseline writers, and run tokens are recomputed here
independently of the product fingerprint helper.
"""
from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any

import pytest

import unrest_harness.run_control as runs
from unrest_harness import foundation_tools
from unrest_harness.canonical_identity import FoundationValidationError
from unrest_harness.foundation_store import FoundationStore
from unrest_harness.foundation_tools import public_error
from unrest_harness.run_control import RunControl, RunControlError


EXECUTOR = "json:dumps"
OWNER_PID = 5151
CANARY = "CANARY-adm-7f3a"
RESULT = {
    "dag": None,
    "harnessRoot": "/nonexistent/.unrest",
    "projectId": "adm-project",
    "projectRoot": "/nonexistent",
    "state": {"state": "done"},
}
NEW_CODES = {
    "admission_incomplete": "integrity_error",
    "admission_key_conflict": "conflict",
    "admission_resource_blocked": "conflict",
    "admission_io_not_committed": "internal_error",
    "admission_io_unknown": "internal_error",
    "admission_committed_io_error": "internal_error",
}
MARKED_CANCEL = {
    "cancel_idempotency_digest": "sha256:" + "0" * 64,
    "reason_digest": "sha256:" + "1" * 64,
    "stop_custody": 1,
}


class Crash(BaseException):
    """Simulated process crash at an injected cut (not an Exception)."""


class ForbiddenEffect(AssertionError):
    """A real process or signal primitive was reached."""


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def token_for(operation: str, arguments: dict[str, Any], key: Any) -> str:
    body = {"arguments": arguments, "idempotency_key": key, "operation": operation, "schema_version": 1}
    return hashlib.sha256(canonical(body)).hexdigest()


def args(project: str, steps: int = 1) -> dict[str, Any]:
    return {"project_id": project, "max_steps": steps}


def run_id_for(project: str, key: str, steps: int = 1) -> str:
    return "run:" + token_for("advance_project", args(project, steps), key)


def index_bytes(key: str, run_id: str) -> bytes:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return canonical({"key_digest": "sha256:" + digest, "run_id": run_id, "schema_version": 1})


@dataclass
class FakeProcesses:
    live: set[int] = field(default_factory=set)
    signals: list[tuple[int, int]] = field(default_factory=list)

    def kill(self, pid: int, sig: int) -> None:
        if sig == 0:
            if pid in self.live:
                return
            raise ProcessLookupError(pid)
        self.signals.append((pid, sig))
        raise ForbiddenEffect(f"signal {sig}")

    def getpgid(self, pid: int) -> int:
        if pid in self.live:
            return pid
        raise ProcessLookupError(pid)

    def getsid(self, pid: int) -> int:
        return self.getpgid(pid)


class Env:
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeProcesses) -> None:
        self.root = root
        self.mp = monkeypatch
        self.fake = fake
        self.spawned: list[str] = []
        self.forbidden: list[str] = []

    # ------------------------------------------------------------- controllers
    def control(self, owner_id: str = "server:adm", **kwargs: Any) -> RunControl:
        kwargs.setdefault("recover", False)
        return RunControl(self.root, executor_ref=EXECUTOR, owner_id=owner_id, **kwargs)

    def submit(self, control: RunControl, project: str, key: str | None = None, steps: int = 1) -> Any:
        return control.submit_run("advance_project", args(project, steps), key or f"idem:{project}")

    # ------------------------------------------------------------------- paths
    @property
    def durable(self) -> Path:
        return self.root / ".unrest" / "runs"

    @property
    def runtime(self) -> Path:
        return self.root / ".unrest-runtime" / "runs"

    def run_dir(self, run_id: str) -> Path:
        return self.durable / run_id.removeprefix("run:")

    def index_path(self, key: str) -> Path:
        return self.durable / "idempotency" / (hashlib.sha256(key.encode()).hexdigest() + ".json")

    def cursor(self, run_id: str) -> Path:
        return self.runtime / (hashlib.sha256(run_id.encode()).hexdigest() + ".worker.json")

    def run_lock(self, run_id: str) -> Path:
        return self.runtime / (hashlib.sha256(run_id.encode()).hexdigest() + ".lock")

    def events(self, run_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(path.read_bytes())
            for path in sorted((self.run_dir(run_id) / "events").glob("*.json"))
        ]

    def states(self, run_id: str) -> list[str]:
        return [event["state"] for event in self.events(run_id)]

    def request(self, run_id: str) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads((self.run_dir(run_id) / "request.json").read_bytes())
        return loaded

    def request_count(self) -> int:
        return len(list(self.durable.glob("*/request.json")))

    def journal_files(self) -> list[Path]:
        return sorted((self.root / ".unrest" / "foundation" / "public-mutations").glob("*"))

    def snapshot(self) -> dict[str, bytes]:
        """Every entry below .unrest and .unrest-runtime except admission/run lock files."""
        result: dict[str, bytes] = {}
        for base in (self.root / ".unrest", self.root / ".unrest-runtime"):
            for path in sorted(base.rglob("*")):
                relative = str(path.relative_to(self.root))
                if path.parent == self.runtime and path.name.endswith(".lock"):
                    continue
                if path.is_symlink():
                    result[relative] = b"<link>" + os.readlink(path).encode()
                elif path.is_dir():
                    result[relative] = b"<dir>"
                else:
                    result[relative] = path.read_bytes()
        return result

    # ---------------------------------------------------------------- fixtures
    def plant(
        self,
        control: RunControl,
        project: str,
        key: str,
        *,
        steps: int = 1,
        queued: bool = True,
        index: bool = True,
    ) -> str:
        """Write a run with the unchanged baseline writers (no admission checks)."""
        arguments = args(project, steps)
        token = token_for("advance_project", arguments, key)
        run_id = "run:" + token
        resource_key, project_id = runs._resource_for("advance_project", arguments)
        identities = control._construct_identities(run_id, "advance_project", key, "sha256:" + token)
        for identity in identities:
            control.foundation.append_identity(identity)
        issuer, run_identity, control_identity = identities
        control._append_request(
            runs._Request(
                run_id=run_id,
                operation="advance_project",
                arguments=dict(arguments),
                idempotency_key=key,
                resource_key=resource_key,
                project_id=project_id,
                created_at=runs._utc_now(),
                run_identity_digest=run_identity.digest,
                control_identity_digest=control_identity.digest,
                issuer_identity_digest=issuer.digest,
                generation=1,
            )
        )
        if queued:
            control._append_event(run_id, "queued", {"owner_id": control.owner_id})
        if index:
            control._append_idempotency(key, run_id)
        return run_id

    def start(self, run_id: str) -> RunControl:
        owner = self.control(owner_id=f"worker:{OWNER_PID}:1")
        self.fake.live.add(OWNER_PID)
        assert owner.worker_start(run_id, pid=OWNER_PID, pgid=OWNER_PID, generation=1)
        return owner

    def effect_complete(self, run_id: str, *, keep_cursor: bool = False) -> None:
        owner = self.start(run_id)
        owner.worker_effect_complete(run_id, RESULT)
        if not keep_cursor:
            self.cursor(run_id).unlink()

    def write_event(self, run_id: str, state: str, sequence: int, previous: str | None) -> str:
        body = {
            "details": {},
            "observed_at": "2026-11-03T00:00:00.000Z",
            "previous_event_digest": previous,
            "run_id": run_id,
            "schema_version": 1,
            "sequence": sequence,
            "state": state,
        }
        digest = "sha256:" + hashlib.sha256(b"unrest.run-event.v1\0" + canonical(body)).hexdigest()
        path = self.run_dir(run_id) / "events" / f"{sequence:020d}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical({**body, "event_digest": digest}))
        return digest


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    fake = FakeProcesses()
    environment = Env(tmp_path, monkeypatch, fake)

    def forbidden(name: str) -> Callable[..., Any]:
        def call(*_args: Any, **_kwargs: Any) -> Any:
            environment.forbidden.append(name)
            raise ForbiddenEffect(name)

        return call

    monkeypatch.setattr(runs.subprocess, "Popen", forbidden("subprocess.Popen"))
    for name in (
        "fork", "forkpty", "posix_spawn", "posix_spawnp", "system", "killpg",
        "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
    ):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden(f"os.{name}"))
    monkeypatch.setattr(os, "kill", fake.kill)
    monkeypatch.setattr(os, "getpgid", fake.getpgid)
    monkeypatch.setattr(os, "getsid", fake.getsid)
    monkeypatch.setattr(
        RunControl, "_spawn", lambda self, request: environment.spawned.append(request.run_id)
    )
    yield environment
    assert environment.forbidden == []
    assert fake.signals == []


def _once(predicate: Callable[..., bool], error: BaseException) -> Callable[..., None]:
    fired = {"done": False}

    def check(*call_args: Any) -> None:
        if not fired["done"] and predicate(*call_args):
            fired["done"] = True
            raise error

    return check


def _assert_code(caught: pytest.ExceptionInfo[RunControlError], code: str) -> None:
    assert caught.value.code == code, (caught.value.code, caught.value.public_message)


def _sorted_runs(*run_ids: str) -> list[str]:
    return sorted(run_ids)


def _project_sorting(key: str, relation: Callable[[str], bool], prefix: str = "q") -> str:
    """Deterministically pick a project whose run_id satisfies ``relation``."""
    for number in range(500):
        project = f"{prefix}{number}"
        if relation(run_id_for(project, key)):
            return project
    raise AssertionError("no project satisfies the ordering")


# =================================================================== VAL-ADM-01


def _cut_patch(env: Env, cut: str, patch: pytest.MonkeyPatch) -> None:
    if cut == "C1p":
        original_identity = FoundationStore.append_identity
        check = _once(lambda *_: True, Crash("C1p"))

        def identity(self: FoundationStore, record: Any) -> Any:
            check()
            return original_identity(self, record)

        patch.setattr(FoundationStore, "append_identity", identity)
    elif cut == "C1":
        def request(self: RunControl, *_: Any) -> None:
            raise Crash("C1")

        patch.setattr(RunControl, "_append_request", request)
    elif cut == "C2":
        original_event = RunControl._append_event

        def event(self: RunControl, run_id: str, state: str, details: Any) -> Any:
            if state == "queued":
                raise Crash("C2")
            return original_event(self, run_id, state, details)

        patch.setattr(RunControl, "_append_event", event)
    elif cut == "C3":
        def index(self: RunControl, *_: Any) -> None:
            raise Crash("C3")

        patch.setattr(RunControl, "_append_idempotency", index)
    elif cut == "C4":
        def spawn(self: RunControl, request: Any) -> None:
            raise Crash("C4")

        patch.setattr(RunControl, "_spawn", spawn)


@pytest.mark.parametrize("cut", ["C1p", "C1", "C2", "C3", "C4", "C5"])
def test_val01_commit_authority_by_cut(env: Env, cut: str) -> None:
    control = env.control()
    run_id = run_id_for("pa", "idem:pa")
    if cut == "C5":
        env.submit(control, "pa")
        env.spawned.clear()
    else:
        with pytest.MonkeyPatch.context() as patch:
            _cut_patch(env, cut, patch)
            with pytest.raises(Crash):
                env.submit(control, "pa")
    assert env.spawned == []
    # inspect
    if cut in {"C1p", "C1"}:
        with pytest.raises(RunControlError) as missing:
            control.inspect_run(run_id)
        _assert_code(missing, "not_found")
    elif cut == "C2":
        with pytest.raises(RunControlError) as incomplete:
            control.inspect_run(run_id)
        _assert_code(incomplete, "admission_incomplete")
    else:
        assert control.inspect_run(run_id).state == "queued"
    # exact retry
    before = env.snapshot()
    if cut in {"C1p", "C1"}:
        assert env.submit(control, "pa").run_id == run_id
        assert env.spawned == [run_id]
        env.spawned.clear()
    elif cut == "C2":
        with pytest.raises(RunControlError) as held:
            env.submit(control, "pa")
        _assert_code(held, "admission_incomplete")
        assert env.snapshot() == before
    else:
        receipt = env.submit(control, "pa")
        assert (receipt.run_id, receipt.state) == (run_id, "queued")
        assert receipt.created_at == env.request(run_id)["created_at"]
        assert env.snapshot() == before
        assert env.spawned == []
    # recover
    restarted = env.control(recover=True)
    if cut == "C2":
        assert restarted.recovery_blocked == ((run_id, "admission_incomplete"),)
        assert env.spawned == []
        assert env.states(run_id) == []
    else:
        assert restarted.recovery_blocked == ()
        assert env.spawned == [run_id]
        assert env.index_path("idem:pa").read_bytes() == index_bytes("idem:pa", run_id)


def test_val01_deleting_only_the_index_does_not_revoke_the_binding(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control, "pa").run_id
    env.index_path("idem:pa").unlink()
    before = env.snapshot()
    with pytest.raises(RunControlError) as rebind:
        env.submit(control, "pb", key="idem:pa")
    _assert_code(rebind, "conflict")
    assert env.submit(control, "pa").run_id == run_id
    assert env.snapshot() == before
    assert env.request_count() == 1


# =================================================================== VAL-ADM-02


@pytest.mark.parametrize("mode", ["crash", "enospc_queued_link", "enospc_request_postlink"])
def test_val02_incomplete_admission_is_isolated(env: Env, mode: str) -> None:
    control = env.control()
    torn = run_id_for("pa", "idem:pa")
    with pytest.MonkeyPatch.context() as patch:
        if mode == "crash":
            original_event = RunControl._append_event

            def event(self: RunControl, run_id: str, state: str, details: Any) -> Any:
                if state == "queued":
                    raise Crash("C2")
                return original_event(self, run_id, state, details)

            patch.setattr(RunControl, "_append_event", event)
            with pytest.raises(Crash):
                env.submit(control, "pa")
        elif mode == "enospc_queued_link":
            original_link = os.link
            check = _once(
                lambda source, target: Path(target).parent.name == "events",
                OSError(errno.ENOSPC, "No space left on device"),
            )

            def link(source: Any, target: Any, *a: Any, **k: Any) -> None:
                check(source, target)
                original_link(source, target, *a, **k)

            patch.setattr(runs.os, "link", link)
            with pytest.raises(RunControlError) as unknown:
                env.submit(control, "pa")
            _assert_code(unknown, "admission_io_unknown")
        else:
            original_fsync = runs._fsync_directory
            check = _once(
                lambda path: path == env.run_dir(torn),
                OSError(errno.ENOSPC, "No space left on device"),
            )

            def fsync_directory(path: Path) -> None:
                check(path)
                original_fsync(path)

            patch.setattr(runs, "_fsync_directory", fsync_directory)
            with pytest.raises(RunControlError) as not_committed:
                env.submit(control, "pa")
            _assert_code(not_committed, "admission_io_not_committed")
    assert (env.run_dir(torn) / "request.json").is_file()
    assert env.states(torn) == []
    torn_before = {
        str(path): path.read_bytes() for path in sorted(env.run_dir(torn).rglob("*")) if path.is_file()
    }
    # unrelated key and resource proceed in the same controller
    other = env.submit(control, "pb").run_id
    assert env.spawned == [other]
    # affected key and resource are held
    for call, code in (
        (lambda: env.submit(control, "pa"), "admission_incomplete"),
        (lambda: env.submit(control, "pa", steps=2), "conflict"),
        (lambda: env.submit(control, "pa", key="idem:new-key"), "admission_resource_blocked"),
    ):
        before = env.snapshot()
        with pytest.raises(RunControlError) as held:
            call()
        _assert_code(held, code)
        assert env.snapshot() == before
    # reopen: no exception, scoped report, no launch of the torn claim
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == ((torn, "admission_incomplete"),)
    assert torn not in env.spawned
    assert env.states(torn) == []
    assert torn_before == {
        str(path): path.read_bytes() for path in sorted(env.run_dir(torn).rglob("*")) if path.is_file()
    }


def test_val02_persistent_enospc_gives_typed_codes_not_integrity_error(env: Env) -> None:
    control = env.control()

    def link(*_: Any, **__: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    env.mp.setattr(runs.os, "link", link)
    for project in ("pa", "pb"):
        with pytest.raises(RunControlError) as failed:
            env.submit(control, project)
        _assert_code(failed, "admission_io_not_committed")
    assert env.spawned == []


# =================================================================== VAL-ADM-03


def test_val03_incomplete_claim_does_not_change_recovery_order(env: Env) -> None:
    control = env.control()
    torn = env.plant(control, "torn", "idem:torn", queued=False, index=False)
    before_project = _project_sorting("idem:h1", lambda rid: rid < torn, "h")
    after_project = _project_sorting("idem:h2", lambda rid: rid > torn, "k")
    first = env.plant(control, before_project, "idem:h1")
    last = env.plant(control, after_project, "idem:h2")
    assert first < torn < last
    restarted = env.control(recover=True)
    assert sorted(env.spawned) == sorted([first, last])
    assert restarted.recovery_blocked == ((torn, "admission_incomplete"),)


@pytest.mark.parametrize("indexed", [True, False])
@pytest.mark.parametrize("position", ["before", "after"])
def test_val03_corruption_anywhere_blocks_before_any_action(
    env: Env, position: str, indexed: bool
) -> None:
    control = env.control()
    healthy = env.plant(control, "healthy", "idem:healthy")
    relation: Callable[[str], bool] = (
        (lambda rid: rid < healthy) if position == "before" else (lambda rid: rid > healthy)
    )
    corrupt_project = _project_sorting("idem:corrupt", relation, "c")
    corrupt = env.plant(control, corrupt_project, "idem:corrupt")
    event_path = sorted((env.run_dir(corrupt) / "events").glob("*.json"))[0]
    event_path.write_text('{"brief":"TOP-SECRET"}\n', encoding="utf-8")
    if not indexed:
        # Without an index record nothing but the stream itself reveals the defect.
        env.index_path("idem:corrupt").unlink()
    before = env.snapshot()
    with pytest.raises(RunControlError) as corrupted:
        env.control(recover=True)
    _assert_code(corrupted, "integrity_error")
    assert "TOP-SECRET" not in str(corrupted.value)
    assert env.spawned == []
    assert env.snapshot() == before


# =================================================================== VAL-ADM-04


def _committed_without_index(env: Env, control: RunControl, project: str = "pa") -> str:
    original_link = os.link

    def link(source: Any, target: Any, *a: Any, **k: Any) -> None:
        if Path(target).parent.name == "idempotency":
            raise OSError(errno.EIO, "I/O error")
        original_link(source, target, *a, **k)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runs.os, "link", link)
        with pytest.raises(RunControlError) as failed:
            env.submit(control, project)
    _assert_code(failed, "admission_committed_io_error")
    run_id = run_id_for(project, f"idem:{project}")
    assert env.states(run_id) == ["queued"]
    assert not env.index_path(f"idem:{project}").exists()
    return run_id


@pytest.mark.parametrize("state", ["queued", "running", "succeeded", "cancelled"])
def test_val04_c3_exact_retry_is_read_only_dedupe(env: Env, state: str) -> None:
    calls: list[str] = []

    def inspector(project_id: str) -> dict[str, Any]:
        calls.append(project_id)
        return {"active_attempts": []}

    control = env.control(project_inspector=inspector)
    run_id = _committed_without_index(env, control)
    assert env.spawned == []
    if state in {"running", "succeeded"}:
        owner = env.start(run_id)
        if state == "succeeded":
            owner.worker_effect_complete(run_id, RESULT)
            owner.worker_report_complete(run_id)
            owner.worker_succeeded(run_id)
    elif state == "cancelled":
        assert control.cancel_run(run_id, "stop", "cancel:c3").state == "cancelled"
    assert env.states(run_id)[-1] == state
    first_event = env.events(run_id)[0]
    calls.clear()
    for instance in (control, env.control(project_inspector=inspector)):
        before = env.snapshot()
        receipt = env.submit(instance, "pa")
        assert (receipt.run_id, receipt.state) == (run_id, "queued")
        assert receipt.created_at == env.request(run_id)["created_at"]
        assert receipt.updated_at == first_event["observed_at"]
        assert env.snapshot() == before
        assert not env.index_path("idem:pa").exists()
    assert calls == []
    assert env.spawned == []
    # after recover-only repair the same receipt is returned
    env.control(recover=True)
    assert env.index_path("idem:pa").read_bytes() == index_bytes("idem:pa", run_id)
    env.spawned.clear()
    assert env.submit(env.control(), "pa").created_at == env.request(run_id)["created_at"]
    assert env.spawned == []


# =================================================================== VAL-ADM-05


def test_val05_key_mismatch_precedes_busy(env: Env) -> None:
    control = env.control()
    env.submit(control, "pa")
    for project, steps in (("pa", 2), ("pb", 1)):
        before = env.snapshot()
        with pytest.raises(RunControlError) as conflict:
            env.submit(control, project, key="idem:pa", steps=steps)
        _assert_code(conflict, "conflict")
        assert env.snapshot() == before
    assert env.request_count() == 1
    with pytest.raises(RunControlError) as busy:
        env.submit(control, "pa", key="idem:other")
    _assert_code(busy, "busy")


# =================================================================== VAL-ADM-06


def _group(env: Env, control: RunControl, index: str) -> tuple[str, str]:
    first = env.plant(control, "ga", "idem:group", index=False)
    second = env.plant(control, "gb", "idem:group", index=False)
    low, high = sorted((first, second))
    if index != "none":
        control._append_idempotency("idem:group", low if index == "first" else high)
    return low, high


@pytest.mark.parametrize("index", ["first", "second", "none"])
def test_val06_duplicate_claims_quarantine_the_whole_key(env: Env, index: str) -> None:
    control = env.control()
    low, high = _group(env, control, index)
    index_before = env.index_path("idem:group").read_bytes() if index != "none" else None
    for call, code in (
        (lambda: env.submit(control, "ga", key="idem:group"), "admission_key_conflict"),
        (lambda: env.submit(control, "gb", key="idem:group"), "admission_key_conflict"),
        (lambda: env.submit(control, "gc", key="idem:group"), "admission_key_conflict"),
        (lambda: env.submit(control, "ga", key="idem:new-a"), "admission_resource_blocked"),
        (lambda: env.submit(control, "gb", key="idem:new-b"), "admission_resource_blocked"),
    ):
        before = env.snapshot()
        with pytest.raises(RunControlError) as refused:
            call()
        _assert_code(refused, code)
        assert env.snapshot() == before
    requests = {run_id: (env.run_dir(run_id) / "request.json").read_bytes() for run_id in (low, high)}
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == (
        (low, "admission_key_conflict"),
        (high, "admission_key_conflict"),
    )
    assert env.spawned == []
    assert env.states(low) == env.states(high) == ["queued"]
    if index_before is None:
        assert not env.index_path("idem:group").exists()
    else:
        assert env.index_path("idem:group").read_bytes() == index_before
    assert requests == {
        run_id: (env.run_dir(run_id) / "request.json").read_bytes() for run_id in (low, high)
    }


def test_val06_incomplete_and_committed_claim_quarantine(env: Env) -> None:
    control = env.control()
    committed = env.plant(control, "ga", "idem:group")
    torn = env.plant(control, "gb", "idem:group", queued=False, index=False)
    with pytest.raises(RunControlError) as refused:
        env.submit(control, "gb", key="idem:group")
    _assert_code(refused, "admission_key_conflict")
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == tuple(
        sorted([(committed, "admission_key_conflict"), (torn, "admission_key_conflict")])
    )
    assert env.spawned == []


@pytest.mark.parametrize("shape", ["all_terminal", "mixed"])
def test_val06_terminal_members_keep_resources_held(env: Env, shape: str) -> None:
    control = env.control()
    low, high = _group(env, control, "first")
    assert control.cancel_run(low, "stop", "cancel:low").state == "cancelled"
    if shape == "all_terminal":
        assert control.cancel_run(high, "stop", "cancel:high").state == "cancelled"
    for project in ("ga", "gb"):
        with pytest.raises(RunControlError) as held:
            env.submit(control, project, key=f"idem:new-{project}")
        _assert_code(held, "admission_resource_blocked")
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == (
        (low, "admission_key_conflict"),
        (high, "admission_key_conflict"),
    )
    assert env.spawned == []


def _drive_member(env: Env, control: RunControl, run_id: str, member_state: str) -> None:
    if member_state == "effect_complete":
        env.effect_complete(run_id)
    elif member_state == "report_complete":
        owner = env.start(run_id)
        owner.worker_effect_complete(run_id, RESULT)
        owner.worker_report_complete(run_id)
        env.cursor(run_id).unlink()
    elif member_state == "cancel_requested":
        control._append_event(run_id, "cancel_requested", dict(MARKED_CANCEL))
    elif member_state == "pending_receipt":
        env.start(run_id)
        env.cursor(run_id).unlink()
        receipt = control._construct_run_receipt(control._load_request(run_id), "failed")
        control.foundation.append_receipt(receipt, custodian=runs._run_custodian())
    else:  # live owner
        env.start(run_id)


def _new_entries(before: dict[str, bytes], after: dict[str, bytes]) -> dict[str, bytes]:
    for name, content in before.items():
        assert after[name] == content, name
    return {name: content for name, content in after.items() if name not in before}


def _entry_shape(entries: dict[str, bytes]) -> list[str]:
    return sorted(
        name.rsplit("/", 1)[0] + "/<receipt>" if "/foundation/receipts/" in name else name
        for name in entries
    )


@pytest.mark.parametrize(
    "member_state", ["effect_complete", "report_complete", "cancel_requested", "pending_receipt", "live"]
)
def test_val06_quarantine_preserves_stop_reconciliation(
    env: Env, tmp_path_factory: pytest.TempPathFactory, member_state: str
) -> None:
    control = env.control()
    member = env.plant(control, "ga", "idem:group")
    other = env.plant(control, "gb", "idem:group", index=False)
    _drive_member(env, control, member, member_state)
    # Oracle: the same tree without the second claim (no quarantine).
    single_root = tmp_path_factory.mktemp("single") / "root"
    shutil.copytree(env.root, single_root, symlinks=True)
    shutil.rmtree(single_root / ".unrest" / "runs" / other.removeprefix("run:"))
    oracle = Env(single_root, env.mp, env.fake)
    oracle_before = oracle.snapshot()
    oracle.control(recover=True)
    oracle_new = _new_entries(oracle_before, oracle.snapshot())
    env.spawned.clear()

    before = env.snapshot()
    restarted = env.control(recover=True)
    created = _new_entries(before, env.snapshot())
    assert restarted.recovery_blocked == tuple(
        sorted([(member, "admission_key_conflict"), (other, "admission_key_conflict")])
    )
    assert "recovery_halted" not in {code for _, code in restarted.recovery_blocked}
    assert env.spawned == []
    assert env.states(other) == ["queued"]
    assert env.states(member) == oracle.states(member)
    # Receipt names are content digests that bind finish time: compare shape.
    assert _entry_shape(created) == _entry_shape(oracle_new)
    if member_state == "live":
        assert created == {}
    else:
        assert created, "the permitted non-dispatch transition ran"


# =================================================================== VAL-ADM-07


def _two_unindexed(env: Env, control: RunControl) -> tuple[str, str]:
    first = env.plant(control, "ra", "idem:ra", index=False)
    second = env.plant(control, "rb", "idem:rb", index=False)
    return sorted((first, second))[0], sorted((first, second))[1]


def _key_of(env: Env, run_id: str) -> str:
    return str(env.request(run_id)["idempotency_key"])


def test_val07_recover_repairs_index_with_baseline_bytes(
    env: Env, tmp_path_factory: pytest.TempPathFactory
) -> None:
    control = env.control()
    run_id = env.plant(control, "ra", "idem:ra", index=False)
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == ()
    repaired = env.index_path("idem:ra").read_bytes()
    assert repaired == index_bytes("idem:ra", run_id)
    healthy = Env(tmp_path_factory.mktemp("healthy"), env.mp, env.fake)
    healthy.plant(healthy.control(), "ra", "idem:ra")
    assert healthy.index_path("idem:ra").read_bytes() == repaired
    assert env.states(run_id) == ["queued"]
    before = env.snapshot()
    env.control(recover=True)
    assert env.snapshot() == before


def test_val07_differing_index_is_corruption_without_overwrite(env: Env) -> None:
    control = env.control()
    run_id = env.plant(control, "ra", "idem:ra")
    path = env.index_path("idem:ra")
    path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    before = env.snapshot()
    with pytest.raises(RunControlError) as corrupted:
        env.control(recover=True)
    _assert_code(corrupted, "integrity_error")
    assert env.snapshot() == before
    assert env.spawned == []
    assert env.states(run_id) == ["queued"]


def _repair_fault(env: Env, patch: pytest.MonkeyPatch, point: str, target: str) -> None:
    def ours(path: Any) -> bool:
        return Path(path).parent.name == "idempotency" or Path(path).name == "idempotency"

    if point == "mkdir":
        original_mkdir = Path.mkdir
        check = _once(lambda path: path.name == "idempotency", OSError(errno.EACCES, "denied"))

        def mkdir(path: Path, *a: Any, **k: Any) -> None:
            check(path)
            original_mkdir(path, *a, **k)

        patch.setattr(Path, "mkdir", mkdir)
    elif point in {"mkstemp", "write"}:
        original_mkstemp = runs.tempfile.mkstemp
        fired = {"done": False}

        def mkstemp(*a: Any, **k: Any) -> Any:
            if not fired["done"] and Path(str(k.get("dir"))).name == "idempotency":
                fired["done"] = True
                if point == "mkstemp":
                    raise OSError(errno.ENOSPC, "No space left on device")
                descriptor, name = original_mkstemp(*a, **k)
                os.close(descriptor)
                return os.open(name, os.O_RDONLY), name
            return original_mkstemp(*a, **k)

        patch.setattr(runs.tempfile, "mkstemp", mkstemp)
    elif point == "link":
        original_link = os.link
        check = _once(lambda source, dest: ours(dest), OSError(errno.EIO, "I/O error"))

        def link(source: Any, dest: Any, *a: Any, **k: Any) -> None:
            check(source, dest)
            original_link(source, dest, *a, **k)

        patch.setattr(runs.os, "link", link)
    elif point == "dir_fsync":
        original_fsync = runs._fsync_directory
        check = _once(lambda path: path.name == "idempotency", OSError(errno.EIO, "I/O error"))

        def fsync_directory(path: Path) -> None:
            check(path)
            original_fsync(path)

        patch.setattr(runs, "_fsync_directory", fsync_directory)
    elif point == "temp_unlink":
        original_unlink = Path.unlink
        check = _once(
            lambda path: path.parent.name == "idempotency" and path.name.startswith(".run-"),
            OSError(errno.EIO, "I/O error"),
        )

        def unlink(path: Path, *a: Any, **k: Any) -> None:
            check(path)
            original_unlink(path, *a, **k)

        patch.setattr(Path, "unlink", unlink)
    elif point == "conflict":
        original_link = os.link
        fired = {"done": False}

        def link(source: Any, dest: Any, *a: Any, **k: Any) -> None:
            if not fired["done"] and ours(dest):
                fired["done"] = True
                Path(dest).write_bytes(b'{"foreign":true}\n')
                raise FileExistsError(errno.EEXIST, "exists")
            original_link(source, dest, *a, **k)

        patch.setattr(runs.os, "link", link)
    else:  # pragma: no cover - parameter guard
        raise AssertionError(point)


@pytest.mark.parametrize(
    "point", ["mkdir", "mkstemp", "write", "link", "dir_fsync", "temp_unlink", "conflict"]
)
def test_val07_repair_failure_halts_the_pass(env: Env, point: str) -> None:
    control = env.control()
    first, second = _two_unindexed(env, control)
    with pytest.MonkeyPatch.context() as patch:
        _repair_fault(env, patch, point, first)
        restarted = env.control(recover=True)
    expected = "admission_key_conflict" if point == "conflict" else "admission_committed_io_error"
    assert restarted.recovery_blocked == ((first, expected), (second, "recovery_halted"))
    assert env.spawned == []
    assert not env.index_path(_key_of(env, second)).exists()
    for run_id in (first, second):
        assert env.states(run_id) == ["queued"]
        assert len(list(env.durable.glob("*/request.json"))) == 2
    if point == "conflict":
        return
    # a later pass without the fault repairs and dispatches both
    again = env.control(recover=True)
    assert again.recovery_blocked == ()
    assert sorted(env.spawned) == [first, second]
    for run_id in (first, second):
        key = _key_of(env, run_id)
        assert env.index_path(key).read_bytes() == index_bytes(key, run_id)


# =================================================================== VAL-ADM-08


def test_val08_c4_retry_never_launches_and_c5_is_unchanged(env: Env) -> None:
    control = env.control()
    with pytest.MonkeyPatch.context() as patch:
        _cut_patch(env, "C4", patch)
        with pytest.raises(Crash):
            env.submit(control, "pa")
    run_id = run_id_for("pa", "idem:pa")
    for _ in range(2):
        assert env.submit(control, "pa").run_id == run_id
    assert env.spawned == []
    env.control(recover=True)
    assert env.spawned == [run_id]
    # C5: completed admission
    done = env.submit(control, "pb").run_id
    assert env.submit(control, "pb").run_id == done
    with pytest.raises(RunControlError) as conflict:
        env.submit(control, "pc", key="idem:pb")
    _assert_code(conflict, "conflict")
    assert control.cancel_run(done, "stop", "cancel:pb").state == "cancelled"
    receipt = env.submit(control, "pb")
    assert (receipt.run_id, receipt.state) == (done, "queued")


# =================================================================== VAL-ADM-09


def _stage_fault(env: Env, patch: pytest.MonkeyPatch, stage: str, run_id: str) -> None:
    canary_error = OSError(errno.ENOSPC, f"No space left: /secret/{CANARY}")
    if stage == "S-ID":
        def identity(self: FoundationStore, record: Any) -> Any:
            raise canary_error

        patch.setattr(FoundationStore, "append_identity", identity)
    elif stage in {"S-REQ-mkstemp", "S-Q-mkstemp"}:
        directory = "events" if stage == "S-Q-mkstemp" else run_id.removeprefix("run:")
        original_mkstemp = runs.tempfile.mkstemp

        def mkstemp(*a: Any, **k: Any) -> Any:
            if Path(str(k.get("dir"))).name == directory:
                raise canary_error
            return original_mkstemp(*a, **k)

        patch.setattr(runs.tempfile, "mkstemp", mkstemp)
    elif stage in {"S-Q-link", "S-IDX-link"}:
        directory = "events" if stage == "S-Q-link" else "idempotency"
        original_link = os.link

        def link(source: Any, dest: Any, *a: Any, **k: Any) -> None:
            if Path(dest).parent.name == directory:
                raise canary_error
            original_link(source, dest, *a, **k)

        patch.setattr(runs.os, "link", link)
    elif stage == "S-Q-dir-fsync":
        original_fsync = runs._fsync_directory

        def fsync_directory(path: Path) -> None:
            if path.name == "events":
                raise canary_error
            original_fsync(path)

        patch.setattr(runs, "_fsync_directory", fsync_directory)
    elif stage == "S-Q-cleanup":
        original_unlink = Path.unlink

        def unlink(path: Path, *a: Any, **k: Any) -> None:
            if path.parent.name == "events" and path.name.startswith(".run-"):
                raise canary_error
            original_unlink(path, *a, **k)

        patch.setattr(Path, "unlink", unlink)
    else:  # pragma: no cover - parameter guard
        raise AssertionError(stage)


@pytest.mark.parametrize(
    ("stage", "code"),
    [
        ("S-ID", "admission_io_not_committed"),
        ("S-REQ-mkstemp", "admission_io_not_committed"),
        ("S-Q-mkstemp", "admission_io_unknown"),
        ("S-Q-link", "admission_io_unknown"),
        ("S-Q-dir-fsync", "admission_io_unknown"),
        ("S-Q-cleanup", "admission_io_unknown"),
        ("S-IDX-link", "admission_committed_io_error"),
    ],
)
def test_val09_stage_codes_are_private(env: Env, stage: str, code: str) -> None:
    control = env.control()
    key = f"idem:{CANARY}"
    run_id = run_id_for(CANARY, key)
    with pytest.MonkeyPatch.context() as patch:
        _stage_fault(env, patch, stage, run_id)
        with pytest.raises(RunControlError) as caught:
            env.submit(control, CANARY, key=key)
    error = caught.value
    _assert_code(caught, code)
    rendered = [str(error), repr(error.args), error.public_message, json.dumps(error.as_envelope())]
    for text in rendered:
        assert CANARY not in text and "/secret/" not in text
    assert error.__cause__ is None
    assert not isinstance(error.__context__, OSError)
    wire = public_error(error)
    assert wire.code == NEW_CODES[code]
    assert CANARY not in json.dumps(wire.as_envelope())
    assert env.spawned == []
    if stage == "S-REQ-mkstemp":
        # a pre-link request failure does not block the exact retry (VAL-21)
        assert env.submit(control, CANARY, key=key).run_id == run_id
        assert env.spawned == [run_id]


@pytest.mark.parametrize("kind", ["conflict", "validation", "memory", "crash"])
def test_val09_other_failures_are_not_normalized(env: Env, kind: str) -> None:
    control = env.control()
    with pytest.MonkeyPatch.context() as patch:
        if kind == "conflict":
            def request(self: RunControl, *_: Any) -> None:
                raise RunControlError("conflict", "immutable run record conflicts")

            patch.setattr(RunControl, "_append_request", request)
            expected: type[BaseException] = RunControlError
        elif kind == "validation":
            def identity(self: FoundationStore, record: Any) -> Any:
                raise FoundationValidationError("immutable_conflict")

            patch.setattr(FoundationStore, "append_identity", identity)
            expected = FoundationValidationError
        elif kind == "memory":
            def event(self: RunControl, *_: Any) -> Any:
                raise MemoryError()

            patch.setattr(RunControl, "_append_event", event)
            expected = MemoryError
        else:
            def index(self: RunControl, *_: Any) -> None:
                raise Crash("index")

            patch.setattr(RunControl, "_append_idempotency", index)
            expected = Crash
        with pytest.raises(expected) as caught:
            env.submit(control, "pa")
    assert type(caught.value) is expected
    if kind == "conflict":
        assert isinstance(caught.value, RunControlError) and caught.value.code == "conflict"
    assert env.spawned == []


# =================================================================== VAL-ADM-10


def _counting_recover(env: Env) -> list[str]:
    seen: list[str] = []
    original = RunControl._recover_run_unlocked

    def counting(self: RunControl, request: Any, *a: Any, **k: Any) -> Any:
        seen.append(request.run_id)
        return original(self, request, *a, **k)

    env.mp.setattr(RunControl, "_recover_run_unlocked", counting)
    return seen


def _report_complete_fault(env: Env, patch: pytest.MonkeyPatch, target: str) -> None:
    original_append = RunControl._append_event_unlocked

    def append(self: RunControl, run_id: str, state: str, details: Any) -> Any:
        if run_id == target and state == "report_complete":
            raise OSError(errno.EIO, f"I/O error /secret/{CANARY}")
        return original_append(self, run_id, state, details)

    patch.setattr(RunControl, "_append_event_unlocked", append)


def test_val10b_action_io_fault_halts_every_remaining_action(env: Env) -> None:
    control = env.control()
    planted = sorted(env.plant(control, project, f"idem:{project}") for project in ("x1", "x2", "x3"))
    dispatched, faulted, deferred = planted
    env.effect_complete(faulted)
    env.effect_complete(deferred)
    deferred_before = env.snapshot()
    seen = _counting_recover(env)
    with pytest.MonkeyPatch.context() as patch:
        _report_complete_fault(env, patch, faulted)
        restarted = env.control(recover=True)
    assert restarted.recovery_blocked == (
        (faulted, "recovery_io_unknown"),
        (deferred, "recovery_halted"),
    )
    assert env.spawned == [dispatched]
    assert deferred not in seen
    assert env.states(deferred)[-1] == "effect_complete"
    assert env.states(faulted)[-1] == "effect_complete"
    assert {
        name for name in deferred_before if deferred.removeprefix("run:") in name
    } == {name for name in env.snapshot() if deferred.removeprefix("run:") in name}
    # the next pass performs the deferred reconciliation
    again = env.control(recover=True)
    assert again.recovery_blocked == ()
    assert env.states(faulted)[-1] == env.states(deferred)[-1] == "succeeded"


def test_val10b_halt_also_reports_runs_with_preflight_entries(env: Env) -> None:
    control = env.control()
    low, high = _group(env, control, "first")
    project = _project_sorting("idem:fault", lambda rid: rid < low, "f")
    faulted = env.plant(control, project, "idem:fault")
    env.effect_complete(faulted)
    with pytest.MonkeyPatch.context() as patch:
        _report_complete_fault(env, patch, faulted)
        restarted = env.control(recover=True)
    assert restarted.recovery_blocked == (
        (faulted, "recovery_io_unknown"),
        (low, "admission_key_conflict"),
        (low, "recovery_halted"),
        (high, "admission_key_conflict"),
        (high, "recovery_halted"),
    )
    assert env.spawned == []


def _real_spawn_with_failing_popen(env: Env) -> list[str]:
    attempts: list[str] = []

    def popen(*_: Any, **__: Any) -> Any:
        attempts.append("popen")
        raise OSError(errno.EAGAIN, "Resource temporarily unavailable")

    env.mp.setattr(runs.subprocess, "Popen", popen)
    env.mp.setattr(RunControl, "_spawn", ORIGINAL_SPAWN)
    return attempts


ORIGINAL_SPAWN = RunControl._spawn


def test_val10c_popen_failure_keeps_baseline(env: Env) -> None:
    control = env.control()
    run_id = env.plant(control, "pa", "idem:pa")
    attempts = _real_spawn_with_failing_popen(env)
    with pytest.raises(RunControlError) as failed:
        control.recover()
    _assert_code(failed, "internal_error")
    assert attempts == ["popen"]
    assert env.states(run_id) == ["queued", "failed"]


def test_val10c_failed_write_after_popen_failure_is_attributed_and_releases_lock(env: Env) -> None:
    control = env.control()
    run_id = env.plant(control, "pa", "idem:pa")
    attempts = _real_spawn_with_failing_popen(env)

    def receipt(self: FoundationStore, *_: Any, **__: Any) -> Any:
        raise OSError(errno.EIO, "I/O error")

    env.mp.setattr(FoundationStore, "append_receipt", receipt)
    assert control.recover() == ()
    assert attempts == ["popen"]
    assert control.recovery_blocked == ((run_id, "recovery_io_unknown"),)
    with env.run_lock(run_id).open("a+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    assert env.states(run_id) == ["queued"]


def test_val10c_report_is_current_before_unexpected_exception(env: Env) -> None:
    control = env.control()
    low, high = _group(env, control, "first")
    boom = env.plant(control, "boom", "idem:boom")
    original = RunControl._recover_run_unlocked

    def exploding(self: RunControl, request: Any, *a: Any, **k: Any) -> Any:
        if request.run_id == boom:
            raise RuntimeError("unexpected")
        return original(self, request, *a, **k)

    env.mp.setattr(RunControl, "_recover_run_unlocked", exploding)
    with pytest.raises(RuntimeError):
        control.recover()
    assert (low, "admission_key_conflict") in control.recovery_blocked
    assert (high, "admission_key_conflict") in control.recovery_blocked


# =================================================================== VAL-ADM-11


def test_val11_c1_identities_and_terminal_keys_are_retained(env: Env) -> None:
    control = env.control()
    with pytest.MonkeyPatch.context() as patch:
        _cut_patch(env, "C1", patch)
        with pytest.raises(Crash):
            env.submit(control, "pa")
    identities = {
        str(path): path.read_bytes()
        for path in sorted((env.root / ".unrest" / "foundation").rglob("*"))
        if path.is_file()
    }
    assert identities
    run_id = env.submit(control, "pa").run_id
    for name, content in identities.items():
        assert Path(name).read_bytes() == content
    assert control.cancel_run(run_id, "stop", "cancel:pa").state == "cancelled"
    assert env.submit(control, "pa").run_id == run_id
    with pytest.raises(RunControlError) as conflict:
        env.submit(control, "pb", key="idem:pa")
    _assert_code(conflict, "conflict")


def test_val11_no_new_authority_or_continuation_wiring() -> None:
    source = Path(runs.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any("continuation" in name for name in imported)
    assert "sched" not in imported
    assert "Timer(" not in source
    assert source.count("os.kill(") == 2
    assert "os.killpg" not in source
    assert "signal.signal(" not in source


# =================================================================== VAL-ADM-12

PER_RUN_SURFACES = (
    "inspect_run", "attach_run", "cancel_run", "steer_attempt", "worker_start",
    "worker_draining", "worker_effect_complete", "worker_report_complete",
    "worker_succeeded", "worker_cancelled", "worker_failed",
)


def _run_control_class() -> ast.ClassDef:
    tree = ast.parse(Path(runs.__file__).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "RunControl":
            return node
    raise AssertionError("RunControl not found")


def _mentions_admission(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and item.value == "admission.lock":
            return True
        if isinstance(item, ast.Attribute) and item.attr in {"submit_run", "recover", "_admission_view"}:
            return True
    return False


def test_val12_lock_order_is_admission_then_run_only() -> None:
    cls = _run_control_class()
    for function in cls.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.With) and any(
                "_run_lock" in ast.unparse(item.context_expr) for item in node.items
            ):
                for statement in node.body:
                    assert not _mentions_admission(statement), function.name
        if function.name in PER_RUN_SURFACES:
            assert not _mentions_admission(function), function.name


# =================================================================== VAL-ADM-15


def test_val15_incomplete_admission_per_run_surfaces(env: Env) -> None:
    control = env.control()
    torn = env.plant(control, "pa", "idem:pa", queued=False, index=False)
    before = env.snapshot()
    for call in (
        lambda: control.inspect_run(torn),
        lambda: control.attach_run(torn, timeout_seconds=0.01),
        lambda: control.worker_start(torn, pid=OWNER_PID, pgid=OWNER_PID, generation=1),
    ):
        with pytest.raises(RunControlError) as incomplete:
            call()
        _assert_code(incomplete, "admission_incomplete")
    with pytest.raises(RunControlError) as steer:
        control.steer_attempt(torn, {"project_id": "pa", "actor": "orchestrator"})
    _assert_code(steer, "invalid_transition")
    with pytest.raises(RunControlError) as cancel:
        control.cancel_run(torn, "stop", "cancel:torn")
    _assert_code(cancel, "not_found")
    assert env.journal_files() == []
    assert env.snapshot() == before
    assert env.states(torn) == []


@pytest.mark.parametrize("evidence", ["X1", "X2", "X3", "X4", "X5"])
def test_val15_contradictory_empty_stream_is_corruption(env: Env, evidence: str) -> None:
    control = env.control()
    torn = env.plant(control, "pa", "idem:pa", queued=False, index=False)
    directory = env.run_dir(torn)
    if evidence == "X1":
        (directory / "result.json").write_text("{}\n")
    elif evidence == "X2":
        (directory / "private").mkdir()
    elif evidence == "X3":
        (directory / "stop").mkdir()
    elif evidence == "X4":
        env.cursor(torn).write_text("{}\n")
    else:
        control._append_idempotency("idem:pa", torn)
    before = env.snapshot()
    with pytest.raises(RunControlError) as inspected:
        control.inspect_run(torn)
    _assert_code(inspected, "integrity_error")
    with pytest.raises(RunControlError) as preflight:
        env.submit(control, "pb")
    _assert_code(preflight, "integrity_error")
    with pytest.raises(RunControlError) as cancel:
        control.cancel_run(torn, "stop", "cancel:torn")
    _assert_code(cancel, "not_found")
    assert env.journal_files() == []
    assert env.snapshot() == before
    assert env.spawned == []


# =================================================================== VAL-ADM-16


def _rewrite_request(env: Env, target: str, /, **changes: Any) -> None:
    run_id = target
    value = env.request(run_id)
    for name, content in changes.items():
        if content is _DELETE:
            del value[name]
        else:
            value[name] = content
    (env.run_dir(run_id) / "request.json").write_bytes(canonical(value))


_DELETE = object()


def _consistent_foreign_request(env: Env, run_id: str, **raw: Any) -> None:
    """Move a request to the token of its (possibly ill-typed) raw fields."""
    value = env.request(run_id)
    value.update(raw)
    token = token_for(value["operation"], value["arguments"], value["idempotency_key"]) if isinstance(
        value["arguments"], dict
    ) else hashlib.sha256(canonical({
        "arguments": value["arguments"],
        "idempotency_key": value["idempotency_key"],
        "operation": value["operation"],
        "schema_version": 1,
    })).hexdigest()
    value["run_id"] = "run:" + token
    shutil.rmtree(env.run_dir(run_id))
    target = env.durable / token
    target.mkdir()
    (target / "request.json").write_bytes(canonical(value))


def _corrupt(env: Env, control: RunControl, variant: str) -> None:
    run_id = env.plant(control, "pa", "idem:pa")
    directory = env.run_dir(run_id)
    if variant == "dir_not_hex":
        directory.rename(env.durable / ("x" * 64))
    elif variant == "request_symlink":
        request = directory / "request.json"
        copy = env.root / "request-copy.json"
        copy.write_bytes(request.read_bytes())
        request.unlink()
        request.symlink_to(copy)
    elif variant == "request_bad_json":
        (directory / "request.json").write_text("{", encoding="utf-8")
    elif variant == "request_missing_field":
        _rewrite_request(env, run_id, created_at=_DELETE)
    elif variant == "run_id_mismatch":
        _rewrite_request(env, run_id, run_id="run:" + "a" * 64)
    elif variant == "fingerprint_arguments":
        _rewrite_request(env, run_id, arguments=args("pa", 2))
    elif variant == "fingerprint_key":
        _rewrite_request(env, run_id, idempotency_key="idem:other")
    elif variant == "fingerprint_operation":
        _rewrite_request(env, run_id, operation="end_mission")
    elif variant == "token_renamed":
        token = "b" * 64
        directory.rename(env.durable / token)
        _rewrite_request(env, "run:" + token, run_id="run:" + token)
    elif variant == "raw_key_type":
        env.index_path("idem:pa").unlink()
        _consistent_foreign_request(env, run_id, idempotency_key=7)
    elif variant == "coerced_key_type":
        env.index_path("idem:pa").unlink()
        value = env.request(run_id)
        value["idempotency_key"] = 7
        token = token_for(value["operation"], value["arguments"], "7")
        value["run_id"] = "run:" + token
        shutil.rmtree(directory)
        (env.durable / token).mkdir()
        (env.durable / token / "request.json").write_bytes(canonical(value))
    elif variant == "raw_operation_type":
        env.index_path("idem:pa").unlink()
        _consistent_foreign_request(env, run_id, operation=["advance_project"])
    elif variant == "raw_arguments_type":
        env.index_path("idem:pa").unlink()
        _consistent_foreign_request(env, run_id, arguments=["pa"])
    elif variant == "operation_not_admissible":
        env.index_path("idem:pa").unlink()
        _consistent_foreign_request(env, run_id, operation="inspect_run")
    elif variant == "first_event_not_queued":
        shutil.rmtree(directory / "events")
        env.write_event(run_id, "running", 1, None)
    elif variant == "event_chain_tamper":
        first = sorted((directory / "events").glob("*.json"))[0]
        first.write_text('{"state":"queued"}\n', encoding="utf-8")
    elif variant == "orphan_index":
        orphan = env.index_path("idem:ghost")
        orphan.write_bytes(index_bytes("idem:ghost", "run:" + "c" * 64))
    elif variant == "index_to_incomplete":
        torn = env.plant(control, "pb", "idem:pb", queued=False, index=False)
        control._append_idempotency("idem:pb", torn)
    elif variant == "index_noncanonical":
        path = env.index_path("idem:pa")
        path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=2).encode())
    elif variant == "index_name_not_hex":
        (env.durable / "idempotency" / "not-a-digest.json").write_bytes(
            env.index_path("idem:pa").read_bytes()
        )
    elif variant == "index_key_mismatch":
        other = env.index_path("idem:elsewhere")
        digest = hashlib.sha256(b"idem:elsewhere").hexdigest()
        other.write_bytes(canonical({"key_digest": "sha256:" + digest, "run_id": run_id, "schema_version": 1}))
    elif variant == "index_not_regular":
        path = env.index_path("idem:pa")
        copy = env.root / "index-copy.json"
        copy.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(copy)
    else:  # pragma: no cover - parameter guard
        raise AssertionError(variant)


CORRUPTION_VARIANTS = [
    "dir_not_hex", "request_symlink", "request_bad_json", "request_missing_field",
    "run_id_mismatch", "fingerprint_arguments", "fingerprint_key", "fingerprint_operation",
    "token_renamed", "raw_key_type", "coerced_key_type", "raw_operation_type", "raw_arguments_type",
    "operation_not_admissible", "first_event_not_queued", "event_chain_tamper",
    "orphan_index", "index_to_incomplete", "index_noncanonical", "index_name_not_hex",
    "index_key_mismatch", "index_not_regular",
]


@pytest.mark.parametrize("variant", CORRUPTION_VARIANTS)
def test_val16_corruption_fails_closed_before_any_effect(env: Env, variant: str) -> None:
    control = env.control()
    _corrupt(env, control, variant)
    env.spawned.clear()
    before = env.snapshot()
    with pytest.raises(RunControlError) as submitted:
        env.submit(control, "unrelated")
    _assert_code(submitted, "integrity_error")
    with pytest.raises(RunControlError) as recovered:
        env.control(recover=True)
    _assert_code(recovered, "integrity_error")
    assert env.snapshot() == before
    assert env.spawned == []


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("start_project", {"brief": "été ✓ 日本", "workspace_dir": "/tmp/ws-ü"}),
        ("start_project", {"brief": "b", "workspace_dir": "/w", "worker_model": None}),
        ("advance_project", {"project_id": "p", "max_steps": None}),
        ("abort_project", {"project_id": "p", "reason": "r"}),
        ("end_mission", {"project_id": "p", "deliverable_roots": ["a", "b"]}),
        ("decide_attention", {"project_id": "p", "decisions": [{"action": "continue", "item_id": "i"}]}),
        ("submit_plan", {"project_id": "p", "task_list": {"tasks": [
            {"body": "x", "id": "T1", "targets": ["A-1"], "type": "work", "depends_on": []}
        ]}}),
    ],
)
def test_val16_synthetic_requests_pass_strict_identity(
    env: Env, operation: str, arguments: dict[str, Any]
) -> None:
    """Synthetic (not legacy-corpus) shapes: product-admitted runs pass V4."""
    control = env.control()
    run = control.submit_run(operation, arguments, f"idem:{operation}:ü")
    assert run.run_id == "run:" + token_for(operation, arguments, f"idem:{operation}:ü")
    env.control(recover=True)
    assert env.submit(control, "after").state == "queued"


CORPUS = Path(__file__).parent / "fixtures" / "adm_v047_corpus"


def _corpus_cases() -> list[dict[str, Any]]:
    manifest = json.loads((CORPUS / "manifest.json").read_bytes())
    assert manifest["baseline_commit"] == "b307cc619cc042f47161ba0b22fa4b5475729fff"
    cases: list[dict[str, Any]] = manifest["cases"]
    return cases


def test_val16_legacy_corpus_passes_strict_preflight_with_baseline_tokens(env: Env) -> None:
    """Admission-only v0.4.7 corpus: original bytes, baseline-returned tokens."""
    cases = _corpus_cases()
    admitted = [case for case in cases if case["outcome"] == "admitted"]
    assert len(admitted) == 26
    assert {case["operation"] for case in admitted} == set(runs.RUN_OPERATIONS)
    for case in cases:
        if case["outcome"] == "refused":
            # Baseline refusals (for example max_steps 0/True/1.0) persisted nothing.
            assert case["durable_entries_added"] == []
    shutil.copytree(CORPUS / "runs", env.durable)
    control = env.control()
    before = env.snapshot()
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == ()
    assert env.snapshot() == before
    expected = sorted("run:" + case["expected_token"] for case in admitted)
    assert sorted(env.spawned) == expected
    env.spawned.clear()
    for case in admitted:
        run_id = "run:" + case["expected_token"]
        raw = env.request(run_id)
        assert raw["run_id"] == run_id
        assert control.inspect_run(run_id).state == "queued"
        receipt = control.submit_run(raw["operation"], raw["arguments"], raw["idempotency_key"])
        assert (receipt.run_id, receipt.created_at) == (run_id, raw["created_at"])
    assert env.snapshot() == before
    assert env.spawned == []


def test_val16_legacy_corpus_index_repair_reproduces_baseline_bytes(env: Env) -> None:
    shutil.copytree(CORPUS / "runs", env.durable)
    original = {
        path.name: path.read_bytes() for path in sorted((env.durable / "idempotency").glob("*.json"))
    }
    assert len(original) == 26
    shutil.rmtree(env.durable / "idempotency")
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == ()
    assert {
        path.name: path.read_bytes() for path in sorted((env.durable / "idempotency").glob("*.json"))
    } == original


# =================================================================== VAL-ADM-17


def _report_scenario(env: Env, order: list[str]) -> dict[str, str]:
    control = env.control()
    names: dict[str, str] = {}
    for step in order:
        if step == "torn":
            names[step] = env.plant(control, "shared", "idem:torn", queued=False, index=False)
        elif step == "group":
            names["g1"], names["g2"] = _group(env, control, "none")
        elif step == "gated":
            names[step] = env.plant(control, "shared", "idem:gated")
        elif step == "live":
            names[step] = env.plant(control, "shared", "idem:live")
            env.start(names[step])
    return names


@pytest.mark.parametrize("order", [["torn", "group", "gated", "live"], ["live", "gated", "group", "torn"]])
def test_val17_report_is_deterministic_and_gate_ranked(env: Env, order: list[str]) -> None:
    names = _report_scenario(env, order)
    expected = tuple(
        sorted(
            [
                (names["torn"], "admission_incomplete"),
                (names["g1"], "admission_key_conflict"),
                (names["g2"], "admission_key_conflict"),
                (names["gated"], "admission_resource_blocked"),
            ]
        )
    )
    for _ in range(2):
        assert env.control(recover=True).recovery_blocked == expected
    assert env.spawned == []
    assert env.states(names["live"]) == ["queued", "running"]


def test_val17_report_is_reset_for_each_pass(env: Env) -> None:
    control = env.control()
    torn = env.plant(control, "pa", "idem:pa", queued=False, index=False)
    restarted = env.control(recover=True)
    assert restarted.recovery_blocked == ((torn, "admission_incomplete"),)
    # Manual disposition outside RunControl removes the incomplete claim.
    shutil.rmtree(env.run_dir(torn))
    assert restarted.recover() == ()
    assert restarted.recovery_blocked == ()


def test_val17_halted_pass_reports_gate_runs_as_halted_only(env: Env) -> None:
    control = env.control()
    env.plant(control, "shared", "idem:torn", queued=False, index=False)
    gated = env.plant(control, "shared", "idem:gated")
    project = _project_sorting("idem:fault", lambda rid: rid < gated, "f")
    faulted = env.plant(control, project, "idem:fault")
    env.effect_complete(faulted)
    with pytest.MonkeyPatch.context() as patch:
        _report_complete_fault(env, patch, faulted)
        restarted = env.control(recover=True)
    codes = dict(
        ((run_id, code) for run_id, code in restarted.recovery_blocked if run_id == gated)
    )
    assert codes == {gated: "recovery_halted"}
    assert (faulted, "recovery_io_unknown") in restarted.recovery_blocked


# =================================================================== VAL-ADM-18


def test_val18_preflight_never_calls_project_inspector(env: Env) -> None:
    calls: list[str] = []

    def inspector(project_id: str) -> dict[str, Any]:
        calls.append(project_id)
        return {"active_attempts": []}

    control = env.control(project_inspector=inspector)
    active = env.submit(control, "pa").run_id
    calls.clear()
    before = env.snapshot()
    with pytest.raises(RunControlError) as busy:
        env.submit(control, "pa", key="idem:other")
    _assert_code(busy, "busy")
    assert env.submit(control, "pa").run_id == active
    assert env.snapshot() == before
    assert calls == []
    project = _project_sorting("idem:corrupt", lambda rid: rid > active, "z")
    corrupt = env.plant(control, project, "idem:corrupt")
    sorted((env.run_dir(corrupt) / "events").glob("*.json"))[0].write_text("{}\n")
    with pytest.raises(RunControlError):
        env.control(recover=True, project_inspector=inspector)
    assert calls == []


# =================================================================== VAL-ADM-19


def _tracked_locks(env: Env) -> list[str]:
    held: list[str] = []
    original = runs._exclusive_lock

    @contextmanager
    def tracking(path: Path) -> Iterator[Any]:
        with original(path) as stream:
            held.append(str(path))
            try:
                yield stream
            finally:
                held.remove(str(path))

    env.mp.setattr(runs, "_exclusive_lock", tracking)
    return held


@pytest.mark.parametrize("gap", ["transient", "persistent"])
def test_val19_suspicious_stream_is_confirmed_under_the_run_lock(env: Env, gap: str) -> None:
    control = env.control()
    target = env.plant(control, "pa", "idem:pa")
    env.start(target)
    held = _tracked_locks(env)
    original = RunControl._load_events
    confirmations: list[list[str]] = []

    def loading(self: RunControl, run_id: str) -> Any:
        if run_id == target:
            under_lock = str(env.run_lock(target)) in held
            if under_lock:
                confirmations.append(list(held))
            if gap == "persistent" or not under_lock:
                raise RunControlError("integrity_error", "run event chain is invalid")
        return original(self, run_id)

    env.mp.setattr(RunControl, "_load_events", loading)
    if gap == "transient":
        admitted = env.submit(control, "pb").run_id
        assert env.spawned == [admitted]
        assert confirmations, "the stream was re-read under its run lock"
        assert any(str(env.runtime / "admission.lock") in locks for locks in confirmations)
    else:
        before = env.snapshot()
        with pytest.raises(RunControlError) as corrupted:
            env.submit(control, "pb")
        _assert_code(corrupted, "integrity_error")
        assert env.snapshot() == before
        assert env.spawned == []
        assert len(confirmations) == 1


# =================================================================== VAL-ADM-20


@pytest.mark.parametrize(("code", "stable"), sorted(NEW_CODES.items()))
def test_val20_new_codes_have_explicit_frozen_wire_mapping(code: str, stable: str) -> None:
    wire = public_error(RunControlError(code, "fixed"))
    assert wire.code == stable
    assert wire.code != "invalid_argument"
    assert wire.public_message == stable.replace("_", " ")
    assert foundation_tools._ERROR_MAP[code] == stable


def test_val20_report_codes_are_not_wire_codes() -> None:
    for code in ("recovery_io_unknown", "recovery_halted"):
        assert code not in foundation_tools._ERROR_MAP
    assert set(NEW_CODES) <= set(foundation_tools._ERROR_MAP)


# =================================================================== VAL-ADM-21


@pytest.mark.parametrize(
    "entry", ["events", "result", "stop", "private", "foreign", "symlink_dir", "symlink_staging"]
)
def test_val21_foreign_run_directory_blocks_before_writes(env: Env, entry: str) -> None:
    control = env.control()
    directory = env.run_dir(run_id_for("pa", "idem:pa"))
    if entry == "symlink_dir":
        elsewhere = env.root / "elsewhere"
        elsewhere.mkdir()
        directory.symlink_to(elsewhere, target_is_directory=True)
    else:
        directory.mkdir()
        if entry in {"events", "stop", "private"}:
            (directory / entry).mkdir()
        elif entry == "result":
            (directory / "result.json").write_text("{}\n")
        elif entry == "foreign":
            (directory / "notes.txt").write_text("x\n")
        else:
            (env.root / "staging-target").write_bytes(b"x")
            (directory / ".run-link").symlink_to(env.root / "staging-target")
    before = env.snapshot()
    with pytest.raises(RunControlError) as refused:
        env.submit(control, "pa")
    _assert_code(refused, "integrity_error")
    assert env.snapshot() == before
    assert env.spawned == []


@pytest.mark.parametrize("contents", ["empty", "staging_only"])
def test_val21_empty_or_staging_only_directory_admits(env: Env, contents: str) -> None:
    control = env.control()
    run_id = run_id_for("pa", "idem:pa")
    directory = env.run_dir(run_id)
    directory.mkdir()
    if contents == "staging_only":
        (directory / ".run-x").write_bytes(b"partial staging")
    assert env.submit(control, "pa").run_id == run_id
    assert env.spawned == [run_id]
    if contents == "staging_only":
        assert (directory / ".run-x").read_bytes() == b"partial staging"


@pytest.mark.parametrize("point", ["mkstemp", "write", "fsync"])
def test_val21_prelink_request_failure_allows_exact_retry(env: Env, point: str) -> None:
    control = env.control()
    run_id = run_id_for("pa", "idem:pa")
    token = run_id.removeprefix("run:")
    with pytest.MonkeyPatch.context() as patch:
        if point == "fsync":
            original_fsync = os.fsync
            check = _once(lambda fd: True, OSError(errno.EIO, "I/O error"))
            original_mkstemp = runs.tempfile.mkstemp
            armed: dict[str, Any] = {"fd": None}

            def mkstemp(*a: Any, **k: Any) -> Any:
                descriptor, name = original_mkstemp(*a, **k)
                if Path(str(k.get("dir"))).name == token and armed["fd"] is None:
                    armed["fd"] = descriptor
                return descriptor, name

            def fsync(fd: int) -> None:
                if armed["fd"] is not None:
                    check(fd)
                original_fsync(fd)

            patch.setattr(runs.tempfile, "mkstemp", mkstemp)
            patch.setattr(runs.os, "fsync", fsync)
        else:
            original_mkstemp = runs.tempfile.mkstemp

            def failing(*a: Any, **k: Any) -> Any:
                if Path(str(k.get("dir"))).name == token:
                    if point == "mkstemp":
                        raise OSError(errno.ENOSPC, "No space left on device")
                    descriptor, name = original_mkstemp(*a, **k)
                    os.close(descriptor)
                    return os.open(name, os.O_RDONLY), name
                return original_mkstemp(*a, **k)

            patch.setattr(runs.tempfile, "mkstemp", failing)
        with pytest.raises(RunControlError) as failed:
            env.submit(control, "pa")
    _assert_code(failed, "admission_io_not_committed")
    assert not (env.run_dir(run_id) / "request.json").exists()
    assert env.submit(control, "pa").run_id == run_id
    assert env.spawned == [run_id]
    assert env.states(run_id) == ["queued"]
