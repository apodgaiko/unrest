"""RCR (ADR-0503): typed integrity of durable run requests and event histories.

Every case is in-process and hermetic. ``RunControl._spawn`` records an intent;
``subprocess.Popen``, fork/exec/spawn primitives and ``os.killpg`` raise and are
recorded, so an unexpected launch fails the case even when it is caught.
``os.kill`` is a recorder that never delivers a signal; ``os.getpgid`` and
``os.getsid`` answer from a fake live set. ``os.getpid`` is patched only in the
fake-identity (H-F) cases. Every ``RunControl`` is built with ``recover=False``
unless recovery is the surface under test.

Fixture classes (contract section 11): H-P trees come from public HEAD writers,
H-F adds fake OS identity, H-C injects a crash, H-V uses the private validated
writer, S-E are synthetic writer-format chains that are legal under the
lifecycle relation without any writer path, N are negatives, and B-N/B-L are
the byte-identical baseline b307cc6 trees below ``fixtures/rcr_b307cc6_events``.
Synthetic chains are not legacy evidence.
"""
from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

import pytest

import unrest_harness.run_control as runs
from unrest_harness import foundation_tools
from unrest_harness.canonical_identity import FoundationValidationError
from unrest_harness.foundation_tools import public_error
from unrest_harness.run_control import RunControl, RunControlError, StopCustodyInvalid


EXECUTOR = "json:dumps"
CANARY = "CNRYrcr7Q2xLm9Pw"
FIXTURES = Path(__file__).parent / "fixtures" / "rcr_b307cc6_events"
RESULT = {
    "dag": None,
    "harnessRoot": "/nonexistent/.unrest",
    "projectId": "rcr-project",
    "projectRoot": "/nonexistent",
    "state": {"state": "done"},
}
FAILURE = {
    runs.EXECUTOR_FAILURE_KEY: {
        "public_error": {"error": {"code": "invalid_argument", "message": "refused"}},
        "private_tool_error": {"code": "tool_failed", "details": ["d"], "message": "m"},
    }
}
EDGES = {
    None: {"queued"},
    "queued": {"cancel_requested", "failed", "running"},
    "running": {"attention", "cancel_requested", "draining", "effect_complete", "failed"},
    "cancel_requested": {"attention", "cancelled", "draining", "effect_complete", "failed"},
    "draining": {"attention", "cancelled", "effect_complete", "failed"},
    "effect_complete": {"attention", "cancel_requested", "failed", "report_complete"},
    "report_complete": {"attention", "cancel_requested", "failed", "succeeded"},
}
STATES = (
    "queued", "running", "cancel_requested", "draining", "effect_complete",
    "report_complete", "succeeded", "cancelled", "failed", "attention",
)
TERMINALS = ("attention", "cancelled", "failed", "succeeded")


class ForbiddenEffect(AssertionError):
    """A real process primitive was reached."""


class Crash(BaseException):
    """Simulated process crash at an injected cut (not an Exception)."""


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def render(value: Any, raws: dict[str, str | bytes]) -> bytes:
    """Writer-format bytes with placeholder strings replaced by raw JSON text."""
    data = (
        json.dumps(value, allow_nan=True, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8", "surrogatepass")
    for placeholder, text in raws.items():
        marker = json.dumps(placeholder).encode()
        assert data.count(marker) == 1, placeholder
        data = data.replace(marker, text if isinstance(text, bytes) else text.encode("utf-8"))
    return data


def event_digest(body: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(b"unrest.run-event.v1\0" + canonical(body)).hexdigest()


def token_for(operation: str, arguments: Any, key: Any) -> str:
    body = {"arguments": arguments, "idempotency_key": key, "operation": operation, "schema_version": 1}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    ).hexdigest()


def deep(depth: int) -> Any:
    assert 1 <= depth <= 2048
    value: Any = 0
    for _ in range(depth):
        value = [value]
    return value


def deep_text(depth: int) -> str:
    assert 1 <= depth <= 2048
    return "[" * depth + "0" + "]" * depth


@dataclass
class FakeProcesses:
    live: set[int] = field(default_factory=set)
    signals: list[tuple[int, int]] = field(default_factory=list)

    def kill(self, pid: int, sig: int) -> None:
        if sig != 0:
            self.signals.append((pid, sig))
        if pid not in self.live:
            raise ProcessLookupError(pid)

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
    def control(self, owner_id: str = "server:rcr", **kwargs: Any) -> RunControl:
        kwargs.setdefault("recover", False)
        return RunControl(self.root, executor_ref=EXECUTOR, owner_id=owner_id, **kwargs)

    def submit(self, control: RunControl | None = None, project: str = "p1", key: str | None = None) -> str:
        control = control or self.control()
        arguments = {"project_id": project, "reason": f"brief {CANARY}"}
        run_id = control.submit_run("abort_project", arguments, key or f"idem:{project}").run_id
        self.spawned.remove(run_id)  # fixture setup; only later dispatch is observed
        return run_id

    def submit_advance(self, control: RunControl, project: str = "adv") -> str:
        run_id = control.submit_run(
            "advance_project", {"project_id": project, "max_steps": 1}, f"idem:{project}"
        ).run_id
        self.spawned.remove(run_id)
        return run_id

    def bound(self, project: str = "p1") -> tuple[RunControl, str]:
        """H-P: own-pid owner (``os.getpid`` unpatched) bound by worker_start."""
        owner = self.control(owner_id="worker:own:1")
        run_id = self.submit(owner, project)
        assert owner.worker_start(run_id, pid=os.getpid(), pgid=os.getpid(), generation=1)
        return owner, run_id

    @contextmanager
    def as_pid(self, pid: int) -> Iterator[None]:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(runs.os, "getpid", lambda: pid)
            yield

    # ------------------------------------------------------------------- paths
    @property
    def durable(self) -> Path:
        return self.root / ".unrest" / "runs"

    @property
    def runtime(self) -> Path:
        return self.root / ".unrest-runtime" / "runs"

    def run_dir(self, run_id: str) -> Path:
        return self.durable / run_id.removeprefix("run:")

    def request_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "request.json"

    def event_path(self, run_id: str, sequence: int) -> Path:
        return self.run_dir(run_id) / "events" / f"{sequence:020d}.json"

    def cursor(self, run_id: str) -> Path:
        return self.runtime / (hashlib.sha256(run_id.encode()).hexdigest() + ".worker.json")

    def index_path(self, key: str) -> Path:
        return self.durable / "idempotency" / (hashlib.sha256(key.encode()).hexdigest() + ".json")

    def journal_files(self) -> list[Path]:
        return sorted((self.root / ".unrest" / "foundation" / "public-mutations").glob("*"))

    def receipts(self) -> list[Path]:
        return sorted((self.root / ".unrest" / "foundation" / "receipts").rglob("*.json"))

    def request(self, run_id: str) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(self.request_path(run_id).read_bytes())
        return loaded

    def events(self, run_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(path.read_bytes())
            for path in sorted((self.run_dir(run_id) / "events").glob("*.json"))
        ]

    def states(self, run_id: str) -> list[str]:
        return [event["state"] for event in self.events(run_id)]

    def snapshot(self) -> dict[str, bytes]:
        """Every entry below .unrest and .unrest-runtime except lock files."""
        result: dict[str, bytes] = {}
        for base in (self.root / ".unrest", self.root / ".unrest-runtime"):
            for path in sorted(base.rglob("*")):
                if path.name.endswith(".lock"):
                    continue
                relative = str(path.relative_to(self.root))
                if path.is_symlink():
                    result[relative] = b"<link>" + os.readlink(path).encode()
                elif path.is_dir():
                    result[relative] = b"<dir>"
                else:
                    result[relative] = path.read_bytes()
        return result

    # ---------------------------------------------------------------- planting
    @staticmethod
    def write(path: Path, data: bytes) -> None:
        assert len(data) < 128 * 1024
        if path.exists():
            os.chmod(path, 0o600)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def set_request(
        self,
        run_id: str,
        changes: dict[str, Any] | None = None,
        *,
        delete: tuple[str, ...] = (),
        raws: dict[str, str | bytes] | None = None,
    ) -> None:
        value = self.request(run_id)
        for key in delete:
            del value[key]
        for dotted, new in (changes or {}).items():
            cursor = value
            parts = dotted.split(".")
            for part in parts[:-1]:
                cursor = cursor[part]
            cursor[parts[-1]] = new
        self.write(self.request_path(run_id), render(value, raws or {}))

    def set_event(
        self,
        run_id: str,
        sequence: int,
        changes: dict[str, Any] | None = None,
        *,
        delete: tuple[str, ...] = (),
        raws: dict[str, str | bytes] | None = None,
        recompute: bool = True,
    ) -> None:
        """Rewrite one event; the digest is recomputed over the decoded new body."""
        path = self.event_path(run_id, sequence)
        value = json.loads(path.read_bytes())
        original = value.pop("event_digest")
        for key in delete:
            value.pop(key, None)
        for dotted, new in (changes or {}).items():
            cursor = value
            parts = dotted.split(".")
            for part in parts[:-1]:
                cursor = cursor[part]
            cursor[parts[-1]] = new
        digest: Any = original
        if recompute and "event_digest" not in delete:
            decoded = json.loads(render(value, raws or {}))
            digest = "sha256:" + hashlib.sha256(
                b"unrest.run-event.v1\0" + runs._json_bytes(decoded)
            ).hexdigest()
        if "event_digest" not in delete and "event_digest" not in (changes or {}):
            value["event_digest"] = digest
        self.write(path, render(value, raws or {}))

    def write_chain(
        self,
        run_id: str,
        states: list[str],
        details: dict[int, dict[str, Any]] | None = None,
        extras: dict[int, dict[str, Any]] | None = None,
    ) -> None:
        """S-E: replace the stream by a writer-format, digest-consistent chain."""
        directory = self.run_dir(run_id) / "events"
        for path in directory.glob("*.json"):
            os.chmod(path, 0o600)
            path.unlink()
        previous: str | None = None
        for sequence, state in enumerate(states, 1):
            body = {
                "details": (details or {}).get(sequence, {}),
                "observed_at": "2026-11-03T00:00:00.000Z",
                "previous_event_digest": previous,
                "run_id": run_id,
                "schema_version": 1,
                "sequence": sequence,
                "state": state,
                **(extras or {}).get(sequence, {}),
            }
            previous = event_digest(body)
            self.write(self.event_path(run_id, sequence), canonical({**body, "event_digest": previous}))

    def append_event(self, run_id: str, state: str, details: dict[str, Any] | None = None) -> None:
        """Digest-consistent planted append (never through a writer)."""
        existing = self.events(run_id)
        body = {
            "details": details or {},
            "observed_at": "2026-11-03T00:00:01.000Z",
            "previous_event_digest": existing[-1]["event_digest"] if existing else None,
            "run_id": run_id,
            "schema_version": 1,
            "sequence": len(existing) + 1,
            "state": state,
        }
        self.write(
            self.event_path(run_id, len(existing) + 1),
            canonical({**body, "event_digest": event_digest(body)}),
        )


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


def _code(caught: pytest.ExceptionInfo[RunControlError]) -> tuple[str, str]:
    return caught.value.code, caught.value.public_message


INVALID_REQUEST = ("integrity_error", "run request is invalid")
INVALID_RECORD = ("integrity_error", "run record is invalid")
INVALID_EVENT = ("integrity_error", "run event is invalid")
INVALID_CHAIN = ("integrity_error", "run event chain is invalid")
NO_ADMISSION = ("integrity_error", "run has no admission event")
INVALID_INDEX = ("integrity_error", "idempotency record is invalid")


# ------------------------------------------------------------------ surfaces
def _attach(control: RunControl, run_id: str) -> Any:
    return control.attach_run(run_id, timeout_seconds=0)


def _lock(control: RunControl, run_id: str) -> str:
    with control.resource_lock(run_id):
        return "entered"


def _steer(control: RunControl, run_id: str) -> Any:
    return control.steer_attempt(run_id, {"project_id": "p1", "actor": "orchestrator"})


REQUEST_SURFACES: dict[str, Callable[[RunControl, str], Any]] = {
    "inspect_run": lambda c, r: c.inspect_run(r),
    "attach_run": _attach,
    "steer_attempt": _steer,
    "inspect_stop": lambda c, r: c.inspect_stop(r),
    "worker_start": lambda c, r: c.worker_start(r, pid=4242, pgid=4242, generation=1),
    "resource_lock": _lock,
    "request_payload": lambda c, r: c.request_payload(r),
    "cancel_run": lambda c, r: c.cancel_run(r, "reason", "cancel:rcr"),
    "recover": lambda c, r: c.recover(),
    "submit_run": lambda c, r: c.submit_run(
        "abort_project", {"project_id": "other", "reason": "r"}, "idem:other"
    ),
}
EVENT_SURFACES = {
    name: REQUEST_SURFACES[name]
    for name in (
        "inspect_run", "attach_run", "steer_attempt", "inspect_stop", "worker_start",
        "cancel_run", "recover", "submit_run",
    )
}


def _assert_refused(
    env: Env,
    surface: Callable[[RunControl, str], Any],
    run_id: str,
    expected: tuple[str, str],
    control: RunControl | None = None,
) -> None:
    """RBA: the refusal leaves non-lock state, spawn, signals and journal untouched."""
    before = env.snapshot()
    spawned = list(env.spawned)
    signals = list(env.fake.signals)
    with pytest.raises(RunControlError) as caught:
        surface(control or env.control(), run_id)
    assert _code(caught) == expected
    assert env.snapshot() == before
    assert env.spawned == spawned
    assert env.fake.signals == signals


# ================================================================= VAL-RCR-01

REQUIRED_REQUEST_FIELDS = (
    "run_id", "operation", "idempotency_key", "arguments", "resource_key", "project_id",
    "created_at", "run_identity_digest", "control_identity_digest",
    "issuer_identity_digest", "generation",
)
WRONG_VALUES: dict[str, Any] = {
    "bool": True, "str": "1", "float": 1.5, "list": [], "dict": {}, "null": None, "int": 7,
}
EXPECTED_TYPE = {
    "run_id": "str", "operation": "str", "idempotency_key": "str", "arguments": "dict",
    "resource_key": "str", "project_id": "str", "created_at": "str",
    "run_identity_digest": "str", "control_identity_digest": "str",
    "issuer_identity_digest": "str", "generation": "int",
}


def _wrong_cells() -> list[tuple[str, str]]:
    cells = []
    for name in REQUIRED_REQUEST_FIELDS:
        for label in WRONG_VALUES:
            if label == EXPECTED_TYPE[name]:
                continue
            if name == "project_id" and label == "null":
                continue  # null project_id is admitted (start_project)
            cells.append((name, label))
    return cells


@pytest.mark.parametrize(("name", "label"), _wrong_cells())
@pytest.mark.parametrize("surface", sorted(REQUEST_SURFACES))
def test_rcr01_native_request_field_types(env: Env, name: str, label: str, surface: str) -> None:
    run_id = env.submit()
    env.set_request(run_id, {name: WRONG_VALUES[label]})
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


@pytest.mark.parametrize("name", ("operation", "idempotency_key", "arguments"))
@pytest.mark.parametrize("label", ("bool", "int", "list", "null"))
def test_rcr01_fingerprint_fields_with_recomputed_token(env: Env, name: str, label: str) -> None:
    """The wrong type is refused even when the directory token matches its bytes."""
    if name == "arguments" and label == "list":
        label = "int"
    run_id = env.submit()
    value = env.request(run_id)
    value[name] = WRONG_VALUES[label]
    token = token_for(value["operation"], value["arguments"], value["idempotency_key"])
    target = env.durable / token
    shutil.move(env.run_dir(run_id), target)
    value["run_id"] = "run:" + token
    env.write(target / "request.json", canonical(value))
    for surface in ("inspect_run", "request_payload", "worker_start", "recover"):
        _assert_refused(env, REQUEST_SURFACES[surface], "run:" + token, INVALID_REQUEST)


@pytest.mark.parametrize("name", REQUIRED_REQUEST_FIELDS)
@pytest.mark.parametrize("surface", ("inspect_run", "request_payload", "cancel_run", "recover"))
def test_rcr01_missing_request_keys(env: Env, name: str, surface: str) -> None:
    run_id = env.submit()
    env.set_request(run_id, delete=(name,))
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


def test_rcr01_null_project_id_and_extra_keys_are_admitted(env: Env) -> None:
    run_id = env.submit()
    env.set_request(run_id, {"project_id": None, "probe_extra": {"nested": [1, "x", 2.5]}})
    control = env.control()
    assert control.inspect_run(run_id).project_id is None
    assert control.request_payload(run_id)[0] == "abort_project"
    control.recover()
    assert env.spawned == [run_id]


@pytest.mark.parametrize("name", ("operation", "resource_key", "generation", "created_at"))
@pytest.mark.parametrize(
    "surface",
    ("effect_success", "report_complete", "worker_succeeded", "worker_cancelled", "worker_failed"),
)
def test_rcr01_bound_request_reading_surfaces(env: Env, name: str, surface: str) -> None:
    """M12-M14, M16, M17: request-only corruption refuses before writes on a bound tree."""
    owner, run_id = env.bound()
    if surface == "report_complete":
        owner.worker_effect_complete(run_id, RESULT)
    env.set_request(run_id, {name: ["wrong"]})
    calls: dict[str, Callable[[RunControl, str], Any]] = {
        "effect_success": lambda c, r: c.worker_effect_complete(r, RESULT),
        "report_complete": lambda c, r: c.worker_report_complete(r),
        "worker_succeeded": lambda c, r: c.worker_succeeded(r),
        "worker_cancelled": lambda c, r: c.worker_cancelled(r),
        "worker_failed": lambda c, r: c.worker_failed(r),
    }
    _assert_refused(env, calls[surface], run_id, INVALID_REQUEST, control=owner)


# ================================================================= VAL-RCR-02

GENERATIONS: dict[str, str] = {
    "True": "true", "str1": '"1"', "float1": "1.0", "float19": "1.9", "float25": "2.5",
    "zero": "0", "minus1": "-1", "null": "null", "abc": '"abc"', "Infinity": "Infinity",
    "1e999": "1e999", "NaN": "NaN", "minusInfinity": "-Infinity",
}


@pytest.mark.parametrize("label", sorted(GENERATIONS))
@pytest.mark.parametrize(
    "surface", ("inspect_run", "worker_start", "recover", "submit_run", "cancel_run", "resource_lock")
)
def test_rcr02_generation_refused_before_dispatch_and_cursor(env: Env, label: str, surface: str) -> None:
    run_id = env.submit()
    env.set_request(run_id, {"generation": "@@G@@"}, raws={"@@G@@": GENERATIONS[label]})
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)
    assert not env.cursor(run_id).exists()


def test_rcr02_native_generations(env: Env) -> None:
    run_id = env.submit()
    control = env.control()
    assert control.worker_start(run_id, pid=4242, pgid=4242, generation=1)
    other = env.submit(control, "p2")
    env.set_request(other, {"generation": 2})  # well-typed: accepted, not protected
    with pytest.raises(RunControlError) as caught:
        control.worker_start(other, pid=4243, pgid=4243, generation=1)
    assert caught.value.code == "stale"
    control.recover()
    assert other in env.spawned
    assert control.worker_start(other, pid=4243, pgid=4243, generation=2)


def test_rcr02_request_corruption_precedes_stale(env: Env) -> None:
    run_id = env.submit()
    env.set_request(run_id, {"generation": True})
    with pytest.raises(RunControlError) as caught:
        env.control().worker_start(run_id, pid=1, pgid=1, generation=2)
    assert _code(caught) == INVALID_REQUEST
    with pytest.raises(RunControlError) as caught:
        env.control().worker_start(run_id, pid=1, pgid=1, generation=True)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_argument"


# ================================================================= VAL-RCR-03


@pytest.mark.parametrize("label", ("list", "int", "null", "dict", "bool"))
def test_rcr03_resource_key_refused_before_lock_path(env: Env, label: str) -> None:
    run_id = env.submit()
    env.set_request(run_id, {"resource_key": WRONG_VALUES[label]})
    locks_before = sorted(path.name for path in (env.runtime / "locks").glob("*"))
    for surface in ("resource_lock", "recover", "submit_run"):
        _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)
    assert sorted(path.name for path in (env.runtime / "locks").glob("*")) == locks_before


def test_rcr03_foreign_resource_string_is_accepted(env: Env) -> None:
    """Type-only strings: an alias or foreign key is not an authenticity check."""
    run_id = env.submit()
    env.set_request(run_id, {"resource_key": "project:foreign"})
    control = env.control()
    assert _lock(control, run_id) == "entered"
    assert control.inspect_run(run_id).resource_key == "project:foreign"


# ================================================================= VAL-RCR-04

NONFINITE = ("NaN", "Infinity", "-Infinity", "1e999")
REQUEST_READERS = ("inspect_run", "request_payload", "resource_lock", "worker_start", "cancel_run",
                   "recover", "submit_run")


@pytest.mark.parametrize("token", NONFINITE)
@pytest.mark.parametrize("nested", (False, True))
@pytest.mark.parametrize("surface", REQUEST_READERS)
def test_rcr04a_nonfinite_request_extra_key(env: Env, token: str, nested: bool, surface: str) -> None:
    run_id = env.submit()
    raw = f'[{{"v":{token}}}]' if nested else token
    env.set_request(run_id, {"probe_extra": "@@X@@"}, raws={"@@X@@": raw})
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


@pytest.mark.parametrize("token", NONFINITE)
@pytest.mark.parametrize("surface", ("inspect_run", "request_payload", "worker_start", "recover"))
def test_rcr04b_nonfinite_request_arguments(env: Env, token: str, surface: str) -> None:
    run_id = env.submit()
    env.set_request(run_id, {"arguments.probe": "@@X@@"}, raws={"@@X@@": token})
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


@pytest.mark.parametrize("token", NONFINITE)
@pytest.mark.parametrize("where", ("details", "extra", "nested"))
@pytest.mark.parametrize("surface", ("inspect_run", "worker_start", "cancel_run", "recover", "submit_run"))
def test_rcr04c_nonfinite_event_values(env: Env, token: str, where: str, surface: str) -> None:
    run_id = env.submit()
    key = {"details": "details.probe", "extra": "probe_extra", "nested": "details.deep"}[where]
    raw = f'{{"a":[{token}]}}' if where == "nested" else token
    env.set_event(run_id, 1, {key: "@@X@@"}, raws={"@@X@@": raw}, recompute=False)
    _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_EVENT)


def test_rcr04_finite_floats_in_running_details_are_accepted(env: Env) -> None:
    """U3: float pid/pgid reach running.details only through a direct library call."""
    control = env.control()
    run_id = env.submit(control)
    assert control.worker_start(run_id, pid=12.5, pgid=3.25, generation=1)  # type: ignore[arg-type]
    assert env.events(run_id)[1]["details"]["pid"] == 12.5
    assert control.inspect_run(run_id).state == "running"
    assert [event.state for event in control._load_events(run_id)] == ["queued", "running"]


def test_rcr04_duplicate_keys_keep_last_wins(env: Env) -> None:
    """An overwritten nonfinite duplicate is not a refusal (Amendment-1 item 2)."""
    run_id = env.submit()
    value = env.request(run_id)
    text = canonical(value).decode()
    env.write(env.request_path(run_id), text.replace('{"arguments"', '{"probe":1e999,"probe":0,"arguments"', 1).encode())
    control = env.control()
    assert control.inspect_run(run_id).state == "queued"
    event = env.events(run_id)[0]
    body = {k: v for k, v in event.items() if k != "event_digest"}
    raw = canonical({**body, "event_digest": event["event_digest"]}).decode()
    env.write(env.event_path(run_id, 1), raw.replace('"details":{', '"details":{"x":NaN,"x":1,', 1).encode())
    event_body = json.loads(env.event_path(run_id, 1).read_bytes())
    event_body.pop("event_digest")
    fixed = env.event_path(run_id, 1).read_bytes().decode().replace(
        event["event_digest"], event_digest(event_body)
    )
    env.write(env.event_path(run_id, 1), fixed.encode())
    assert [event.state for event in control._load_events(run_id)] == ["queued"]
    control.recover()
    assert env.spawned == [run_id]


# ================================================================= VAL-RCR-05


@contextmanager
def _lock_spy(env: Env) -> Iterator[list[str]]:
    seen: list[str] = []
    original = runs._exclusive_lock

    @contextmanager
    def spy(path: Path) -> Iterator[Any]:
        seen.append(path.name)
        with original(path) as handle:
            yield handle

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runs, "_exclusive_lock", spy)
        yield seen


PER_RUN_V = {
    "V3-run_id": lambda run_id, other: {"run_id": other},
    "V2-operation": lambda run_id, other: {"operation": "bogus_operation"},
    "V2-empty-key": lambda run_id, other: {"idempotency_key": ""},
    "V4-arguments": lambda run_id, other: {"arguments.reason": "changed"},
    "V4-key": lambda run_id, other: {"idempotency_key": "idem:changed"},
}


@pytest.mark.parametrize("violation", sorted(PER_RUN_V))
@pytest.mark.parametrize("surface", ("inspect_run", "worker_start", "resource_lock", "request_payload"))
def test_rcr05_per_run_v1_v5_without_admission_lock(env: Env, violation: str, surface: str) -> None:
    run_id = env.submit()
    other = env.submit(project="p2")
    env.set_request(run_id, PER_RUN_V[violation](run_id, other))
    with _lock_spy(env) as seen:
        _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)
    assert "admission.lock" not in seen


# ================================================================= VAL-RCR-06

ENVELOPE_TYPES: list[tuple[str, Any, tuple[str, str]]] = [
    ("sequence", True, INVALID_EVENT),
    ("sequence", 1.0, INVALID_EVENT),
    ("sequence", "1", INVALID_EVENT),
    ("state", 7, INVALID_EVENT),
    ("state", None, INVALID_EVENT),
    ("state", ["queued"], INVALID_EVENT),
    ("observed_at", 5, INVALID_EVENT),
    ("observed_at", None, INVALID_EVENT),
    ("observed_at", [], INVALID_EVENT),
    ("details", [], INVALID_EVENT),
    ("details", "x", INVALID_EVENT),
    ("details", None, INVALID_EVENT),
    ("event_digest", 5, INVALID_EVENT),
    ("event_digest", None, INVALID_EVENT),
    ("previous_event_digest", 5, INVALID_EVENT),
    ("previous_event_digest", "sha256:" + "0" * 64, INVALID_CHAIN),
    ("run_id", 5, INVALID_EVENT),
    ("run_id", "run:" + "0" * 64, INVALID_CHAIN),
]


@pytest.mark.parametrize(("name", "value", "expected"), ENVELOPE_TYPES)
@pytest.mark.parametrize("position", (1, 2))
@pytest.mark.parametrize("surface", ("inspect_run", "recover", "cancel_run"))
def test_rcr06_event_envelope_types(
    env: Env, name: str, value: Any, expected: tuple[str, str], position: int, surface: str
) -> None:
    control = env.control()
    run_id = env.submit(control)
    if position == 2:
        assert control.worker_start(run_id, pid=4242, pgid=4242, generation=1)
    if name == "event_digest":
        env.set_event(run_id, position, {name: value}, recompute=False)
    else:
        env.set_event(run_id, position, {name: value})
    _assert_refused(env, EVENT_SURFACES[surface], run_id, expected)


@pytest.mark.parametrize(
    "name", ("sequence", "state", "observed_at", "details", "previous_event_digest", "run_id", "event_digest")
)
@pytest.mark.parametrize("surface", ("inspect_run", "recover"))
def test_rcr06_missing_envelope_keys(env: Env, name: str, surface: str) -> None:
    """F-D: a missing previous_event_digest was accepted on baseline 4f689de."""
    run_id = env.submit()
    env.set_event(run_id, 1, delete=(name,))
    _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_EVENT)


def test_rcr06_nonstring_observed_at_refused_in_shared_reader(env: Env) -> None:
    """F-C: baseline recover raised raw FoundationValidationError from receipt parsing."""
    run_id = env.submit()
    env.set_event(run_id, 1, {"observed_at": 5})
    for surface in ("inspect_run", "recover", "cancel_run", "worker_start"):
        _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_EVENT)


# ================================================================= VAL-RCR-07


def _three_runs(env: Env) -> list[str]:
    control = env.control()
    return sorted(env.submit(control, project) for project in ("pa", "pb", "pc"))


@pytest.mark.parametrize("where", ("first", "middle", "last"))
@pytest.mark.parametrize("target", (0, 1, 2))
def test_rcr07_unknown_state_blocks_recovery_and_admission(env: Env, where: str, target: int) -> None:
    run_ids = _three_runs(env)
    run_id = run_ids[target]
    states = {
        "first": ["bogus", "running"],
        "middle": ["queued", "bogus", "running"],
        "last": ["queued", "running", "bogus"],
    }[where]
    env.write_chain(run_id, states)
    expected = NO_ADMISSION if where == "first" else INVALID_EVENT
    # Phase B would repair a missing index of a healthy run; it must not run.
    healthy = run_ids[(target + 1) % 3]
    healthy_index = env.index_path(env.request(healthy)["idempotency_key"])
    os.chmod(healthy_index, 0o600)
    healthy_index.unlink()
    _assert_refused(env, REQUEST_SURFACES["recover"], run_id, expected)
    _assert_refused(env, REQUEST_SURFACES["submit_run"], run_id, expected)
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        env.control(recover=True)
    assert _code(caught) == expected
    assert env.snapshot() == before
    assert env.spawned == []
    for surface in ("inspect_run", "attach_run", "worker_start", "cancel_run", "inspect_stop"):
        _assert_refused(env, EVENT_SURFACES[surface], run_id, expected)


def test_rcr07_submit_on_same_resource_is_refused(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control, "same")
    env.write_chain(run_id, ["queued", "bogus"])
    before = env.snapshot()
    with pytest.raises(RunControlError) as caught:
        control.submit_run("abort_project", {"project_id": "same", "reason": "again"}, "idem:again")
    assert _code(caught) == INVALID_EVENT
    assert env.snapshot() == before


# ================================================================= VAL-RCR-08

FORBIDDEN_CHAINS = {
    "rewind-running-queued": ["queued", "running", "queued"],
    "queued-succeeded": ["queued", "succeeded"],
    "after-terminal": ["queued", "running", "failed", "attention"],
    "first-running": ["running"],
    "first-succeeded": ["succeeded"],
    "queued-twice": ["queued", "queued"],
    "draining-to-report": ["queued", "running", "draining", "report_complete"],
}


@pytest.mark.parametrize("chain", sorted(FORBIDDEN_CHAINS))
@pytest.mark.parametrize("surface", ("inspect_run", "worker_start", "cancel_run", "recover", "inspect_stop"))
def test_rcr08_persisted_edges_outside_e(env: Env, chain: str, surface: str) -> None:
    run_id = env.submit()
    env.write_chain(run_id, FORBIDDEN_CHAINS[chain])
    expected = NO_ADMISSION if chain.startswith("first-") else INVALID_CHAIN
    _assert_refused(env, EVENT_SURFACES[surface], run_id, expected)
    assert env.journal_files() == []
    assert not env.cursor(run_id).exists()


def _terminal_tree(env: Env, kind: str) -> str:
    control = env.control()
    run_id = env.submit(control, f"t-{kind}")
    if kind == "cancelled":
        control.cancel_run(run_id, "r", f"cancel:{kind}")
        return run_id
    if kind == "failed":
        control.worker_failed(run_id)
        return run_id
    assert control.worker_start(run_id, pid=4242, pgid=4242, generation=1)
    if kind == "attention":
        control.worker_failed(run_id)
    elif kind == "failed-envelope":
        control.worker_effect_complete(run_id, FAILURE)
    elif kind == "succeeded":
        control.worker_effect_complete(run_id, RESULT)
        control.worker_report_complete(run_id)
        control.worker_succeeded(run_id)
    return run_id


@pytest.mark.parametrize("kind", ("succeeded", "attention", "failed", "failed-envelope", "cancelled"))
def test_rcr08_rewound_terminal_trees_are_refused(env: Env, kind: str) -> None:
    """H3'': appending queued after a writer-built terminal no longer redispatches."""
    run_id = _terminal_tree(env, kind)
    receipts = env.receipts()
    env.append_event(run_id, "queued", {"owner_id": "server:rcr"})
    for surface in ("recover", "worker_start", "cancel_run", "inspect_run"):
        _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_CHAIN)
    assert env.spawned == []
    assert env.receipts() == receipts
    assert env.journal_files() == [] or kind == "cancelled"


def test_rcr08_first_running_cancel_refuses_before_journal_claim(env: Env) -> None:
    """F-E: baseline claimed the journal, then refused, leaving it applying."""
    run_id = env.submit()
    env.write_chain(run_id, ["running"], details={1: {"generation": 1, "owner_id": "x", "pgid": 9, "pid": 9}})
    _assert_refused(env, REQUEST_SURFACES["cancel_run"], run_id, NO_ADMISSION)
    assert env.journal_files() == []


# ================================================================= VAL-RCR-09


def _path_to(state: str) -> list[str]:
    """Shortest E path from the empty stream to ``state``."""
    frontier: list[list[str]] = [["queued"]]
    while frontier:
        path = frontier.pop(0)
        if path[-1] == state:
            return path
        for nxt in sorted(EDGES.get(path[-1], set())):
            if nxt not in path:
                frontier.append([*path, nxt])
    raise AssertionError(state)


ALL_EDGES = sorted(
    (previous, state) for previous, targets in EDGES.items() if previous is not None for state in targets
)


def test_rcr09_edge_table_matches_contract() -> None:
    assert len(ALL_EDGES) == 25
    for previous in [None, *STATES]:
        for state in STATES:
            allowed = state in EDGES.get(previous, set())
            if allowed:
                RunControl._validate_transition(previous, state)
            else:
                with pytest.raises(RunControlError) as caught:
                    RunControl._validate_transition(previous, state)
                assert caught.value.code == "invalid_transition"


@pytest.mark.parametrize(("previous", "state"), ALL_EDGES)
def test_rcr09_every_e_edge_is_accepted_s_e(env: Env, previous: str, state: str) -> None:
    """S-E: synthetic E-legal chain ending with the edge; not legacy evidence."""
    run_id = env.submit()
    chain = [*_path_to(previous), state]
    env.write_chain(run_id, chain)
    control = env.control()
    assert [event.state for event in control._load_events(run_id)] == chain
    assert control.inspect_run(run_id).state == state


@pytest.mark.parametrize(
    "chain",
    (
        ["queued", "running", "cancel_requested", "effect_complete", "cancel_requested"],
        ["queued", "cancel_requested", "cancelled"],
        ["queued", "running", "draining", "effect_complete", "report_complete", "succeeded"],
        ["queued", "running", "effect_complete", "report_complete", "cancel_requested", "attention"],
    ),
)
def test_rcr09_writerless_e_legal_chains_are_accepted_s_e(env: Env, chain: list[str]) -> None:
    """Repeated cancel_requested and cancel_requested->cancelled have no writer path."""
    run_id = env.submit()
    env.write_chain(run_id, chain)
    control = env.control()
    assert [event.state for event in control._load_events(run_id)] == chain
    assert control.inspect_run(run_id).state == chain[-1]


def test_rcr09_h_p_normal_and_library_producers(env: Env) -> None:
    control = env.control()
    produced: set[tuple[str | None, str]] = set()

    def record(run_id: str) -> None:
        states = [event.state for event in control._load_events(run_id)]
        produced.update(zip([None, *states[:-1]], states))

    for kind in ("succeeded", "attention", "failed", "failed-envelope", "cancelled"):
        record(_terminal_tree(env, kind))
    # library-only edges
    late = env.submit(control, "late-effect")
    assert control.worker_start(late, pid=4242, pgid=4242, generation=1)
    control.worker_effect_complete(late, RESULT)
    control.worker_effect_complete(late, FAILURE)
    record(late)
    report = env.submit(control, "late-report")
    assert control.worker_start(report, pid=4242, pgid=4242, generation=1)
    control.worker_effect_complete(report, RESULT)
    control.worker_report_complete(report)
    control.worker_effect_complete(report, FAILURE)
    record(report)
    # owner draining without cancel (bound own pid)
    owner, bound = env.bound("drain")
    owner.worker_draining(bound)
    owner.worker_effect_complete(bound, RESULT)
    owner.worker_report_complete(bound)
    owner.worker_succeeded(bound)
    record(bound)
    for previous, state in produced:
        assert state in EDGES[previous]
    assert ("effect_complete", "failed") in produced
    assert ("report_complete", "failed") in produced
    assert ("running", "draining") in produced
    assert ("draining", "effect_complete") in produced
    assert ("queued", "failed") in produced


def test_rcr09_h_f_cancel_requested_to_failed(env: Env) -> None:
    """H-F recipe: foreign live pid, recorded SIGTERM, then the owner fails."""
    pid = 777_001
    env.fake.live.add(pid)
    owner = env.control(owner_id=f"worker:{pid}:1")
    run_id = env.submit(owner, "hf")
    assert owner.worker_start(run_id, pid=pid, pgid=pid, generation=1)
    env.control().cancel_run(run_id, "stop", "cancel:hf")
    assert env.states(run_id)[-1] == "cancel_requested"
    assert env.fake.signals and env.fake.signals[0][0] == pid
    with env.as_pid(pid):
        owner.worker_effect_complete(run_id, FAILURE)
    assert env.states(run_id)[-2:] == ["cancel_requested", "failed"]
    assert env.control().inspect_run(run_id).state == "failed"


def test_rcr09_h_f_cancel_after_report_complete_and_late_progress(env: Env) -> None:
    """H-F: cancel after report_complete; late effect_complete after cancel_requested."""
    pid = 777_003
    env.fake.live.add(pid)
    owner = env.control(owner_id=f"worker:{pid}:1")
    reported = env.submit(owner, "reported")
    late = env.submit(owner, "late")
    for run_id in (reported, late):
        assert owner.worker_start(run_id, pid=pid, pgid=pid, generation=1)
    with env.as_pid(pid):
        owner.worker_effect_complete(reported, RESULT)
        owner.worker_report_complete(reported)
    env.control().cancel_run(reported, "stop", "cancel:reported")
    env.control().cancel_run(late, "stop", "cancel:late")
    with env.as_pid(pid):
        owner.worker_effect_complete(late, RESULT)
    assert env.states(reported)[-2:] == ["report_complete", "cancel_requested"]
    assert env.states(late)[-2:] == ["cancel_requested", "effect_complete"]
    for run_id in (reported, late):
        states = [event.state for event in env.control()._load_events(run_id)]
        assert all(b in EDGES[a] for a, b in zip([None, *states[:-1]], states))


def test_rcr09_h_c_adopted_pending_receipt(env: Env) -> None:
    """H-C: crash between receipt and terminal event; recovery adopts the receipt."""
    control = env.control()
    run_id = env.submit(control, "hc")
    original = RunControl._append_event_unlocked
    fired = {"done": False}

    def crashing(self: RunControl, run: str, state: str, details: Any) -> Any:
        if state == "cancelled" and not fired["done"]:
            fired["done"] = True
            raise Crash(state)
        return original(self, run, state, details)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(RunControl, "_append_event_unlocked", crashing)
        with pytest.raises(Crash):
            control.cancel_run(run_id, "r", "cancel:hc")
    env.control(recover=True)
    states = env.states(run_id)
    assert states[-1] == "cancelled"
    assert env.events(run_id)[-1]["details"].get("terminal_source") == "pending_receipt"
    assert env.control().inspect_run(run_id).state == "cancelled"


def test_rcr09_h_v_legacy_draining_shape(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control, "hv")
    assert control.worker_start(run_id, pid=4242, pgid=4242, generation=1)
    control._append_event(run_id, "draining", {})
    assert env.control().inspect_run(run_id).state == "draining"


# ================================================================= VAL-RCR-10


def test_rcr10_requested_invalid_transition_stays_invalid_transition(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    with pytest.raises(RunControlError) as caught:
        control._append_event(run_id, "succeeded", {})
    assert caught.value.code == "invalid_transition"
    assert env.states(run_id) == ["queued"]


def test_rcr10_caller_and_absent_domains(env: Env) -> None:
    control = env.control()
    with pytest.raises(RunControlError) as caught:
        control.inspect_run("run:not-hex")
    assert caught.value.code == "invalid_argument"
    with pytest.raises(RunControlError) as caught:
        control.inspect_run("run:" + "a" * 64)
    assert _code(caught) == ("not_found", "run was not found")


def _c2(env: Env, operation: str = "abort_project") -> str:
    """A request without events (C2), written by the unchanged baseline writer."""
    control = env.control()
    run_id = env.submit_advance(control, "c2") if operation == "advance_project" else env.submit(control, "c2")
    for path in (env.run_dir(run_id) / "events").glob("*.json"):
        os.chmod(path, 0o600)
        path.unlink()
    index = env.index_path(env.request(run_id)["idempotency_key"])
    os.chmod(index, 0o600)
    index.unlink()
    return run_id


def test_rcr10_c2_domains(env: Env) -> None:
    run_id = _c2(env, "advance_project")
    control = env.control()
    assert control.request_payload(run_id)[0] == "advance_project"
    with pytest.raises(RunControlError) as caught:
        control.inspect_run(run_id)
    assert caught.value.code == "admission_incomplete"
    with pytest.raises(RunControlError) as caught:
        control.steer_attempt(run_id, {"project_id": "c2", "actor": "orchestrator"})
    assert _code(caught) == ("invalid_transition", "run is not an active advance_project or end_mission")
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "r", "cancel:c2")
    assert caught.value.code == "not_found"
    env.set_request(run_id, {"created_at": 5})
    for surface in ("inspect_run", "steer_attempt", "cancel_run", "request_payload"):
        _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


def test_rcr10_record_entry_messages(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    path = env.request_path(run_id)
    content = path.read_bytes()
    os.chmod(path, 0o600)
    path.unlink()
    path.mkdir()
    with pytest.raises(RunControlError) as caught:
        control.inspect_run(run_id)
    assert _code(caught) == ("not_found", "run was not found")
    path.rmdir()
    elsewhere = env.root / "elsewhere.json"
    elsewhere.write_bytes(content)
    path.symlink_to(elsewhere)
    with pytest.raises(RunControlError) as caught:
        control.inspect_run(run_id)
    assert _code(caught) == ("integrity_error", "run record is not a regular file")
    path.unlink()
    path.write_bytes(content)
    original = Path.read_text

    def vanished(self: Path, *args: Any, **kwargs: Any) -> str:
        if self == path:
            raise FileNotFoundError(str(self))
        return original(self, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_text", vanished)
        with pytest.raises(RunControlError) as caught:
            control.inspect_run(run_id)
    assert _code(caught) == ("not_found", "run record was not found")


@pytest.mark.parametrize("surface", ("inspect_run", "recover", "submit_run"))
def test_rcr10_nonstring_first_state_message_delta(env: Env, surface: str) -> None:
    """Typed-envelope precedence: baseline admission reported no admission event."""
    run_id = env.submit()
    env.set_event(run_id, 1, {"state": 7})
    _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_EVENT)


@pytest.mark.parametrize("state", ("running", "bogus", "succeeded"))
@pytest.mark.parametrize("surface", ("inspect_run", "recover", "worker_start"))
def test_rcr10_first_event_not_queued_message(env: Env, state: str, surface: str) -> None:
    run_id = env.submit()
    env.set_event(run_id, 1, {"state": state})
    _assert_refused(env, EVENT_SURFACES[surface], run_id, NO_ADMISSION)


# ================================================================= VAL-RCR-11


class _Injector:
    """Replaces run_control's ``json``/``math``; a marker in the input selects a failure."""

    kinds = {"RecursionError": RecursionError, "AttributeError": AttributeError, "MemoryError": MemoryError}

    def __init__(self) -> None:
        self.fired: list[str] = []

    def _pick(self, text: str, prefix: str) -> type[BaseException] | None:
        for name, kind in self.kinds.items():
            if prefix + name in text:
                return kind
        return None

    def loads(self, data: Any, *args: Any, **kwargs: Any) -> Any:
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
        kind = self._pick(text, "INJL_")
        if kind is not None:
            self.fired.append("loads")
            raise kind("injected")
        return json.loads(data, *args, **kwargs)

    def dumps(self, value: Any, *args: Any, **kwargs: Any) -> str:
        kind = self._pick(repr(value), "INJD_")
        if kind is not None:
            self.fired.append("dumps")
            raise kind("injected")
        return json.dumps(value, *args, **kwargs)

    def isfinite(self, value: float) -> bool:
        self.fired.append("isfinite")
        raise RecursionError("injected")

    def __getattr__(self, name: str) -> Any:
        return getattr(json, name)


@contextmanager
def _inject(target: str = "json") -> Iterator[_Injector]:
    injector = _Injector()
    with pytest.MonkeyPatch.context() as patch:
        if target == "json":
            patch.setattr(runs, "json", injector)
        else:
            class _Math:
                isfinite = staticmethod(injector.isfinite)
            patch.setattr(runs, "math", _Math())
        yield injector


def _plant_index_extra(env: Env, run_id: str, raw: str) -> None:
    key = env.request(run_id)["idempotency_key"]
    path = env.index_path(key)
    env.write(path, path.read_bytes()[:-2] + raw.encode() + b"}\n")


@pytest.mark.parametrize(
    ("record", "point"),
    (
        ("request", "loads"), ("event", "loads"), ("index", "loads"),
        ("request", "dumps"), ("event", "dumps"), ("index", "dumps"),
    ),
)
def test_rcr11_injected_recursion_error_is_contained(env: Env, record: str, point: str) -> None:
    run_id = env.submit()
    marker = ("INJL_" if point == "loads" else "INJD_") + "RecursionError"
    expected = {
        ("request", "loads"): INVALID_RECORD,
        ("event", "loads"): INVALID_RECORD,
        ("index", "loads"): INVALID_INDEX,
        ("request", "dumps"): INVALID_REQUEST,
        ("event", "dumps"): INVALID_EVENT,
        ("index", "dumps"): INVALID_INDEX,
    }[(record, point)]
    if record == "request":
        key = "probe" if point == "loads" else "arguments.probe"
        env.set_request(run_id, {key: marker})
    elif record == "event":
        env.set_event(run_id, 1, {"details.probe": marker})
    elif point == "loads":
        _plant_index_extra(env, run_id, f',"probe":"{marker}"')
    else:
        key = env.request(run_id)["idempotency_key"]
        digest = hashlib.sha256(key.encode()).hexdigest()
        env.write(env.index_path(key), canonical(
            {"key_digest": "sha256:" + digest, "run_id": f"run:{marker}", "schema_version": 1}
        ))
    surface = "inspect_run" if record != "index" else "recover"
    if record == "request" and point == "dumps":
        surface = "recover"  # the fingerprint is serialized on V4 paths
    with _inject() as injector:
        _assert_refused(env, REQUEST_SURFACES[surface], run_id, expected)
    assert injector.fired


@pytest.mark.parametrize("record", ("request", "event"))
def test_rcr11_injected_recursion_in_finite_walk_is_contained(env: Env, record: str) -> None:
    run_id = env.submit()
    if record == "request":
        env.set_request(run_id, {"probe": 1.5})
        expected = INVALID_REQUEST
    else:
        env.set_event(run_id, 1, {"details.probe": 1.5})
        expected = INVALID_EVENT
    with _inject("math") as injector:
        _assert_refused(env, REQUEST_SURFACES["inspect_run"], run_id, expected)
    assert injector.fired == ["isfinite"]


@pytest.mark.parametrize("kind", ("AttributeError", "MemoryError"))
@pytest.mark.parametrize("record", ("request", "event", "index"))
def test_rcr11_programmer_errors_are_not_translated(env: Env, kind: str, record: str) -> None:
    run_id = env.submit()
    marker = "INJL_" + kind
    if record == "request":
        env.set_request(run_id, {"probe": marker})
    elif record == "event":
        env.set_event(run_id, 1, {"details.probe": marker})
    else:
        _plant_index_extra(env, run_id, f',"probe":"{marker}"')
    control = env.control()
    with _inject(), pytest.raises(_Injector.kinds[kind]):
        if record == "index":
            control.recover()
        else:
            control.inspect_run(run_id)


def test_rcr11_lone_surrogate_in_event_and_index(env: Env) -> None:
    run_id = env.submit()
    other = env.submit(project="p2")
    env.set_event(run_id, 1, {"observed_at": "@@S@@"}, raws={"@@S@@": '"2026\\ud800"'}, recompute=False)
    for surface in ("inspect_run", "recover", "cancel_run"):
        _assert_refused(env, EVENT_SURFACES[surface], run_id, INVALID_EVENT)
    key = env.request(other)["idempotency_key"]
    digest = hashlib.sha256(key.encode()).hexdigest()
    env.write(env.index_path(key), b'{"key_digest":"sha256:' + digest.encode()
              + b'","run_id":"run:\\ud800","schema_version":1}\n')
    env.set_event(run_id, 1, {"observed_at": "2026-11-03T00:00:00.000Z"})
    for surface in ("recover", "submit_run"):
        _assert_refused(env, REQUEST_SURFACES[surface], other, INVALID_INDEX)


@pytest.mark.parametrize("record", ("request", "event"))
@pytest.mark.parametrize("surface", ("inspect_run", "recover"))
def test_rcr11_overlong_integer_is_contained(env: Env, record: str, surface: str) -> None:
    run_id = env.submit()
    digits = "9" * (sys.get_int_max_str_digits() + 1)
    if record == "request":
        env.set_request(run_id, {"probe": "@@B@@"}, raws={"@@B@@": digits})
    else:
        env.set_event(run_id, 1, {"details.probe": "@@B@@"}, raws={"@@B@@": digits}, recompute=False)
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_RECORD)


def test_rcr11_index_overlong_integer_and_deep_index(env: Env) -> None:
    run_id = env.submit()
    _plant_index_extra(env, run_id, ',"probe":' + "9" * 5000)
    _assert_refused(env, REQUEST_SURFACES["recover"], run_id, INVALID_INDEX)


# ================================================================= VAL-RCR-12

REQUEST_CLASSES: dict[str, Callable[[Env, str], None]] = {
    "type": lambda env, run_id: env.set_request(run_id, {"generation": "1"}),
    "finite": lambda env, run_id: env.set_request(run_id, {"x": "@@N@@"}, raws={"@@N@@": "NaN"}),
    "v4": lambda env, run_id: env.set_request(run_id, {"arguments.reason": "forged"}),
    "schema": lambda env, run_id: env.set_request(run_id, {"schema_version": True}),
}
EVENT_CLASSES: dict[str, tuple[Callable[[Env, str], None], tuple[str, str]]] = {
    "type": (lambda env, run_id: env.set_event(run_id, 1, {"sequence": True}), INVALID_EVENT),
    "finite": (
        lambda env, run_id: env.set_event(run_id, 1, {"details.x": "@@N@@"}, raws={"@@N@@": "NaN"},
                                          recompute=False),
        INVALID_EVENT,
    ),
    "state": (lambda env, run_id: env.write_chain(run_id, ["queued", "bogus"]), INVALID_EVENT),
    "edge": (lambda env, run_id: env.write_chain(run_id, ["queued", "running", "queued"]), INVALID_CHAIN),
    "first": (lambda env, run_id: env.write_chain(run_id, ["succeeded"]), NO_ADMISSION),
}


@pytest.mark.parametrize("klass", sorted(REQUEST_CLASSES))
@pytest.mark.parametrize("surface", sorted(REQUEST_SURFACES))
def test_rcr12_request_rba_matrix(env: Env, klass: str, surface: str) -> None:
    run_id = env.submit()
    REQUEST_CLASSES[klass](env, run_id)
    _assert_refused(env, REQUEST_SURFACES[surface], run_id, INVALID_REQUEST)


@pytest.mark.parametrize("klass", sorted(EVENT_CLASSES))
@pytest.mark.parametrize("surface", sorted(EVENT_SURFACES))
def test_rcr12_event_rba_matrix(env: Env, klass: str, surface: str) -> None:
    run_id = env.submit()
    plant, expected = EVENT_CLASSES[klass]
    plant(env, run_id)
    _assert_refused(env, EVENT_SURFACES[surface], run_id, expected)


@pytest.mark.parametrize("klass", sorted(EVENT_CLASSES))
@pytest.mark.parametrize(
    "surface", ("worker_draining", "effect_success", "effect_failure", "report_complete",
                "worker_succeeded", "worker_cancelled", "worker_failed")
)
def test_rcr12_event_rba_worker_surfaces(env: Env, klass: str, surface: str) -> None:
    owner, run_id = env.bound()
    plant, expected = EVENT_CLASSES[klass]
    plant(env, run_id)
    calls: dict[str, Callable[[RunControl, str], Any]] = {
        "worker_draining": lambda c, r: c.worker_draining(r),
        "effect_success": lambda c, r: c.worker_effect_complete(r, RESULT),
        "effect_failure": lambda c, r: c.worker_effect_complete(r, FAILURE),
        "report_complete": lambda c, r: c.worker_report_complete(r),
        "worker_succeeded": lambda c, r: c.worker_succeeded(r),
        "worker_cancelled": lambda c, r: c.worker_cancelled(r),
        "worker_failed": lambda c, r: c.worker_failed(r),
    }
    _assert_refused(env, calls[surface], run_id, expected, control=owner)


def test_rcr12_worker_start_precedence(env: Env) -> None:
    run_id = env.submit()
    env.write_chain(run_id, ["queued", "running", "queued"])
    control = env.control()
    with pytest.raises(RunControlError) as caught:
        control.worker_start(run_id, pid=1, pgid=1, generation=0)
    assert caught.value.code == "invalid_argument"
    with pytest.raises(RunControlError) as caught:
        control.worker_start(run_id, pid=1, pgid=1, generation=2)
    assert caught.value.code == "stale"
    env.set_request(run_id, {"generation": 1.0})
    with pytest.raises(RunControlError) as caught:
        control.worker_start(run_id, pid=1, pgid=1, generation=2)
    assert _code(caught) == INVALID_REQUEST


# ================================================================= VAL-RCR-13


def test_rcr13_completed_cancel_replay_after_corruption(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control)
    first = control.cancel_run(run_id, "r", "cancel:replay")
    assert first.state == "cancelled"
    assert control.cancel_run(run_id, "r", "cancel:replay").state == "cancelled"
    journals = {path: path.read_bytes() for path in env.journal_files()}
    env.set_request(run_id, {"created_at": 7})
    _assert_refused(env, REQUEST_SURFACES["cancel_run"], run_id, INVALID_REQUEST)
    assert {path: path.read_bytes() for path in env.journal_files()} == journals


def test_rcr13_existing_applying_journal_is_untouched(env: Env) -> None:
    """An applying record (F-A tree) stays byte-identical; nothing is repaired."""
    control = env.control()
    run_id = env.submit(control)
    env.set_request(run_id, {"created_at": "@@S@@"}, raws={"@@S@@": '"2026\\ud800"'})
    with pytest.raises(RunControlError):
        control.cancel_run(run_id, "r", "cancel:fa")
    journals = {path: path.read_bytes() for path in env.journal_files()}
    assert any(b'"applying"' in data for data in journals.values())
    env.set_request(run_id, {"created_at": 7})
    _assert_refused(env, REQUEST_SURFACES["cancel_run"], run_id, INVALID_REQUEST)
    assert {path: path.read_bytes() for path in env.journal_files()} == journals


def test_rcr13_terminal_cancel_returns_summary_without_stop_validation(env: Env) -> None:
    """D6: a terminal valid history returns its summary; STOP records are not read."""
    run_id = _terminal_tree(env, "succeeded")
    garbage = env.run_dir(run_id) / "stop" / "garbage"
    garbage.parent.mkdir(parents=True, exist_ok=True)
    garbage.write_bytes(b"x")
    assert env.control().cancel_run(run_id, "r", "cancel:done").state == "succeeded"


# ================================================================= VAL-RCR-14


def _chain_items(exc: BaseException) -> list[BaseException]:
    seen: set[int] = set()
    queue: list[BaseException | None] = [exc]
    items: list[BaseException] = []
    while queue:
        item = queue.pop(0)
        if item is None or id(item) in seen:
            continue
        seen.add(id(item))
        items.append(item)
        queue.extend((item.__cause__, item.__context__))
    return items


PRIVACY_CASES: dict[str, tuple[Callable[[Env, str], None], str, int]] = {
    # name: (plant, surface, Unicode causes allowed)
    "request-utf8": (
        lambda env, r: env.set_request(r, {"created_at": "@@C@@"}, raws={"@@C@@": b'"2026\xff"'}),
        "inspect_run", 1,
    ),
    "request-utf8-extra-canary": (
        lambda env, r: env.set_request(r, {"created_at": "@@C@@", "probe_note": CANARY},
                                       raws={"@@C@@": b'"2026\xff"'}),
        "recover", 1,
    ),
    "event-utf8": (
        lambda env, r: env.set_event(r, 1, {"observed_at": "@@C@@", "details.note": CANARY},
                                     raws={"@@C@@": b'"2026\xff"'}, recompute=False),
        "inspect_run", 1,
    ),
    "event-surrogate": (
        lambda env, r: env.set_event(r, 1, {"observed_at": "@@S@@", "details.note": CANARY},
                                     raws={"@@S@@": '"2026\\ud800"'}, recompute=False),
        "inspect_run", 1,
    ),
    "index-surrogate": (
        lambda env, r: env.write(
            env.index_path(env.request(r)["idempotency_key"]),
            b'{"key_digest":"sha256:' + hashlib.sha256(env.request(r)["idempotency_key"].encode()).hexdigest().encode()
            + b'","note":"' + CANARY.encode() + b'","run_id":"run:\\ud800","schema_version":1}\n',
        ),
        "recover", 1,
    ),
    "generation-canary": (lambda env, r: env.set_request(r, {"generation": CANARY}), "inspect_run", 0),
    "syntax": (
        lambda env, r: env.write(env.request_path(r), env.request_path(r).read_bytes()[:-3]),
        "inspect_run", 0,
    ),
    "event-nan": (
        lambda env, r: env.set_event(r, 1, {"details.note": CANARY, "details.x": "@@N@@"},
                                     raws={"@@N@@": "NaN"}, recompute=False),
        "recover", 0,
    ),
    "overlong-int": (
        lambda env, r: env.set_request(r, {"probe": "@@B@@"}, raws={"@@B@@": "9" * 5000}),
        "inspect_run", 0,
    ),
    "unknown-state": (
        lambda env, r: env.write_chain(r, ["queued", "bogus"], details={2: {"note": CANARY}}),
        "recover", 0,
    ),
    "v4": (lambda env, r: env.set_request(r, {"arguments.reason": f"forged {CANARY}"}), "recover", 0),
}


@pytest.mark.parametrize("case", sorted(PRIVACY_CASES))
def test_rcr14_narrow_privacy_claim(env: Env, case: str) -> None:
    run_id = env.submit()  # the canary is in arguments.reason of every request
    plant, surface, unicode_allowed = PRIVACY_CASES[case]
    plant(env, run_id)
    with pytest.raises(Exception) as caught:
        REQUEST_SURFACES[surface](env.control(), run_id)
    exc = caught.value
    if isinstance(exc, RunControlError):
        assert CANARY not in json.dumps(exc.as_envelope())
        assert CANARY not in str(public_error(exc)) and CANARY not in str(public_error(exc).code)
    assert CANARY not in str(exc) and CANARY not in repr(exc)
    items = _chain_items(exc)
    excluded = [item for item in items if isinstance(item, (UnicodeDecodeError, UnicodeEncodeError))]
    assert len(excluded) <= unicode_allowed
    for item in items:
        assert CANARY not in str(item), (type(item).__name__, case)
        if item not in excluded:
            assert CANARY not in repr(item), (type(item).__name__, case)
    # Privacy is asserted first; the typed domain is the separate RCR outcome.
    assert isinstance(exc, RunControlError) and exc.code == "integrity_error"


# ================================================================= VAL-RCR-15


def test_rcr15a_writer_bytes_are_golden(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "_utc_now", lambda: "2026-11-03T00:00:00.000Z")
    control = env.control(owner_id="server:golden")
    arguments = {"project_id": "golden", "reason": "r"}
    run_id = control.submit_run("abort_project", arguments, "idem:golden").run_id
    token = token_for("abort_project", arguments, "idem:golden")
    assert run_id == "run:" + token
    request = env.request(run_id)
    assert env.request_path(run_id).read_bytes() == canonical(request)
    assert sorted(request) == sorted([*REQUIRED_REQUEST_FIELDS, "schema_version"])
    assert request["schema_version"] == 1 and request["generation"] == 1
    body = {
        "details": {"owner_id": "server:golden"},
        "observed_at": "2026-11-03T00:00:00.000Z",
        "previous_event_digest": None,
        "run_id": run_id,
        "schema_version": 1,
        "sequence": 1,
        "state": "queued",
    }
    assert env.event_path(run_id, 1).read_bytes() == canonical({**body, "event_digest": event_digest(body)})
    key_digest = "sha256:" + hashlib.sha256(b"idem:golden").hexdigest()
    assert env.index_path("idem:golden").read_bytes() == canonical(
        {"key_digest": key_digest, "run_id": run_id, "schema_version": 1}
    )


def test_rcr15a_public_error_surface_is_unchanged() -> None:
    mapping = json.dumps(sorted(foundation_tools._ERROR_MAP.items()))
    assert hashlib.sha256(mapping.encode()).hexdigest() == ERROR_MAP_SHA256
    assert public_error(RunControlError("integrity_error", "x")).code == "integrity_error"


ERROR_MAP_SHA256 = "e734cd429f94bd14ab6f2746a041cc7e46653405e318c938f50955eb29202f5c"


def test_rcr15a_valid_cursor_and_stop_readers_are_preserved(env: Env) -> None:
    pid = 777_002
    env.fake.live.add(pid)
    owner = env.control(owner_id=f"worker:{pid}:1")
    run_id = env.submit(owner, "stop")
    assert owner.worker_start(run_id, pid=pid, pgid=pid, generation=1)
    control = env.control()
    status = control.inspect_stop(run_id)
    assert status.request == "none"
    control.cancel_run(run_id, "stop", "cancel:stop")
    status = control.inspect_stop(run_id)
    assert status.request != "none"
    assert env.cursor(run_id).exists()


def test_rcr15b_result_reader_scope_is_unchanged(env: Env) -> None:
    run_id = _terminal_tree(env, "succeeded")
    result = env.run_dir(run_id) / "result.json"
    env.write(result, b'{"probe":NaN}\n')
    summary = env.control().inspect_run(run_id)
    assert summary.state == "succeeded"
    assert summary.result is not None and summary.result["probe"] != summary.result["probe"]


def test_rcr15c_invalid_events_precede_stop_validation(env: Env) -> None:
    control = env.control()
    run_id = env.submit(control, "stopc")
    garbage = env.run_dir(run_id) / "stop" / "garbage"
    garbage.parent.mkdir(parents=True)
    garbage.write_bytes(b"x")
    with pytest.raises(StopCustodyInvalid):
        control.inspect_stop(run_id)
    env.set_event(run_id, 1, {"sequence": True})
    with pytest.raises(RunControlError) as caught:
        control.inspect_stop(run_id)
    assert not isinstance(caught.value, StopCustodyInvalid)
    assert _code(caught) == INVALID_EVENT


# ================================================================= VAL-RCR-16 (LG-2)


def _corpus_cases() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    for side in ("A", "B"):
        manifest = json.loads((FIXTURES / "corpus" / side / "manifest.json").read_text())
        cases.extend((side, case) for case in manifest["cases"])
    return cases


def test_rcr16_lg2_fixture_bytes_match_manifest() -> None:
    count = 0
    for side in ("A", "B"):
        manifest = json.loads((FIXTURES / "corpus" / side / "manifest.json").read_text())
        for entry in manifest["files"]:
            data = (FIXTURES / "corpus" / side / entry["path"]).read_bytes()
            assert len(data) == entry["bytes"]
            assert hashlib.sha256(data).hexdigest() == entry["sha256"], entry["path"]
            count += 1
    assert count > 0
    assert len(_corpus_cases()) == 66


@pytest.mark.parametrize(
    ("side", "case"), _corpus_cases(), ids=[f"{side}-{case['case_id']}" for side, case in _corpus_cases()]
)
def test_rcr16_lg2_baseline_trees_are_accepted(env: Env, side: str, case: dict[str, Any]) -> None:
    """B-N/B-L b307cc6 writer trees pass the strict readers unchanged."""
    shutil.rmtree(env.root)
    shutil.copytree(FIXTURES / "corpus" / side / "cases" / case["case_id"] / "tree", env.root, symlinks=True)
    control = env.control()
    run_id = case["run_id"]
    assert [event.state for event in control._load_events(run_id)] == case["states"]
    assert control._load_request(run_id).run_id == run_id
    assert control.inspect_run(run_id).state == case["states"][-1]
    control.inspect_stop(run_id)
    control.recover()
    assert control.recovery_blocked == ()


# ================================================================= VAL-RCR-18


def test_rcr18_isolation_of_a_corrupt_run(env: Env) -> None:
    control = env.control()
    corrupt = env.submit(control, "corrupt")
    healthy = env.submit(control, "healthy")
    env.set_request(corrupt, {"generation": "1"})
    corrupt_before = {
        path: path.read_bytes() for path in sorted(env.run_dir(corrupt).rglob("*")) if path.is_file()
    }
    _assert_refused(env, REQUEST_SURFACES["recover"], corrupt, INVALID_REQUEST)
    _assert_refused(env, REQUEST_SURFACES["submit_run"], corrupt, INVALID_REQUEST)
    assert control.inspect_run(healthy).state == "queued"
    assert control.worker_start(healthy, pid=4242, pgid=4242, generation=1)
    assert control.cancel_run(healthy, "r", "cancel:healthy").state in {"cancel_requested", "cancelled"}
    assert {
        path: path.read_bytes() for path in sorted(env.run_dir(corrupt).rglob("*")) if path.is_file()
    } == corrupt_before


# ================================================================= VAL-RCR-19

SCHEMA_VALUES: dict[str, tuple[str | None, bool]] = {
    # label: (raw JSON or None for absent, accepted)
    "absent": (None, True), "1": ("1", True), "0": ("0", True), "-1": ("-1", True), "2": ("2", True),
    "True": ("true", False), "str1": ('"1"', False), "float1": ("1.0", False), "null": ("null", False),
    "list": ("[]", False), "dict": ("{}", False), "NaN": ("NaN", False), "1e999": ("1e999", False),
}


@pytest.mark.parametrize("label", sorted(SCHEMA_VALUES))
@pytest.mark.parametrize("record", ("request", "event"))
@pytest.mark.parametrize("path", ("per_run", "admission"))
def test_rcr19_schema_version_grid(env: Env, label: str, record: str, path: str) -> None:
    run_id = env.submit()
    raw, accepted = SCHEMA_VALUES[label]
    token_before = run_id
    if record == "request":
        if raw is None:
            env.set_request(run_id, delete=("schema_version",))
        else:
            env.set_request(run_id, {"schema_version": "@@V@@"}, raws={"@@V@@": raw})
        expected = INVALID_REQUEST
    else:
        if raw is None:
            env.set_event(run_id, 1, delete=("schema_version",))
        else:
            env.set_event(run_id, 1, {"schema_version": "@@V@@"}, raws={"@@V@@": raw},
                          recompute=label not in {"NaN", "1e999"})
        expected = INVALID_EVENT
    surface = "inspect_run" if path == "per_run" else "recover"
    if accepted:
        REQUEST_SURFACES[surface](env.control(), run_id)
        assert env.control().inspect_run(token_before).run_id == token_before
        if path == "admission":
            assert env.spawned == [run_id]
    else:
        _assert_refused(env, REQUEST_SURFACES[surface], run_id, expected)


# ================================================================= VAL-RCR-20

DEPTHS = (100, 999, 1000, 1001, 1500, 2048)


def test_rcr20_records_recursion_limit_and_discriminator() -> None:
    """M-27 needs a baseline-accepted depth above this process's recursion limit."""
    limit = sys.getrecursionlimit()
    print(f"RCR20 recursionlimit={limit} discriminating_depths={[d for d in DEPTHS if d > limit]}")
    assert any(depth > limit for depth in DEPTHS)


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("record", ("request", "event"))
@pytest.mark.parametrize("surface", ("inspect_run", "recover"))
def test_rcr20_deep_finite_records_are_accepted(env: Env, depth: int, record: str, surface: str) -> None:
    run_id = env.submit()
    if record == "request":
        env.set_request(run_id, {"probe_deep": "@@D@@"}, raws={"@@D@@": deep_text(depth)})
    else:
        env.set_event(run_id, 1, {"details.probe_deep": "@@D@@"}, raws={"@@D@@": deep_text(depth)})
    REQUEST_SURFACES[surface](env.control(), run_id)
    if surface == "recover":
        assert env.spawned == [run_id]


def test_rcr20_iterative_walk_handles_maximum_depth() -> None:
    assert runs._all_finite(deep(2048))
    nested = deep(2047)
    nested_with_nan: Any = [nested, [float("nan")]]
    assert not runs._all_finite(nested_with_nan)


# ================================================================= VAL-RCR-21 (LIM)


def test_rcr21_lim_m8_m9_do_not_read_events(env: Env) -> None:
    run_id = env.submit()
    env.write_chain(run_id, ["queued", "running", "queued"])
    control = env.control()
    assert _lock(control, run_id) == "entered"
    assert control.request_payload(run_id)[0] == "abort_project"


def test_rcr21_lim_m10_worker_draining_appends_without_request(env: Env) -> None:
    """Section 9.3 oracle: +1 draining, cursor bytes unchanged, nothing else."""
    owner, run_id = env.bound()
    cursor = env.cursor(run_id).read_bytes()
    env.set_request(run_id, {"generation": "1"})
    before = env.snapshot()
    owner.worker_draining(run_id)
    after = env.snapshot()
    added = sorted(set(after) - set(before))
    assert added == [str(env.event_path(run_id, 3).relative_to(env.root))]
    assert {k: v for k, v in after.items() if k not in added} == before
    assert env.events(run_id)[-1]["state"] == "draining"
    assert env.events(run_id)[-1]["details"] == {"stop_actor": "owner"}
    assert env.cursor(run_id).read_bytes() == cursor
    assert env.spawned == [] and env.fake.signals == []


def _m10_unbound(env: Env) -> tuple[RunControl, RunControl, str]:
    control = env.control(owner_id="worker:own:1")
    return control, control, env.submit(control, "unbound")


def _m10_foreign_pid(env: Env) -> tuple[RunControl, RunControl, str]:
    control = env.control(owner_id="worker:own:1")
    run_id = env.submit(control, "foreign")
    assert control.worker_start(run_id, pid=os.getpid() + 1, pgid=1, generation=1)
    return control, control, run_id


def _m10_other_owner(env: Env) -> tuple[RunControl, RunControl, str]:
    owner, run_id = env.bound("other-owner")
    return owner, env.control(owner_id="worker:else:1"), run_id


def _m10_effect(env: Env) -> tuple[RunControl, RunControl, str]:
    owner, run_id = env.bound("effect")
    owner.worker_effect_complete(run_id, RESULT)
    return owner, owner, run_id


def _m10_drained(env: Env) -> tuple[RunControl, RunControl, str]:
    owner, run_id = env.bound("drained")
    owner.worker_draining(run_id)
    return owner, owner, run_id


def _m10_terminal(env: Env) -> tuple[RunControl, RunControl, str]:
    owner, run_id = env.bound("done")
    owner.worker_failed(run_id)
    return owner, owner, run_id


M10_CELLS: dict[str, tuple[Callable[[Env], tuple[RunControl, RunControl, str]], tuple[str, str] | None]] = {
    "unbound": (_m10_unbound, ("integrity_error", "caller is not the bound run owner")),
    "foreign_pid": (_m10_foreign_pid, ("integrity_error", "caller is not the bound run owner")),
    "other_owner": (_m10_other_owner, ("integrity_error", "caller is not the bound run owner")),
    "effect_complete_last": (_m10_effect, ("invalid_transition", "")),
    "draining_last": (_m10_drained, ("invalid_transition", "")),
    "terminal_last": (_m10_terminal, None),
}


@pytest.mark.parametrize("cell", sorted(M10_CELLS))
def test_rcr21_lim_m10_companion_cells(env: Env, cell: str) -> None:
    """Request-only corruption; worker_draining never reads the request (M10)."""
    build, expected = M10_CELLS[cell]
    _owner, caller, run_id = build(env)
    env.set_request(run_id, {"generation": "1"})
    before = env.snapshot()
    if expected is None:
        caller.worker_draining(run_id)
    else:
        with pytest.raises(RunControlError) as caught:
            caller.worker_draining(run_id)
        assert caught.value.code == expected[0]
        if expected[1]:
            assert caught.value.public_message == expected[1]
    assert env.snapshot() == before
    assert env.spawned == [] and env.fake.signals == []


def test_rcr21_lim_m11_failure_branch_writes_private_before_refusal(env: Env) -> None:
    owner, run_id = env.bound()
    cursor = env.cursor(run_id).read_bytes()
    env.set_request(run_id, {"generation": None})
    receipts = env.receipts()
    with pytest.raises(RunControlError) as caught:
        owner.worker_effect_complete(run_id, FAILURE)
    assert _code(caught) == INVALID_REQUEST
    assert (env.run_dir(run_id) / "private" / "tool-error.json").exists()
    assert env.receipts() == receipts
    assert env.states(run_id) == ["queued", "running"]
    assert env.cursor(run_id).read_bytes() == cursor


@pytest.mark.parametrize("terminal", ("worker_succeeded", "worker_cancelled"))
def test_rcr21_lim_m15_terminal_unlinks_cursor_without_request(env: Env, terminal: str) -> None:
    owner, run_id = env.bound()
    cursor = env.cursor(run_id).read_bytes()
    owner.worker_failed(run_id)
    assert not env.cursor(run_id).exists()
    env.write(env.cursor(run_id), cursor)
    env.set_request(run_id, {"generation": "1"})
    getattr(owner, terminal)(run_id)
    assert not env.cursor(run_id).exists()


# ================================================================= VAL-RCR-22 (LIM)


@pytest.mark.parametrize("name", ("run_identity_digest", "issuer_identity_digest"))
def test_rcr22_lim_identity_digest_format_is_not_validated(env: Env, name: str) -> None:
    """RCR-FOLLOWUP-02: a well-typed malformed digest reaches receipt construction.

    Records the retained limitation (raw foundation failure after the journal
    claim); it is evidence, not a normative behaviour oracle.
    """
    run_id = env.submit()
    env.set_request(run_id, {name: "not-a-digest"})
    control = env.control()
    assert control.inspect_run(run_id).state == "queued"
    with pytest.raises(FoundationValidationError):
        control.cancel_run(run_id, "r", "cancel:fb")
    assert any(b'"applying"' in path.read_bytes() for path in env.journal_files())


@pytest.mark.parametrize("name", ("run_identity_digest", "issuer_identity_digest"))
def test_rcr22_nonstring_identity_digest_is_refused_pre_journal(env: Env, name: str) -> None:
    """The type class (RCR-01) is refused before the journal claim."""
    run_id = env.submit()
    env.set_request(run_id, {name: 5})
    _assert_refused(env, REQUEST_SURFACES["cancel_run"], run_id, INVALID_REQUEST)
    assert env.journal_files() == []


def test_rcr22_lim_surrogate_strings_remain_type_only(env: Env) -> None:
    """RCR-FOLLOWUP-01: cancellation effects precede the journal serialization failure."""
    run_id = env.submit()
    env.set_request(run_id, {"resource_key": "@@S@@"}, raws={"@@S@@": '"project:\\ud800"'})
    control = env.control()
    assert control.inspect_run(run_id).state == "queued"
    with pytest.raises(UnicodeEncodeError):
        _lock(control, run_id)
    with pytest.raises(RunControlError) as caught:
        control.cancel_run(run_id, "r", "cancel:fa")
    assert caught.value.code == "invalid_argument"
    assert env.states(run_id)[-1] == "cancelled"
    assert any(b'"applying"' in path.read_bytes() for path in env.journal_files())


# ================================================================= static evidence


def test_rcr_single_edge_table_and_unchanged_callers() -> None:
    """Section 6.3: exactly one lifecycle table; the reader reuses the predicate."""
    source = Path(runs.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    keys = {None, "queued", "running", "cancel_requested", "draining", "effect_complete", "report_complete"}
    tables = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        and {getattr(key, "value", object()) for key in node.keys if isinstance(key, ast.Constant)} == keys
        and len(node.keys) == len(keys)
    ]
    assert len(tables) == 1
    loader = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_load_events"
    )
    assert any(
        isinstance(node, ast.Attribute) and node.attr == "_validate_transition" for node in ast.walk(loader)
    )
    callers = sorted(
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(isinstance(sub, ast.Attribute) and sub.attr == "_validate_transition" for sub in ast.walk(node))
    )
    assert callers == [
        "_append_event_unlocked", "_finalize_terminal_unlocked", "_load_events", "_pending_receipt_unlocked",
    ]


def test_rcr_finite_walk_is_not_recursive_and_no_decoder_hooks() -> None:
    source = Path(runs.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    walker = next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_all_finite"
    )
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_all_finite"
        for node in ast.walk(walker)
    )
    readers = {"_read_record", "_load_events", "_request_from_value", "_validated_request", "_index_target"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in readers:
            text = ast.get_source_segment(source, node) or ""
            assert "parse_constant" not in text and "parse_float" not in text, node.name
