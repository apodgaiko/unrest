"""Guard setup precedes the unchanged rendezvous, never creates a session."""

from copy import deepcopy
import json
import os
from types import SimpleNamespace

import pytest

from finite import cohort_startup as hook
from finite.endpoint import latest_wait_registration


class Refusal(RuntimeError):
    pass


def context(tmp_path):
    state = {
        "class": "pytest-root",
        "case": sorted(hook.CASES)[0],
        "events": str(tmp_path),
        "pin": "manifest",
        "guard_sha256": "guard",
        "registry": {"sha256": "registry"},
        "checkout": "/source",
        "runtime": {"sha256": "runtime", "paths": ["/python"]},
        "guard": str(tmp_path / "runtime_guard.py"),
        "direct_support": {"files": {str(tmp_path / "linux_identity.py"): "identity-pin"}},
    }
    birth = dict(pid=123, ppid=os.getpid(), uid=os.geteuid(), start_ticks=456)
    events = []
    guard = SimpleNamespace(
        _STATE=state,
        append=events.append,
        checked_source=lambda path, pin: {"identity": lambda pid: dict(birth)},
    )

    def refuse(reason):
        raise Refusal(reason)

    endpoint = SimpleNamespace(
        STATE={"spec": {"nonce": "nonce"}},
        refuse=refuse,
        latest_wait_registration=latest_wait_registration,
    )
    ready = dict(
        kind="ready",
        token="child",
        owner_pid=123,
        parent_pid=os.getpid(),
        **{"class": hook.CLASS},
        manifest_sha256="manifest",
        guard_sha256="guard",
        registry_sha256="registry",
        runtime_sha256="runtime",
    )
    complete = dict(
        kind="endpoint_install_complete",
        token="child",
        owner_pid=123,
        parent_pid=os.getpid(),
        identity=birth,
        nonce="nonce",
        manifest_sha256="manifest",
        guard_sha256="guard",
    )
    registration = dict(
        kind="registered",
        token="child",
        owner_pid=os.getpid(),
        pid=123,
        **{"class": hook.CLASS},
        python=True,
        case=state["case"],
    )
    return guard, endpoint, birth, ready, complete, registration, events


def journal(tmp_path, pid, rows):
    (tmp_path / (str(pid) + ".jsonl")).write_bytes(
        b"".join(json.dumps(r).encode() + b"\n" for r in rows)
    )


def handle():
    return SimpleNamespace(
        pid=123,
        poll=lambda: None,
        kill=lambda: pytest.fail("unexpected kill"),
        wait=lambda **kwargs: pytest.fail("unexpected wait"),
    )


def test_exact_ready_endpoint_and_current_birth(tmp_path):
    g, e, b, r, c, registration, events = context(tmp_path)
    journal(tmp_path, 123, [r, c])
    hook.wait_ready(g, e, handle(), registration, lambda pid: dict(b))
    assert events == [
        dict(
            kind="bounded_cohort_endpoint_READY",
            pid=123,
            token="child",
            identity=b,
            deadline_seconds=5,
            original_rendezvous_seconds=1,
            original_protocol_and_deadline_unchanged=True,
        )
    ]


@pytest.mark.parametrize(
    "field",
    ["nonce", "token", "identity", "manifest_sha256", "guard_sha256", "owner_pid", "parent_pid"],
)
def test_changed_endpoint_retains_numeric_failure_wait(tmp_path, monkeypatch, field):
    g, e, b, r, c, registration, events = context(tmp_path)
    c = deepcopy(c)
    c[field] = "foreign"
    journal(tmp_path, 123, [r, c])
    ticks = iter((0, 6))
    monkeypatch.setattr(hook.time, "monotonic", lambda: next(ticks))
    actions = []
    h = SimpleNamespace(
        pid=123,
        poll=lambda: None,
        kill=lambda: actions.append("kill"),
        wait=lambda **kw: actions.append(("actual_wait", kw, -9)) or -9,
    )
    with pytest.raises(Refusal, match="cohort_startup_endpoint_not_READY"):
        hook.wait_ready(g, e, h, registration, lambda pid: dict(b))
    assert actions == ["kill", ("actual_wait", {"timeout": 5}, -9)]
    assert events[-1]["cleanup_verified"] and events[-1]["observed_handle_returncode"] == -9


def test_core_ready_alone_cannot_release_parent(tmp_path, monkeypatch):
    g, e, b, r, c, registration, events = context(tmp_path)
    journal(tmp_path, 123, [r])
    actions = []
    h = SimpleNamespace(pid=123, poll=lambda: 7, wait=lambda **kw: actions.append(7) or 7)
    with pytest.raises(Refusal):
        hook.wait_ready(g, e, h, registration, lambda pid: dict(b))
    assert actions == [7] and events[-1]["observed_handle_returncode"] == 7


def test_birth_replacement_refuses_even_with_complete_records(tmp_path):
    g, e, b, r, c, registration, events = context(tmp_path)
    journal(tmp_path, 123, [r, c])
    identities = iter((b, {**b, "start_ticks": 457}, {**b, "start_ticks": 457}))
    with pytest.raises(Refusal, match="birth_drift"):
        hook.wait_ready(g, e, handle(), registration, lambda pid: next(identities))
    assert not events[-1]["cleanup_verified"] and "UNVERIFIED" in events[-1]["custody"]


def test_original_constructor_and_handle_are_retained(tmp_path, monkeypatch):
    g, e, b, r, c, registration, events = context(tmp_path)
    calls = []

    class Popen:
        def __init__(self, *args, **kwargs):
            self.pid = 123
            calls.append((self, args, kwargs))

        def poll(self):
            return None

    monkeypatch.setattr(hook.subprocess, "Popen", Popen)
    journal(tmp_path, os.getpid(), [registration])
    journal(tmp_path, 123, [r, c])
    hook.install(g, e)
    h = Popen(["/python", "/source/tests/mock_acp_agent.py"], cwd="original-cwd")
    assert calls == [
        (h, (["/python", "/source/tests/mock_acp_agent.py"],), {"cwd": "original-cwd"})
    ]
    assert len(events) == 1
    hook.install(g, e)  # Idempotent, never stacks wrappers.
    g._STATE["case"] = "foreign"
    Popen(["unchanged"])
    assert len(events) == 1 and len(calls) == 2


def test_original_constructor_failure_is_not_caught_or_retried(tmp_path, monkeypatch):
    g, e, *_ = context(tmp_path)

    class Popen:
        def __init__(self, *args, **kwargs):
            raise OSError("original")

    monkeypatch.setattr(hook.subprocess, "Popen", Popen)
    hook.install(g, e)
    with pytest.raises(OSError, match="original"):
        Popen(["original"])


def test_foreign_process_class_keeps_original_constructor(tmp_path, monkeypatch):
    g, e, *_ = context(tmp_path)
    g._STATE["class"] = "source-cohort2:mock-agent"
    original = hook.subprocess.Popen.__init__
    hook.install(g, e)
    assert hook.subprocess.Popen.__init__ is original


def test_malformed_child_journal_settles_only_proven_child(tmp_path):
    g, e, b, r, c, registration, events = context(tmp_path)
    (tmp_path / "123.jsonl").write_bytes(b"invalid\n")
    actions = []
    h = SimpleNamespace(
        pid=123,
        poll=lambda: None,
        kill=lambda: actions.append("kill"),
        wait=lambda **kw: actions.append(("wait", kw)) or -9,
    )
    with pytest.raises(Refusal, match="invalid_evidence"):
        hook.wait_ready(g, e, h, registration, lambda pid: dict(b))
    assert actions == ["kill", ("wait", {"timeout": 5})]
    assert events[-1]["observed_handle_returncode"] == -9


@pytest.mark.parametrize("problem", ["parent", "identity-unreadable", "birth-drift"])
def test_uncertain_identity_never_signals_or_waits(tmp_path, problem):
    g, e, b, r, c, registration, events = context(tmp_path)
    journal(tmp_path, 123, [r, c])

    def identity(pid):
        if problem == "identity-unreadable":
            raise OSError("unavailable")
        if problem == "parent":
            return {**b, "ppid": os.getppid()}
        return next(values)

    values = iter((b, {**b, "start_ticks": 999}, {**b, "start_ticks": 999}))
    with pytest.raises(Refusal):
        hook.wait_ready(g, e, handle(), registration, identity)
    assert events[-1]["cleanup_verified"] is False


def test_exhausted_actual_cleanup_wait_remains_unverified_and_refuses(tmp_path):
    g, e, b, r, c, registration, events = context(tmp_path)
    journal(tmp_path, 123, [r])

    def wait(**kwargs):
        raise hook.subprocess.TimeoutExpired("original", 5)

    h = SimpleNamespace(pid=123, poll=lambda: 7, wait=wait)
    with pytest.raises(Refusal):
        hook.wait_ready(g, e, h, registration, lambda pid: dict(b))
    assert (
        not events[-1]["cleanup_verified"] and events[-1]["cleanup_error_type"] == "TimeoutExpired"
    )


@pytest.mark.parametrize("field", ["registry_sha256", "runtime_sha256", "token", "class"])
def test_changed_core_ready_cannot_release_parent(tmp_path, field):
    g, e, b, r, c, registration, events = context(tmp_path)
    r[field] = "foreign"
    journal(tmp_path, 123, [r, c])
    h = SimpleNamespace(pid=123, poll=lambda: 7, wait=lambda **kw: 7)
    with pytest.raises(Refusal):
        hook.wait_ready(g, e, h, registration, lambda pid: dict(b))
    assert events[-1]["kind"] == "failed_cohort_endpoint_READY"
    assert events[-1]["observed_handle_returncode"] == 7


def test_constructor_hook_replacement_is_refused(tmp_path, monkeypatch):
    g, e, *_ = context(tmp_path)

    class Popen:
        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setattr(hook.subprocess, "Popen", Popen)
    hook.install(g, e)
    monkeypatch.setattr(Popen, "__init__", lambda *args: None)
    with pytest.raises(Refusal, match="hook_drift"):
        hook.install(g, e)


@pytest.mark.parametrize("field", ["python", "case", "malformed"])
def test_outer_registration_failure_is_sticky_and_explicitly_unverified(
    tmp_path, monkeypatch, field
):
    g, e, b, r, c, registration, events = context(tmp_path)

    class Popen:
        def __init__(self, *args, **kwargs):
            self.pid = 123

        def poll(self):
            pytest.fail("uncertain child must not be reaped")

        def kill(self):
            pytest.fail("uncertain child must not be signalled")

    monkeypatch.setattr(hook.subprocess, "Popen", Popen)
    registration[field] = "foreign"
    journal(tmp_path, os.getpid(), [registration])
    if field == "malformed":
        (tmp_path / (str(os.getpid()) + ".jsonl")).write_bytes(b"invalid\n")
    hook.install(g, e)
    with pytest.raises(Refusal):
        Popen(["/python", "/source/tests/mock_acp_agent.py"])
    assert not events[-1]["cleanup_verified"] and "UNVERIFIED" in events[-1]["custody"]
