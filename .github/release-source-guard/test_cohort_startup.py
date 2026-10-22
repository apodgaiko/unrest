"""Guard setup precedes the unchanged rendezvous, never creates a session."""

from copy import deepcopy
import json
import os
from pathlib import Path
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


def constructor_frame(tmp_path):
    import dis
    import hashlib
    import types

    g, e, b, r, c, registration, events = context(tmp_path)
    source = tmp_path / "runtime_guard.py"
    source.write_text(
        "def install():\n def initialize_inner():\n  return None\n return initialize_inner\n"
    )
    code = compile(source.read_bytes(), str(source), "exec", dont_inherit=True)

    def named(code, name):
        for value in code.co_consts:
            if isinstance(value, types.CodeType):
                if value.co_name == name:
                    return value
                found = named(value, name)
                if found is not None:
                    return found

    selected = named(code, "initialize_inner")
    g._STATE["guard_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    g._STATE["isolated_named"] = named
    local = dict(
        state=g._STATE,
        handle=handle(),
        registration={"class": hook.CLASS, "python": True},
        argv=["/python", "/source/tests/mock_acp_agent.py"],
        launch_token="a" * 32,
    )
    frame = SimpleNamespace(
        f_code=selected,
        f_globals=vars(g),
        f_locals=local,
        f_lasti=next(
            i.offset for i in dis.get_instructions(selected) if i.opname.startswith("RETURN")
        ),
    )
    return g, e, frame


def test_normal_original_constructor_return_preserves_handle_and_token(tmp_path, monkeypatch):
    g, e, frame = constructor_frame(tmp_path)
    calls = []
    monkeypatch.setattr(hook, "wait_ready", lambda *args: calls.append(args))
    original = hook.subprocess.Popen.__init__
    hook.observe(g, e, frame, "return", None)
    assert len(calls) == 1 and calls[0][2] is frame.f_locals["handle"]
    assert calls[0][3] == {"class": hook.CLASS, "python": True, "token": "a" * 32}
    assert hook.subprocess.Popen.__init__ is original


@pytest.mark.parametrize(
    "change",
    ["event", "case", "root-class", "globals", "path", "name", "unwind", "registration-class"],
)
def test_unrelated_events_and_original_exception_unwind_are_not_changed(
    tmp_path, monkeypatch, change
):
    g, e, frame = constructor_frame(tmp_path)
    event = "return"
    monkeypatch.setattr(hook, "wait_ready", lambda *args: pytest.fail("unbound wait"))
    if change == "event":
        event = "call"
    elif change == "case":
        g._STATE["case"] = "foreign"
    elif change == "root-class":
        g._STATE["class"] = "foreign"
    elif change == "globals":
        frame.f_globals = dict(frame.f_globals)
    elif change == "path":
        frame.f_code = frame.f_code.replace(co_filename="/foreign")
    elif change == "name":
        frame.f_code = frame.f_code.replace(co_name="foreign")
    elif change == "unwind":
        frame.f_lasti = 0
    else:
        frame.f_locals["registration"]["class"] = "foreign"
    hook.observe(g, e, frame, event, None)


@pytest.mark.parametrize(
    "change", ["source-bytes", "code", "state", "python", "argv", "runtime", "token", "handle"]
)
def test_changed_bound_constructor_context_is_refused(tmp_path, monkeypatch, change):
    g, e, frame = constructor_frame(tmp_path)
    monkeypatch.setattr(hook, "wait_ready", lambda *args: pytest.fail("unbound wait"))
    if change == "source-bytes":
        Path(g._STATE["guard"]).write_text("def install():\n def initialize_inner():\n  return 9\n")
    elif change == "code":
        frame.f_code = frame.f_code.replace(co_firstlineno=999)
    elif change == "state":
        frame.f_locals["state"] = dict(g._STATE)
    elif change == "python":
        frame.f_locals["registration"]["python"] = False
    elif change == "argv":
        frame.f_locals["argv"].append("foreign")
    elif change == "runtime":
        frame.f_locals["argv"][0] = "/foreign"
    elif change == "token":
        frame.f_locals["launch_token"] = "foreign"
    else:
        frame.f_locals["handle"] = None
    with pytest.raises(Refusal, match="constructor_context"):
        hook.observe(g, e, frame, "return", None)
