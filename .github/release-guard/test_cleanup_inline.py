"""Original inline catalogue parity, without starting any process."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from content_manifest import Refused
from cleanup_inline import (
    CASES,
    STARTUP,
    CLIENT,
    INFLIGHT,
    NO_LAUNCH,
    SLEEP,
    EXIT,
    body,
    child_count,
    source_site,
    scheduling_site,
)
from cleanup_launch import TEST


def test_inline_bodies_and_effect_lines_are_original_source():
    file = (
        next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file()) / TEST
    )
    tree = ast.parse(file.read_bytes())
    calls = {node.lineno: node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for line in (61, 269, 299, 429):
        assert line in calls
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) is str
    }
    assert SLEEP in constants and EXIT in constants
    assert len(CASES) == 21 and len(set(CASES)) == 21
    assert (len(STARTUP), len(CLIENT), len(INFLIGHT), len(NO_LAUNCH)) == (9, 3, 2, 7)


@pytest.mark.parametrize("case", CASES)
def test_inline_parameters_keep_original_effect_counts_and_source_sites(case):
    if case in NO_LAUNCH:
        assert child_count(case) == 0 and scheduling_site(case) is None
        with pytest.raises(Refused):
            body(case)
        with pytest.raises(Refused):
            source_site(case)
    else:
        assert body(case) == (EXIT if case in STARTUP and STARTUP[case][1] == "exit" else SLEEP)
        assert child_count(case) == (
            1 if case in STARTUP or CLIENT.get(case, (None, None))[1] == "reader" else 3
        )
        assert source_site(case) in (61, 269, 299, 429)
    if case in INFLIGHT:
        assert source_site(case, terminal=True) == 1034 and scheduling_site(case) == 478
    else:
        with pytest.raises(Refused):
            source_site(case, terminal=True)


@pytest.mark.parametrize(
    "case", [True, "", "tests/test_acp_cleanup.py::foreign", CASES[0] + "-foreign"]
)
def test_no_generic_inline_selection(case):
    with pytest.raises(Refused):
        body(case)


def test_inline_options_and_vectors_are_closed():
    from cleanup_inline import expected

    root = {"HOME": "/owned/home", "TMPDIR": "/owned/tmp", "PATH": "/usr/bin:/bin"}
    for case in CASES:
        if case in NO_LAUNCH:
            with pytest.raises(Refused):
                expected(case, "/native", "a" * 64, Path("/source"), root)
            continue
        result, site = expected(case, "/native", "a" * 64, Path("/source"), root)
        assert result.argv == ("/native", "-c", body(case)) and result.cwd == "/source"
        assert dict(result.environment) == {
            **root,
            "PYTEST_VERSION": "9.0.2",
            "PYTEST_CURRENT_TEST": case + " (call)",
        }
        assert site == source_site(case)
    case = next(iter(INFLIGHT))
    result, site = expected(
        case,
        "/native",
        "a" * 64,
        Path("/source"),
        root,
        base=Path("/owned/pytest/case"),
        terminal=True,
    )
    assert result.cwd == "/owned/pytest/case" and result.environment == () and site == 1034


@pytest.mark.parametrize("case", NO_LAUNCH)
def test_numeric_cases_cannot_enter_a_child_profile_or_mint_an_intent(tmp_path, case):
    from source_profile import FIELDS, validate
    from test_source_integration import backend_request

    profile = dict.fromkeys(FIELDS)
    profile.update(
        schema="unrest.bootstrap-source.v1", role="cleanup-acp", case=case, cases=list(NO_LAUNCH)
    )
    with pytest.raises(Refused, match="closed profile"):
        validate(profile, "cpython.run_file", ("foreign.py",))
    observer, actor, request = backend_request(tmp_path)
    observer.case = request["case"] = case
    with pytest.raises(Refused, match="declared launch case"):
        observer.launch(actor, request)
    assert observer.intents == {}


@pytest.mark.parametrize("case", tuple(STARTUP))
def test_preflight_only_command_never_matches_a_child_rule(case):
    import hashlib
    from cleanup_inline import expected
    from launch_policy import Observation, match

    root = {"HOME": "/owned/home", "TMPDIR": "/owned/tmp", "PATH": "/usr/bin:/bin"}
    result, _ = expected(case, "/native", "a" * 64, Path("/source"), root)
    inert = Observation(
        "/native",
        "a" * 64,
        ("/native", "-c", "pass"),
        result.environment,
        "/source",
        "python-command",
        hashlib.sha256(b"pass").hexdigest(),
    )
    with pytest.raises(Refused):
        match((result,), inert, result.owner, case)


def test_native_instance_dictionary_ignores_custom_accessors():
    from operands import instance_fields

    callbacks = []

    class Meta(type):
        def __getattribute__(self, name):
            callbacks.append("metaclass")
            raise AssertionError("custom metaclass access")

    class Instance(metaclass=Meta):
        def __getattribute__(self, name):
            callbacks.append("instance")
            raise AssertionError("custom instance access")

    value = Instance()
    object.__setattr__(value, "expected", 7)
    callbacks.clear()
    assert instance_fields(value)["expected"] == 7 and callbacks == []

    class Property:
        @property
        def __dict__(self):
            callbacks.append("property")
            raise AssertionError("custom dictionary property")

    with pytest.raises(Refused, match="instance dictionary"):
        instance_fields(Property())
    assert callbacks == []


def negative_probe(tmp_path, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from endpoint_policy import Socket
    from test_source_integration import backend_request
    import source_observer

    observer, actor, _ = backend_request(tmp_path)
    observer.case = next(iter(STARTUP))
    observer.probe_ports = {}
    observer.endpoints = SimpleNamespace(routes={}, tickets={}, connections={})
    fresh = Socket(actor["birth"], 7, 101, 201, 7, 20000, ("0.0.0.0", 0), None)
    observer.bindings = {
        (actor["birth"], 7): {"socket": fresh, "tag": "mcp-probe", "case": observer.case}
    }
    bound = replace(fresh, local=("127.0.0.1", 12345))
    monkeypatch.setattr(source_observer, "acquire_tcp", lambda *args, **kwargs: bound)
    assert observer.dispatch(actor, {"kind": "bound", "payload": {"fd": 7}}) == {"ok": True}
    client = replace(fresh, fd=8, inode=102, cookie=202)
    monkeypatch.setattr(source_observer, "acquire_tcp", lambda *args, **kwargs: client)
    request = {"kind": "connect", "payload": {"fd": 8, "address": ["127.0.0.1", 12345]}}
    return observer, actor, request, client


def test_negative_readiness_attempts_never_mint_connection_authority(tmp_path, monkeypatch):
    observer, actor, request, _ = negative_probe(tmp_path, monkeypatch)
    for _ in range(16):
        assert observer.dispatch(actor, request) == {"ok": True, "probe": True}
    assert (
        observer.endpoints.routes
        == observer.endpoints.tickets
        == observer.endpoints.connections
        == {}
    )
    with pytest.raises(Refused, match="finite negative readiness probe"):
        observer.dispatch(actor, request)
    assert observer.probe_ports[observer.case]["attempts"] == 16


@pytest.mark.parametrize(
    "mutation", ("port", "owner", "uid", "state", "remote", "bound-client", "case")
)
def test_negative_readiness_has_no_generic_loopback_permission(mutation, tmp_path, monkeypatch):
    from dataclasses import replace
    import source_observer

    observer, actor, request, client = negative_probe(tmp_path, monkeypatch)
    if mutation == "port":
        request["payload"]["address"][1] += 1
    elif mutation == "owner":
        client = replace(client, owner=replace(client.owner, ticks=client.owner.ticks + 1))
    elif mutation == "uid":
        # Socket's own identity constructor rejects a foreign UID first.
        with pytest.raises(Refused):
            replace(client, uid=20001)
        return
    elif mutation == "state":
        client = replace(client, state=1, local=("127.0.0.1", 23456), remote=("127.0.0.1", 12345))
    elif mutation == "remote":
        with pytest.raises(Refused):
            replace(client, remote=("127.0.0.1", 12345))
        return
    elif mutation == "bound-client":
        client = replace(client, local=("127.0.0.1", 12346))
    else:
        observer.case = next(case for case in STARTUP if case != observer.case)
    monkeypatch.setattr(source_observer, "acquire_tcp", lambda *args, **kwargs: client)
    with pytest.raises(Refused, match="finite negative readiness probe"):
        observer.dispatch(actor, request)
    assert observer.endpoints.connections == {}


@pytest.mark.parametrize("outcome", ("pending", "refused", "connected", "zero", "bool"))
def test_negative_probe_socket_hook_never_reports_a_connection(outcome):
    import errno
    from types import SimpleNamespace
    from source_sockets import Hooks

    calls = []
    case = next(iter(STARTUP))

    def refuse(code):
        raise Refused(code)

    policy = SimpleNamespace(
        profile={"role": "root", "case": "<bootstrap>"},
        case=case,
        calls=SimpleNamespace(connection=lambda port: None),
        refuse=refuse,
    )
    hooks = object.__new__(Hooks)
    hooks.policy, hooks.local = policy, SimpleNamespace()
    hooks.descriptor = lambda stream: 8

    def request(kind, payload):
        calls.append(kind)
        assert kind == "connect"
        return {"ok": True, "probe": True}

    hooks.rpc = request

    def connect(stream, address):
        if outcome == "pending":
            raise BlockingIOError(errno.EINPROGRESS, "controlled pending attempt")
        if outcome == "refused":
            raise ConnectionRefusedError(errno.ECONNREFUSED, "controlled refused attempt")
        return None if outcome == "connected" else 0 if outcome == "zero" else True

    hooks.original = {"connect": connect}
    error = (
        BlockingIOError
        if outcome == "pending"
        else ConnectionRefusedError
        if outcome == "refused"
        else Refused
    )
    with pytest.raises(error):
        hooks.call("connect", object(), ("127.0.0.1", 12345))
    assert calls == ["connect"] and hooks.local.socket is None
