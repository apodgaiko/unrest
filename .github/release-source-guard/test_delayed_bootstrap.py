"""Closed bootstrap wrapper custody; original product-route controls stay separate."""

import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace, FunctionType

import pytest

from test_backend_postimages import load, named
from unrest_harness import experimental_session as session
from tests import test_experimental_bootstrap as original

ROUTE = load("delayed_bootstrap")
ROOT = Path(__file__).resolve().parents[2]
CASE = ROUTE.CASES[0]


def test_original_module_collection_and_diagnostic_scope_remain_exact():
    from primary_policy import TEST_BOOTSTRAP_CASES, root_seconds
    from primary_source_inputs import test_plan as plan

    assert TEST_BOOTSTRAP_CASES == ROUTE.CASES and len(set(ROUTE.CASES)) == 27
    assert hashlib.sha256((ROOT / ROUTE.SOURCE).read_bytes()).hexdigest() == ROUTE.PIN
    command = ("env -u CODEX_PATH uv run pytest -q " + " ".join(ROUTE.CASES)).encode()
    p = plan(command, "bootstrap", "TEST-positive")
    assert (
        p["timeout_seconds"] == root_seconds(p) == 600
        and not p["source_checkpoint_ready"]
        and p["selected_carrier"] is None
    )
    for changed in (
        command + b" -k readiness",
        command.replace(ROUTE.CASES[0].encode(), b"tests/other.py::test_other"),
    ):
        with pytest.raises(RuntimeError):
            plan(changed, "bootstrap", "TEST-positive")


@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "token",
        "class",
        "source-pin",
        "delay",
        "delay-type",
        "script",
        "args",
        "cwd",
        "environment-copy",
        "launch",
        "missing-frame",
        "duplicate-frame",
        "frame-line",
        "frame-code",
        "globals",
        "stdin",
        "stdout",
        "stderr",
        "limit",
        "close-fds",
        "session",
        "extra-option",
        "product-vector",
        "product-missing",
        "product-registration",
        "product-caller",
        "environment-function",
        "environment-capture",
        "installed-wrapper",
        "constant",
        "constant-type",
        "limit-type",
        "stdin-type",
    ],
)
@pytest.mark.parametrize("delay", [32, 0.5])
def test_exact_live_wrapper_refuses_drift(tmp_path, monkeypatch, change, delay):
    isolated = load("isolated_refusal")
    code = isolated.source_code(ROOT / ROUTE.SOURCE)
    fixture_code = named(code, "delayed_backend")
    delayed_code = named(named(fixture_code, "install"), "delayed")
    environment = {"PATH": "/exact-original"}
    argv0 = [str(Path(sys.executable).resolve()), str(tmp_path / "fake-app-server"), "app-server"]
    argv = ROUTE.vector(argv0, delay)
    options = {
        "cwd": tmp_path,
        "env": environment,
        "stdin": -1,
        "stdout": -1,
        "stderr": -1,
        "close_fds": True,
        "start_new_session": True,
        "limit": session.PREFLIGHT_BYTES - 1,
    }
    import asyncio.subprocess

    local = {
        "delay": delay,
        "script": ROUTE.script(delay),
        "args": tuple(argv),
        "kwargs": options,
        "launch": asyncio.subprocess.create_subprocess_exec,
        "observed": [],
    }

    def cell(value):
        return (lambda: value).__closure__[0]

    live = FunctionType(
        delayed_code,
        vars(original),
        closure=tuple(cell(local[n]) for n in delayed_code.co_freevars),
    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", live)
    environment_code = named(fixture_code, "controlled_environment")
    captured_environment = session._SessionOwner._environment
    controlled_environment = FunctionType(
        environment_code, vars(original), closure=(cell(captured_environment),)
    )
    monkeypatch.setattr(session._SessionOwner, "_environment", controlled_environment)
    wrapper = SimpleNamespace(
        f_code=delayed_code, f_globals=vars(original), f_lineno=38, f_locals=local
    )
    owner = SimpleNamespace(
        f_code=session._SessionOwner._open_role_owned.__code__,
        f_globals=vars(session),
        f_lineno=506,
        f_locals={"argv": argv0},
    )
    frames = [wrapper, owner]
    registration = {
        "class": "source-controlled-backend-postimage",
        "source_binding": {
            "path": str(ROOT / "src/unrest_harness/experimental_session.py"),
            "line": 506,
        },
        "script_sha256": "a" * 64,
    }
    state = {
        "checkout": str(ROOT),
        "guard": str(Path(ROUTE.__file__).with_name("runtime_guard.py")),
        "product_pins": {ROUTE.SOURCE: ROUTE.PIN},
        "case": CASE if delay == 32 else ROUTE.CUTOFF_CASES[1],
        "token": "root",
        "class": "pytest-root",
        "isolated_source_code": isolated.source_code,
        "isolated_named": isolated.named,
        "direct_support": {
            "files": {
                str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path(ROUTE.__file__).parent.glob("*.py")
            }
        },
    }

    def checked(path, pin):
        name = path.name
        if name == "fallback_binding.py":
            return {
                "active_frames": lambda: list(frames),
                "matches": lambda *a: None if change == "product-caller" else {},
            }
        if name == "backend_postimage_catalog.py":
            return {"PINS": {}, "CASES": {}}
        assert name == "backend_postimage_route.py"
        return {
            "select": lambda *a: None if change == "product-registration" else registration,
            "original_function": load("backend_postimage_route").original_function,
        }

    monkeypatch.setitem(sys.modules, "runtime_guard", SimpleNamespace(checked_source=checked))
    if change in {"case", "token", "class"}:
        state[change] = "unrelated"
    elif change == "source-pin":
        state["product_pins"][ROUTE.SOURCE] = "0" * 64
    elif change == "delay":
        local["delay"] = 60
    elif change == "delay-type":
        local["delay"] = 32.0
    elif change == "script":
        local["script"] += "; pass"
    elif change == "args":
        local["args"] = tuple(argv + ["extra"])
    elif change == "cwd":
        options["cwd"] = tmp_path / "other"
    elif change == "environment-copy":
        options["env"] = dict(environment)
    elif change == "launch":
        local["launch"] = lambda *a: None
    elif change == "missing-frame":
        frames.remove(wrapper)
    elif change == "duplicate-frame":
        frames.append(SimpleNamespace(**vars(wrapper)))
    elif change == "frame-line":
        wrapper.f_lineno = 39
    elif change == "frame-code":
        wrapper.f_code = code
    elif change == "globals":
        wrapper.f_globals = dict(vars(original))
    elif change in {"stdin", "stdout", "stderr", "limit"}:
        options[change] = 0
    elif change == "close-fds":
        options["close_fds"] = False
    elif change == "session":
        options["start_new_session"] = False
    elif change == "extra-option":
        options["shell"] = True
    elif change == "product-vector":
        owner.f_locals["argv"] = argv0 + ["extra"]
    elif change == "product-missing":
        frames.remove(owner)

    if change == "environment-function":
        monkeypatch.setattr(session._SessionOwner, "_environment", lambda *a: {})
    elif change == "environment-capture":
        forged = FunctionType(environment_code, vars(original), closure=(cell(lambda *a: {}),))
        monkeypatch.setattr(session._SessionOwner, "_environment", forged)
    elif change == "installed-wrapper":
        monkeypatch.setattr(asyncio, "create_subprocess_exec", lambda *a: None)
    elif change == "constant":
        monkeypatch.setattr(session, "PREFLIGHT_BYTES", 123)
    elif change == "constant-type":
        monkeypatch.setattr(session, "PREFLIGHT_BYTES", 262144.0)
    elif change == "limit-type":
        options["limit"] = 262143.0
    elif change == "stdin-type":
        options["stdin"] = -1.0

    def refuse(reason):
        raise RuntimeError(reason)

    if change is None:
        selected, vector = ROUTE.select(argv, tmp_path, environment, state, lambda e: None, refuse)
        if delay == 32:
            assert selected["class"] == ROUTE.CLASS and selected["delay"] == 32 and vector == argv
        else:
            assert selected["class"] == "source-canonical-stdlib-backend" and selected["delay"] == 0.5
            assert vector == [argv[0], "-I", "-S", *argv[1:]]
    elif change in {"case", "token", "class"}:
        assert ROUTE.select(argv, tmp_path, environment, state, lambda e: None, refuse) is None
    else:
        with pytest.raises(RuntimeError):
            ROUTE.select(argv, tmp_path, environment, state, lambda e: None, refuse)


def test_wrapper_never_intercepts_original_noninline_acp():
    assert (
        ROUTE.select(
            ["/python", "/fixture.py", "--controlled-local-acp-v1"],
            None,
            None,
            {"case": CASE, "token": "root", "class": "pytest-root"},
            None,
            None,
        )
        is None
    )


def test_every_extended_selection_has_one_producer_and_consumer_allocation():
    from primary_policy import EXTENDED_TEST_SELECTIONS, root_seconds
    from primary_source_inputs import test_plan as plan
    for cases in EXTENDED_TEST_SELECTIONS:
        command = ('env -u CODEX_PATH uv run pytest -q ' + ' '.join(cases)).encode()
        for mode in ('TEST-positive', 'TEST-poison'):
            selected = plan(command, 'bounded', mode)
            assert selected['timeout_seconds'] == root_seconds(selected) == 600
            assert not selected['source_checkpoint_ready'] and selected['selected_carrier'] is None


@pytest.mark.parametrize("case", ROUTE.CASES)
@pytest.mark.parametrize("change", [None, "class", "case", "line", "path", "pin", "flags", "LANG", "LC_ALL", "LC_CTYPE"])
def test_only_exact_delayed_wrapper_projects_cpython_locale(case, change):
    from primary_source_inputs import python_environment

    row = {"class": ROUTE.CLASS, "case": case,
           "source_binding": {"path": "/source/" + ROUTE.SOURCE,
                              "line": 38, "sha256": ROUTE.PIN}}
    environment = {"CODEX_HOME": "/owned/home", "PRIVATE_MARKER": "retained"}
    flags = [0, 0, 0]
    if change in {"class", "case"}:
        row[change] += "-foreign"
    elif change in {"line", "path", "pin"}:
        row["source_binding"]["sha256" if change == "pin" else change] = "foreign"
    elif change == "flags":
        flags = [1, 1, 0]
    elif change in {"LANG", "LC_ALL", "LC_CTYPE"}:
        environment[change] = "C"
    before = dict(environment)
    actual = python_environment(environment, row, flags)
    assert environment == before
    assert actual == ({**environment, "LC_CTYPE": "C.UTF-8"}
                      if change is None and ROUTE.delay_for(case) is not None else environment)
