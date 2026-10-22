"""Read original code identities without invoking or replacing an original test."""

import hashlib
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

acp_runner = importlib.import_module("unrest_harness.acp_runner")
original = importlib.import_module("tests.test_capability_policy")
SUPPORT = Path(__file__).with_name("finite")
SPEC = importlib.util.spec_from_file_location(
    "indirect_terminal_control", SUPPORT / "indirect_terminal_binding.py"
)
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


def named(code, name):
    if getattr(code, "co_name", None) == name:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType) and (result := named(value, name)) is not None:
            return result
    return None


@pytest.mark.parametrize(
    "profile,role,provider",
    [
        (p, r, v)
        for p in ("safe", "unsafe-development-unrestricted")
        for r in ("worker", "validator", "terminal_reviewer")
        for v in ("claude", "codex")
    ],
)
@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "class",
        "token",
        "payload",
        "phase",
        "request-key",
        "request-vector",
        "handler",
        "instance-handler",
        "handler-code",
        "handler-globals",
        "caller-code",
        "caller-globals",
        "missing-owner",
        "duplicate-owner",
        "client",
        "policy",
        "role",
        "cwd",
        "parent-cwd",
        "env",
        "env-copy",
        "vector",
        "executable",
        "runtime",
        "source",
        "registration",
        "owner-function",
        "nested-wrong",
        "nested-token",
    ],
)
def test_environment_request_binding(tmp_path, monkeypatch, change, profile, role, provider):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = original._resolved(tmp_path, profile=profile, role=role, provider_name=provider)
    env = {
        "PATH": __import__("os").environ["PATH"],
        "SSL_CERT_DIR": "MONKEY",
        "NO_PROXY": "ordinary-equal-free-value",
        "TMP": "dGVybWluYWwtc2VudGluZWwtMS1hbnRocm9waWNfYXV0aF90b2tlbg==",
    }
    client = acp_runner.ACPClient(object(), str(workspace), policy=policy, terminal_environment=env)
    env = dict(env)
    vector = [sys.executable, *BINDING.ENV_VECTOR]
    request = {"command": sys.executable, "args": list(BINDING.ENV_VECTOR)}
    fn = getattr(original, BINDING.ENV_OWNER)
    handler = acp_runner.ACPClient._handle_terminal_create
    owner = types.SimpleNamespace(
        f_code=fn.__code__,
        f_globals=vars(original),
        f_lineno=625,
        f_locals={
            "client": client,
            "terminal_environment": env,
            "policy": policy,
            "tmp_path": tmp_path,
            "profile": profile,
            "role": role,
            "provider_name": provider,
            "script": BINDING.ENV_SCRIPT,
            "observed_names": BINDING.ENV_NAMES,
        },
    )
    launch = types.SimpleNamespace(
        f_code=handler.__code__,
        f_globals=vars(acp_runner),
        f_lineno=1034,
        f_locals={
            "self": client,
            "params": request,
            "command": sys.executable,
            "args": request["args"],
            "env": env,
            "cwd": workspace,
        },
    )
    frames = [launch, owner]
    pins = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in ("tests/test_capability_policy.py", "src/unrest_harness/acp_runner.py")
    }
    state = {
        "checkout": str(ROOT),
        "owned_root": str(tmp_path),
        "guard": str(SUPPORT / "runtime_guard.py"),
        "product_pins": pins,
        "phase": "READY",
        "class": "pytest-root",
        "token": "root",
        "case": BINDING.ENV_CASE + "[" + profile + "-" + role + "-" + provider + "]",
        "isolated_named": named,
        "isolated_source_code": lambda p: fn.__code__,
        "runtime": {
            "paths": [sys.executable],
            "realpath": str(Path(sys.executable).resolve()),
            "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        },
    }
    reg = {
        "class": "reference-descendant:terminal-environment",
        "argv": list(BINDING.ENV_VECTOR),
        "python": True,
        "caller_bindings": [],
        "checkout_cwd": True,
        "source_binding": {
            "path": str(ROOT / "tests/test_capability_policy.py"),
            "line": 628,
            "sha256": pins["tests/test_capability_policy.py"],
        },
    }
    ready = []
    guard = types.SimpleNamespace(require_ready=ready.append)
    monkeypatch.setitem(sys.modules, "runtime_guard", guard)
    monkeypatch.chdir(ROOT)
    cwd = str(workspace)
    if change in {"case", "class", "token", "phase"}:
        state[change] = "foreign"
    elif change == "payload":
        state["registered_payload"] = {"token": "foreign"}
    elif change == "request-key":
        request["env"] = []
    elif change == "request-vector":
        request["args"][-1] = "pass"
    elif change == "handler":
        monkeypatch.setattr(acp_runner.ACPClient, "_handle_terminal_create", lambda: None)
    elif change == "instance-handler":
        client._handle_terminal_create = lambda: None
    elif change == "handler-code":
        launch.f_code = launch.f_code.replace(co_name="foreign")
    elif change == "handler-globals":
        launch.f_globals = dict(launch.f_globals)
    elif change == "caller-code":
        owner.f_code = owner.f_code.replace(co_name="foreign")
    elif change == "caller-globals":
        owner.f_globals = dict(owner.f_globals)
    elif change == "missing-owner":
        frames.pop()
    elif change == "duplicate-owner":
        frames.append(types.SimpleNamespace(**vars(owner)))
    elif change == "client":
        launch.f_locals["self"] = object()
    elif change == "policy":
        owner.f_locals["policy"] = object()
    elif change == "role":
        client._policy = original._resolved(tmp_path, role="orchestrator")
        owner.f_locals["policy"] = client._policy
    elif change == "cwd":
        cwd = str(tmp_path)
    elif change == "parent-cwd":
        monkeypatch.chdir(tmp_path)
    elif change == "env":
        env["EXTRA"] = "foreign"
    elif change == "env-copy":
        env = dict(env)
    elif change == "vector":
        vector[-1] = "pass"
    elif change == "executable":
        vector[0] += "-foreign"
    elif change == "runtime":
        state["runtime"]["sha256"] = "0" * 64
    elif change == "source":
        pins["src/unrest_harness/acp_runner.py"] = "0" * 64
    elif change == "registration":
        reg["source_binding"]["line"] = 546
    elif change == "owner-function":
        monkeypatch.setattr(original, BINDING.ENV_OWNER, lambda: None)
    elif change in {"nested-wrong", "nested-token"}:
        state.update(case=BINDING.OUTER, token="child", registered_payload={"token": "other"})
    result = BINDING.matches(reg, vector, cwd, env, state, frames)
    assert bool(result) is (change is None)
    if result:
        assert result["line"] == 625 and result["handler_line"] == 1034
        assert ready == ["root"]


def test_prepared_literal_registry_contains_exact_environment_vector():
    import ast

    rows = ast.literal_eval(ast.parse((SUPPORT / "registry.py").read_bytes()).body[1].value)
    selected = [r for r in rows if r["class"] == "reference-descendant:terminal-environment"]
    assert len(selected) == 1
    assert selected[0]["argv"] == BINDING.ENV_VECTOR
    assert selected[0]["source_binding"]["line"] == 628
    assert len(BINDING.ENV_CASES) == 12
    assert (
        hashlib.sha256(BINDING.ENV_SCRIPT.encode()).hexdigest()
        == "52dfcc2a3a4a04e0db1943f3b43a2791d1c3c854d7fb73a05e28bc9c8f0e6295"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "case",
        "token",
        "owner_pid",
        "line",
        "pin",
        "extra-env",
        "credential-env",
        "locale",
        "transform",
        "argv",
        "bootstrap",
        "parent",
    ],
)
def test_consumed_transform_environment_has_no_generic_locale_exemption(mutation):
    import json
    import primary_source_inputs as inputs
    from test_terminal_locale import fixture

    registration, environment, context = fixture()
    registration.update(
        {
            "class": "reference-descendant:terminal-environment",
            "case": next(iter(BINDING.ENV_CASES)),
            "source_binding": {**registration["source_binding"], "line": 628},
        }
    )
    environment = {
        "PATH": environment["PATH"],
        "SSL_CERT_DIR": "MONKEY",
        "NO_PROXY": "ordinary-equal-free-value",
        "TMP": "dGVybWluYWwtc2VudGluZWwtMS1hbnRocm9waWNfYXV0aF90b2tlbg==",
    }

    def sha(body):
        return hashlib.sha256(body).hexdigest()

    registration["argv_sha256"] = sha(
        json.dumps([context["vector"][0], *BINDING.ENV_VECTOR]).encode()
    )
    context["selected"].update(
        case=registration["case"],
        environment_sha256=sha(json.dumps(environment, sort_keys=True).encode()),
    )
    if mutation in {"case", "token", "owner_pid"}:
        registration[mutation] = "foreign"
    elif mutation == "line":
        registration["source_binding"]["line"] = 549
    elif mutation == "pin":
        registration["source_binding"]["sha256"] = "0" * 64
    elif mutation == "extra-env":
        environment["EXTRA"] = "x"
    elif mutation == "credential-env":
        environment["ZAI_API_KEY"] = "synthetic"
    elif mutation == "locale":
        environment["LC_CTYPE"] = "C"
    elif mutation == "transform":
        environment["TMP"] = "other"
    elif mutation == "argv":
        registration["argv_sha256"] = "0" * 64
    elif mutation == "bootstrap":
        context["selected"]["bootstrap_sha256"] = "0" * 64
    elif mutation == "parent":
        context["parent"] += 1
    actual = inputs.python_environment(environment, registration, [0, 0, 0], lease_context=context)
    assert actual == ({**environment, "LC_CTYPE": "C.UTF-8"} if mutation is None else environment)
