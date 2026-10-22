"""Finite postimage selection negatives; never invoke original test bodies."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import types

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from unrest_harness import experimental_session as session  # noqa: E402


def load(name):
    path = Path(__file__).with_name("finite") / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


route = load("backend_postimage_route")
catalog = load("backend_postimage_catalog")
CASE = "tests/test_controlled_acp_cancel.py::test_owned_cancel_wire_and_cleanup[pending]"


def named(code, name):
    if code.co_name == name:
        return code
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            found = named(value, name)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize(
    "change",
    [
        None,
        "case",
        "source-pin",
        "controlled",
        "package",
        "transport",
        "runtime",
        "transport-fixture",
        "digest",
        "owner-root",
        "owner-type",
        "cwd",
        "environment-copy",
        "argv",
        "copied-bytes",
        "frame-code",
        "frame-globals",
        "frame-line",
        "missing-frame",
        "duplicate-frame",
        "symlink",
        "role",
        "filename",
    ],
)
def test_exact_pending_selection(tmp_path, change):
    body = (
        (ROOT / "tests/fixtures/experimental_session_app_server.py")
        .read_text()
        .replace(
            "def emit(value):",
            "def emit(value):\n    if 'turn' in value.get('result', {}):\n        return",
        )
        .encode()
    )
    root = tmp_path / "pending-owner"
    root.mkdir()
    (root / "worker").mkdir()
    (root / "fake-app-server").write_bytes(body)
    transport = session.ControlledTransport(ROOT / route.ACP, Path(sys.executable))
    owner = object.__new__(session.SyntheticSession)
    owner.controlled, owner.provider_config, owner.provider_package = True, None, None
    owner.root, owner.transport = root, transport
    owner.backend_digest = catalog.CASES[CASE]["script_sha256"]
    owner.backend_launcher = root / "fake-app-server"
    environment = {"PATH": "/original-controlled-path"}
    argv = [str(transport.interpreter.resolve()), str(owner.backend_launcher), "app-server"]
    local = {
        "self": owner,
        "name": "worker",
        "home": root / "worker",
        "backend_environment": environment,
        "argv": list(argv),
    }
    frame = SimpleNamespace(
        f_code=session._SessionOwner._open_role_owned.__code__,
        f_globals=vars(session),
        f_lineno=506,
        f_locals=local,
    )
    frames = [frame]
    state = {
        "checkout": str(ROOT),
        "owned_root": str(tmp_path),
        "case": CASE,
        "product_pins": {**catalog.PINS, **catalog.CASES[CASE]["sources"]},
        "runtime": {"realpath": str(transport.interpreter.resolve())},
    }
    cwd = root / "worker"
    if change == "case":
        state["case"] = CASE.replace("[pending]", "[idle]")
    elif change == "source-pin":
        state["product_pins"][route.PRODUCT] = "0" * 64
    elif change == "controlled":
        owner.controlled = False
    elif change == "package":
        owner.provider_package = root
    elif change == "transport":
        owner.transport = None
    elif change == "runtime":
        state["runtime"]["realpath"] = "/foreign-python"
    elif change == "transport-fixture":
        owner.transport = session.ControlledTransport(root / "foreign.py", transport.interpreter)
    elif change == "digest":
        owner.backend_digest = "0" * 64
    elif change == "owner-root":
        owner.root = tmp_path.parent / "foreign-owner"
    elif change == "owner-type":
        local["self"] = SimpleNamespace(**owner.__dict__)
    elif change == "cwd":
        cwd = root
    elif change == "environment-copy":
        environment = dict(environment)
    elif change == "argv":
        argv = [*argv, "extra"]
    elif change == "copied-bytes":
        owner.backend_launcher.write_bytes(body + b"\n")
    elif change == "frame-code":
        frame.f_code = (lambda: None).__code__
    elif change == "frame-globals":
        frame.f_globals = dict(vars(session))
    elif change == "frame-line":
        frame.f_lineno += 1
    elif change == "missing-frame":
        frames = []
    elif change == "duplicate-frame":
        frames.append(SimpleNamespace(**frame.__dict__))
    elif change == "role":
        local["name"] = "foreign"
    elif change == "filename":
        owner.backend_launcher = root / "foreign.py"
    elif change == "symlink":
        owner.backend_launcher.rename(root / "target")
        owner.backend_launcher.symlink_to(root / "target")
    selected = route.select(argv, cwd, environment, state, frames, vars(catalog))
    assert (selected is not None) is (change is None)


def test_catalog_closes_original_sources_without_native_or_parking_negatives():
    assert len(catalog.CASES) == 80
    assert len({r["script_sha256"] for r in catalog.CASES.values()}) == 26
    for case, row in catalog.CASES.items():
        assert case.split("::")[0] in row["sources"]
        assert "parking_admission" not in case and "runtime_pin" not in case
        for path, pin in {**catalog.PINS, **row["sources"]}.items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == pin
    assert (
        ast.literal_eval(ast.parse(Path(catalog.__file__).read_bytes()).body[2].value)
        == catalog.CASES
    )


def test_configuration_function_authentication_rejects_substitution():
    from unrest_harness import experimental_provider_config as config

    path = ROOT / route.CONFIG
    state = {"isolated_named": named}
    assert route.original_function(config, config.ProviderConfig.argv, path, state)
    assert not route.original_function(config, lambda: None, path, state)


@pytest.mark.parametrize(
    "change", [None, "override-argv", "override-inputs", "foreign-config-root", "extra-argument"]
)
def test_configured_pending_vector_retains_exact_rendering(tmp_path, change):
    from unrest_harness import experimental_provider_config as config_module

    root = tmp_path / "pending-owner"
    root.mkdir()
    home = root / "worker"
    home.mkdir()
    body = (
        (ROOT / "tests/fixtures/experimental_session_app_server.py")
        .read_text()
        .replace(
            "def emit(value):",
            "def emit(value):\n    if 'turn' in value.get('result', {}):\n        return",
        )
        .encode()
    )
    launcher = root / "fake-app-server"
    launcher.write_bytes(body)
    config = config_module.ProviderConfig(
        codex_home=tmp_path / "subscription",
        user_home=tmp_path / "user",
        cwd=root,
        ambient={},
        system=tmp_path / "system",
    )
    owner = object.__new__(session._SessionOwner)
    owner.root, owner.controlled, owner.provider_config, owner.provider_package = (
        root,
        True,
        config,
        None,
    )
    owner.backend_launcher, owner.backend_digest = launcher, hashlib.sha256(body).hexdigest()
    owner.transport = session.ControlledTransport(ROOT / route.ACP, Path(sys.executable))
    argv = [str(owner.transport.interpreter.resolve()), *config.argv(launcher, home)]
    environment = {"PATH": "/original-controlled-path"}
    frame = SimpleNamespace(
        f_code=session._SessionOwner._open_role_owned.__code__,
        f_globals=vars(session),
        f_lineno=506,
        f_locals={
            "self": owner,
            "name": "worker",
            "home": home,
            "argv": list(argv),
            "backend_environment": environment,
        },
    )
    state = {
        "checkout": str(ROOT),
        "owned_root": str(tmp_path),
        "case": CASE,
        "product_pins": {**catalog.PINS, **catalog.CASES[CASE]["sources"]},
        "runtime": {"realpath": argv[0]},
        "isolated_named": named,
    }
    if change == "override-argv":
        config.argv = lambda *args: argv[1:]
    elif change == "override-inputs":
        config.inputs.verify = lambda: None
    elif change == "foreign-config-root":
        config.codex_home = tmp_path.parent / "foreign"
    elif change == "extra-argument":
        argv.append("extra")
        frame.f_locals["argv"] = list(argv)
    assert (route.select(argv, home, environment, state, [frame], vars(catalog)) is not None) is (
        change is None
    )


def test_diagnostic_groups_are_closed_and_do_not_certify_source():
    import primary_policy as policy
    import primary_source_inputs as inputs

    groups = policy.TEST_BACKEND_POSTIMAGE_GROUPS
    assert [len(g) for g in groups] == [20, 15, 15, 10, 10, 10]
    assert set(c for g in groups for c in g) == set(catalog.CASES)
    assert len([c for g in groups for c in g]) == 80
    for group in groups:
        script = ("env -u CODEX_PATH uv run pytest -q " + " ".join(group)).encode()
        plan = inputs.test_plan(script, "diagnostic", "TEST-positive")
        assert policy.root_seconds(plan) == plan["timeout_seconds"] == 600
        assert plan["source_checkpoint_ready"] is False and plan["selected_carrier"] is None
    assert policy.SOURCE_BUDGET == {
        "root_seconds": 7200,
        "collection_seconds": 300,
        "drain_seconds": 60,
    }


def test_diagnostic_destination_uses_existing_supported_workflow_namespace():
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/v046-source-readiness.yml").read_text())
    job = workflow["jobs"]["controlled-backend-postimage-diagnosis"]
    ref = "refs/heads/codex/source-guard-structured-20261018-source-composition-postimages-20261022"
    assert job["if"] == "${{ github.ref == '" + ref + "' }}"
    syntax = ast.parse(Path(__file__).with_name("ci_shell.py").read_bytes())
    existing = [
        n.args[0]
        for n in ast.walk(syntax)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "startswith"
        and n.args
        and isinstance(n.args[0], ast.Tuple)
    ]
    assert any(
        any(ref.startswith(prefix) for prefix in ast.literal_eval(node)) for node in existing
    )
    assert all(
        ref != "refs/heads/" + name for name in ("main", "codex/release-v047-direct-20261020")
    )
