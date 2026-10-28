"""Exact original import/reload child: no arbitrary inline or descendant entry."""

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import RELOAD_CASE, RELOAD_NAME, RELOAD_TEST, expected, script

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


def fixture():
    calls = []
    host = SimpleNamespace(
        case=RELOAD_CASE,
        meta={"checkout": str(ROOT), "owned": "/owned"},
        binding={"entry": {"path": "/native/python", "sha256": "a" * 64}},
        meta_environment=lambda: {"PATH": "/usr/bin:/bin"},
        launch_owner=lambda actor: None,
        intents={},
        ledger=SimpleNamespace(reaped=lambda *args: True),
    )

    def admit(actor, declaration, *args, **kwargs):
        calls.append((declaration, args, kwargs))
        host.intents[1] = {}
        return {"ok": True, "ticket": 1, "token": "t"}

    host.admit_launch = admit
    environment = {
        **host.meta_environment(),
        "PYTEST_VERSION": "9.0.2",
        "PYTEST_CURRENT_TEST": RELOAD_CASE + " (call)",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    value = expected(RELOAD_CASE, "reload", "/native/python", "a" * 64, ROOT, environment)
    raw = {
        "case": RELOAD_CASE,
        "executable": value.executable,
        "argv": list(value.argv),
        "environment": environment,
        "cwd": str(ROOT),
        "stdin": None,
    }
    return host, calls, value, raw


def test_original_reload_body_and_assertions_are_unchanged():
    tree = ast.parse((ROOT / RELOAD_TEST).read_bytes())
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == RELOAD_NAME
    )
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "_isolated_python"
    )
    assert script(ROOT, "reload") == call.args[0].value
    assert any(isinstance(n, ast.Assert) for n in function.body)
    host, calls, value, raw = fixture()
    answer = proposal(host, {"role": "root"}, raw)
    assert answer["translated"] == ["/native/python", "-I", "-S", *value.argv[1:]]
    assert value.payload_sha256 == hashlib.sha256(call.args[0].value.encode()).hexdigest()
    assert calls[0][1:] == (
        ("fixed-inline", answer["translated"], value.payload_sha256),
        {"maximum": 1, "environment": None, "inherited": [], "port": None},
    )


@pytest.mark.parametrize(
    "mutation", ("body", "environment", "cwd", "image", "extra", "stdin", "exhausted")
)
def test_reload_proposal_is_exact_and_single_use(mutation):
    host, calls, value, raw = fixture()
    if mutation == "body":
        raw["argv"][-1] = "pass"
    elif mutation == "environment":
        raw["environment"]["EXTRA"] = "1"
    elif mutation == "cwd":
        raw["cwd"] = "/owned"
    elif mutation == "image":
        raw["executable"] = raw["argv"][0] = "/other/python"
    elif mutation == "extra":
        raw["payload_sha256"] = value.payload_sha256
    elif mutation == "stdin":
        raw["stdin"] = "pass"
    else:
        host.intents[0] = {
            "case": RELOAD_CASE,
            "role": "fixed-inline",
            "consumed": True,
            "birth": object(),
            "token": "old",
        }
    with pytest.raises(Refused):
        proposal(host, {"role": "root"}, raw)
    assert not calls


def test_reload_child_cannot_request_a_repository_query():
    with pytest.raises(Refused, match="descendant"):
        expected(RELOAD_CASE, "reload", "/native/python", "a" * 64, ROOT, {}, query=True)
    with pytest.raises(Refused, match="closed"):
        expected(RELOAD_CASE, "check", "/native/python", "a" * 64, ROOT, {})
