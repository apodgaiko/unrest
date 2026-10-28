"""Finite startup rejection declarations; execution remains a native component gate."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import PINS, STDIO, STDIO_BODY, STDIO_INVALID, startup_expected, translated

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


@pytest.mark.parametrize("case", STDIO)
def test_exact_startup_rejection_operands_and_translation(tmp_path, case):
    home = tmp_path / "pytest/case"
    home.mkdir(parents=True)
    expected = startup_expected(case, "/native/python", "a" * 64, str(home), tmp_path)
    role, index = STDIO[case]
    assert expected.argv == ("/native/python", "-I", "-c", STDIO_BODY, "--mode", role)
    assert expected.payload_sha256 == hashlib.sha256(STDIO_BODY.encode()).hexdigest()
    assert dict(expected.environment) == {
        "PATH": "/bin:/usr/bin",
        "HOME": str(home),
        "UNREST_HOME": str(home / "home"),
        **STDIO_INVALID[index],
    }
    calls = []
    host = SimpleNamespace(
        case=case,
        meta={"owned": str(tmp_path), "checkout": str(ROOT)},
        binding={"entry": {"path": "/native/python", "sha256": "a" * 64}},
        intents={},
        launch_owner=lambda actor: None,
        meta_environment=lambda: {},
    )

    def launch(actor, declaration, *args, **kwargs):
        calls.append((declaration,args))
        host.intents[1] = {}
        return {"ok": True, "ticket": 1, "token": "t"}

    host.admit_launch = launch
    raw = {
        "case": case,
        "executable": "/native/python",
        "argv": list(expected.argv),
        "cwd": str(home),
        "environment": dict(expected.environment),
        "stdin": None,
    }
    answer = proposal(host, {"role": "root"}, raw)
    assert (
        answer["translated"]
        == list(translated(expected))
        == ["/native/python", "-I", "-S", "-c", STDIO_BODY, "--mode", role]
    )
    assert calls[0][0] == expected
    assert calls[0][1][0] == "fixed-inline"
    host.intents.clear()
    raw["environment"]["FOREIGN"] = "1"
    with pytest.raises(Refused):
        proposal(host, {"role": "root"}, raw)
    assert len(calls) == 1


def test_startup_source_pin_and_closed_fixture_root(tmp_path):
    path = "tests/test_stdio_startup.py"
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == PINS[path]
    with pytest.raises(Refused):
        startup_expected(
            "foreign", "/native/python", "a" * 64, str(tmp_path / "pytest/case"), tmp_path
        )
    with pytest.raises(Refused):
        startup_expected(
            next(iter(STDIO)), "/native/python", "a" * 64, str(tmp_path / "foreign"), tmp_path
        )
