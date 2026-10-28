"""Three finite fresh-process import probes, preserving their exact source body."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import (
    OBSERVATION_CASE,
    OBSERVATION_OPERATIONS,
    OBSERVATION_ARGUMENTS,
    script,
    expected,
)

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


@pytest.mark.parametrize("ordinal,operation", enumerate(OBSERVATION_OPERATIONS))
def test_observation_probe_has_exact_body_arguments_and_finite_ordinal(ordinal, operation):
    calls = []
    host = SimpleNamespace(
        case=OBSERVATION_CASE,
        meta={"checkout": str(ROOT), "owned": "/owned"},
        binding={"entry": {"path": "/native/python", "sha256": "a" * 64}},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        launch_owner=lambda actor: None,
        intents={i: {"case": OBSERVATION_CASE, "role": "fixed-inline"} for i in range(ordinal)},
    )

    def launch(actor, payload):
        calls.append(payload)
        host.intents[100] = {}
        return {"ok": True, "ticket": 100, "token": "t"}

    host.launch = launch
    environment = {
        "PATH": "/bin:/usr/bin",
        "PYTEST_VERSION": "9.0.2",
        "PYTEST_CURRENT_TEST": OBSERVATION_CASE + " (call)",
    }
    value = expected(OBSERVATION_CASE, operation, "/native/python", "a" * 64, ROOT, environment)
    assert value.argv == (
        "/native/python",
        "-c",
        script(ROOT, operation),
        *OBSERVATION_ARGUMENTS[operation],
    )
    raw = {
        "case": OBSERVATION_CASE,
        "executable": "/native/python",
        "argv": list(value.argv),
        "cwd": str(ROOT),
        "environment": environment,
        "stdin": None,
    }
    assert proposal(host, {"role": "root"}, raw)["translated"] == [
        "/native/python",
        "-I",
        "-S",
        *value.argv[1:],
    ]
    assert calls[0]["original"] == value.wire()
    host.intents.pop(100)
    raw["argv"][-1] = "foreign"
    with pytest.raises(Refused):
        proposal(host, {"role": "root"}, raw)
    assert len(calls) == 1


def test_observation_probe_has_no_repository_query_or_unknown_operation():
    for operation in (*OBSERVATION_OPERATIONS, "foreign"):
        with pytest.raises(Refused):
            expected(OBSERVATION_CASE, operation, "/native/python", "a" * 64, ROOT, {}, query=True)
