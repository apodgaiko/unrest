"""Five original shared-fixture commands retain all result and timing gates."""

import ast
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import expected, SEQUENCES
from speed_inline import CLI_CASE, CLI_TOOL, CLI_PIN
import speed_inline

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


def host_and_request(tmp_path, monkeypatch, ordinal):
    monkeypatch.setattr(speed_inline, "OWNER", os.getuid())
    base = tmp_path / "pytest" / "v04-speed-runs0"
    base.mkdir(parents=True)
    run = base / f"run-{ordinal}"
    run.mkdir()
    calls = []
    host = SimpleNamespace(
        case=CLI_CASE,
        meta={"checkout": str(ROOT), "owned": str(tmp_path)},
        binding={"entry": {"path": "/native/python", "sha256": "a" * 64}},
        fixture_roots={},
        meta_environment=lambda: {"PATH": "/bin:/usr/bin"},
        launch_owner=lambda actor: None,
        ledger=SimpleNamespace(reaped=lambda *args: True),
        intents={
            i: {
                "case": CLI_CASE,
                "role": "fixed-inline",
                "consumed": True,
                "birth": object(),
                "token": str(i),
            }
            for i in range(ordinal)
        },
    )

    def admit(actor, value, *args, **kwargs):
        calls.append((value, args, kwargs))
        host.intents[99] = {}
        return {"ok": True, "ticket": 99, "token": "new"}

    host.admit_launch = admit
    value = expected(
        CLI_CASE, SEQUENCES[CLI_CASE][ordinal], "/native/python", "a" * 64, ROOT, {}, root=base
    )
    raw = {
        "case": CLI_CASE,
        "executable": value.executable,
        "argv": list(value.argv),
        "cwd": str(ROOT),
        "environment": dict(value.environment),
        "stdin": None,
    }
    return host, calls, value, raw


@pytest.mark.parametrize("ordinal", range(5))
def test_each_original_cli_run_has_exact_script_arguments_and_parent_wait_order(
    tmp_path, monkeypatch, ordinal
):
    host, calls, value, raw = host_and_request(tmp_path, monkeypatch, ordinal)
    assert (
        hashlib.sha256((ROOT / CLI_TOOL).read_bytes()).hexdigest()
        == CLI_PIN
        == value.payload_sha256
    )
    tree = ast.parse((ROOT / "tests/test_v04_speed_runner.py").read_bytes())
    constants = {
        node.targets[0].id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is str
    }
    assert value.argv[-4:] == (
        "--candidate-head",
        constants["HEAD"],
        "--candidate-tree",
        constants["TREE"],
    )
    assert value.environment == (("LANG", "C"), ("LC_ALL", "C"), ("PYTHONUTF8", "1"), ("TZ", "UTC"))
    answer = proposal(host, {"role": "root"}, raw)
    assert answer["translated"] == ["/native/python", "-I", "-S", *value.argv[1:]]
    assert calls[0][-1]["maximum"] == 5 and len(calls) == 1
    assert host.intents[99]["fixed_operation"] == f"run-{ordinal}"


@pytest.mark.parametrize(
    "mutation",
    ("body", "flags", "output", "environment", "image", "cwd", "unreaped", "changed_base"),
)
def test_cli_inputs_and_shared_fixture_are_closed(tmp_path, monkeypatch, mutation):
    host, calls, _, raw = host_and_request(tmp_path, monkeypatch, 1)
    if mutation == "body":
        raw["argv"][1] = "other.py"
    elif mutation == "flags":
        raw["argv"][6] = "--foreign"
    elif mutation == "output":
        raw["argv"][9] = raw["argv"][9].replace("run-1", "run-0")
    elif mutation == "environment":
        raw["environment"]["EXTRA"] = "1"
    elif mutation == "image":
        raw["argv"][0] = raw["executable"] = "/other"
    elif mutation == "cwd":
        raw["cwd"] = str(tmp_path)
    elif mutation == "unreaped":
        host.ledger.reaped = lambda *args: False
    else:
        host.fixture_roots[CLI_CASE] = ("old", 0, 0, 0, 0)
    with pytest.raises(Refused):
        proposal(host, {"role": "root"}, raw)
    assert not calls and 99 not in host.intents
