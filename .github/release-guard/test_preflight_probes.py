"""Two finite pristine preflight probes: exact body, arguments, cwd and owned home."""

import ast
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import owned_fixture
from content_manifest import Refused
from effect_proposals import proposal
from fixed_inline import PINS, PREFLIGHT_CASES, PREFLIGHT_TEST, SEQUENCES, expected, query_expected

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
NATIVE = "/native/python"
BASE = {"PATH": "/usr/bin:/bin"}
G1 = ["continuation-preflight", "--project", "p1", "--mission", "mission-001", "--task", "working"]
G2 = ["continuation-preflight", "--project", "p1", "--mission", "none", "--task", "T1"]
ORACLE = {
    "g1": G1, "g2": G2, "x1": G1, "m18": G1, "help": ["continuation-preflight", "--help"],
    "root-help": ["--help"], "list": ["list-projects"], "observe-help": ["observe-project", "--help"],
}


def _source_value(name):
    tree = ast.parse((ROOT / PREFLIGHT_TEST).read_bytes())
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and n.targets[0].id == name)
    return eval(compile(ast.Expression(node.value), PREFLIGHT_TEST, "eval"), {})


def _home(case, base, operation):
    return base / operation / "home" if case == PREFLIGHT_CASES[0] else base / "home"


@pytest.fixture
def owned(tmp_path, monkeypatch):
    acquire = owned_fixture.acquire
    monkeypatch.setattr(owned_fixture, "acquire",
                        lambda path, owned, owner: acquire(path, owned, os.getuid()))
    root = tmp_path.resolve() / "owned"
    (root / "pytest" / "node0").mkdir(parents=True)
    (root / "pytest" / "node1").mkdir()
    return root


def _host(case, owned, checkout=ROOT):
    host = SimpleNamespace(
        case=case, meta={"checkout": str(checkout), "owned": str(owned)},
        binding={"entry": {"path": NATIVE, "sha256": "a" * 64}}, fixture_roots={}, intents={},
        launch_owner=lambda actor: None, meta_environment=lambda: dict(BASE),
        ledger=SimpleNamespace(reaped=lambda *args: True), admitted=[],
    )

    def admit(actor, declaration, role, vector, script_pin, **options):
        host.admitted.append((declaration, role, vector, options))
        ticket = len(host.intents) + 1
        host.intents[ticket] = {"case": case, "role": role, "consumed": True,
                                "birth": ticket, "token": str(ticket)}
        return {"ok": True, "ticket": ticket, "token": str(ticket)}

    host.admit_launch = admit
    return host


def _raw(case, operation, home, checkout=ROOT):
    environment = {**BASE, "PYTEST_VERSION": "9.0.2", "PYTEST_CURRENT_TEST": case + " (call)",
                   "UNREST_HOME": str(home)}
    argv = [NATIVE, "-c", _source_value("PRISTINE_SCRIPT"), json.dumps(ORACLE[operation]),
            json.dumps(_source_value("FORBIDDEN_MODULES"))]
    return {"case": case, "executable": NATIVE, "argv": argv, "cwd": str(checkout),
            "environment": environment, "stdin": None}


def test_preflight_pin_sequences_and_independent_derivation():
    assert PINS[PREFLIGHT_TEST] == "ccce4799735b7554116e5d79cdd8a553063148611ceb615cfc563c1432a78459"
    assert SEQUENCES[PREFLIGHT_CASES[0]] == ("g1", "g2", "x1", "m18", "help")
    assert SEQUENCES[PREFLIGHT_CASES[1]] == ("root-help", "list", "observe-help", "help", "g1")
    forbidden = _source_value("FORBIDDEN_MODULES")
    assert len(forbidden) == 19 and all(name.startswith("unrest_harness.") for name in forbidden)
    for case in PREFLIGHT_CASES:
        for operation in SEQUENCES[case]:
            value = expected(case, operation, NATIVE, "a" * 64, ROOT, {}, root=Path("/o/pytest/n"))
            assert value.argv[3:] == (json.dumps(ORACLE[operation]), json.dumps(forbidden))
            assert value.argv[:3] == (NATIVE, "-c", _source_value("PRISTINE_SCRIPT"))
            assert dict(value.environment) == {"UNREST_HOME": str(_home(case, Path("/o/pytest/n"), operation))}
            with pytest.raises(Refused, match="query scope"):
                query_expected(case, operation, ROOT, {})
        with pytest.raises(Refused, match="closed"):
            expected(case, "unregistered", NATIVE, "a" * 64, ROOT, {}, root=Path("/o"))


@pytest.mark.parametrize("case", PREFLIGHT_CASES)
def test_preflight_sequence_admits_exact_operands_then_exhausts(case, owned):
    host, base = _host(case, owned), owned / "pytest" / "node0"
    for operation in SEQUENCES[case]:
        raw = _raw(case, operation, _home(case, base, operation))
        answer = proposal(host, {"role": "root"}, raw)
        declaration, role, vector, options = host.admitted[-1]
        assert answer["translated"] == vector == [NATIVE, "-I", "-S", *raw["argv"][1:]]
        assert role == "fixed-inline" and options["maximum"] == 5
        assert dict(declaration.environment) == raw["environment"] and declaration.cwd == str(ROOT)
        assert host.intents[answer["ticket"]]["fixed_operation"] == operation
    with pytest.raises(Refused, match="exhausted"):
        proposal(host, {"role": "root"}, _raw(case, "g1", _home(case, base, "g1")))
    assert len(host.admitted) == 5


MUTATIONS = ("arguments", "forbidden", "body", "outside", "dotdot", "symlink", "leaf", "base",
             "extra-env", "home-env", "missing-home", "cwd", "unreaped", "descendant")


@pytest.mark.parametrize("mutation", MUTATIONS)
@pytest.mark.parametrize("case", PREFLIGHT_CASES)
def test_preflight_negative_controls_refuse_without_admission(case, mutation, owned, tmp_path):
    host, base = _host(case, owned), owned / "pytest" / "node0"
    first = SEQUENCES[case][0]
    proposal(host, {"role": "root"}, _raw(case, first, _home(case, base, first)))
    operation = SEQUENCES[case][1]
    raw = _raw(case, operation, _home(case, base, operation))
    environment, actor = raw["environment"], {"role": "root"}
    if mutation == "arguments":
        raw["argv"][3] = json.dumps(["observe-project", *ORACLE[operation][1:]])
    elif mutation == "forbidden":
        raw["argv"][4] = json.dumps(json.loads(raw["argv"][4])[1:])
    elif mutation == "body":
        raw["argv"][2] += "\n"
    elif mutation == "outside":
        environment["UNREST_HOME"] = str(_home(case, tmp_path.resolve() / "foreign", operation))
    elif mutation == "dotdot":
        environment["UNREST_HOME"] = str(_home(case, base / "x" / "..", operation))
    elif mutation == "symlink":
        (owned / "pytest" / "alias").symlink_to(base)
        environment["UNREST_HOME"] = str(_home(case, owned / "pytest" / "alias", operation))
    elif mutation == "leaf":
        environment["UNREST_HOME"] = str(base / first / "home" if case == PREFLIGHT_CASES[0]
                                         else base / "other")
    elif mutation == "base":
        environment["UNREST_HOME"] = str(_home(case, owned / "pytest" / "node1", operation))
    elif mutation == "extra-env":
        environment["PYTHONPATH"] = str(ROOT / "src")
    elif mutation == "home-env":
        environment["HOME"] = str(base)
    elif mutation == "missing-home":
        del environment["UNREST_HOME"]
    elif mutation == "cwd":
        raw["cwd"] = str(base)
    elif mutation == "unreaped":
        host.ledger.reaped = lambda *args: False
    elif mutation == "descendant":
        actor = {"role": "fixed-inline"}
    with pytest.raises(Refused):
        proposal(host, actor, raw)
    assert len(host.admitted) == 1


def test_preflight_source_drift_and_unregistered_neighbour_refuse(owned, tmp_path):
    case = PREFLIGHT_CASES[1]
    checkout = tmp_path.resolve() / "checkout"
    (checkout / "tests").mkdir(parents=True)
    shutil.copyfile(ROOT / PREFLIGHT_TEST, checkout / PREFLIGHT_TEST)
    with (checkout / PREFLIGHT_TEST).open("ab") as stream:
        stream.write(b"\n")
    host = _host(case, owned, checkout)
    raw = _raw(case, "root-help", owned / "pytest" / "node0" / "home", checkout)
    with pytest.raises(Refused, match="original source bytes"):
        proposal(host, {"role": "root"}, raw)
    neighbour = PREFLIGHT_TEST + "::test_pf24_help_does_not_need_the_module"
    host = _host(neighbour, owned)
    raw = {**_raw(case, "root-help", owned / "pytest" / "node0" / "home"), "case": neighbour}
    with pytest.raises(Refused, match="no declaration"):
        proposal(host, {"role": "root"}, raw)
    assert host.admitted == []
