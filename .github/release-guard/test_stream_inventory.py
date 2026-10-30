"""Finite oversized-stream leaves retain descriptor custody and constructor scope."""

import hashlib
import os
from types import SimpleNamespace

import pytest

from content_manifest import Refused
from process_ledger import Birth
from readiness_launch import STREAM_CASES, PROGRAM_PINS, proposal
from source_entry import Policy
from effect_proposals import proposal_operands

BODY = (
    "import sys; sys.stdout.write('stdout-cause-oversized-child-secret-' + 'o'*524288); "
    "sys.stdout.flush(); sys.stderr.write('stderr-cause-oversized-child-secret-' + 'e'*524288); sys.stderr.flush()"
)


@pytest.mark.parametrize("case", STREAM_CASES)
@pytest.mark.parametrize("mutation", [None, "body", "environment", "cwd", "descendant", "fd"])
def test_stream_leaf_keeps_exact_program_environment_directory_and_read_pipe(
    tmp_path, monkeypatch, case, mutation
):
    import cleanup_launch
    import owned_fixture

    assert hashlib.sha256(BODY.encode()).hexdigest() == PROGRAM_PINS[case]
    base = tmp_path / "case"
    (base / "workspace").mkdir(parents=True)
    birth = Birth(100, 100, 10, 123, "boot", 20000)
    actor = {"role": "root", "birth": birth}
    acquisitions = []

    def retained(host, path, uid):
        assert path == base and uid == 20000
        return base

    def pipe(owner, fd):
        if owner != birth or type(fd) is not int or fd != 8:
            raise Refused("wrong read pipe")
        acquisitions.append((owner, fd))
        return [fd, 1, 2]

    monkeypatch.setattr(owned_fixture, "retain", retained)
    monkeypatch.setattr(cleanup_launch, "read_pipe", pipe)
    calls = []
    host = SimpleNamespace(
        case=case,
        meta={"checkout": str(tmp_path / "source")},
        binding={"entry": {"path": "/native", "sha256": "a" * 64}},
        meta_environment=lambda: {"PATH": "/bin"},
        root_only=lambda value: (
            None if value["role"] == "root" else (_ for _ in ()).throw(Refused("root only"))
        ),
        admit_launch=lambda *args, **kwargs: calls.append((args, kwargs)) or {"ticket": 1},
    )
    env = {"PATH": "/bin"}
    if case == STREAM_CASES[0]:
        env["UNREST_NODE_ASSIGNMENT"] = '{"targets":["VAL-SEC-014"],"task_type":"work"}'
    raw = {
        "case": case,
        "argv": ["/native", "-c", BODY],
        "executable": "/native",
        "cwd": str(base / "workspace"),
        "environment": env,
        "stdin": None,
        "inventory_fd": 8,
    }
    if mutation == "body":
        raw["argv"][2] += '; print("different")'
    elif mutation == "environment":
        raw["environment"]["EXTRA"] = "different"
    elif mutation == "cwd":
        raw["cwd"] = str(base / "other")
    elif mutation == "descendant":
        actor["role"] = "fixed-inline"
    elif mutation == "fd":
        raw["inventory_fd"] = True
    if mutation:
        with pytest.raises(Refused):
            proposal(host, actor, raw)
        assert not calls
    else:
        assert proposal(host, actor, raw)["translated"] == ["/native", "-I", "-S", "-c", BODY]
        assert acquisitions == [(birth, 8)]
        assert calls[0][0][2] == "fixed-inline" and calls[0][1]["inherited"] == [[8, 1, 2]]


@pytest.mark.parametrize("descriptors", [(8,), (), (8, 9), [8], (True,), (-1,), (1025,)])
def test_constructor_descriptor_selector_is_one_bounded_integer(tmp_path, descriptors):
    calls = []

    def request(kind, payload):
        calls.append((kind, payload))
        return {"ok": True, "ticket": 1, "token": "owned", "translated": ["/native", "-c", BODY]}

    policy = Policy(tmp_path, {"role": "root"}, {}, SimpleNamespace(request=request))
    policy.case = STREAM_CASES[0]
    policy.local.passfds = descriptors
    if descriptors == (8,) and type(descriptors) is tuple:
        policy.popen(("/native", ["/native", "-c", BODY], str(tmp_path), {"PATH": "/bin"}))
        assert calls[0][1]["inventory_fd"] == 8
    else:
        with pytest.raises(Refused):
            policy.popen(("/native", ["/native", "-c", BODY], str(tmp_path), {"PATH": "/bin"}))
        assert not any(kind == "launch-proposal" for kind, _ in calls)
        assert policy.poison


def test_inventory_selector_is_not_a_generic_proposal_field(tmp_path):
    raw = {
        "case": "tests/other.py::node",
        "argv": ["/native", "-c", "pass"],
        "executable": "/native",
        "cwd": str(tmp_path),
        "environment": {},
        "stdin": None,
        "inventory_fd": 8,
    }
    with pytest.raises(Refused, match="schema"):
        proposal_operands(raw, raw["case"])


@pytest.mark.parametrize("failed", [False, True])
def test_constructor_restores_thread_state_on_success_and_failure(tmp_path, monkeypatch, failed):
    import subprocess

    policy = Policy(
        tmp_path,
        {"role": "root"},
        {},
        SimpleNamespace(
            request=lambda kind, payload: {
                "ok": True,
                "ticket": 1,
                "token": "owned",
                "translated": ["/native", "-c", BODY],
            }
        ),
    )
    policy.case = STREAM_CASES[0]
    policy.local.passfds = (99,)

    class Process:
        def __init__(self, args, **kwargs):
            assert policy.local.passfds == (8,)
            if failed:
                raise RuntimeError("constructor failed")
            policy.popen(("/native", list(args), str(tmp_path), {"PATH": "/bin"}))
            self.pid = 123

    monkeypatch.setattr(subprocess, "Popen", Process)
    monkeypatch.setattr(subprocess, "run", subprocess.run)
    monkeypatch.setattr(os, "kill", os.kill)
    monkeypatch.setattr(os, "killpg", os.killpg)
    policy.install_process_hooks()
    if failed:
        with pytest.raises(RuntimeError, match="constructor failed"):
            Process(["/native", "-c", BODY], pass_fds=(8,))
    else:
        Process(["/native", "-c", BODY], pass_fds=(8,))
        assert policy.children[123]["token"] == "owned"
    assert policy.local.passfds == (99,)


@pytest.mark.parametrize("provider", ["claude", "codex"])
def test_crash_mock_environment_does_not_forward_another_providers_credential(tmp_path, provider):
    from node_environment import baseline, environment as node_environment
    from ordinary_acp import CRASH_CASES, environment
    base = tmp_path
    ambient = {"PATH": "/bin"}
    observed = node_environment(ambient, base / ".unrest", "p1", "v-good", "validate", "attempt")
    if provider == "claude":
        observed["ANTHROPIC_API_KEY"] = "batch-crash-known-value"
    else:
        observed.update(INITIAL_AGENT_MODE="agent", CODEX_CONFIG='{"approval_policy":"on-request","model_reasoning_effort":"medium","sandbox_mode":"workspace-write"}')
    case = next(case for case in CRASH_CASES if case.endswith("[" + provider + "]"))
    assert environment(case, base, ambient, observed) == observed
    assert baseline(ambient, base / ".unrest", "p1").items() <= observed.items()
    extra = {**observed, "ANTHROPIC_API_KEY" if provider == "codex" else "CODEX_CONFIG": "foreign"}
    with pytest.raises(Refused, match="exact security environment"):
        environment(case, base, ambient, extra)
