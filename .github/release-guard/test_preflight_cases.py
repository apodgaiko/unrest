"""Complete-module discovery and explicit zero-effect case contracts."""

from pathlib import Path
from types import SimpleNamespace
import threading
import pytest

from content_manifest import Refused
from test_preflight_inventory import CASES, NO_EFFECT
from plan_launch import CASES as LAUNCHES
from source_entry import Policy
from source_context import Context

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())


def test_module_collection_matches_full_ordered_inventory_before_bodies(monkeypatch):
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    collected = []

    class Collector:
        def pytest_collection_finish(self, session):
            collected.extend(item.nodeid for item in session.items)

    code = pytest.main(
        [
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "pytest_asyncio.plugin",
            "-p",
            "pytest_mock",
            "tests/test_launch_preflight.py",
        ],
        plugins=[Collector()],
    )
    assert code == 0 and tuple(collected) == CASES
    assert len(CASES) == 54 and len(NO_EFFECT) == 45 and set(CASES) == set(LAUNCHES) | NO_EFFECT
    assert not set(LAUNCHES) & NO_EFFECT


def policy():
    value = object.__new__(Policy)
    value.poison = False
    records = []

    def request(kind, payload):
        if kind == "launch-proposal":
            raise Refused("finite undeclared process")
        records.append(kind)

    value.client = SimpleNamespace(request=request)
    value.profile = {"role": "root"}
    value.case = next(iter(NO_EFFECT))
    value.local = threading.local()
    value.calls = Context(value)
    value.children = {}
    return value, records


def test_no_effect_process_attempt_stays_fatal_when_caught():
    value, records = policy()
    with pytest.raises(Refused, match="undeclared process"):
        value.audit("subprocess.Popen", ("/usr/bin/true", ["/usr/bin/true"], "/owned", {}))
    assert value.poison and records == ["guard-refusal"]


@pytest.mark.parametrize(
    "event,arguments", [("socket.bind", (None, ("127.0.0.1", 0))), ("os.kill", (123, 15))]
)
def test_no_effect_endpoint_and_signal_requests_are_sticky(event, arguments):
    value, records = policy()
    value.sockets = None
    with pytest.raises(Refused):
        value.audit(event, arguments)
    assert value.poison and records == ["guard-refusal"]


@pytest.mark.parametrize("with_child", [False, True])
def test_no_effect_host_requires_zero_children_not_observed_child_count(with_child):
    from source_observer import Observer
    from process_ledger import Birth

    observer = object.__new__(Observer)
    observer.full, observer.outcomes = False, []
    observer.frames=[]
    root = Birth(100, 100, 99, 1, "boot", 20000)
    case = next(iter(NO_EFFECT))
    actor = {"birth": root, "role": "root", "case": case}
    observer.root_birth = root
    observer.finished = False
    observer.case = case
    observer.actors = {100: actor}
    observer.eof_drains = {}
    observer.intents = {}
    observer.completed = []
    if with_child:
        observer.actors[101] = {"role": "foreign", "case": case}
        with pytest.raises(Refused, match="actual cleanup incomplete"):
            observer.dispatch(actor, {"kind": "case-finish", "payload": {"case": case}})
        assert not observer.completed
    else:
        assert observer.dispatch(actor, {"kind": "case-finish", "payload": {"case": case}}) == {
            "ok": True
        }
        assert observer.completed == [case]
