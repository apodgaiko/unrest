"""A pure two-node child never receives inner-case or release-root authority."""

from types import SimpleNamespace

import pytest

from content_manifest import Refused
from nested_pytest import CASE, NODES, selected as make_selected
from source_observer import Observer
from source_profile import case_seal
import source_root


def selected(monkeypatch):
    calls = []
    policy = SimpleNamespace(
        profile={"cases": [CASE]},
        case=CASE,
        poison=False,
        client=SimpleNamespace(request=lambda *args: calls.append(args)),
    )
    proof = make_selected(policy)
    items = [SimpleNamespace(nodeid=node) for node in NODES]
    monkeypatch.setattr(source_root, "Function", SimpleNamespace)
    proof.pytest_collection_finish(SimpleNamespace(items=items))
    return policy, proof, items, calls


def test_child_reports_both_original_nodes_without_advancing_parent_case(monkeypatch):
    policy, proof, items, calls = selected(monkeypatch)
    for item in items:
        protocol = proof.pytest_runtest_protocol(item, None)
        next(protocol)
        assert policy.case == CASE
        for phase in ("setup", "call", "teardown"):
            proof.pytest_runtest_logreport(
                SimpleNamespace(nodeid=item.nodeid, when=phase, outcome="passed", failed=False)
            )
        with pytest.raises(StopIteration):
            next(protocol)
        assert policy.case == CASE
    assert proof.completed == list(NODES)
    assert calls == [("preselected-finish", case_seal(NODES))]


@pytest.mark.parametrize(
    "phase,outcome", (("setup", "skipped"), ("call", "failed"), ("teardown", "failed"))
)
def test_missing_or_incomplete_original_outcomes_never_seal(monkeypatch, phase, outcome):
    policy, proof, items, calls = selected(monkeypatch)
    protocol = proof.pytest_runtest_protocol(items[0], None)
    next(protocol)
    proof.reports[NODES[0]] = {
        "setup": "passed",
        "call": "passed",
        "teardown": "passed",
        phase: outcome,
    }
    with pytest.raises(Refused):
        next(protocol)
    assert not calls and not proof.completed and policy.case == CASE


def test_child_selection_order_is_exact(monkeypatch):
    _, proof, items, _ = selected(monkeypatch)
    with pytest.raises(Refused):
        proof.pytest_collection_finish(SimpleNamespace(items=list(reversed(items))))


def server():
    birth = object()
    actor = {
        "role": "pytest-regression",
        "case": CASE,
        "birth": birth,
        "token": "owned",
        "body_ready": True,
    }
    host = object.__new__(Observer)
    host.case = CASE
    host.intents = {
        1: {
            "birth": birth,
            "token": "owned",
            "consumed": True,
            "case": CASE,
            "role": "pytest-regression",
        }
    }
    host.ledger = SimpleNamespace(process=lambda birth: SimpleNamespace(terminal=(1, 0, 0)))
    return host, actor


def test_child_seal_is_separate_from_actual_exit_and_parent_wait():
    host, actor = server()
    assert not host.completed_child(actor)
    assert host.dispatch(actor, {"kind": "preselected-finish", "payload": case_seal(NODES)}) == {
        "ok": True
    }
    assert host.completed_child(actor)
    with pytest.raises(Refused):
        host.dispatch(actor, {"kind": "preselected-finish", "payload": case_seal(NODES)})
    for status in (1, -9):
        host.ledger.process = lambda birth: SimpleNamespace(terminal=(1, 0, status))
        assert not host.completed_child(actor)


@pytest.mark.parametrize(
    "mutation", ("role", "case", "birth", "token", "body", "intent", "selection")
)
def test_foreign_or_incomplete_actor_cannot_seal(monkeypatch, mutation):
    host, actor = server()
    payload = case_seal(NODES)
    if mutation == "role":
        actor["role"] = "root"
    elif mutation == "case":
        actor["case"] = "foreign"
    elif mutation == "birth":
        actor["birth"] = object()
    elif mutation == "token":
        actor["token"] = "foreign"
    elif mutation == "body":
        actor["body_ready"] = False
    elif mutation == "intent":
        host.intents[1]["consumed"] = False
    else:
        payload = case_seal(tuple(reversed(NODES)))
    with pytest.raises(Refused):
        host.dispatch(actor, {"kind": "preselected-finish", "payload": payload})
    assert not actor.get("preselected_complete")


def test_original_nested_command_keeps_exact_two_nodes_and_no_descendant_role():
    import ast
    from pathlib import Path
    from fixed_inline import expected, translated
    from execution_spec import issue, validate

    root = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
    tree = ast.parse((root / "tests/test_v04_speed_runner.py").read_bytes())
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == CASE.split("::")[1]
    )
    call = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "run"
    )
    assert tuple(ast.literal_eval(node) for node in call.args[0].elts[1:]) == (
        "-m",
        "pytest",
        "-q",
        *NODES,
    )
    value = expected(CASE, "pytest", "/native/python", "a" * 64, root, {"PATH": "/bin:/usr/bin"})
    assert value.argv == ("/native/python", "-m", "pytest", "-q", *NODES)
    vector = list(translated(value))
    profile = {
        "role": "pytest-regression",
        "argv": vector,
        "script": None,
        "execution": issue("pytest-regression", vector, None, None),
    }
    validate(profile, "cpython.run_module", ("pytest",), root)
    from source_entry import Policy

    policy = object.__new__(Policy)
    policy.profile = {"role": "pytest-regression"}
    policy.case = CASE
    with pytest.raises(Refused, match="undeclared process role"):
        policy.popen(("/native/python", [], None, {}))


def test_hermetic_literal_environment_and_selection_match_original_source():
    import importlib.util
    from pathlib import Path
    from fixed_inline import expected, translated
    from nested_pytest import HERMETIC, HERMETIC_TEST, CASES
    root = next(p for p in Path(__file__).resolve().parents if (p/'pyproject.toml').is_file())
    spec = importlib.util.spec_from_file_location('original_environment_probe',root/HERMETIC_TEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    environment = {'PATH':'/bin:/usr/bin','PYTEST_CURRENT_TEST':HERMETIC+' (call)'}
    value = expected(HERMETIC,'pytest','/native/python','a'*64,root,environment)
    assert value.argv == ('/native/python','-c',module._PYTEST_RESTORE_PROBE,'-q',
        *(str(root/node) for node in CASES[HERMETIC][:2]),CASES[HERMETIC][2])
    assert dict(value.environment) == {**environment,**module._adversarial_environment(),
        module._UNRELATED_ENV:'outer-unrelated-value'}
    assert translated(value) == ('/native/python','-I','-S',*value.argv[1:])
    with pytest.raises(Refused):
        expected(HERMETIC,'pytest','/native/python','a'*64,root,environment,query=True)


def test_hermetic_child_seals_all_three_nodes_without_advancing_outer_case(monkeypatch):
    from nested_pytest import HERMETIC, CASES
    calls = []
    policy = SimpleNamespace(profile={'cases':[HERMETIC]},case=HERMETIC,poison=False,
        client=SimpleNamespace(request=lambda *args:calls.append(args)))
    proof = make_selected(policy)
    nodes = CASES[HERMETIC]
    items = [SimpleNamespace(nodeid=node) for node in nodes]
    monkeypatch.setattr(source_root,'Function',SimpleNamespace)
    proof.pytest_collection_finish(SimpleNamespace(items=items))
    for item in items:
        protocol = proof.pytest_runtest_protocol(item,None)
        next(protocol)
        for phase in ('setup','call','teardown'):
            proof.pytest_runtest_logreport(SimpleNamespace(nodeid=item.nodeid,when=phase,outcome='passed',failed=False))
        with pytest.raises(StopIteration):
            next(protocol)
        assert policy.case == HERMETIC
    assert calls == [('preselected-finish',case_seal(nodes))]



def test_each_bounded_nested_frontier_is_independently_closed():
    import ast
    from pathlib import Path
    from fixed_inline import GROUPS
    from nested_pytest import HERMETIC
    from source_host import main
    import inspect
    declared={node.value for node in ast.walk(ast.parse(inspect.getsource(main)))
              if isinstance(node,ast.Constant) and type(node.value) is str}
    assert {'nested-speed1','hermetic1'} <= declared
    assert (CASE,) in GROUPS and (HERMETIC,) in GROUPS
