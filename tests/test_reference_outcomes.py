"""Actual pytest hook dispatch rejects incomplete contract evidence."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.reference_outcomes import ReferenceOutcomes, ReferenceRunError


REFERENCE = "tests/test_plain.py::test_one"


def collected(tmp_path, *, arguments=("tests",), nodes=(REFERENCE,), deselect=False):
    binder = ReferenceOutcomes()
    manager = pytest.PytestPluginManager()
    manager.register(binder)
    module = SimpleNamespace(SCENARIOS=(("VAL", "scenario", REFERENCE),))
    # Modules must be hashable, as real imported modules are.
    from types import ModuleType
    manifest = ModuleType("contract")
    manifest.SCENARIOS = module.SCENARIOS
    contract = SimpleNamespace(nodeid="tests/contracts/test_plain.py::test_crosswalk", module=manifest)
    items = [contract, *(SimpleNamespace(nodeid=node, module=manifest) for node in nodes)]
    if deselect:
        class Selection:
            def pytest_collection_modifyitems(self, items):
                items[:] = [contract]
        manager.register(Selection())
    config = SimpleNamespace(args=arguments, rootpath=Path.cwd())
    manager.hook.pytest_collection_modifyitems(session=None, config=config, items=items)
    return binder, manager, items


def report(manager, node=REFERENCE, phase="call", outcome="passed", xfail=False):
    value = pytest.TestReport(node, ("test_plain.py", 1, "test_one"), {}, outcome, None, phase, [])
    if xfail:
        value.wasxfail = "expected"
    manager.hook.pytest_runtest_logreport(report=value)


def test_actual_reports_complete_before_crosswalk(tmp_path):
    binder, manager, items = collected(tmp_path)
    assert [item.nodeid for item in items] == [REFERENCE, "tests/contracts/test_plain.py::test_crosswalk"]
    for phase in ("setup", "call", "teardown"):
        report(manager, phase=phase)
    binder.require((REFERENCE,))
    session = SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace(collectonly=False)), exitstatus=0)
    manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    assert session.exitstatus == 0


@pytest.mark.parametrize("mutation", ["missing", "partial", "deselected", "duplicate-node", "duplicate-phase", "skip", "fail", "xfail", "xpass", "incomplete"])
def test_fake_completion_is_rejected_without_running_another_pytest(tmp_path, mutation):
    nodes = () if mutation == "missing" else (REFERENCE, REFERENCE) if mutation == "duplicate-node" else (REFERENCE,)
    arguments = (REFERENCE + "[only-one]",) if mutation == "partial" else ("tests",)
    binder, manager, _ = collected(tmp_path, nodes=nodes, arguments=arguments, deselect=mutation == "deselected")
    for phase in ("setup", "call", "teardown"):
        if mutation == "incomplete" and phase == "teardown":
            continue
        outcome = "skipped" if mutation in ("skip", "xfail") and phase == "call" else "failed" if mutation == "fail" and phase == "call" else "passed"
        report(manager, phase=phase, outcome=outcome, xfail=mutation in ("xfail", "xpass") and phase == "call")
    if mutation == "duplicate-phase":
        report(manager)
    with pytest.raises(ReferenceRunError):
        binder.require((REFERENCE,))
    session = SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace(collectonly=False)), exitstatus=0)
    manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


def test_every_parameter_expansion_is_required_even_if_fixture_never_runs(tmp_path):
    nodes = (REFERENCE + "[one]", REFERENCE + "[two]")
    binder, manager, _ = collected(tmp_path, nodes=nodes)
    for phase in ("setup", "call", "teardown"):
        report(manager, node=nodes[0], phase=phase)
    with pytest.raises(ReferenceRunError, match="two"):
        binder.require((REFERENCE,))
    session = SimpleNamespace(config=SimpleNamespace(option=SimpleNamespace(collectonly=False)), exitstatus=0)
    manager.hook.pytest_sessionfinish(session=session, exitstatus=0)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


def test_deselected_contract_consumers_do_not_obligate_an_unrelated_focused_run(tmp_path):
    binder = ReferenceOutcomes()
    manager = pytest.PytestPluginManager()
    manager.register(binder)
    from types import ModuleType
    module = ModuleType("contract")
    module.SCENARIOS = (("VAL", "scenario", REFERENCE),)
    contract = SimpleNamespace(nodeid="tests/contracts/test_plain.py::test_crosswalk", module=module)
    plain = SimpleNamespace(nodeid=REFERENCE, module=module)

    class Selection:
        def pytest_collection_modifyitems(self, items):
            items[:] = [plain]

    manager.register(Selection())
    items = [contract, plain]
    manager.hook.pytest_collection_modifyitems(
        session=None, config=SimpleNamespace(args=("tests",), rootpath=Path.cwd()), items=items
    )
    assert not binder.required and not binder.errors
    binder.require(())
