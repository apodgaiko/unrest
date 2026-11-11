"""Governed S1 route, mid stability and health-pass traces (VAL-56..62, TR-1..8)."""
from __future__ import annotations

import ast
import os
import re
import threading
from pathlib import Path

import pytest

from tests.governed_s1_support import (
    abandon_request,
    governed_dir,
    governed_project,
    make_controller,
    request,
    start,
    tree_snapshot,
    work_plan,
    write_criteria,
)
from unrest_harness import coordinator as coordinator_module
from unrest_harness import governed_admission as ga
from unrest_harness import governed_records as gr
from unrest_harness import storage
from unrest_harness.acp_runner import ACPNodeRunner
from unrest_harness.controller import ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.models import (
    ContractStateFile,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "unrest_harness"
STEP_HELPERS = ("_reconcile_provider_denials", "poll_supervision", "_reconcile_pending_attempts",
                "_try_evaluate_a_gate", "_select_dispatch_tasks", "_dispatch_one",
                "_dispatch_batch")


def _coordinator(controller, project_id, route=True) -> MissionCoordinator:
    return MissionCoordinator(controller.store, project_id, controller.dispatcher,
                              controller.terminal_reviewer, governed_delivery_route=route)


def _forbid_helpers(monkeypatch, store) -> None:
    for name in STEP_HELPERS:
        monkeypatch.setattr(MissionCoordinator, name,
                            lambda *a, _n=name, **k: (_ for _ in ()).throw(AssertionError(_n)))
    monkeypatch.setattr(store, "load_task_list",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("load_task_list")))
    monkeypatch.setattr(store, "save_contract_state",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("save_cs")))


def _ambiguous(tmp_path):
    controller, project_id, mid = governed_project(tmp_path, admit=False)
    real = ga.publish
    ga.publish = lambda fd, name, *a, **k: ((_ for _ in ()).throw(OSError("cut"))
                                            if name == "commit.json" else real(fd, name, *a, **k))
    try:
        with pytest.raises(ToolError):
            controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request())
    finally:
        ga.publish = real
    return controller, project_id, mid


# VAL-56 / VAL-26 (replacement) -----------------------------------------------


@pytest.mark.parametrize("variant", ["ambiguous", "unavailable", "executions_unavailable",
                                     "committed_route_false"])
def test_val56_refusal_precedes_every_step_effect(tmp_path, monkeypatch, variant):
    route = True
    if variant == "ambiguous":
        controller, project_id, mid = _ambiguous(tmp_path)
        expected = "governed_admission_unresolved"
    else:
        controller, project_id, mid = governed_project(tmp_path)
        expected = "governed_content_unavailable"
        g = governed_dir(controller.store, project_id, mid)
        if variant == "unavailable":
            (crit,) = list(g.glob("admission/*/criteria/VAL-A.v1.md"))
            crit.chmod(0o600)
            crit.write_text("tampered\n")
        elif variant == "executions_unavailable":
            (g / "executions").mkdir()
            (g / "executions" / "junk").write_text("x")
        else:
            route = False
            expected = "governed_route_unsupported"
    controller.store.save_contract_state(project_id, mid, ContractStateFile(items={}))
    runtime = controller.store.unrest_runtime_dir(project_id)
    before = tree_snapshot(runtime)
    _forbid_helpers(monkeypatch, controller.store)
    assert _coordinator(controller, project_id, route).step().detail == expected
    assert tree_snapshot(runtime) == before
    assert controller.dispatcher.calls == []


# VAL-57 (TR-5, TR-8) ---------------------------------------------------------


def test_tr8_coordinator_construction_tripwire():
    sites: list[tuple[str, int, bool]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(
                    "MissionCoordinator"):
                route = any(kw.arg == "governed_delivery_route"
                            and ast.unparse(kw.value) == "True" for kw in node.keywords)
                sites.append((path.name, node.lineno, route))
    assert sorted((name, route) for name, _, route in sites) == [
        ("cli.py", False), ("controller.py", True), ("controller.py", True)]


def test_tr5_helpers_require_explicit_mode():
    coordinator = MissionCoordinator.__new__(MissionCoordinator)
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    for call in (lambda: coordinator._dispatch_one("mission-001", task),  # type: ignore[call-arg]
                 lambda: coordinator._dispatch_batch(  # type: ignore[call-arg]
                     "mission-001", TaskList(tasks=[task]), None, [task]),  # type: ignore[arg-type]
                 lambda: coordinator._dispatch_isolated_work_batch(  # type: ignore[call-arg]
                     "mission-001", None, [task]),  # type: ignore[arg-type]
                 lambda: coordinator._dispatch_requests("mission-001", [])):  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            call()


# VAL-58 (TR-1, TR-2, TR-4, TR-6) ---------------------------------------------


def test_tr1_admission_paused_at_each_point_e13_never_dispatches(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path, admit=False)
    observations: list[tuple[str, str, str]] = []
    step_mission_calls: list[str] = []
    real_step_mission = MissionCoordinator._step_mission

    def spy_step_mission(self, m):
        step_mission_calls.append(m)
        return real_step_mission(self, m)

    monkeypatch.setattr(MissionCoordinator, "_step_mission", spy_step_mission)

    def e13(point: str) -> None:
        result: list[str] = []
        before = len(step_mission_calls)
        thread = threading.Thread(target=lambda: result.append(
            _coordinator(controller, project_id, False).step().detail))
        thread.start()
        thread.join(30)
        state = controller.store.load_state(project_id)
        kind = type(state).__name__
        observations.append((point, kind, result[0]))
        if isinstance(state, MissionPlanning):
            assert len(step_mission_calls) == before and result == [""]

    real_publish, real_atomic, real_mkdir = ga.publish, storage.atomic_write_text, ga.mkdir_open

    def publish(fd, name, *a, **k):
        out = real_publish(fd, name, *a, **k)
        e13(f"publish:{name}")
        return out

    def atomic(path, *a, **k):
        out = real_atomic(path, *a, **k)
        e13(f"product:{Path(path).name}")
        return out

    def mkdir(parent, name, *, reuse):
        out = real_mkdir(parent, name, reuse=reuse)
        e13(f"mkdir:{name if len(name) != 32 else 'A'}")
        return out

    monkeypatch.setattr(ga, "publish", publish)
    monkeypatch.setattr(storage, "atomic_write_text", atomic)
    monkeypatch.setattr(ga, "mkdir_open", mkdir)
    controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request())
    by_point = {point: (kind, detail) for point, kind, detail in observations}
    assert by_point["mkdir:governed"] == ("MissionPlanning", "")
    assert by_point["publish:intent.json"] == ("MissionPlanning", "")
    assert by_point["product:state.json"] == ("MissionRunning", "governed_admission_unresolved")
    assert by_point["publish:commit.json"] == ("MissionRunning", "governed_route_unsupported")
    assert controller.dispatcher.calls == []


def test_tr2_mid_read_once_per_step(tmp_path, monkeypatch):
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    seen: list[str] = []
    real_classify = coordinator_module.classify

    def classify_then_transition(store, pid, mid, **kw):
        result = real_classify(store, pid, mid, **kw)
        store.save_state(pid, MissionPlanning(mission_id="mission-002"))
        return result

    for name in ("load_task_list", "load_task_state", "load_contract_state"):
        real = getattr(controller.store, name)
        monkeypatch.setattr(controller.store, name,
                            lambda pid, mid, *a, _r=real, **k: seen.append(mid) or _r(pid, mid,
                                                                                    *a, **k))
    monkeypatch.setattr(coordinator_module, "classify", classify_then_transition)
    monkeypatch.setattr(MissionCoordinator, "_lookup_mid_for_state",
                        lambda self: (_ for _ in ()).throw(AssertionError("lookup")))
    _coordinator(controller, project_id).step()
    assert seen and set(seen) == {"mission-001"}
    assert isinstance(controller.dispatcher.calls[0].governance, gr.LegacyNoAdmission)


def test_tr6_abandon_then_legacy_then_regovern_refused(tmp_path):
    controller, project_id, mid = governed_project(tmp_path)
    controller.abandon_governance(project_id, mid, abandon_request())
    controller.advance_project(project_id, 1)
    assert isinstance(controller.dispatcher.calls[0].governance, gr.LegacyAfterAbandon)
    g = governed_dir(controller.store, project_id, mid)
    before = {p.name for p in g.iterdir()}
    with pytest.raises(ToolError) as caught:
        controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request("new"))
    assert caught.value.code == "governed_abandoned"
    assert {p.name for p in g.iterdir()} == before and "abandoned.json" in before


def test_tr7_hypothetical_p3_p4_violation(tmp_path, monkeypatch):
    """HYPOTHETICAL (declared limit, not a runtime reproduction or a product guarantee).

    Checks only that a mission planned through legacy ``submit_plan`` while criteria
    files exist classifies ``NONE`` and maps to ``LegacyNoAdmission``. The P3/P4
    violation itself (rewriting Running(m) to Planning(m) and deleting the runtime)
    is not executed here."""
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    stale = gr.classify(controller.store, project_id, "mission-001")
    assert stale.admission_status == "NONE"
    assert ga.legacy_mode(stale) == gr.LegacyNoAdmission()


# VAL-59 (TR-3) ---------------------------------------------------------------


def test_val59_gate_uses_step_mid(tmp_path, monkeypatch):
    plan = TaskList(tasks=[
        Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s"),
        Task(id="v0", type="validate", body="c", targets=["VAL-A"], skill="s",
             depends_on=["w0"]),
        Task(id="g0", type="gate", body="", targets=["VAL-A"], depends_on=["v0"])])
    controller, project_id, mid = governed_project(tmp_path, plan=plan)
    monkeypatch.setattr(MissionCoordinator, "_lookup_mid_for_state",
                        lambda self: (_ for _ in ()).throw(AssertionError("lookup")))
    gate_mids: list[str | None] = []
    real_gate = MissionCoordinator._evaluate_gate

    def gate_spy(self, tl, task_state, gate, *, mid=None):
        gate_mids.append(mid)
        self.store.save_state(self.project_id, MissionPlanning(mission_id="mission-009"))
        return real_gate(self, tl, task_state, gate, mid=mid)

    monkeypatch.setattr(MissionCoordinator, "_evaluate_gate", gate_spy)
    for _ in range(6):
        state = controller.store.load_state(project_id)
        if not isinstance(state, MissionRunning):
            break
        _coordinator(controller, project_id).step()
    assert gate_mids == [mid]


# VAL-61 / VAL-62 -------------------------------------------------------------


def test_val61_corrupt_non_target_criterion(tmp_path, monkeypatch):
    plan = TaskList(tasks=[
        Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s"),
        Task(id="w1", type="work", body="do", targets=["VAL-B"], skill="s", depends_on=["w0"])])
    controller, project_id, mid = governed_project(
        tmp_path, criteria={"VAL-A": "a\n", "VAL-B": "b\n"}, plan=plan)
    (crit,) = list(governed_dir(controller.store, project_id, mid).glob(
        "admission/*/criteria/VAL-B.v1.md"))
    crit.chmod(0o600)
    crit.write_text("tampered\n")
    assert _coordinator(controller, project_id).step().detail == "governed_content_unavailable"
    with pytest.raises(ToolError) as caught:
        controller.abandon_governance(project_id, mid, abandon_request())
    assert caught.value.code == "governed_content_unavailable"
    calls: list[str] = []
    monkeypatch.setattr(gr, "classify", lambda *a, **k: calls.append("c"))
    monkeypatch.setattr(coordinator_module, "classify", lambda *a, **k: calls.append("c"))
    monkeypatch.setattr(ga, "classify", lambda *a, **k: calls.append("c"))
    controller.abort_project(project_id, "stop")
    assert calls == []


def test_val62_same_buffer_object_and_no_reopen(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path)
    captured: list[gr.Classification] = []
    real_classify = coordinator_module.classify
    opens: list[str] = []
    real_open = os.open

    def classify_spy(*a, **k):
        c = real_classify(*a, **k)
        captured.append(c)
        return c

    def open_spy(path, *a, **k):
        opens.append(os.fspath(path))
        return real_open(path, *a, **k)

    monkeypatch.setattr(coordinator_module, "classify", classify_spy)
    monkeypatch.setattr(os, "open", open_spy)
    coordinator = _coordinator(controller, project_id)
    coordinator.step()
    (request_,) = controller.dispatcher.calls
    governance = request_.governance
    assert isinstance(governance, gr.GovernedBound)
    ((aid, _, body),) = governance.template.criteria
    assert body is captured[0].criteria_buffers[aid]
    criterion_opens = [p for p in opens if re.search(r"VAL-A\.v1\.md$", p)]
    assert len(criterion_opens) == 1
    opens.clear()
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    variables = ACPNodeRunner._build_template_vars(
        None,  # type: ignore[arg-type]
        task=task, mission_id=mid, project_bucket=str(controller.store.bucket_root(project_id)),
        workspace_dir=str(tmp_path), store=controller.store, project_id=project_id,
        governance=governance)
    assert body.decode() in variables["contract_assertions"]
    assert not [p for p in opens if p.endswith(".md")]
    controller.store.save_state(project_id, MissionRunning(mission_id=mid))
    task_state = controller.store.load_task_state(project_id, mid)
    task_state.set_status("w0", "pending")
    controller.store.save_task_state(project_id, mid, task_state)
    opens.clear()
    _coordinator(controller, project_id).step()
    assert len([p for p in opens if re.search(r"VAL-A\.v1\.md$", p)]) == 1


def test_val62_render_refuses_unadmitted_target(tmp_path):
    from unrest_harness.acp_runner import GovernedRenderRefused

    controller, project_id, mid = governed_project(tmp_path)
    c = gr.classify(controller.store, project_id, mid)
    template = gr.GovernedTemplate(c.admission_id or "", gr.RENDER_VERSION, ())
    scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                              project_id=project_id, mission_id=mid,
                              admission_id=c.admission_id or "",
                              attempt_id="2000-01-01T00-00-00Z-0001", node_id="w0", inventory={})
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    with pytest.raises(GovernedRenderRefused):
        ACPNodeRunner._build_template_vars(
            None,  # type: ignore[arg-type]
            task=task, mission_id=mid, project_bucket="/b", workspace_dir="/w",
            store=controller.store, project_id=project_id,
            governance=gr.GovernedBound(template=template, scope=scope))
