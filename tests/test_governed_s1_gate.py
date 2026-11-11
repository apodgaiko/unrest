"""Governed S1 dispatch gate, route, binding and reason parity (VAL-17..29)."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import pytest

from tests.governed_s1_support import (
    CapableDispatcher,
    abandon_request,
    governed_dir,
    governed_project,
    make_config,
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
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import DispatchRequest, MockTerminalReviewer
from unrest_harness.models import (
    Aborted,
    AttentionNeeded,
    Decision,
    Done,
    Draft,
    Failed,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskListPatch,
    WorkHandoff,
)

ROOT = Path(__file__).resolve().parents[1]
CLI_SHA = "2ca82d15f3ad4bbc877971bfde90f20bcea8a4a1631641584f7077e785bc0b87"


class Recorder(CapableDispatcher):
    pass


def _step(controller: ProjectController, project_id: str, *, route: bool = True):
    coordinator = MissionCoordinator(
        controller.store, project_id, controller.dispatcher, controller.terminal_reviewer,
        governed_delivery_route=route,
    )
    return coordinator.step()


def _runtime_bytes(controller, project_id, base: Path) -> dict[str, str]:
    root = controller.store.unrest_runtime_dir(project_id)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "mutation.lock":
            data = path.read_bytes().replace(os.fsencode(base), b"<base>")
            # Monotonic clock readings are the only run-specific values.
            data = re.sub(rb'("[a-z_]*_nanoseconds": )[0-9]+', rb"\1<ns>", data)
            result[str(path.relative_to(root))] = hashlib.sha256(data).hexdigest()
    return result


def _ambiguous(tmp_path: Path, plan: TaskList | None = None, criteria=None, **kwargs):
    controller, project_id, mission_id = governed_project(tmp_path, admit=False,
                                                          criteria=criteria, **kwargs)
    real_publish = ga.publish

    def cut(dir_fd, name, data, limit, **kw):
        if name == "commit.json":
            raise OSError("cut")
        return real_publish(dir_fd, name, data, limit, **kw)

    ga.publish = cut
    try:
        with pytest.raises(ToolError):
            controller.submit_governed_plan(project_id, mission_id,
                                            plan or work_plan(sorted(criteria or {"VAL-A": 1})),
                                            request())
    finally:
        ga.publish = real_publish
    assert gr.classify(controller.store, project_id, mission_id).admission_status == "AMBIGUOUS"
    return controller, project_id, mission_id


def _corrupt_criterion(controller, project_id, mission_id, aid="VAL-A"):
    admission = governed_dir(controller.store, project_id, mission_id) / "admission"
    (aid_dir,) = list(admission.iterdir())
    target = aid_dir / "criteria" / f"{aid}.v1.md"
    target.chmod(0o600)
    target.write_bytes(b"tampered\n")


def _unavailable(tmp_path: Path, **kwargs):
    controller, project_id, mission_id = governed_project(tmp_path, **kwargs)
    _corrupt_criterion(controller, project_id, mission_id)
    c = gr.classify(controller.store, project_id, mission_id)
    assert c.admission_status == "UNAVAILABLE"
    return controller, project_id, mission_id


# VAL-17 ----------------------------------------------------------------------


def test_val17_legacy_mission_unchanged_and_cheap(tmp_path, monkeypatch):
    from unrest_harness import storage

    monkeypatch.setattr(coordinator_module, "utc_now_filesafe", lambda: "20260101T000000Z")
    monkeypatch.setattr(storage, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")

    def run(base: Path, mock_classify: bool):
        controller = make_controller(base, capable=False)
        monkeypatch.setattr(type(controller.store), "generate_project_id",
                            lambda self, brief: "p-1")
        project_id = start(controller, base)
        write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
        counts = {"lstat": 0, "open": 0}
        anchor = os.fspath(controller.store.unrest_dir(project_id) / "missions" / "mission-001")
        real_classify = coordinator_module.classify
        real_lstat, real_open = os.lstat, os.open

        def lstat_spy(path, *args, **kw):
            if os.fspath(path).startswith(anchor):
                counts["lstat"] += 1
            return real_lstat(path, *args, **kw)

        def open_spy(path, *args, **kw):
            if not isinstance(path, int) and os.fspath(path).startswith(anchor):
                counts["open"] += 1
            return real_open(path, *args, **kw)

        def classify_spy(*args, **kw):
            if mock_classify:
                return gr.Classification("NONE", "no_governed_tree")
            monkeypatch.setattr(os, "lstat", lstat_spy)
            monkeypatch.setattr(os, "open", open_spy)
            try:
                return real_classify(*args, **kw)
            finally:
                monkeypatch.setattr(os, "lstat", real_lstat)
                monkeypatch.setattr(os, "open", real_open)

        monkeypatch.setattr(coordinator_module, "classify", classify_spy)
        envelope = controller.advance_project(project_id, 1)
        monkeypatch.setattr(coordinator_module, "classify", real_classify)
        assert not governed_dir(controller.store, project_id, "mission-001").exists()
        calls = controller.dispatcher.calls  # type: ignore[attr-defined]
        assert calls and all(isinstance(c.governance, gr.LegacyNoAdmission) for c in calls)
        dumped = json.loads(json.dumps(envelope.model_dump(mode="json")).replace(
            os.fspath(base), "<base>"))
        return dumped, _runtime_bytes(controller, project_id, base), counts

    real_env, real_bytes, counts = run(tmp_path / "real", False)
    base_env, base_bytes, _ = run(tmp_path / "base", True)
    assert real_env == base_env
    assert real_bytes == base_bytes
    assert counts["lstat"] <= 3 and counts["open"] == 0


def test_val17_legacy_renderer_reads_authoring(tmp_path, monkeypatch):
    from unrest_harness import acp_runner

    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "authoring\n"})
    calls: list[str] = []
    real = type(controller.store).load_contract_assertion

    def spy(self, pid, mid, aid):
        calls.append(aid)
        return real(self, pid, mid, aid)

    monkeypatch.setattr(type(controller.store), "load_contract_assertion", spy)
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    variables = acp_runner.ACPNodeRunner._build_template_vars(
        None,  # type: ignore[arg-type]  # the method reads no runner state
        task=task, mission_id="mission-001",
        project_bucket=str(controller.store.bucket_root(project_id)),
        workspace_dir=str(tmp_path / "workspace"), store=controller.store,
        project_id=project_id, governance=gr.LegacyNoAdmission())
    assert calls == ["VAL-A"]
    assert "authoring" in json.dumps(variables)


# VAL-18 ----------------------------------------------------------------------


@pytest.mark.parametrize("state", [Draft(), MissionPlanning(mission_id="mission-001"),
                                   MissionRunning(mission_id="mission-001"),
                                   AttentionNeeded(items=[]), Done(),
                                   Failed(reason="x"), Aborted(reason="x")])
def test_val18_absent_g_is_none_for_every_state(tmp_path, state):
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    controller.store.save_state(project_id, state)
    c = gr.classify(controller.store, project_id, "mission-001")
    assert (c.admission_status, c.status_reason) == ("NONE", "no_governed_tree")


@pytest.mark.parametrize("variant", ["no_missions", "no_mid", "no_governed", "symlink_mid",
                                     "file_missions", "chmod_mid"])
def test_val18_absence_probe_components(tmp_path, variant):
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    unrest = controller.store.unrest_dir(project_id)
    missions = unrest / "missions"
    shutil.rmtree(missions, ignore_errors=True)
    expected = ("NONE", "no_governed_tree")
    if variant == "no_mid":
        missions.mkdir()
    elif variant == "no_governed":
        (missions / "mission-001").mkdir(parents=True)
    elif variant == "symlink_mid":
        missions.mkdir()
        (tmp_path / "real-mid").mkdir()
        (missions / "mission-001").symlink_to(tmp_path / "real-mid")
        expected = ("UNAVAILABLE", "pre_governed_component_invalid")
    elif variant == "file_missions":
        missions.write_text("x")
        expected = ("UNAVAILABLE", "pre_governed_component_invalid")
    elif variant == "chmod_mid":
        if os.geteuid() == 0:
            pytest.skip("NOTRUN: euid 0 bypasses permissions")
        (missions / "mission-001").mkdir(parents=True)
        (missions / "mission-001").chmod(0)
        expected = ("UNAVAILABLE", "io_unavailable")
    try:
        c = gr.classify(controller.store, project_id, "mission-001")
    finally:
        if variant == "chmod_mid":
            (missions / "mission-001").chmod(0o700)
    assert (c.admission_status, c.status_reason) == expected


def _orphan(tmp_path):
    controller, project_id, mission_id = governed_project(tmp_path, admit=False)
    real_publish = ga.publish

    def cut(dir_fd, name, data, limit, **kw):
        if name == "intent.json":
            raise OSError("cut")
        return real_publish(dir_fd, name, data, limit, **kw)

    ga.publish = cut
    try:
        with pytest.raises(ToolError):
            controller.submit_governed_plan(project_id, mission_id, work_plan(["VAL-A"]),
                                            request())
    finally:
        ga.publish = real_publish
    return controller, project_id, mission_id


@pytest.mark.parametrize("variant", ["planning", "running", "missing", "malformed", "oversize"])
def test_val18_orphan_discriminator(tmp_path, variant):
    controller, project_id, mission_id = _orphan(tmp_path)
    state = controller.store.unrest_runtime_dir(project_id) / "state.json"
    expected = ("AMBIGUOUS", "orphan_staging_without_planning")
    if variant == "planning":
        expected = ("NONE", "orphan_staging_present")
    elif variant == "running":
        controller.store.save_state(project_id, MissionRunning(mission_id=mission_id))
    elif variant == "missing":
        state.unlink()
    elif variant == "malformed":
        state.write_text("{")
    else:
        state.write_text(json.dumps({"state": "mission_planning", "mission_id": mission_id,
                                     "pad": "x" * 5000}))
    c = gr.classify(controller.store, project_id, mission_id)
    assert c.admission_status == expected[0]
    if expected[0] == "NONE":
        assert c.status_reason == expected[1]


def test_val18_intent_with_running_is_ambiguous(tmp_path):
    controller, project_id, mission_id = _ambiguous(tmp_path)
    assert isinstance(controller.store.load_state(project_id), MissionRunning)
    c = gr.classify(controller.store, project_id, mission_id)
    assert (c.admission_status, c.status_reason) == ("AMBIGUOUS", "intent_without_commit")


# VAL-19 ----------------------------------------------------------------------


def test_val19_forced_unsupported(tmp_path, monkeypatch):
    controller, project_id, mission_id = governed_project(tmp_path / "g")
    monkeypatch.setattr(gr, "GOVERNED_FS_CAPABLE", False)
    assert _step(controller, project_id).detail == "governed_platform_unsupported"
    assert controller.dispatcher.calls == []
    controller.store.save_state(project_id, MissionPlanning(mission_id=mission_id))
    assert pytest.raises(ToolError, controller.submit_plan, project_id,
                         work_plan(["VAL-A"])).value.code == "governed_admission_unresolved"
    legacy = make_controller(tmp_path / "l")
    pid = start(legacy, tmp_path / "l")
    write_criteria(legacy.store, pid, "mission-001", {"VAL-A": "a\n"})
    before = tree_snapshot(legacy.store.bucket_root(pid))
    assert pytest.raises(ToolError, legacy.submit_governed_plan, pid, "mission-001",
                         work_plan(["VAL-A"]), request()).value.code == (
        "governed_platform_unsupported")
    assert tree_snapshot(legacy.store.bucket_root(pid)) == before
    legacy.submit_plan(pid, work_plan(["VAL-A"]))
    legacy.advance_project(pid, 1)
    assert legacy.dispatcher.calls
    assert not governed_dir(legacy.store, pid, "mission-001").exists()


# VAL-20 / VAL-21 -------------------------------------------------------------


def _plans():
    single = TaskList(tasks=[
        Task(id="w0", type="work", body="do", targets=["VAL-A", "VAL-B"], skill="s")])
    validation = TaskList(tasks=[
        Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s"),
        Task(id="w1", type="work", body="do", targets=["VAL-B"], skill="s"),
        Task(id="v0", type="validate", body="c", targets=["VAL-A"], skill="s",
             depends_on=["w0", "w1"]),
        Task(id="v1", type="validate", body="c", targets=["VAL-B"], skill="s",
             depends_on=["w0", "w1"])])
    isolated = TaskList(tasks=[
        Task(id="w0", type="work", body="do\nWrites: a.txt", targets=["VAL-A"], skill="s",
             auto_merge=True),
        Task(id="w1", type="work", body="do\nWrites: b.txt", targets=["VAL-B"], skill="s",
             auto_merge=True)])
    return {"single": single, "validation": validation, "isolated": isolated}


def _works_done(controller, project_id, mid):
    task_state = controller.store.load_task_state(project_id, mid)
    for task_id in ("w0", "w1"):
        task_state.set_status(task_id, "cleared")
    controller.store.save_task_state(project_id, mid, task_state)


@pytest.mark.parametrize("shape", ["single", "validation", "isolated"])
@pytest.mark.parametrize("status", ["AMBIGUOUS", "UNAVAILABLE"])
def test_val20_refusal_before_any_effect(tmp_path, monkeypatch, shape, status):
    criteria = {"VAL-A": "a\n", "VAL-B": "b\n"}
    plan = _plans()[shape]
    if status == "AMBIGUOUS":
        controller, project_id, mid = _ambiguous(tmp_path, plan, criteria, max_parallel_nodes=2)
    else:
        controller, project_id, mid = governed_project(tmp_path, criteria=criteria, plan=plan,
                                                       max_parallel_nodes=2)
        _corrupt_criterion(controller, project_id, mid)
    if shape == "validation":
        _works_done(controller, project_id, mid)
    monkeypatch.setattr(coordinator_module.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("git")))
    supervision: list[str] = []
    monkeypatch.setattr(MissionCoordinator, "_begin_supervision_attempt",
                        lambda self, *a, **k: supervision.append("x"))
    task_state = controller.store.mission_runtime_dir(project_id, mid) / "task-state.json"
    before = task_state.read_bytes()
    result = _step(controller, project_id)
    expected = ("governed_admission_unresolved" if status == "AMBIGUOUS"
                else "governed_content_unavailable")
    assert result.detail == expected
    assert task_state.read_bytes() == before
    assert controller.dispatcher.calls == [] and supervision == []


def test_val21_one_corrupt_criterion_idles_whole_batch(tmp_path):
    criteria = {"VAL-A": "a\n", "VAL-B": "b\n"}
    controller, project_id, mid = governed_project(
        tmp_path, criteria=criteria, plan=_plans()["validation"], max_parallel_nodes=2)
    _works_done(controller, project_id, mid)
    _corrupt_criterion(controller, project_id, mid, "VAL-B")
    result = _step(controller, project_id)
    assert result.detail == "governed_content_unavailable"
    task_state = controller.store.load_task_state(project_id, mid)
    assert all(task_state.status_of(t) != "running" for t in ("v0", "v1"))


# VAL-22 ----------------------------------------------------------------------


def test_val22_per_request_bindings_frozen_and_not_retained(tmp_path):
    criteria = {"VAL-A": "a\n", "VAL-B": "b\n"}
    controller, project_id, mid = governed_project(
        tmp_path, criteria=criteria, plan=_plans()["validation"], max_parallel_nodes=2)
    _works_done(controller, project_id, mid)
    coordinator = MissionCoordinator(controller.store, project_id, controller.dispatcher,
                                     controller.terminal_reviewer, governed_delivery_route=True)
    before_dispatcher = dict(vars(controller.dispatcher))
    before_dispatcher.pop("calls")
    before_coordinator = dict(vars(coordinator))
    coordinator.step()
    calls = controller.dispatcher.calls
    assert len(calls) == 2
    templates = {c.task.id: c.governance.template for c in calls}
    assert templates["v0"].criteria != templates["v1"].criteria
    assert calls[0].governance.scope is not calls[1].governance.scope
    with pytest.raises(dataclasses.FrozenInstanceError):
        templates["v0"].admission_id = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        calls[0].governance.template = templates["v1"]  # type: ignore[misc]
    after_dispatcher = dict(vars(controller.dispatcher))
    after_dispatcher.pop("calls")
    assert after_dispatcher == before_dispatcher
    assert vars(coordinator) == before_coordinator


# VAL-23 ----------------------------------------------------------------------


def test_val23_non_capable_dispatcher_refused(tmp_path):
    controller, project_id, _ = governed_project(tmp_path, capable=False)
    assert _step(controller, project_id).detail == "governed_dispatcher_unsupported"
    assert controller.dispatcher.calls == []


@pytest.mark.parametrize("status", ["COMMITTED", "AMBIGUOUS", "UNAVAILABLE"])
def test_val23_terminal_review_baseline(tmp_path, status):
    controller, project_id, mid = governed_project(tmp_path)
    for _ in range(4):
        controller.advance_project(project_id, 1)
    if status == "UNAVAILABLE":
        _corrupt_criterion(controller, project_id, mid)
    elif status == "AMBIGUOUS":
        admission = governed_dir(controller.store, project_id, mid) / "admission"
        (aid_dir,) = list(admission.iterdir())
        (aid_dir / "commit.json").unlink()
    legacy = make_controller(tmp_path / "legacy")
    pid = start(legacy, tmp_path / "legacy")
    write_criteria(legacy.store, pid, "mission-001", {"VAL-A": "Criterion A body.\n"})
    legacy.submit_plan(pid, work_plan(["VAL-A"]))
    for _ in range(4):
        legacy.advance_project(pid, 1)
    governed_end = controller.end_mission(project_id)
    legacy_end = legacy.end_mission(pid)
    assert governed_end.state.state == legacy_end.state.state
    assert type(controller.terminal_reviewer) is MockTerminalReviewer


# VAL-24 ----------------------------------------------------------------------


def test_val24_patch_target_not_admitted(tmp_path):
    def fail(request: DispatchRequest):
        return WorkHandoff(node_id=request.task.id, done=False, report="blocked")

    controller, project_id, mid = governed_project(tmp_path, responder=fail)
    controller.advance_project(project_id, 1)
    write_criteria(controller.store, project_id, mid, {"VAL-B": "b\n"})
    items = controller.store.load_attention(project_id)
    controller.decide_attention(project_id, [Decision(
        item_id=items[0].id, action="patch", patch=TaskListPatch(
            add_items=["VAL-B"],
            add=[Task(id="w9", type="work", body="do", targets=["VAL-A", "VAL-B"],
                      skill="s")],
            supersede={"w0": "w9"}))])
    assert _step(controller, project_id).detail == "governed_content_unavailable"
    page = controller.inspect_governed(project_id, mid, "task_gate")
    rows = page["governed_inspection"]["rows"]
    assert {"task_id": "w9", "reason": "target_not_admitted"} in rows


# VAL-25 ----------------------------------------------------------------------


def test_val25_abandoned_is_legacy_after_abandon(tmp_path):
    controller, project_id, mid = governed_project(tmp_path)
    receipt = controller.abandon_governance(project_id, mid, abandon_request())
    controller.advance_project(project_id, 1)
    (call,) = controller.dispatcher.calls
    assert isinstance(call.governance, gr.LegacyAfterAbandon)
    assert call.governance.abandon_id == receipt["governed_abandon"]["abandon_id"]


def test_val25_governance_is_mandatory():
    task = Task(id="w0", type="work", body="do", targets=["VAL-A"], skill="s")
    with pytest.raises(TypeError):
        DispatchRequest(project_id="p", mission_id="mission-001", task=task,  # type: ignore[call-arg]
                        spawn_ts="20260101T000000Z")
    coordinator = MissionCoordinator.__new__(MissionCoordinator)
    with pytest.raises(TypeError):
        coordinator._dispatch_one("mission-001", task)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        coordinator._dispatch_batch("mission-001", TaskList(tasks=[task]), None, [task])  # type: ignore[call-arg,arg-type]
    with pytest.raises(TypeError):
        coordinator._dispatch_isolated_work_batch("mission-001", None, [task])  # type: ignore[call-arg,arg-type]


# VAL-26 ----------------------------------------------------------------------


def test_val26_default_route_refuses_committed(tmp_path):
    controller, project_id, _ = governed_project(tmp_path)
    assert _step(controller, project_id, route=False).detail == "governed_route_unsupported"
    assert controller.dispatcher.calls == []
    legacy = make_controller(tmp_path / "l")
    pid = start(legacy, tmp_path / "l")
    write_criteria(legacy.store, pid, "mission-001", {"VAL-A": "a\n"})
    legacy.submit_plan(pid, work_plan(["VAL-A"]))
    _step(legacy, pid, route=False)
    assert isinstance(legacy.dispatcher.calls[0].governance, gr.LegacyNoAdmission)
    abandoned, apid, amid = governed_project(tmp_path / "a")
    abandoned.abandon_governance(apid, amid, abandon_request())
    _step(abandoned, apid, route=False)
    assert isinstance(abandoned.dispatcher.calls[0].governance, gr.LegacyAfterAbandon)
    assert hashlib.sha256((ROOT / "src/unrest_harness/cli.py").read_bytes()).hexdigest() == CLI_SHA


# VAL-27 ----------------------------------------------------------------------


def test_val27_executor_invoke_delivers_template(tmp_path):
    from unrest_harness import runtime_executor

    controller, project_id, _ = governed_project(tmp_path)
    runtime_executor._invoke(controller, "advance_project", {"project_id": project_id,
                                                             "max_steps": 1})
    (call,) = controller.dispatcher.calls
    assert isinstance(call.governance, gr.GovernedBound)


def test_val27_executor_execute_ambiguous_idles(tmp_path, monkeypatch):
    from unrest_harness import runtime_executor
    from unrest_harness.config import HarnessConfig

    controller, project_id, mid = _ambiguous(tmp_path)
    config = make_config(tmp_path)
    monkeypatch.setattr(HarnessConfig, "discover", classmethod(lambda cls, *a, **k: config))
    task_state = controller.store.mission_runtime_dir(project_id, mid) / "task-state.json"
    before = task_state.read_bytes()
    payload = runtime_executor.execute("advance_project", {"project_id": project_id,
                                                           "max_steps": 1}, object())
    assert payload["state"] == {"state": "mission_running", "mission_id": mid}
    assert task_state.read_bytes() == before
    assert not list(controller.store.mission_runtime_dir(project_id, mid).glob("attempts/*"))


# VAL-28 ----------------------------------------------------------------------


@pytest.mark.parametrize("corruption", ["foreign_member", "foreign_admission"])
def test_val28_corrupt_executions(tmp_path, corruption):
    controller, project_id, mid = governed_project(tmp_path)
    controller.advance_project(project_id, 1)
    executions = governed_dir(controller.store, project_id, mid) / "executions"
    (scope,) = list(executions.iterdir())
    if corruption == "foreign_member":
        (scope / "stray").write_text("x")
    else:
        opened = scope / "opened.json"
        record = json.loads(opened.read_bytes())
        record["admission_id"] = "f" * 32
        opened.chmod(0o600)
        opened.write_bytes(gr.canonical_bytes(record))
    assert _step(controller, project_id).detail == "governed_content_unavailable"
    assert pytest.raises(ToolError, controller.abandon_governance, project_id, mid,
                         abandon_request()).value.code == "governed_content_unavailable"
    replay = controller.submit_governed_plan(project_id, mid, work_plan(["VAL-A"]), request())
    assert replay["governed_admission"]["replayed"] is True
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert summary["admission_status"] == "COMMITTED"
    assert summary["executions_status"] == "unavailable"
    admission = governed_dir(controller.store, project_id, mid) / "admission"
    (aid_dir,) = list(admission.iterdir())
    (aid_dir / "manifest.json").chmod(0o600)
    (aid_dir / "manifest.json").write_text("{")
    code = pytest.raises(ToolError, controller.submit_governed_plan, project_id, mid,
                         work_plan(["VAL-A"]), request()).value.code
    assert code == "governed_admission_unresolved", code


# VAL-29 ----------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["governed_admission_unresolved",
                                    "governed_content_unavailable",
                                    "governed_platform_unsupported",
                                    "governed_witness_unavailable", None])
def test_val29_same_cut_parity(tmp_path, monkeypatch, reason):
    if reason == "governed_admission_unresolved":
        controller, project_id, mid = _ambiguous(tmp_path)
    elif reason == "governed_content_unavailable":
        controller, project_id, mid = _unavailable(tmp_path)
    else:
        controller, project_id, mid = governed_project(tmp_path)
    if reason == "governed_platform_unsupported":
        monkeypatch.setattr(gr, "GOVERNED_FS_CAPABLE", False)
    if reason == "governed_witness_unavailable":
        real_classify = gr.classify

        def at_capacity(*args, **kwargs):
            c = real_classify(*args, **kwargs)
            views = dict(c.executions)
            views.update({f"x{i}": None for i in range(gr.EXECUTIONS_MAX)})
            return dataclasses.replace(c, executions=views)  # type: ignore[arg-type]

        monkeypatch.setattr(ga, "classify", at_capacity)
        monkeypatch.setattr(coordinator_module, "count_executions",
                            lambda *a: gr.EXECUTIONS_MAX)
    gate = controller.inspect_governed(project_id, mid)["governed_inspection"]["dispatch_gate"]
    result = _step(controller, project_id)
    if reason is None:
        assert gate["reason"] is None and gate["mode"] == "governed_bound"
        assert len(controller.dispatcher.calls) == 1
    else:
        assert result.detail == reason == gate["reason"]
        assert controller.dispatcher.calls == []
