"""Governed S1 inspector: lock-free reads, pagination, budget, determinism (VAL-45..49, 54)."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from tests.governed_s1_support import (
    governed_dir,
    governed_project,
    make_controller,
    request,
    start,
    tree_snapshot,
    work_plan,
    write_criteria,
)
from unrest_harness import governed_admission as ga
from unrest_harness import governed_records as gr
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.models import Task, TaskList

ROOT = Path(__file__).resolve().parents[1]
CATALOG_SHAS = {
    "docs/v03/v0.3.1/public-surface.v1.json":
        "2d500d39a401837162625254d954cb3431760a10b78661f3156ec08bc956c4ad",
    "src/unrest_harness/bundled/foundation/public-surface.v1.json":
        "df5a5f15a9c4840849b9ead85d52d12b8af52a5607ee30cf7bff4d44300fe051",
    "docs/architecture/approval-recovery.md":
        "622c17d22e82bcbf6e79e27c8c17f59da05eed02ac1d8adc590a22f38ee53496",
}


def _close_scopes(controller, project_id, mid, count, start_index=0):
    c = gr.classify(controller.store, project_id, mid)
    for index in range(start_index, start_index + count):
        scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                                  project_id=project_id, mission_id=mid,
                                  admission_id=c.admission_id or "",
                                  attempt_id=f"2000-01-01T00-00-00Z-{index:04d}",
                                  node_id="w0", inventory={})
        gr.open_scope(controller.store, scope)
        gr.close_scope(scope, effect_started=False, outcome=None)


def _orphans(controller, project_id, mid, count, plan):
    real = ga.publish

    def cut(fd, name, *args, **kwargs):
        if name == "intent.json":
            raise OSError("cut")
        return real(fd, name, *args, **kwargs)

    ga.publish = cut
    try:
        for _ in range(count):
            with pytest.raises(ToolError):
                controller.submit_governed_plan(project_id, mid, plan, request())
    finally:
        ga.publish = real


# VAL-45 ----------------------------------------------------------------------


def test_val45_inspect_is_write_free_and_lock_free(tmp_path, monkeypatch):
    import fcntl

    controller, project_id, mid = governed_project(tmp_path)
    MissionCoordinator(controller.store, project_id, controller.dispatcher,
                       controller.terminal_reviewer, governed_delivery_route=True).step()
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    monkeypatch.setattr(fcntl, "flock", lambda *a: (_ for _ in ()).throw(AssertionError("lock")))
    monkeypatch.setattr(type(controller.store), "recover_patch_transactions",
                        lambda *a: (_ for _ in ()).throw(AssertionError("recovery")))
    for section in ("summary", "criteria", "task_gate", "executions"):
        controller.inspect_governed(project_id, mid, section)
    assert tree_snapshot(bucket) == before


def test_val45_membership_change_single_recheck(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path)
    calls: list[int] = []
    real = ga.membership_fingerprint

    def changing(*args):
        calls.append(1)
        value = real(*args)
        return value if len(calls) == 1 else (*value, "changed")

    monkeypatch.setattr(ga, "membership_fingerprint", changing)
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert summary["status_reason"] == "concurrent_change" and len(calls) == 2
    assert summary["dispatch_gate"]["reason"] == "governed_content_unavailable"


def test_val45_committed_survives_product_byte_changes(tmp_path):
    controller, project_id, mid = governed_project(tmp_path)
    tasks = controller.store.mission_runtime_dir(project_id, mid) / "task-state.json"
    tasks.write_text(tasks.read_text() + " ")
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert summary["admission_status"] == "COMMITTED"


# VAL-46 ----------------------------------------------------------------------


def _pages(controller, project_id, mid, section):
    cursor = None
    pages = []
    while True:
        result = controller.inspect_governed(project_id, mid, section, cursor)
        size = len(gr.canonical_bytes(result))
        assert size <= gr.OUTPUT_LIMIT
        page = result["governed_inspection"]
        pages.append(page)
        assert page["page"]["complete"] == (page["page"]["next_cursor"] is None)
        cursor = page["page"]["next_cursor"]
        if cursor is None:
            return pages


def test_val46_criteria_pages(tmp_path):
    criteria = {f"VAL-C{index:03d}": f"criterion {index}\n" for index in range(256)}
    plan = TaskList(tasks=[Task(id="w0", type="work", body="do", targets=sorted(criteria),
                                skill="s")])
    controller, project_id, mid = governed_project(tmp_path, criteria=criteria, plan=plan)
    pages = _pages(controller, project_id, mid, "criteria")
    assert [len(page["rows"]) for page in pages] == [64, 64, 64, 64]
    assert all(page["page"]["total"] == 256 for page in pages)
    assert [page["page"]["complete"] for page in pages] == [False, False, False, True]
    ids = [row["assertion_id"] for page in pages for row in page["rows"]]
    assert ids == sorted(criteria) and len(set(ids)) == 256


def test_val46_task_gate_and_execution_pages(tmp_path):
    plan = TaskList(tasks=[Task(id="t000", type="work", body="do", targets=["VAL-A"],
                                skill="s")] + [
        Task(id=f"t{index:03d}", type="validate", body="check", targets=["VAL-A"], skill="s",
             depends_on=["t000"]) for index in range(1, 300)])
    controller, project_id, mid = governed_project(tmp_path, plan=plan)
    pages = _pages(controller, project_id, mid, "task_gate")
    assert [len(page["rows"]) for page in pages] == [256, 44]
    ids = [row["task_id"] for page in pages for row in page["rows"]]
    assert len(set(ids)) == 300
    _close_scopes(controller, project_id, mid, 20)
    pages = _pages(controller, project_id, mid, "executions")
    assert [len(page["rows"]) for page in pages] == [8, 8, 4]
    assert len({row["attempt_id"] for page in pages for row in page["rows"]}) == 20


@pytest.mark.parametrize(("section", "cursor"), [
    ("criteria", "../x"), ("task_gate", ""), ("executions", "bad"), ("summary", "x"),
    ("nope", None), ("criteria", 7)])
def test_val46_invalid_request(tmp_path, section, cursor):
    controller, project_id, mid = governed_project(tmp_path)
    with pytest.raises(ToolError) as caught:
        controller.inspect_governed(project_id, mid, section, cursor)
    assert caught.value.code == "governed_request_invalid"


def test_val46_output_limit_refuses_not_truncates(tmp_path, monkeypatch):
    controller, project_id, mid = governed_project(tmp_path)
    monkeypatch.setattr(ga, "OUTPUT_LIMIT_ACTIVE", [64])
    with pytest.raises(ToolError) as caught:
        controller.inspect_governed(project_id, mid)
    assert caught.value.code == "governed_output_unavailable"


# VAL-47 ----------------------------------------------------------------------


@pytest.mark.parametrize(("n_a", "n_x"), [(1, 0), (3, 5), (16, 40)])
def test_val47_health_pass_budget(tmp_path, monkeypatch, n_a, n_x):
    criteria = {f"VAL-C{index:03d}": f"criterion {index}\n" for index in range(256)}
    plan = TaskList(tasks=[Task(id="w0", type="work", body="do", targets=sorted(criteria),
                                skill="s")])
    controller, project_id, mid = governed_project(tmp_path, criteria=criteria, plan=plan,
                                                   admit=False)
    _orphans(controller, project_id, mid, n_a - 1, plan)
    controller.submit_governed_plan(project_id, mid, plan, request())
    _close_scopes(controller, project_id, mid, n_x)
    files: list[str] = []
    opened: list[str] = []
    read_bytes = [0]
    classify_calls = [0]
    real_open, real_read, real_classify = os.open, os.read, gr.classify
    import stat as stat_module

    names: dict[int, str] = {}

    def open_spy(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if not stat_module.S_ISDIR(os.fstat(fd).st_mode):
            names[fd] = os.fspath(path)
            opened.append(os.fspath(path))
        return fd

    def read_spy(fd, n):
        data = real_read(fd, n)
        read_bytes[0] += len(data)
        if fd in names:
            files.append(names.pop(fd))
        return data

    import unrest_harness.coordinator as coordinator_module

    def classify_spy(*args, **kwargs):
        classify_calls[0] += 1
        monkeypatch.setattr(os, "open", open_spy)
        monkeypatch.setattr(os, "read", read_spy)
        try:
            return real_classify(*args, **kwargs)
        finally:
            monkeypatch.setattr(os, "open", real_open)
            monkeypatch.setattr(os, "read", real_read)

    monkeypatch.setattr(coordinator_module, "classify", classify_spy)
    MissionCoordinator(controller.store, project_id, controller.dispatcher,
                       controller.terminal_reviewer, governed_delivery_route=True).step()
    assert classify_calls[0] == 1
    reads_max = 262 + 3 * n_x
    bytes_max = 34_938_880 + 262 + n_x * 3 * (4_096 + 1)
    assert len(files) <= reads_max and read_bytes[0] <= bytes_max, files[:3] + files[-6:]
    # fstat-only post-images are opened but never read (amendment §2.2).
    assert len(opened) - len(files) <= 3
    criterion_opens = [name for name in opened if re.fullmatch(r"VAL-C\d{3}\.v1\.md", name)]
    assert sorted(criterion_opens) == sorted(f"{aid}.v1.md" for aid in criteria)


def test_val60_ceiling_arithmetic():
    rows = [(1, 65_536), (1, 4_096), (1, 1_048_576), (256, 65_536), (1, 16_777_216),
            (1, 262_144), (1, 4_096), (12_288, 4_096)]
    total = sum(count * (limit + 1) for count, limit in rows)
    assert total == 85_283_078 <= 82 * 1024 * 1024
    assert (gr.INTENT_LIMIT, gr.SMALL_RECORD_LIMIT, gr.MANIFEST_LIMIT, gr.CRITERION_LIMIT,
            gr.POST_IMAGE_LIMIT, gr.ABANDON_LIMIT, gr.STATE_LIMIT, gr.EXECUTIONS_MAX,
            gr.CRITERIA_MAX) == (65_536, 4_096, 1_048_576, 65_536, 16_777_216, 262_144,
                                 4_096, 4_096, 256)


# VAL-48 / VAL-49 -------------------------------------------------------------


def test_val48_deterministic_across_dispatchers(tmp_path):
    controller, project_id, mid = governed_project(tmp_path)
    other = ProjectController(controller.config, make_controller(tmp_path / "o",
                                                                 capable=False).dispatcher,
                              controller.terminal_reviewer)
    for section in ("summary", "criteria", "task_gate", "executions"):
        left = controller.inspect_governed(project_id, mid, section)
        right = other.inspect_governed(project_id, mid, section)
        assert gr.canonical_bytes(left) == gr.canonical_bytes(right)
    summary = controller.inspect_governed(project_id, mid)["governed_inspection"]
    assert summary["dispatch_gate"]["assumed_route"] == "e1_e3"


def test_val49_declared_limit_stage_change_not_detected(tmp_path, monkeypatch):
    """Declared limit N6: a stage file edited between classify and its read is not
    reported as concurrent_change. The test pins the limit; it does not hide it."""
    controller, project_id, mid = governed_project(tmp_path)
    c = gr.classify(controller.store, project_id, mid)
    scope = gr.ExecutionScope(anchor=controller.store.unrest_dir(project_id),
                              project_id=project_id, mission_id=mid,
                              admission_id=c.admission_id or "",
                              attempt_id="2000-01-01T00-00-00Z-0001", node_id="w0",
                              inventory={})
    gr.open_scope(controller.store, scope)
    wid = gr.register_witness(scope)
    assert wid is not None
    gr.publish_witness_stage(scope, wid, "prepared", gr.witness_record(
        scope, wid, "prepared", "initial", jsonrpc_id=1, render_version=gr.RENDER_VERSION,
        criteria=[]), [{}])
    gr.close_scope(scope, effect_started=True, outcome="completed")
    stage = scope.anchor.joinpath(*scope.components(), "submissions", wid, "prepared.json")
    real = ga.read_witness_stages

    def mutate_then_read(*args):
        stage.chmod(0o600)
        stage.write_text("{}")
        return real(*args)

    monkeypatch.setattr(ga, "read_witness_stages", mutate_then_read)
    page = controller.inspect_governed(project_id, mid, "executions")["governed_inspection"]
    assert page["status_reason"] != "concurrent_change"
    assert page["rows"][0]["witnesses"][0]["submission_outcome"] == "unavailable"


# VAL-54 ----------------------------------------------------------------------


def test_val54_catalogs_and_api_unchanged():
    from unrest_harness import api

    for relative, digest in CATALOG_SHAS.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest
    bundled = json.loads((ROOT / "src/unrest_harness/bundled/foundation/"
                                 "public-surface.v1.json").read_text())
    text = json.dumps(bundled)
    for name in ("submit_governed_plan", "abandon_governance", "inspect_governed"):
        assert name not in text
    assert len(api.__all__) == 27


def test_val54_server_registers_three_lifecycle_tools(tmp_path):
    import asyncio

    from unrest_harness.server import create_orchestrator_server

    controller = make_controller(tmp_path)
    server = create_orchestrator_server(controller.config, controller)
    tools = {tool.name for tool in asyncio.run(server.list_tools())}
    assert {"submit_governed_plan", "abandon_governance", "inspect_governed"} <= tools


def test_val54_server_tools_round_trip(tmp_path):
    import asyncio

    from unrest_harness.server import create_orchestrator_server

    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    server = create_orchestrator_server(controller.config, controller)

    async def call(name, arguments):
        result = await server.call_tool(name, arguments)
        return result.structured_content

    receipt = asyncio.run(call("submit_governed_plan", {
        "project_id": project_id, "mission_id": "mission-001",
        "task_list": work_plan(["VAL-A"]).model_dump(mode="json"), "governed": request()}))
    assert receipt["governed_admission"]["status"] == "COMMITTED"
    summary = asyncio.run(call("inspect_governed", {"project_id": project_id,
                                                    "mission_id": "mission-001"}))
    assert summary["governed_inspection"]["admission_status"] == "COMMITTED"
    refused = asyncio.run(call("abandon_governance", {
        "project_id": project_id, "mission_id": "mission-001",
        "governed_abandon": {"schema": "bad", "idempotency_key": "k"}}))
    assert refused["error"] == "governed_request_invalid"
    assert governed_dir(controller.store, project_id, "mission-001").exists()
