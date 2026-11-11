"""Governed S1 identity (ADR-0507): ownership, four-way classification,
reservation allocation, capacity, consumption marker (IC-01..10, ID-01..14)."""
from __future__ import annotations

import ast
import json
import os
import shutil
from pathlib import Path

import pytest

from tests.governed_s1_support import (
    governed_dir,
    make_controller,
    request,
    start,
    tree_snapshot,
    work_plan,
    workspace,
    write_criteria,
)
from unrest_harness import governed_admission as ga
from unrest_harness import governed_records as gr
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.envelope import public_attention_items
from unrest_harness.models import (
    AttentionItemInternal,
    AttentionNeeded,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
)

ROOT = Path(__file__).resolve().parents[1]


def _err(callable_, *args, **kwargs) -> ToolError:
    with pytest.raises(ToolError) as caught:
        callable_(*args, **kwargs)
    return caught.value


def _identity(controller: ProjectController, project_id: str) -> Path:
    return controller.store.unrest_dir(project_id) / "identity"


def _reservation_bytes(project_id: str, mid: str, route: str = "next_seal") -> bytes:
    return gr.canonical_bytes({
        "schema": "unrest.governed-mission-reservation.v1", "project_id": project_id,
        "mission_id": mid, "route": route,
    })


def _fill_reservations(controller, project_id: str, total: int) -> None:
    missions = _identity(controller, project_id) / "missions"
    for index in range(2, total + 1):
        mid = gr.mission_name(index)
        (missions / f"{mid}.json").write_bytes(_reservation_bytes(project_id, mid))


def _work(task_id: str) -> Task:
    return Task(id=task_id, type="work", body="do", targets=["VAL-X"], skill="s")


def _attention(controller, project_id: str, mission_id: str = "mission-001",
               *, reviews: int = 1) -> list[AttentionItemInternal]:
    store = controller.store
    write_criteria(store, project_id, mission_id, {"VAL-X": "x\n"})
    store.save_task_list(project_id, mission_id, TaskList(tasks=[_work("w1")]))
    task_state = TaskStateFile()
    task_state.set_status("w1", "failed")
    store.save_task_state(project_id, mission_id, task_state)
    store.save_contract_state(project_id, mission_id,
                              ContractStateFile(items={"VAL-X": ContractStateEntry()}))
    items = [AttentionItemInternal(id="attention-node", report="r", kind="node_failed",
                                   mission_id=mission_id, node_id="w1")]
    items += [AttentionItemInternal(id=f"attention-review-{index}", report="r",
                                    kind="terminal_review", mission_id=mission_id,
                                    terminal_review_id=f"review-{index}")
              for index in range(reviews)]
    store.save_attention(project_id, items)
    store.save_state(project_id, AttentionNeeded(items=public_attention_items(items)))
    record = store.load_project(project_id)
    record.current_mission_id = mission_id
    store.save_project(record)
    return items


def _decisions(branch: str, reviews: int = 1) -> list[Decision]:
    if branch == "transactional":
        result = [Decision(item_id="attention-node", action="patch", patch=TaskListPatch(
            add=[_work("w2")], supersede={"w1": "w2"}))]
    else:
        result = [Decision(item_id="attention-node", action="continue")]
    return result + [Decision(item_id=f"attention-review-{index}", action="next_mission")
                     for index in range(reviews)]


def _legacy_project(tmp_path: Path) -> tuple[ProjectController, str]:
    controller = make_controller(tmp_path)
    record = controller.store.create_project("legacy", workspace(tmp_path), project_id="legacy-1")
    record.current_mission_id = "mission-001"
    controller.store.save_project(record)
    controller.store.save_state("legacy-1", MissionPlanning(mission_id="mission-001"))
    return controller, "legacy-1"


def _project_in_state(tmp_path: Path, state: str) -> tuple[ProjectController, str]:
    if state == "LEGACY":
        return _legacy_project(tmp_path)
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    identity = _identity(controller, project_id)
    if state == "INITIALIZING":
        (identity / "ready.json").unlink()
    elif state == "IDENTITY_UNAVAILABLE":
        (identity / "missions" / "mission-001.json").write_text("{}")
    return controller, project_id


# IC-01 ----------------------------------------------------------------------

IC01 = {
    "enoent": "LEGACY",
    "symlink": "IDENTITY_UNAVAILABLE",
    "dangling_symlink": "IDENTITY_UNAVAILABLE",
    "symlink_loop": "IDENTITY_UNAVAILABLE",
    "file": "IDENTITY_UNAVAILABLE",
    "empty": "IDENTITY_UNAVAILABLE",
    "residue_only": "IDENTITY_UNAVAILABLE",
    "foreign_member": "IDENTITY_UNAVAILABLE",
    "init_missing": "IDENTITY_UNAVAILABLE",
    "init_malformed": "IDENTITY_UNAVAILABLE",
    "init_foreign_pid": "IDENTITY_UNAVAILABLE",
    "init_oversize": "IDENTITY_UNAVAILABLE",
    "missions_missing": "IDENTITY_UNAVAILABLE",
    "missions_symlink": "IDENTITY_UNAVAILABLE",
    "noncanonical_name": "IDENTITY_UNAVAILABLE",
    "content_mismatch": "IDENTITY_UNAVAILABLE",
    "orphan_consumed": "IDENTITY_UNAVAILABLE",
    "no_mission_001": "IDENTITY_UNAVAILABLE",
    "reservations_4097": "IDENTITY_UNAVAILABLE",
    "ready_missing": "INITIALIZING",
    "ready_malformed": "IDENTITY_UNAVAILABLE",
    "ready_valid": "ELIGIBLE",
}


@pytest.mark.parametrize("case", sorted(IC01))
def test_ic01_classify_identity_matrix(tmp_path, case):
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    identity = _identity(controller, project_id)
    missions = identity / "missions"
    elsewhere = tmp_path / "elsewhere"
    if case in ("enoent", "symlink", "dangling_symlink", "symlink_loop", "file", "empty",
                "residue_only"):
        shutil.copytree(identity, elsewhere)
        shutil.rmtree(identity)
        if case == "symlink":
            identity.symlink_to(elsewhere)
        elif case == "dangling_symlink":
            identity.symlink_to(tmp_path / "missing")
        elif case == "symlink_loop":
            identity.symlink_to(identity)
        elif case == "file":
            identity.write_text("x")
        elif case == "empty":
            identity.mkdir()
        elif case == "residue_only":
            identity.mkdir()
            (identity / (".tmp-" + "0" * 32)).write_text("")
    elif case == "foreign_member":
        (identity / "extra.json").write_text("{}")
    elif case == "init_missing":
        (identity / "init.json").unlink()
    elif case == "init_malformed":
        (identity / "init.json").write_text("{ }")
    elif case == "init_foreign_pid":
        (identity / "init.json").write_bytes(gr.canonical_bytes(
            {"schema": "unrest.governed-identity-init.v1", "project_id": "other"}))
    elif case == "init_oversize":
        (identity / "init.json").write_bytes(b" " * 5000)
    elif case == "missions_missing":
        shutil.rmtree(missions)
    elif case == "missions_symlink":
        shutil.copytree(missions, elsewhere)
        shutil.rmtree(missions)
        missions.symlink_to(elsewhere)
    elif case == "noncanonical_name":
        (missions / "mission-0002.json").write_bytes(_reservation_bytes(project_id, "mission-0002"))
    elif case == "content_mismatch":
        (missions / "mission-002.json").write_bytes(_reservation_bytes(project_id, "mission-003"))
    elif case == "orphan_consumed":
        (missions / "mission-002.consumed").write_bytes(gr.canonical_bytes({
            "schema": "unrest.governed-mission-consumed.v1", "project_id": project_id,
            "mission_id": "mission-002"}))
    elif case == "no_mission_001":
        (missions / "mission-002.json").write_bytes(_reservation_bytes(project_id, "mission-002"))
        (missions / "mission-001.json").unlink()
    elif case == "reservations_4097":
        _fill_reservations(controller, project_id, 4097)
    elif case == "ready_missing":
        (identity / "ready.json").unlink()
    elif case == "ready_malformed":
        (identity / "ready.json").write_text("[]")
    assert gr.classify_identity(controller.store, project_id).state == IC01[case]


def test_ic01_identity_unreadable_is_unavailable(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("NOTRUN: euid 0 bypasses permissions")
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    identity = _identity(controller, project_id)
    identity.chmod(0)
    try:
        assert gr.classify_identity(controller.store, project_id).state == "IDENTITY_UNAVAILABLE"
    finally:
        identity.chmod(0o700)


def test_ic01_legacy_only_on_lstat_enoent():
    source = ast.parse(Path(gr.__file__).read_text())
    function = next(node for node in ast.walk(source)
                    if isinstance(node, ast.FunctionDef) and node.name == "classify_identity")
    calls = {ast.unparse(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}
    assert "os.lstat" in calls
    assert not any(name.endswith((".exists", ".is_dir", ".is_file")) for name in calls)


# IC-02 / capacity -------------------------------------------------------------


@pytest.mark.parametrize("branch", ["transactional", "seal"])
@pytest.mark.parametrize("state", ["LEGACY", "INITIALIZING", "ELIGIBLE", "IDENTITY_UNAVAILABLE"])
def test_ic02_next_mission_per_state_and_branch(tmp_path, state, branch):
    controller, project_id = _project_in_state(tmp_path, state)
    _attention(controller, project_id)
    bucket = controller.store.bucket_root(project_id)
    if state == "IDENTITY_UNAVAILABLE":
        before = tree_snapshot(bucket)
        assert _err(controller.decide_attention, project_id,
                    _decisions(branch)).code == "mission_identity_unavailable"
        assert tree_snapshot(bucket) == before
        return
    envelope = controller.decide_attention(project_id, _decisions(branch))
    assert envelope.state.mission_id == "mission-002"
    reservation = _identity(controller, project_id) / "missions" / "mission-002.json"
    assert reservation.exists() == (state != "LEGACY")
    if state == "LEGACY":
        assert not _identity(controller, project_id).exists()
        assert not os.path.lexists(_identity(controller, project_id))
        assert gr.classify_identity(controller.store, project_id).state == "LEGACY"
    else:
        route = "next_tx" if branch == "transactional" else "next_seal"
        assert json.loads(reservation.read_bytes())["route"] == route


@pytest.mark.parametrize("branch", ["transactional", "seal"])
def test_capacity_4095_to_4096_then_refusal_byte_identical(tmp_path, branch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _fill_reservations(controller, project_id, 4095)
    _attention(controller, project_id)
    envelope = controller.decide_attention(project_id, _decisions(branch))
    assert envelope.state.mission_id == "mission-4096"
    missions = _identity(controller, project_id) / "missions"
    assert len(list(missions.glob("*.json"))) == 4096
    assert gr.classify_identity(controller.store, project_id).state == "ELIGIBLE"
    _attention(controller, project_id, "mission-4096")
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    error = _err(controller.decide_attention, project_id, _decisions(branch))
    assert error.code == "mission_identity_capacity_exhausted"
    assert tree_snapshot(bucket) == before
    assert len(list(missions.glob("*.json"))) == 4096
    assert gr.classify_identity(controller.store, project_id).state == "ELIGIBLE"


def test_capacity_preexisting_4097_unavailable_and_legacy_submit_refused(tmp_path):
    # Amended by the S-5 amendment: over-capacity is IDENTITY_UNAVAILABLE and refuses.
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _fill_reservations(controller, project_id, 4097)
    assert gr.classify_identity(controller.store, project_id).state == "IDENTITY_UNAVAILABLE"
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "mission_identity_unavailable"
    assert tree_snapshot(bucket) == before
    assert not (_identity(controller, project_id) / "missions" / "mission-001.consumed").exists()
    _attention(controller, project_id)
    assert _err(controller.decide_attention, project_id,
                _decisions("seal")).code == "mission_identity_unavailable"


def test_capacity_single_function_used_by_every_producer(tmp_path):
    gr.reservation_capacity_check(4095)
    with pytest.raises(gr.IdentityError) as caught:
        gr.reservation_capacity_check(4096)
    assert caught.value.code == "mission_identity_capacity_exhausted"
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    missions = _identity(controller, project_id) / "missions"
    before = sorted(path.name for path in missions.iterdir())
    with pytest.raises(gr.IdentityError):
        gr.reserve_mission(controller.store, project_id, "mission-777", route="next_seal",
                           existing=4096)
    assert sorted(path.name for path in missions.iterdir()) == before
    reserve = ast.parse(Path(gr.__file__).read_text())
    function = next(node for node in ast.walk(reserve)
                    if isinstance(node, ast.FunctionDef) and node.name == "reserve_mission")
    first = function.body[0]
    assert isinstance(first, ast.Expr) and ast.unparse(first.value).startswith(
        "reservation_capacity_check(")
    controller_source = Path(ProjectController.__module__.replace(".", "/") + ".py")
    text = (ROOT / "src" / controller_source).read_text()
    assert 'route="start", existing=0' in text
    allocator = ast.parse(Path(ga.__file__).read_text())
    allocate = next(node for node in ast.walk(allocator)
                    if isinstance(node, ast.FunctionDef) and node.name == "allocate_next_mission")
    assert "existing=len(view.reserved)" in ast.unparse(allocate)


# IC-03..07 -------------------------------------------------------------------


def _next(controller, project_id, mid, branch="seal"):
    _attention(controller, project_id, mid)
    return controller.decide_attention(project_id, _decisions(branch)).state.mission_id


@pytest.mark.parametrize("state", ["INITIALIZING", "ELIGIBLE"])
def test_ic03_id05_runtime_loss_never_reuses(tmp_path, state):
    controller, project_id = _project_in_state(tmp_path, state)
    mids = ["mission-001"]
    for _ in range(3):
        mids.append(_next(controller, project_id, mids[-1]))
    assert mids == ["mission-001", "mission-002", "mission-003", "mission-004"]
    for mid in ("mission-002", "mission-003"):
        shutil.rmtree(controller.store.mission_runtime_dir(project_id, mid))
    assert _next(controller, project_id, "mission-004") == "mission-005"


def test_id05_legacy_count_allocator_documented_reuse(tmp_path):
    controller, project_id = _legacy_project(tmp_path)
    mids = ["mission-001"]
    for _ in range(3):
        mids.append(_next(controller, project_id, mids[-1]))
    for mid in ("mission-002", "mission-003"):
        shutil.rmtree(controller.store.mission_runtime_dir(project_id, mid))
    assert _next(controller, project_id, "mission-004") == "mission-003"


def test_ic04_downgrade_attempts(tmp_path):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _next(controller, project_id, "mission-001")
    identity = _identity(controller, project_id)
    (identity / "ready.json").unlink()
    assert gr.classify_identity(controller.store, project_id).state == "INITIALIZING"
    (identity / "missions" / "mission-002.json").write_text("corrupt")
    assert gr.classify_identity(controller.store, project_id).state == "IDENTITY_UNAVAILABLE"
    assert _err(_next, controller, project_id, "mission-002").code == (
        "mission_identity_unavailable")
    # HYPOTHETICAL (declared limit, not a PASS): deleting the whole footprint.
    shutil.rmtree(identity)
    assert gr.classify_identity(controller.store, project_id).state == "LEGACY"


def test_ic05_two_next_missions_one_reservation_and_failed_batch_orphan(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _attention(controller, project_id, reviews=2)
    envelope = controller.decide_attention(project_id, _decisions("seal", reviews=2))
    assert envelope.state.mission_id == "mission-002"
    missions = _identity(controller, project_id) / "missions"
    assert sorted(p.name for p in missions.glob("*.json")) == ["mission-001.json",
                                                                 "mission-002.json"]
    _attention(controller, project_id, "mission-002")

    def boom(*_args, **_kwargs):
        raise RuntimeError("batch failed after reservation")

    monkeypatch.setattr(type(controller), "_seal_and_plan_next", boom)
    with pytest.raises(RuntimeError):
        controller.decide_attention(project_id, _decisions("seal"))
    monkeypatch.undo()
    assert (missions / "mission-003.json").exists()
    assert controller.decide_attention(project_id, _decisions("seal")).state.mission_id == (
        "mission-004")


@pytest.mark.parametrize("state", ["LEGACY", "INITIALIZING", "ELIGIBLE", "IDENTITY_UNAVAILABLE"])
def test_ic06_r_marker_when_initializing_or_eligible(tmp_path, state):
    # Amended by the S-5 amendment: INITIALIZING also publishes R; ANY
    # IDENTITY_UNAVAILABLE refuses legacy submit before submit effects.
    controller, project_id = _project_in_state(tmp_path, state)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    marker = _identity(controller, project_id) / "missions" / "mission-001.consumed"
    if state == "IDENTITY_UNAVAILABLE":
        bucket = controller.store.bucket_root(project_id)
        before = tree_snapshot(bucket)
        assert _err(controller.submit_plan, project_id,
                    work_plan(["VAL-A"])).code == "mission_identity_unavailable"
        assert tree_snapshot(bucket) == before
    else:
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert marker.exists() == (state in ("INITIALIZING", "ELIGIBLE"))


@pytest.mark.parametrize("state", ["LEGACY", "INITIALIZING", "ELIGIBLE", "IDENTITY_UNAVAILABLE"])
def test_ic07_admission_only_when_eligible(tmp_path, state):
    controller, project_id = _project_in_state(tmp_path, state)
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    if state == "ELIGIBLE":
        receipt = controller.submit_governed_plan(project_id, "mission-001",
                                                  work_plan(["VAL-A"]), request())
        assert receipt["governed_admission"]["status"] == "COMMITTED"
        return
    before = tree_snapshot(controller.store.bucket_root(project_id))
    assert _err(controller.submit_governed_plan, project_id, "mission-001",
                work_plan(["VAL-A"]), request()).code == "governed_identity_unavailable"
    assert tree_snapshot(controller.store.bucket_root(project_id)) == before


# IC-08 -----------------------------------------------------------------------


@pytest.mark.parametrize("code", ["project_id_collision", "mission_id_reserved",
                                  "mission_identity_unavailable",
                                  "mission_identity_capacity_exhausted",
                                  "governed_identity_unavailable", "governed_mission_not_fresh"])
def test_ic08_private_identity_codes_project_to_invalid_argument(code):
    from unrest_harness import runtime_executor

    failure = runtime_executor._payload(ToolError(code, code.replace("_", " ")))[
        runtime_executor.EXECUTOR_FAILURE_KEY]
    assert failure["public_error"]["error"]["code"] == "invalid_argument"
    assert failure["private_tool_error"]["code"] == code
    for catalog in (ROOT / "docs/v03/v0.3.1/public-surface.v1.json",
                    ROOT / "src/unrest_harness/bundled/foundation/public-surface.v1.json"):
        assert code not in catalog.read_text(encoding="utf-8")


# IC-10 / ID-01..03 -----------------------------------------------------------


def test_ic10_incomplete_bucket_not_listed(tmp_path, monkeypatch):
    controller = make_controller(tmp_path)
    monkeypatch.setattr(type(controller.store), "create_project",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        start(controller, tmp_path)
    assert controller.store.list_projects() == []


def test_id01_concurrent_same_pid_one_winner_loser_has_no_effects(tmp_path, monkeypatch):
    import threading

    controller = make_controller(tmp_path)
    monkeypatch.setattr(type(controller.store), "generate_project_id", lambda self, brief: "p-1")
    winner = controller.start_project("brief", str(workspace(tmp_path)))
    assert winner.projectId == "p-1"
    bucket = controller.store.bucket_root("p-1")
    before = tree_snapshot(bucket)
    ws_before = tree_snapshot(workspace(tmp_path))
    other_ws = tmp_path / "other-ws"
    other_ws.mkdir()
    errors: list[str] = []
    barrier = threading.Barrier(2)

    def contender():
        barrier.wait()
        try:
            controller.start_project("brief 2", str(other_ws))
        except ToolError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=contender) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == ["project_id_collision", "project_id_collision"]
    assert tree_snapshot(bucket) == before
    assert tree_snapshot(workspace(tmp_path)) == ws_before
    assert list(other_ws.iterdir()) == []


def test_id02_missing_workspace_no_bucket(tmp_path):
    controller = make_controller(tmp_path)
    with pytest.raises(FileNotFoundError):
        controller.start_project("brief", str(tmp_path / "nope"))
    projects = controller.config.projects_dir
    assert not projects.exists() or list(projects.iterdir()) == []


@pytest.mark.parametrize("cut", ["K-c1", "K-c2", "K-c3", "K-c4", "K-c5", "K-c6"])
def test_id03_crash_cuts_no_cleanup_no_retry(tmp_path, monkeypatch, cut):
    import unrest_harness.controller as controller_module

    controller = make_controller(tmp_path)
    monkeypatch.setattr(type(controller.store), "generate_project_id", lambda self, brief: "p-1")
    targets = {
        "K-c1": (controller_module, "initialize_identity"),
        "K-c2": (controller_module, "reserve_mission"),
        "K-c3": (type(controller.store), "create_project"),
        "K-c4": (type(controller.store), "save_project"),
        "K-c5": (controller_module, "publish_identity_ready"),
    }
    if cut != "K-c6":
        owner, name = targets[cut]
        monkeypatch.setattr(owner, name, lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("crash")))
        with pytest.raises(RuntimeError):
            controller.start_project("brief", str(workspace(tmp_path)))
        monkeypatch.undo()
        monkeypatch.setattr(type(controller.store), "generate_project_id",
                            lambda self, brief: "p-1")
    else:
        controller.start_project("brief", str(workspace(tmp_path)))
    assert _err(controller.start_project, "brief", str(workspace(tmp_path))).code == (
        "project_id_collision")
    if cut == "K-c5":
        assert gr.classify_identity(controller.store, "p-1").state == "INITIALIZING"
        write_criteria(controller.store, "p-1", "mission-001", {"VAL-A": "a\n"})
        assert _err(controller.submit_governed_plan, "p-1", "mission-001",
                    work_plan(["VAL-A"]), request()).code == "governed_identity_unavailable"
        controller.submit_plan("p-1", work_plan(["VAL-A"]))
    elif cut in ("K-c1", "K-c2", "K-c3", "K-c4"):
        assert _err(controller.submit_plan, "p-1", work_plan(["VAL-A"])).code == "not_found"


# ID-04 / ID-06 / ID-07 -------------------------------------------------------


@pytest.mark.parametrize("branch", ["transactional", "seal"])
def test_id04_normal_path_matches_baseline_names(tmp_path, branch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    mids = ["mission-001"]
    for _ in range(3):
        mids.append(_next(controller, project_id, mids[-1], branch))
    assert mids == ["mission-001", "mission-002", "mission-003", "mission-004"]


def test_id06_preexisting_reservation_refuses_before_effects(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _attention(controller, project_id)
    missions = _identity(controller, project_id) / "missions"
    (missions / "mission-002.json").write_bytes(_reservation_bytes(project_id, "mission-002"))
    real = gr.classify_identity

    def stale(store, pid):
        view = real(store, pid)
        return gr.IdentityView(view.state, view.reserved, view.consumed, 1)

    monkeypatch.setattr(ga, "classify_identity", stale)
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    assert _err(controller.decide_attention, project_id,
                _decisions("seal")).code == "mission_id_reserved"
    assert tree_snapshot(bucket) == before


def test_id07_crash_after_reservation_before_transaction(tmp_path, monkeypatch):
    import unrest_harness.controller as controller_module

    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _attention(controller, project_id)
    monkeypatch.setattr(controller_module.PatchTransaction, "execute",
                        lambda self: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        controller.decide_attention(project_id, _decisions("transactional"))
    monkeypatch.undo()
    assert (_identity(controller, project_id) / "missions" / "mission-002.json").exists()
    assert controller.decide_attention(project_id, _decisions("transactional")).state.mission_id == (
        "mission-003")


# ID-08..10 -------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["no_init", "no_ready", "no_reservation", "pid_mismatch",
                                     "mid_mismatch", "malformed", "symlink", "current_mismatch"])
def test_id08_admission_identity_matrix(tmp_path, variant):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    identity = _identity(controller, project_id)
    missions = identity / "missions"
    expected = "governed_identity_unavailable"
    if variant == "no_init":
        (identity / "init.json").unlink()
    elif variant == "no_ready":
        (identity / "ready.json").unlink()
    elif variant == "no_reservation":
        controller.store.save_state(project_id, MissionPlanning(mission_id="mission-002"))
        record = controller.store.load_project(project_id)
        record.current_mission_id = "mission-002"
        controller.store.save_project(record)
    elif variant == "pid_mismatch":
        (identity / "ready.json").write_bytes(gr.canonical_bytes(
            {"schema": "unrest.governed-identity-ready.v1", "project_id": "other"}))
    elif variant == "mid_mismatch":
        (missions / "mission-001.json").write_bytes(_reservation_bytes(project_id, "mission-009"))
    elif variant == "malformed":
        (missions / "mission-001.json").write_text("{")
    elif variant == "symlink":
        target = tmp_path / "res.json"
        target.write_bytes((missions / "mission-001.json").read_bytes())
        (missions / "mission-001.json").unlink()
        (missions / "mission-001.json").symlink_to(target)
    elif variant == "current_mismatch":
        record = controller.store.load_project(project_id)
        record.current_mission_id = "mission-007"
        controller.store.save_project(record)
        expected = "governed_mission_not_fresh"
    mid = "mission-002" if variant == "no_reservation" else "mission-001"
    write_criteria(controller.store, project_id, mid, {"VAL-A": "a\n"})
    assert _err(controller.submit_governed_plan, project_id, mid, work_plan(["VAL-A"]),
                request()).code == expected
    assert not governed_dir(controller.store, project_id, mid).exists()


def test_id09_hypothetical_stale_planning_refused_with_r(tmp_path):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    shutil.rmtree(controller.store.mission_runtime_dir(project_id, "mission-001"))
    controller.store.save_state(project_id, MissionPlanning(mission_id="mission-001"))
    assert _err(controller.submit_governed_plan, project_id, "mission-001",
                work_plan(["VAL-A"]), request()).code == "governed_identity_unavailable"


@pytest.mark.parametrize("cut", ["ensure_contract_dir", "save_task_list"])
def test_id10_marker_idempotent_and_crash_between_marker_and_tasks(tmp_path, monkeypatch,
                                                                   cut):
    # Amended by the S-5 order: R precedes ensure_contract_dir, so both are post-R cuts.
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    monkeypatch.setattr(type(controller.store), cut,
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
    monkeypatch.undo()
    marker = _identity(controller, project_id) / "missions" / "mission-001.consumed"
    assert marker.exists()
    first = marker.read_bytes()
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert marker.read_bytes() == first
    controller.store.save_state(project_id, MissionPlanning(mission_id="mission-001"))
    shutil.rmtree(controller.store.mission_runtime_dir(project_id, "mission-001"))
    assert _err(controller.submit_governed_plan, project_id, "mission-001",
                work_plan(["VAL-A"]), request()).code == "governed_identity_unavailable"


# ID-11..14 -------------------------------------------------------------------


def test_id11_identity_not_read_by_step_inspect_replay_abort(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    controller.submit_governed_plan(project_id, "mission-001", work_plan(["VAL-A"]), request())
    calls: list[str] = []
    real = gr.classify_identity
    monkeypatch.setattr(gr, "classify_identity", lambda *a: calls.append("gr") or real(*a))
    monkeypatch.setattr(ga, "classify_identity", lambda *a: calls.append("ga") or real(*a))
    controller.advance_project(project_id)
    controller.inspect_governed(project_id, "mission-001")
    controller.submit_governed_plan(project_id, "mission-001", work_plan(["VAL-A"]), request())
    controller.abort_project(project_id, "stop")
    assert calls == []


def test_id12_catalogs_unchanged():
    import hashlib

    assert hashlib.sha256((ROOT / "docs/v03/v0.3.1/public-surface.v1.json").read_bytes()
                          ).hexdigest() == (
        "2d500d39a401837162625254d954cb3431760a10b78661f3156ec08bc956c4ad")
    assert hashlib.sha256((ROOT / "src/unrest_harness/bundled/foundation/public-surface.v1.json"
                           ).read_bytes()).hexdigest() == (
        "df5a5f15a9c4840849b9ead85d52d12b8af52a5607ee30cf7bff4d44300fe051")


def test_id13_direct_create_project_is_legacy_and_m1_is_separate(tmp_path):
    controller, project_id = _legacy_project(tmp_path)
    assert gr.classify_identity(controller.store, project_id).state == "LEGACY"
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    assert _err(controller.submit_governed_plan, project_id, "mission-001",
                work_plan(["VAL-A"]), request()).code == "governed_identity_unavailable"
    eligible, pid = _project_in_state(tmp_path / "e", "ELIGIBLE")
    write_criteria(eligible.store, pid, "mission-001", {"VAL-A": "a\n"})
    (eligible.store.mission_dir(pid, "mission-001") / "closeout.md").write_text("x")
    assert _err(eligible.submit_governed_plan, pid, "mission-001", work_plan(["VAL-A"]),
                request()).code == "governed_mission_not_fresh"


def test_id14_identity_survives_runtime_removal_and_admission_refuses(tmp_path):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    shutil.rmtree(controller.store.unrest_runtime_dir(project_id))
    assert gr.classify_identity(controller.store, project_id).state == "ELIGIBLE"
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    error = _err(controller.submit_governed_plan, project_id, "mission-001",
                 work_plan(["VAL-A"]), request())
    assert error.code == "not_found"
    assert not governed_dir(controller.store, project_id, "mission-001").exists()
    assert controller.store.load_state(project_id) is None


def test_ic09_running_state_after_admission(tmp_path):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, "mission-001", {"VAL-A": "a\n"})
    controller.submit_governed_plan(project_id, "mission-001", work_plan(["VAL-A"]), request())
    assert isinstance(controller.store.load_state(project_id), MissionRunning)


# S-2 (declared) ---------------------------------------------------------------


def _rejected_patch_decisions() -> list[Decision]:
    bad = Task(id="w2", type="work", body="do", targets=["VAL-NOPE"], skill="s")
    return [Decision(item_id="attention-node", action="patch",
                     patch=TaskListPatch(add=[bad], supersede={"w1": "w2"})),
            Decision(item_id="attention-review-0", action="next_mission")]


def test_s2_failed_next_batches_consume_capacity(tmp_path):
    """4096 reservations including orphans: rejected next_mission batches consume
    reservations monotonically; no rollback and no reuse."""
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    _fill_reservations(controller, project_id, 4094)
    _attention(controller, project_id)
    missions = _identity(controller, project_id) / "missions"
    for expected in ("mission-4095", "mission-4096"):
        error = _err(controller.decide_attention, project_id, _rejected_patch_decisions())
        assert error.code == "invalid_patch"
        assert (missions / f"{expected}.json").exists()
    assert len(list(missions.glob("*.json"))) == 4096
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    assert _err(controller.decide_attention, project_id,
                _decisions("seal")).code == "mission_identity_capacity_exhausted"
    assert tree_snapshot(bucket) == before


# S-4 (declared) ---------------------------------------------------------------


@pytest.mark.parametrize("route", ["direct", "runtime_executor"])
def test_s4_error_after_project_publication(tmp_path, monkeypatch, route):
    """An exception after project publication (ready.json write) does not mean that no
    project was created. It is not a ToolError, so RunControl's executor does not
    project it through ``_payload`` (IC-08 covers ToolError only). A blind retry creates
    a different project; no idempotency or retry claim."""
    from unrest_harness import controller as controller_module
    from unrest_harness import runtime_executor
    from unrest_harness.config import HarnessConfig

    def ready_fails(store, project_id):
        raise OSError(5, "injected EIO")

    controller = make_controller(tmp_path)
    monkeypatch.setattr(controller_module, "publish_identity_ready", ready_fails)
    if route == "direct":
        with pytest.raises(OSError) as caught:
            start(controller, tmp_path, brief="First demo")
    else:
        config = controller.config
        monkeypatch.setattr(HarnessConfig, "discover", classmethod(lambda cls, *a, **k: config))
        with pytest.raises(OSError) as caught:
            runtime_executor.execute("start_project", {
                "brief": "First demo", "workspace_dir": str(workspace(tmp_path))}, object())
    assert not isinstance(caught.value, ToolError)
    (project,) = controller.store.list_projects()
    first = project.id
    assert controller.store.load_state(first) == MissionPlanning(mission_id="mission-001")
    assert gr.classify_identity(controller.store, first).state == "INITIALIZING"
    monkeypatch.undo()
    second = start(controller, tmp_path, brief="Second demo")
    assert second != first
    assert sorted(p.id for p in controller.store.list_projects()) == sorted([first, second])
