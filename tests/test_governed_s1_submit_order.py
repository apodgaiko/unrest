"""Governed S1 S-5: legacy submit identity gate and beta validation order.

Order for INITIALIZING/ELIGIBLE: identity refusal -> read-only contract/task-list
validation -> option R (create-or-verify ``.consumed``) -> baseline
``ensure_contract_dir`` and submit writes. LEGACY keeps the baseline sequence. Write
spies cover only ``_submit_plan`` (``_project_access`` recovery is outside the claim);
deterministic orderings here are not runtime concurrency evidence.
"""
from __future__ import annotations

import errno
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.governed_s1_support import (
    governed_dir,
    make_controller,
    request,
    start,
    tree_snapshot,
    work_plan,
    write_criteria,
)
from tests.test_governed_s1_identity import (
    _attention,
    _decisions,
    _err,
    _fill_reservations,
    _identity,
    _legacy_project,
    _project_in_state,
)
from unrest_harness import controller as controller_module
from unrest_harness import governed_admission
from unrest_harness import governed_records as gr
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.models import MissionPlanning, Task, TaskList

MID = "mission-001"
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


class WriteSpy:
    """Records mkdir/create/rename/link/unlink calls made inside ``_submit_plan``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.events: list[str] = []
        self.active = False
        self.in_marker = False
        spy = self

        def wrap(name: str, real: Any, is_write: Any = lambda *a, **k: True) -> None:
            def call(*args: Any, **kwargs: Any) -> Any:
                if spy.active and is_write(*args, **kwargs):
                    spy.events.append("R" if spy.in_marker else name)
                return real(*args, **kwargs)

            monkeypatch.setattr(os, name, call)

        wrap("mkdir", os.mkdir)
        wrap("makedirs", os.makedirs)
        wrap("open", os.open, lambda path, flags, *a, **k: bool(flags & _WRITE_FLAGS))
        for name in ("replace", "rename", "link", "unlink", "symlink", "rmdir"):
            wrap(name, getattr(os, name))
        real_submit = ProjectController._submit_plan
        real_mark = gr.mark_mission_consumed

        def submit(self_: ProjectController, *args: Any, **kwargs: Any) -> Any:
            spy.active = True
            try:
                return real_submit(self_, *args, **kwargs)
            finally:
                spy.active = False

        def mark(*args: Any, **kwargs: Any) -> None:
            spy.in_marker = True
            try:
                real_mark(*args, **kwargs)
            finally:
                spy.in_marker = False

        monkeypatch.setattr(ProjectController, "_submit_plan", submit)
        monkeypatch.setattr(gr, "mark_mission_consumed", mark)

    def first_non_marker(self) -> int:
        return next((i for i, e in enumerate(self.events) if e != "R"), len(self.events))


def _marker(controller: ProjectController, project_id: str, mid: str = MID) -> Path:
    return _identity(controller, project_id) / "missions" / f"{mid}.consumed"


def _stale_planning(controller: ProjectController, project_id: str) -> None:
    controller.store.save_state(project_id, MissionPlanning(mission_id=MID))
    shutil.rmtree(controller.store.mission_runtime_dir(project_id, MID))


# Creation branches (no retrofit) ----------------------------------------------


def test_s5_unsupported_host_creates_legacy_without_retrofit(tmp_path, monkeypatch):
    controller = make_controller(tmp_path)
    monkeypatch.setattr(controller_module, "governed_fs_capable", lambda: False)
    project_id = start(controller, tmp_path)
    monkeypatch.undo()
    assert not os.path.lexists(_identity(controller, project_id))
    assert gr.classify_identity(controller.store, project_id).state == "LEGACY"
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert not os.path.lexists(_identity(controller, project_id))


def test_s5_failed_identity_initialization_is_unavailable_not_legacy(tmp_path, monkeypatch):
    controller = make_controller(tmp_path)
    real = gr.publish

    def publish(dir_fd, name, data, limit, **kwargs):
        if name == "init.json":
            raise OSError(errno.EIO, "injected EIO")
        return real(dir_fd, name, data, limit, **kwargs)

    monkeypatch.setattr(gr, "publish", publish)
    monkeypatch.setattr(controller.store, "generate_project_id", lambda brief: "cut-1")
    with pytest.raises(OSError):
        start(controller, tmp_path)
    monkeypatch.undo()
    assert os.path.isdir(_identity(controller, "cut-1"))
    assert gr.classify_identity(controller.store, "cut-1").state == "IDENTITY_UNAVAILABLE"


# ANY IDENTITY_UNAVAILABLE refuses before effects -------------------------------


def _orphan_consumed(controller, project_id):
    _marker(controller, project_id, "mission-005").write_bytes(gr.canonical_bytes({
        "schema": "unrest.governed-mission-consumed.v1", "project_id": project_id,
        "mission_id": "mission-005"}))


def _conflicting_consumed(controller, project_id):
    _marker(controller, project_id).write_bytes(gr.canonical_bytes({
        "schema": "unrest.governed-mission-consumed.v1", "project_id": "other-project",
        "mission_id": MID}))


def _lstat_error(code: int):
    def install(monkeypatch, controller, project_id):
        real = os.lstat
        target = str(_identity(controller, project_id))

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == target:
                raise OSError(code, os.strerror(code))
            return real(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", lstat)
    return install


def _open_error(code: int):
    def install(monkeypatch, controller, project_id):
        def anchored_open(anchor, components):
            # Same translation as the real anchored_open for an OSError.
            raise gr.GovernedRecordError("io_unavailable") from OSError(code, "injected")

        monkeypatch.setattr(gr, "anchored_open", anchored_open)
    return install


def _unsupported(monkeypatch, controller, project_id):
    monkeypatch.setattr(gr, "governed_fs_capable", lambda: False)


UNAVAILABLE_FILES = {
    "init_corrupt": lambda c, p: (_identity(c, p) / "init.json").write_text("{}"),
    "reservation_corrupt": lambda c, p: (
        _identity(c, p) / "missions" / f"{MID}.json").write_text("{}"),
    "reservation_missing": lambda c, p: (_identity(c, p) / "missions" / f"{MID}.json").unlink(),
    "orphan_consumed": _orphan_consumed,
    "conflicting_consumed": _conflicting_consumed,
    "over_capacity": lambda c, p: _fill_reservations(c, p, 4097),
}
UNAVAILABLE_RUNTIME = {
    "unsupported_host": _unsupported,
    "lstat_eacces": _lstat_error(errno.EACCES),
    "lstat_emfile": _lstat_error(errno.EMFILE),
    "lstat_eio": _lstat_error(errno.EIO),
    "open_emfile": _open_error(errno.EMFILE),
    "open_eio": _open_error(errno.EIO),
}


@pytest.mark.parametrize("state", ["ELIGIBLE", "INITIALIZING"])
@pytest.mark.parametrize("case", sorted(UNAVAILABLE_FILES) + sorted(UNAVAILABLE_RUNTIME))
def test_s5_any_unavailable_refuses_submit_and_next_without_effects(
        tmp_path, monkeypatch, state, case):
    controller, project_id = _project_in_state(tmp_path, state)
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    if case in UNAVAILABLE_FILES:
        UNAVAILABLE_FILES[case](controller, project_id)
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    spy = WriteSpy(monkeypatch)
    if case in UNAVAILABLE_RUNTIME:
        UNAVAILABLE_RUNTIME[case](monkeypatch, controller, project_id)
    error = _err(controller.submit_plan, project_id, work_plan(["VAL-A"]))
    assert error.code == "mission_identity_unavailable"
    assert spy.events == []
    monkeypatch.undo()
    assert tree_snapshot(bucket) == before
    _attention(controller, project_id)
    if case in UNAVAILABLE_RUNTIME:
        UNAVAILABLE_RUNTIME[case](monkeypatch, controller, project_id)
    assert _err(controller.decide_attention, project_id,
                _decisions("seal")).code == "mission_identity_unavailable"


def test_s5_raw_oserror_from_identity_read_refuses_submit(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    spy = WriteSpy(monkeypatch)
    monkeypatch.setattr(gr, "scan_dir", lambda fd: (_ for _ in ()).throw(
        OSError(errno.EMFILE, "injected")))
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "mission_identity_unavailable"
    assert spy.events == []
    monkeypatch.undo()
    assert tree_snapshot(bucket) == before


@pytest.mark.parametrize("state", ["ELIGIBLE", "INITIALIZING"])
def test_s5_unreserved_planning_mission_refuses(tmp_path, monkeypatch, state):
    controller, project_id = _project_in_state(tmp_path, state)
    controller.store.save_state(project_id, MissionPlanning(mission_id="mission-002"))
    write_criteria(controller.store, project_id, "mission-002", {"VAL-A": "a\n"})
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    spy = WriteSpy(monkeypatch)
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "mission_identity_unavailable"
    assert spy.events == []
    assert tree_snapshot(bucket) == before


# Roundtrips ---------------------------------------------------------------------


@pytest.mark.parametrize("cause", ["unsupported_host", "open_emfile"])
def test_s5_refused_unspent_roundtrip_first_admission_allowed(tmp_path, monkeypatch, cause):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    UNAVAILABLE_RUNTIME[cause](monkeypatch, controller, project_id)
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "mission_identity_unavailable"
    monkeypatch.undo()
    assert tree_snapshot(bucket) == before
    receipt = controller.submit_governed_plan(project_id, MID, work_plan(["VAL-A"]), request())
    assert receipt["governed_admission"]["status"] == "COMMITTED"


@pytest.mark.parametrize("state", ["ELIGIBLE", "INITIALIZING"])
@pytest.mark.parametrize("transient", [False, True])
def test_s5_consumed_roundtrip_keeps_admission_refused(tmp_path, monkeypatch, state,
                                                       transient):
    controller, project_id = _project_in_state(tmp_path, state)
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert _marker(controller, project_id).exists()
    if state == "INITIALIZING":
        gr.publish_identity_ready(controller.store, project_id)
    _stale_planning(controller, project_id)
    if transient:
        _unsupported(monkeypatch, controller, project_id)
        assert _err(controller.submit_governed_plan, project_id, MID, work_plan(["VAL-A"]),
                    request()).code == "governed_identity_unavailable"
        monkeypatch.undo()
    view = gr.classify_identity(controller.store, project_id)
    assert view.state == "ELIGIBLE" and MID in view.consumed
    assert _err(controller.submit_governed_plan, project_id, MID, work_plan(["VAL-A"]),
                request()).code == "governed_identity_unavailable"
    assert not governed_dir(controller.store, project_id, MID).exists()


# ready/R orders (deterministic; not a concurrency proof) -------------------------


@pytest.mark.parametrize("order", ["marker_then_ready", "ready_then_marker"])
def test_s5_ready_and_marker_orders_preserve_consumption(tmp_path, monkeypatch, order):
    controller, project_id = _project_in_state(tmp_path, "INITIALIZING")
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    ready = _identity(controller, project_id) / "ready.json"
    if order == "ready_then_marker":
        real = controller_module.mark_legacy_consumption

        def mark(store, pid, mid):
            gr.publish_identity_ready(store, pid)
            real(store, pid, mid)

        monkeypatch.setattr(controller_module, "mark_legacy_consumption", mark)
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
        monkeypatch.undo()
        marker_bytes = _marker(controller, project_id).read_bytes()
    else:
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
        marker_bytes = _marker(controller, project_id).read_bytes()
        gr.publish_identity_ready(controller.store, project_id)
    assert ready.read_bytes() == gr.canonical_bytes(
        {"schema": "unrest.governed-identity-ready.v1", "project_id": project_id})
    assert _marker(controller, project_id).read_bytes() == marker_bytes
    view = gr.classify_identity(controller.store, project_id)
    assert view.state == "ELIGIBLE" and MID in view.reserved and MID in view.consumed
    _stale_planning(controller, project_id)
    assert _err(controller.submit_governed_plan, project_id, MID, work_plan(["VAL-A"]),
                request()).code == "governed_identity_unavailable"
    assert _marker(controller, project_id).read_bytes() == marker_bytes


# R publication failure ------------------------------------------------------------


@pytest.mark.parametrize("state", ["ELIGIBLE", "INITIALIZING"])
@pytest.mark.parametrize("outcome", ["not_written", "written_then_error"])
def test_s5_marker_failure_refuses_before_submit_writes(tmp_path, monkeypatch, state,
                                                        outcome):
    controller, project_id = _project_in_state(tmp_path, state)
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    contract = controller.store.contract_dir(project_id, MID)
    real = gr.publish

    def publish(dir_fd, name, data, limit, **kwargs):
        if name.endswith(".consumed"):
            if outcome == "written_then_error":
                real(dir_fd, name, data, limit, **kwargs)
            raise OSError(errno.EIO, "injected EIO")
        return real(dir_fd, name, data, limit, **kwargs)

    spy = WriteSpy(monkeypatch)
    monkeypatch.setattr(gr, "publish", publish)
    ensure_calls: list[str] = []
    real_ensure = type(controller.store).ensure_contract_dir
    monkeypatch.setattr(type(controller.store), "ensure_contract_dir",
                        lambda self, *a: ensure_calls.append("ensure") or real_ensure(self, *a))
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "mission_identity_unavailable"
    assert ensure_calls == []
    assert spy.events == (["R"] * len(spy.events))
    assert not (contract.parent / "task-list.json").exists()
    assert controller.store.load_state(project_id) == MissionPlanning(mission_id=MID)
    assert _marker(controller, project_id).exists() == (outcome == "written_then_error")
    monkeypatch.undo()
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert _marker(controller, project_id).exists()


@pytest.mark.parametrize("variant", ["foreign_project", "noncanonical_same_record"])
def test_s5_conflicting_existing_marker_fails_r_verification(tmp_path, variant):
    """Option R verifies an existing ``.consumed`` byte for byte and refuses a conflicting
    one without replacing it. The conflicting marker is written before the call; no
    concurrent writer is simulated. Submit ordering on R failures is asserted by
    ``test_s5_marker_failure_refuses_before_submit_writes``."""
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    marker = _marker(controller, project_id)
    record = {"schema": "unrest.governed-mission-consumed.v1",
              "project_id": project_id, "mission_id": MID}
    if variant == "foreign_project":
        conflicting = gr.canonical_bytes({**record, "project_id": "other-project"})
    else:
        conflicting = (json.dumps(record, indent=2) + "\n").encode()
    assert conflicting != gr.canonical_bytes(record)
    marker.write_bytes(conflicting)
    members = sorted(p.name for p in marker.parent.iterdir())

    with pytest.raises(ToolError) as refused:
        governed_admission.mark_legacy_consumption(controller.store, project_id, MID)
    assert refused.value.code == "mission_identity_unavailable"
    with pytest.raises(gr.GovernedRecordError) as conflict:
        gr.mark_mission_consumed(controller.store, project_id, MID)
    assert conflict.value.reason == "artifact_identity_conflict"
    assert marker.read_bytes() == conflicting
    assert sorted(p.name for p in marker.parent.iterdir()) == members


def test_s5_success_order_marker_before_first_submit_write(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    shutil.rmtree(controller.store.mission_dir(project_id, MID), ignore_errors=True)
    target = tmp_path / "authoring" / "contract"
    target.mkdir(parents=True)
    (target / "VAL-A.md").write_text("a\n")
    controller.store.mission_dir(project_id, MID).mkdir(parents=True)
    os.symlink(target, controller.store.contract_dir(project_id, MID))
    spy = WriteSpy(monkeypatch)
    controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert spy.events and spy.events[0] == "R"
    assert "R" not in spy.events[spy.first_non_marker():]


# beta differential: LEGACY (baseline sequence) vs ELIGIBLE ------------------------


def _ok_plan() -> TaskList:
    return work_plan(["VAL-A"])


def _bad_plan() -> TaskList:
    return TaskList(tasks=[Task(id="w0", type="work", body="do", targets=["VAL-NOPE"],
                                skill="s")])


def _setup(case: str, mission: Path, outside: Path) -> None:
    contract = mission / "contract"
    if case != "missing_missions_mid":
        mission.mkdir(parents=True, exist_ok=True)
    if case in ("valid", "invalid_task_list", "unreadable_contract", "unsearchable_mission"):
        contract.mkdir()
        (contract / "VAL-A.md").write_text("a\n")
    elif case == "empty_contract":
        contract.mkdir()
    elif case == "malformed_filename":
        contract.mkdir()
        (contract / "VAL-A.md").write_text("a\n")
        (contract / "bad name.md").write_text("x\n")
    elif case == "contract_is_file":
        contract.write_text("x\n")
    elif case == "contract_dangling_symlink":
        os.symlink(outside / "absent", contract)
    elif case == "contract_symlink_dir":
        (outside / "c").mkdir(parents=True)
        (outside / "c" / "VAL-A.md").write_text("a\n")
        os.symlink(outside / "c", contract)
    elif case in ("mission_symlink_dir", "mission_is_file", "mission_dangling_symlink"):
        shutil.rmtree(mission)
        if case == "mission_symlink_dir":
            (outside / "m" / "contract").mkdir(parents=True)
            (outside / "m" / "contract" / "VAL-A.md").write_text("a\n")
            os.symlink(outside / "m", mission)
        elif case == "mission_is_file":
            mission.write_text("x\n")
        else:
            os.symlink(outside / "absent", mission)
    elif case == "missing_missions_mid":
        shutil.rmtree(mission, ignore_errors=True)


_CHMOD = {"unreadable_contract": ("contract", 0o000),
          "unsearchable_mission": ("", 0o000),
          "missing_contract_unwritable_parent": ("", 0o555)}


def _outcome(controller, project_id, case, outside) -> tuple[Any, ...]:
    mission = controller.store.mission_dir(project_id, MID)
    _setup(case, mission, outside)
    chmod = _CHMOD.get(case)
    target = None
    if chmod is not None:
        target = mission / chmod[0]
        os.chmod(target, chmod[1])
    try:
        controller.submit_plan(project_id, _bad_plan() if case == "invalid_task_list"
                               else _ok_plan())
        result: tuple[Any, ...] = ("ok",)
    except ToolError as exc:
        result = ("ToolError", exc.code, [(d.code, d.detail) for d in exc.details or []])
    except OSError as exc:
        result = (type(exc).__name__, exc.errno)
    finally:
        if target is not None:
            os.chmod(target, 0o755)
    return result


_EMPTY = ("ToolError", "invalid_task_list", "EMPTY")
_SAME = "same"
DIFFERENTIAL: dict[str, tuple[Any, Any]] = {
    "missing_missions_mid": (_EMPTY, _SAME),
    "missing_contract": (_EMPTY, _SAME),
    "empty_contract": (_EMPTY, _SAME),
    "valid": (("ok",), _SAME),
    "malformed_filename": (("ToolError", "invalid_contract_dir"), _SAME),
    "invalid_task_list": (("ToolError", "invalid_task_list"), _SAME),
    "contract_symlink_dir": (("ok",), _SAME),
    # The existing governed-path refusal (legacy_submit_refusal, V1) runs first for a
    # non-regular missions/<mid> in both cohorts, so beta is not reached.
    "mission_symlink_dir": (("ToolError", "governed_admission_unresolved"), _SAME),
    "mission_is_file": (("ToolError", "governed_admission_unresolved"), _SAME),
    "mission_dangling_symlink": (("ToolError", "governed_admission_unresolved"), _SAME),
    "unsearchable_mission": (("ToolError", "governed_admission_unresolved"), _SAME),
    "unreadable_contract": (_EMPTY, _SAME),
    # Declared differences (beta never calls mkdir before R):
    "contract_is_file": (("FileExistsError", errno.EEXIST),
                         ("ToolError", "invalid_contract_dir",
                          [("contract_dir_missing", "contract/")])),
    "contract_dangling_symlink": (("FileExistsError", errno.EEXIST), _EMPTY),
    "missing_contract_unwritable_parent": (("PermissionError", errno.EACCES), _EMPTY),
}


EARLY_REFUSALS = ("mission_dangling_symlink", "mission_is_file", "mission_symlink_dir",
                  "unsearchable_mission")


def _matches(expected: Any, actual: tuple[Any, ...]) -> bool:
    if expected == _EMPTY:
        return (actual[:2] == ("ToolError", "invalid_task_list")
                and [code for code, _ in actual[2]] == ["empty_contract"])
    return actual[:len(expected)] == expected


@pytest.mark.skipif(os.geteuid() == 0, reason="permission cases need a non-root euid")
@pytest.mark.parametrize("case", sorted(DIFFERENTIAL))
def test_s5_submit_validation_differential(tmp_path, monkeypatch, case):
    """Public outcome (type, errno, code, details) only; filesystem equality with the
    baseline is not compared. Rows marked 'same' must equal the LEGACY outcome."""
    legacy, legacy_id = _legacy_project(tmp_path / "legacy")
    baseline = _outcome(legacy, legacy_id, case, tmp_path / "legacy-outside")
    controller, project_id = _project_in_state(tmp_path / "eligible", "ELIGIBLE")
    bucket = controller.store.bucket_root(project_id)
    spy = WriteSpy(monkeypatch)
    expected_baseline, expected_beta = DIFFERENTIAL[case]
    observed_before: dict[str, Any] = {}

    real_ensure = type(controller.store).ensure_contract_dir

    def ensure(self, *args):
        observed_before.setdefault("marker", _marker(controller, project_id).exists())
        return real_ensure(self, *args)

    monkeypatch.setattr(type(controller.store), "ensure_contract_dir", ensure)
    real_beta = ProjectController._validate_submission_read_only

    def beta_spy(self, *args):
        observed_before.setdefault("beta", True)
        return real_beta(self, *args)

    monkeypatch.setattr(ProjectController, "_validate_submission_read_only", beta_spy)
    beta = _outcome(controller, project_id, case, tmp_path / "eligible-outside")
    assert _matches(expected_baseline, baseline), (case, baseline)
    if expected_beta == _SAME:
        assert beta == baseline, (case, beta, baseline)
    else:
        assert _matches(expected_beta, beta), (case, beta)
    for item in (beta[2] if beta[0] == "ToolError" else []):
        for private in (str(bucket), str(tmp_path), os.path.expanduser("~")):
            assert private not in item[1]
    if case in EARLY_REFUSALS:
        # Step 1 refuses: beta, R, ensure_contract_dir and the save_* writes are not reached.
        assert observed_before == {} and spy.events == []
        assert not _marker(controller, project_id).exists()
    elif beta == ("ok",):
        assert observed_before == {"beta": True, "marker": True}
        assert spy.events[0] == "R"
    elif "R" in spy.events or "marker" in observed_before:
        # Validation passed; the failure is post-R and R is retained.
        assert _marker(controller, project_id).exists()
    else:
        assert spy.events == []
        assert not _marker(controller, project_id).exists()


def test_s5_validation_refusal_does_not_consume(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    spy = WriteSpy(monkeypatch)
    assert _err(controller.submit_plan, project_id, _bad_plan()).code == "invalid_task_list"
    assert spy.events == []
    assert tree_snapshot(bucket) == before
    monkeypatch.undo()
    receipt = controller.submit_governed_plan(project_id, MID, _ok_plan(), request())
    assert receipt["governed_admission"]["status"] == "COMMITTED"


def test_s5_missing_contract_creates_nothing_before_refusal(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    mission = controller.store.mission_dir(project_id, MID)
    shutil.rmtree(mission, ignore_errors=True)
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    spy = WriteSpy(monkeypatch)
    error = _err(controller.submit_plan, project_id, _ok_plan())
    assert (error.code, [d.code for d in error.details or []]) == (
        "invalid_task_list", ["empty_contract"])
    assert spy.events == []
    assert tree_snapshot(bucket) == before
    assert not os.path.lexists(mission)


def test_s5_contract_change_after_validation_retains_marker(tmp_path, monkeypatch):
    """Read-only validation is not immutability: a post-R refusal keeps R."""
    controller, project_id = _project_in_state(tmp_path, "ELIGIBLE")
    contract = write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    real = controller_module.mark_legacy_consumption

    def mark(store, pid, mid):
        real(store, pid, mid)
        (contract / "VAL-A.md").unlink()

    monkeypatch.setattr(controller_module, "mark_legacy_consumption", mark)
    assert _err(controller.submit_plan, project_id, _ok_plan()).code == "invalid_task_list"
    assert _marker(controller, project_id).exists()


# Early no-follow refusal of non-regular missions/<mid> (V3 6.2/6.5; L1/L-SYMLINK) ----


def _cohort(tmp_path: Path, cohort: str) -> tuple[ProjectController, str]:
    if cohort == "LEGACY":
        return _legacy_project(tmp_path)
    return _project_in_state(tmp_path, cohort)


def _shape(controller, project_id: str, shape: str, outside: Path) -> Path | None:
    """Reshape missions/<mid> (or missions); return an external link target, if any."""
    mission = controller.store.mission_dir(project_id, MID)
    write_criteria(controller.store, project_id, MID, {"VAL-A": "a\n"})
    outside.mkdir(parents=True)
    if shape in ("mid_symlink_dir", "missions_symlink_dir"):
        source = mission if shape == "mid_symlink_dir" else mission.parent
        target = outside / source.name
        shutil.move(str(source), target)
        os.symlink(target, source)
        return target
    if shape == "mid_symlink_empty_dir":
        shutil.rmtree(mission)
        (outside / "empty").mkdir()
        os.symlink(outside / "empty", mission)
        return outside / "empty"
    if shape == "mid_dangling_symlink":
        shutil.rmtree(mission)
        os.symlink(outside / "absent", mission)
    elif shape in ("mid_file", "missions_file"):
        source = mission if shape == "mid_file" else mission.parent
        shutil.rmtree(source)
        source.write_text("x\n")
    return None


EARLY_SHAPES = ["mid_symlink_dir", "mid_symlink_empty_dir", "mid_dangling_symlink", "mid_file", "mid_unsearchable",
                "missions_symlink_dir", "missions_file"]


@pytest.mark.skipif(os.geteuid() == 0, reason="EACCES as root is NOTRUN")
@pytest.mark.parametrize("cohort", ["LEGACY", "ELIGIBLE"])
@pytest.mark.parametrize("shape", EARLY_SHAPES)
def test_s5_nonregular_mission_path_refused_before_beta_for_every_cohort(
        tmp_path, monkeypatch, cohort, shape):
    controller, project_id = _cohort(tmp_path / "p", cohort)
    external = _shape(controller, project_id, shape, tmp_path / "outside")
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    outside_before = tree_snapshot(tmp_path / "outside")
    mission = controller.store.mission_dir(project_id, MID)
    reached: list[str] = []
    for name in ("_validate_submission_read_only",):
        real = getattr(ProjectController, name)
        monkeypatch.setattr(ProjectController, name,
                            lambda self, *a, _r=real, _n=name: reached.append(_n) or _r(self, *a))
    store_type = type(controller.store)
    for name in ("ensure_contract_dir", "save_task_list", "save_task_state",
                 "save_contract_state", "save_state"):
        real = getattr(store_type, name)
        monkeypatch.setattr(store_type, name,
                            lambda self, *a, _r=real, _n=name: reached.append(_n) or _r(self, *a))
    real_mark = controller_module.mark_legacy_consumption
    monkeypatch.setattr(controller_module, "mark_legacy_consumption",
                        lambda *a: reached.append("mark_legacy_consumption") or real_mark(*a))
    spy = WriteSpy(monkeypatch)
    entry: dict[str, Any] = {}
    spied_submit = ProjectController._submit_plan

    def submit(self, *args):
        # Snapshot after the lock-time _project_access recovery (outside the claim).
        entry["bucket"] = tree_snapshot(bucket)
        return spied_submit(self, *args)

    monkeypatch.setattr(ProjectController, "_submit_plan", submit)
    if shape == "mid_unsearchable":
        os.chmod(mission, 0o000)
    locked = tree_snapshot(bucket)
    try:
        error = _err(controller.submit_plan, project_id, work_plan(["VAL-A"]))
        assert tree_snapshot(bucket) == entry["bucket"] == locked
    finally:
        if shape == "mid_unsearchable":
            os.chmod(mission, 0o755)
    assert error.code == "governed_admission_unresolved"
    assert reached == [] and spy.events == []
    assert not os.path.lexists(_marker(controller, project_id))
    assert tree_snapshot(bucket) == before
    # The whole external tree (a link target keeps its existing contract/) is unchanged
    # and no dangling target appears.
    assert tree_snapshot(tmp_path / "outside") == outside_before
    assert not os.path.lexists(tmp_path / "outside" / "absent")
    if external is not None and shape == "mid_symlink_empty_dir":
        assert list(external.iterdir()) == []  # the baseline created contract/ here
    elif external is not None:
        assert (external / ("contract" if shape == "mid_symlink_dir"
                            else f"{MID}/contract") / "VAL-A.md").read_text() == "a\n"
    if shape == "mid_unsearchable":
        monkeypatch.undo()
        controller.submit_plan(project_id, work_plan(["VAL-A"]))
        assert _marker(controller, project_id).exists() == (cohort == "ELIGIBLE")


def test_s5_nonregular_mission_precedes_identity_unavailable(tmp_path, monkeypatch):
    controller, project_id = _project_in_state(tmp_path / "p", "ELIGIBLE")
    _shape(controller, project_id, "mid_symlink_dir", tmp_path / "outside")
    (_identity(controller, project_id) / "init.json").write_text("{}")
    assert gr.classify_identity(controller.store, project_id).state == "IDENTITY_UNAVAILABLE"
    before = tree_snapshot(controller.store.bucket_root(project_id))
    outside_before = tree_snapshot(tmp_path / "outside")
    spy = WriteSpy(monkeypatch)
    assert _err(controller.submit_plan, project_id,
                work_plan(["VAL-A"])).code == "governed_admission_unresolved"
    assert spy.events == []
    assert tree_snapshot(controller.store.bucket_root(project_id)) == before
    assert tree_snapshot(tmp_path / "outside") == outside_before
