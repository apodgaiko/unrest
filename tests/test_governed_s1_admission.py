"""Governed S1 admission: capture, buffers, W-order, cuts, replay (VAL-01..16)."""
from __future__ import annotations

import json
import os
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
from unrest_harness.controller import ToolError
from unrest_harness.models import MissionPlanning, MissionRunning
from unrest_harness.task_validation import parse_contract_dir


def _codes(callable_, *args):
    with pytest.raises(ToolError) as caught:
        callable_(*args)
    return caught.value


def _fresh(tmp_path: Path, criteria: dict[str, bytes | str]):
    controller = make_controller(tmp_path)
    project_id = start(controller, tmp_path)
    contract = write_criteria(controller.store, project_id, "mission-001", criteria)
    return controller, project_id, contract


def _admit(controller, project_id, plan, key="key-1"):
    return controller.submit_governed_plan(project_id, "mission-001", plan, request(key))


# VAL-01 -------------------------------------------------------------------


def test_val01_capture_reads_each_candidate_once_and_stages_snapshot(tmp_path, monkeypatch):
    controller, project_id, contract = _fresh(tmp_path, {"VAL-A": "first\n", "VAL-B": "b\n"})
    opened: list[str] = []
    real_open = os.open

    def spy(path, flags, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(gr.os, "open", spy)
    captured = gr.capture_criteria(controller.store, project_id, "mission-001")
    monkeypatch.setattr(gr.os, "open", real_open)
    assert [aid for aid, _ in captured] == ["VAL-A", "VAL-B"]
    assert opened.count("VAL-A.md") == 1 and opened.count("VAL-B.md") == 1
    receipt = _admit(controller, project_id, work_plan(["VAL-A", "VAL-B"]))["governed_admission"]
    (contract / "VAL-A.md").write_text("changed after admission\n")
    admission = governed_dir(controller.store, project_id, "mission-001") / "admission"
    staged = admission / receipt["admission_id"] / "criteria" / "VAL-A.v1.md"
    assert staged.read_bytes() == b"first\n"


# VAL-02 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"a\nb\n", b"a\nb\n"),
        (b"a\r\nb\r\n", b"a\nb\n"),
        ("text\u3000".encode(), b"text\n"),
        pytest.param(b"x" * 65_535, b"x" * 65_535 + b"\n", id="max_65535"),
    ],
)
def test_val02_canonicalization_accepts(raw, expected):
    assert gr.canonicalize_criterion(raw) == expected
    assert (expected.decode().rstrip() + "\n").encode() == expected


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"a\rb", "criterion_invalid_encoding"),
        (b"\xef\xbb\xbfa", "criterion_invalid_encoding"),
        (b"a\x00b", "criterion_invalid_encoding"),
        (b"\xff\xfe", "criterion_invalid_encoding"),
        (b"  \n\t\n", "criterion_empty"),
        pytest.param(b"x" * 65_536, "criterion_too_large", id="over_65536"),
    ],
)
def test_val02_canonicalization_refuses(raw, code):
    with pytest.raises(gr.CaptureRefusal) as caught:
        gr.canonicalize_criterion(raw)
    assert caught.value.code == code


# VAL-03 -------------------------------------------------------------------


def test_val03_candidate_set_matches_baseline_details(tmp_path):
    controller, project_id, contract = _fresh(tmp_path, {"VAL-A": "a\n"})
    for name in (".x.md", ".md", "README.md", "bad_name.md"):
        (contract / name).write_text("x\n")
    _, baseline = parse_contract_dir(contract)
    error = _codes(_admit, controller, project_id, work_plan(["VAL-A"]))
    assert error.code == "invalid_contract_dir"
    assert [str(detail) for detail in error.details] == [str(detail) for detail in baseline]
    assert not governed_dir(controller.store, project_id, "mission-001").exists()


@pytest.mark.parametrize("variant", ["dir", "symlink", "fifo", "lone_cr", "missing", "symlink_dir",
                                     "too_many"])
def test_val03_declared_strict_differences(tmp_path, variant):
    controller, project_id, contract = _fresh(tmp_path, {"VAL-A": "a\n"})
    expected = "criterion_non_regular"
    if variant == "dir":
        (contract / "VAL-B.md").mkdir()
    elif variant == "symlink":
        (tmp_path / "outside.md").write_text("x\n")
        (contract / "VAL-B.md").symlink_to(tmp_path / "outside.md")
    elif variant == "fifo":
        os.mkfifo(contract / "VAL-B.md")
    elif variant == "lone_cr":
        (contract / "VAL-B.md").write_bytes(b"a\rb")
        expected = "criterion_invalid_encoding"
    elif variant == "missing":
        for path in contract.iterdir():
            path.unlink()
        contract.rmdir()
        expected = "invalid_contract_dir"
    elif variant == "symlink_dir":
        target = tmp_path / "real-contract"
        contract.rename(target)
        contract.symlink_to(target)
        expected = "invalid_contract_dir"
    else:
        for index in range(257):
            (contract / f"VAL-N{index:03d}.md").write_text("n\n")
        expected = "criteria_set_too_large"
    error = _codes(_admit, controller, project_id, work_plan(["VAL-A"]))
    assert error.code == expected
    assert not governed_dir(controller.store, project_id, "mission-001").exists()
    if variant == "missing":
        assert not contract.exists()


# VAL-04 / VAL-05 -----------------------------------------------------------


def test_val04_redactable_criterion_refused_without_substring(tmp_path):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "uses sk-SECRETVALUE123 here\n"})
    controller.store.inventory = {"API_KEY": "sk-SECRETVALUE123"}
    error = _codes(_admit, controller, project_id, work_plan(["VAL-A"]))
    assert error.code == "criterion_contains_redactable"
    assert "SECRETVALUE" not in str(error)
    assert not governed_dir(controller.store, project_id, "mission-001").exists()


def test_val05_identifier_and_buffer_limits(tmp_path, monkeypatch):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    long_task = work_plan(["VAL-A"], prefix="t" * 129)
    error = _codes(_admit, controller, project_id, long_task)
    assert error.code == "governed_limit_exceeded"
    monkeypatch.setattr(ga, "MANIFEST_LIMIT", 10)
    error = _codes(_admit, controller, project_id, work_plan(["VAL-A"]))
    assert error.code == "governed_limit_exceeded"
    monkeypatch.setattr(ga, "MANIFEST_LIMIT", gr.MANIFEST_LIMIT)
    monkeypatch.setattr(ga, "POST_IMAGE_LIMIT", 10)
    error = _codes(_admit, controller, project_id, work_plan(["VAL-A"]))
    assert error.code == "governed_limit_exceeded"
    assert not governed_dir(controller.store, project_id, "mission-001").exists()


# VAL-06 / VAL-07 -----------------------------------------------------------


def test_val06_product_bytes_equal_legacy_submit(tmp_path):
    criteria = {"VAL-B": "b\n", "VAL-A": "a\n", "VAL-C": "c\n"}
    plan = work_plan(sorted(criteria), validate=True)
    governed, gpid, _ = _fresh(tmp_path / "g", criteria)
    legacy = make_controller(tmp_path / "l")
    lpid = start(legacy, tmp_path / "l")
    write_criteria(legacy.store, lpid, "mission-001", criteria)
    _admit(governed, gpid, plan)
    legacy.submit_plan(lpid, plan)
    for name in ("tasks.json", "task-state.json"):
        assert (governed.store.mission_runtime_dir(gpid, "mission-001") / name).read_bytes() == (
            legacy.store.mission_runtime_dir(lpid, "mission-001") / name
        ).read_bytes()
    assert (governed.store.unrest_runtime_dir(gpid) / "state.json").read_bytes() == (
        legacy.store.unrest_runtime_dir(lpid) / "state.json"
    ).read_bytes()
    g_cs = json.loads((governed.store.mission_runtime_dir(gpid, "mission-001")
                       / "contract-state.json").read_bytes())
    l_cs = json.loads((legacy.store.mission_runtime_dir(lpid, "mission-001")
                       / "contract-state.json").read_bytes())
    assert g_cs == l_cs and set(g_cs["items"]) == set(l_cs["items"])
    assert list(g_cs["items"]) == sorted(g_cs["items"])


def test_val07_w_order_intent_before_product_and_no_envelope(tmp_path, monkeypatch):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    events: list[str] = []
    real_publish = ga.publish
    real_atomic = None

    def publish_spy(dir_fd, name, data, limit, **kwargs):
        events.append(f"g:{name}")
        return real_publish(dir_fd, name, data, limit, **kwargs)

    import unrest_harness.storage as storage

    real_atomic = storage.atomic_write_text

    def atomic_spy(path, *args, **kwargs):
        events.append(f"p:{Path(path).name}")
        return real_atomic(path, *args, **kwargs)

    monkeypatch.setattr(ga, "publish", publish_spy)
    monkeypatch.setattr(storage, "atomic_write_text", atomic_spy)
    monkeypatch.setattr(type(controller), "_build_envelope",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("envelope")))
    _admit(controller, project_id, work_plan(["VAL-A"]))
    intent = events.index("g:intent.json")
    products = [index for index, event in enumerate(events) if event.startswith("p:")]
    assert [events[index] for index in products] == [
        "p:tasks.json", "p:task-state.json", "p:contract-state.json", "p:state.json"]
    assert all(index > intent for index in products)
    assert events[-1] == "g:commit.json"


# VAL-08 cuts -----------------------------------------------------------------


class _Cut(Exception):
    pass


@pytest.mark.parametrize("cut", ["K0b", "K1", "K2", "K3-tasks", "K3-task-state",
                                 "K3-contract-state", "K4", "K4-readback"])
def test_val08_fault_injection_cuts(tmp_path, monkeypatch, cut):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    import unrest_harness.storage as storage

    real_publish = ga.publish
    real_atomic = storage.atomic_write_text
    real_mkdir_open = ga.mkdir_open

    def mkdir_spy(parent, name, *, reuse):
        if cut == "K0b" and len(name) == 32:
            raise _Cut()
        return real_mkdir_open(parent, name, reuse=reuse)

    def publish_spy(dir_fd, name, data, limit, **kwargs):
        if cut == "K1" and name == "intent.json":
            raise _Cut()
        if cut == "K4" and name == "commit.json":
            raise _Cut()
        return real_publish(dir_fd, name, data, limit, **kwargs)

    def atomic_spy(path, content, **kwargs):
        name = Path(path).name
        if cut == "K2" and name == "tasks.json":
            raise _Cut()
        mapping = {"K3-tasks": "task-state.json", "K3-task-state": "contract-state.json",
                   "K3-contract-state": "state.json"}
        if mapping.get(cut) == name:
            raise _Cut()
        if cut == "K4-readback" and name == "state.json":
            content = content + " "
        return real_atomic(path, content, **kwargs)

    monkeypatch.setattr(ga, "mkdir_open", mkdir_spy)
    monkeypatch.setattr(ga, "publish", publish_spy)
    monkeypatch.setattr(storage, "atomic_write_text", atomic_spy)
    try:
        _admit(controller, project_id, work_plan(["VAL-A"]))
    except (_Cut, ToolError):
        pass
    monkeypatch.undo()
    result = gr.classify(controller.store, project_id, "mission-001")
    expected = {
        "K0b": ("NONE", "empty_governed_residue"),
        "K1": ("NONE", "orphan_staging_present"),
    }.get(cut, ("AMBIGUOUS", "intent_without_commit"))
    assert (result.admission_status, result.status_reason) == expected
    assert result.admission_status != "COMMITTED"
    if cut == "K0b":
        envelope = controller.submit_plan(project_id, work_plan(["VAL-A"]))
        assert envelope.state.state == "mission_running"


# VAL-09..12 replay -----------------------------------------------------------


def test_val09_replay_after_commit_is_write_free(tmp_path, monkeypatch):
    controller, project_id, mission_id = governed_project(tmp_path)
    plan = work_plan(["VAL-A"])
    contract = controller.store.mission_dir(project_id, mission_id) / "contract"
    (contract / "VAL-A.md").write_text("changed authoring\n")
    controller.advance_project(project_id)
    bucket = controller.store.bucket_root(project_id)
    before = tree_snapshot(bucket)
    monkeypatch.setattr(type(controller.store), "recover_patch_transactions",
                        lambda *a: (_ for _ in ()).throw(AssertionError("recovery")))
    monkeypatch.setattr(type(controller), "_build_envelope",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("envelope")))
    receipt = controller.submit_governed_plan(project_id, mission_id, plan, request())
    assert receipt["governed_admission"]["replayed"] is True
    assert tree_snapshot(bucket) == before


def test_val09_replay_never_touches_executions(tmp_path, monkeypatch):
    controller, project_id, mission_id = governed_project(tmp_path)
    controller.advance_project(project_id)
    executions = governed_dir(controller.store, project_id, mission_id) / "executions"
    (executions / "junk").write_text("foreign")
    sentinels = {(executions.stat().st_dev, executions.stat().st_ino)}
    for child in executions.iterdir():
        sentinels.add((child.lstat().st_dev, child.lstat().st_ino))
    touched: list[str] = []
    real_open, real_scandir, real_stat, real_lstat = os.open, os.scandir, os.stat, os.lstat

    def check_fd(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) in sentinels:
            touched.append("fd")

    def open_spy(path, *args, **kwargs):
        if os.fspath(path) == "executions" or "executions" in os.fspath(path).split(os.sep):
            touched.append(os.fspath(path))
        fd = real_open(path, *args, **kwargs)
        check_fd(fd)
        return fd

    def stat_spy(path, *args, **kwargs):
        if not isinstance(path, int) and "executions" in os.fspath(path).split(os.sep):
            touched.append(os.fspath(path))
        return real_stat(path, *args, **kwargs)

    def lstat_spy(path, *args, **kwargs):
        if "executions" in os.fspath(path).split(os.sep):
            touched.append(os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    def scandir_spy(path=".", *args):
        if isinstance(path, int):
            check_fd(path)
        elif "executions" in os.fspath(path).split(os.sep):
            touched.append(os.fspath(path))
        return real_scandir(path, *args)

    monkeypatch.setattr(os, "open", open_spy)
    monkeypatch.setattr(os, "stat", stat_spy)
    monkeypatch.setattr(os, "lstat", lstat_spy)
    monkeypatch.setattr(os, "scandir", scandir_spy)
    receipt = controller.submit_governed_plan(project_id, mission_id, work_plan(["VAL-A"]),
                                              request())
    monkeypatch.undo()
    assert receipt["governed_admission"]["replayed"] is True
    assert touched == []
    if os.geteuid() != 0:
        executions.chmod(0)
        try:
            again = controller.submit_governed_plan(project_id, mission_id,
                                                    work_plan(["VAL-A"]), request())
        finally:
            executions.chmod(0o700)
        assert again == receipt


def test_val10_replay_decision_table(tmp_path, monkeypatch):
    controller, project_id, mission_id = governed_project(tmp_path)
    other = work_plan(["VAL-A"], prefix="x")
    assert _codes(controller.submit_governed_plan, project_id, mission_id, other,
                  request()).code == "admission_retry_mismatch"
    assert _codes(controller.submit_governed_plan, project_id, mission_id, work_plan(["VAL-A"]),
                  request("key-2")).code == "governed_already_admitted"
    controller.abandon_governance(project_id, mission_id, {
        "schema": "unrest.governed-abandon-request.v1", "idempotency_key": "ab"})
    assert _codes(controller.submit_governed_plan, project_id, mission_id, work_plan(["VAL-A"]),
                  request()).code == "governed_abandoned"


def test_val10_ambiguous_admission_is_unresolved(tmp_path, monkeypatch):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    real_publish = ga.publish

    def no_commit(dir_fd, name, data, limit, **kwargs):
        if name == "commit.json":
            raise OSError("cut")
        return real_publish(dir_fd, name, data, limit, **kwargs)

    monkeypatch.setattr(ga, "publish", no_commit)
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == (
        "governed_admission_unresolved")
    monkeypatch.undo()
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == (
        "governed_admission_unresolved")


def test_val11_inventory_change_is_retry_mismatch(tmp_path):
    controller, project_id, mission_id = governed_project(tmp_path)
    controller.store.inventory = {"TOKEN": "do"}
    assert _codes(controller.submit_governed_plan, project_id, mission_id, work_plan(["VAL-A"]),
                  request()).code == "admission_retry_mismatch"


def test_val12_wrong_state_and_replay_after_next_mission(tmp_path):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    assert _codes(controller.submit_governed_plan, project_id, "mission-002",
                  work_plan(["VAL-A"]), request()).code == "wrong_state"
    _admit(controller, project_id, work_plan(["VAL-A"]))
    store = controller.store
    store.save_state(project_id, MissionPlanning(mission_id="mission-002"))
    receipt = controller.submit_governed_plan(project_id, "mission-001", work_plan(["VAL-A"]),
                                              request())
    assert receipt["governed_admission"]["replayed"] is True


# VAL-13 / VAL-14 -------------------------------------------------------------


def test_val13_sixteen_orphans_then_limit_then_abandon_then_legacy(tmp_path, monkeypatch):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    real_publish = ga.publish

    def no_intent(dir_fd, name, data, limit, **kwargs):
        if name == "intent.json":
            raise OSError("cut")
        return real_publish(dir_fd, name, data, limit, **kwargs)

    monkeypatch.setattr(ga, "publish", no_intent)
    for _ in range(16):
        assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == (
            "governed_io_unavailable")
    monkeypatch.undo()
    admission = governed_dir(controller.store, project_id, "mission-001") / "admission"
    assert len(list(admission.iterdir())) == 16
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == (
        "governed_limit_exceeded")
    assert len(list(admission.iterdir())) == 16
    receipt = controller.abandon_governance(project_id, "mission-001", {
        "schema": "unrest.governed-abandon-request.v1", "idempotency_key": "ab"})
    assert receipt["governed_abandon"]["admission_phase"] == "precommit_orphan"
    envelope = controller.submit_plan(project_id, work_plan(["VAL-A"]))
    assert envelope.state.state == "mission_running"
    assert gr.classify(controller.store, project_id, "mission-001").admission_status == (
        "ABANDONED")


def test_val14_lock_eligibility(tmp_path, monkeypatch):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    record = controller.store.unrest_runtime_dir(project_id) / "project.json"
    saved = record.read_bytes()
    record.unlink()
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == "not_found"
    assert _codes(controller.abandon_governance, project_id, "mission-001", {
        "schema": "unrest.governed-abandon-request.v1", "idempotency_key": "a"}).code == "not_found"
    record.mkdir()
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == "not_found"
    record.rmdir()
    record.write_bytes(saved)
    import unrest_harness.project_lock as project_lock

    def lock_error(*_args, **_kwargs):
        raise project_lock.ProjectLockError

    monkeypatch.setattr(project_lock, "project_lock_path", lock_error)
    assert _codes(_admit, controller, project_id, work_plan(["VAL-A"])).code == (
        "project_lock_error")
    monkeypatch.undo()
    lock = project_lock.ProjectMutationLock(
        project_lock.project_lock_path(controller.store, project_id), create=True)
    assert lock.acquire(blocking=False)
    try:
        import threading

        result: list[str] = []

        def other_thread():
            try:
                _admit(controller, project_id, work_plan(["VAL-A"]))
            except ToolError as exc:
                result.append(exc.code)

        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join()
        assert result == ["project_busy"]
    finally:
        lock.release()
    assert not governed_dir(controller.store, project_id, "mission-001").exists()


# VAL-15 / VAL-16 -------------------------------------------------------------


@pytest.mark.parametrize("variant", ["absent", "empty_residue", "orphan", "ambiguous", "committed",
                                     "foreign_member", "abandon_without_a", "abandoned"])
def test_val15_legacy_submit_eligibility(tmp_path, monkeypatch, variant):
    controller, project_id, _ = _fresh(tmp_path, {"VAL-A": "a\n"})
    g = governed_dir(controller.store, project_id, "mission-001")
    expected: str | None = None
    if variant == "empty_residue":
        (g / "admission").mkdir(parents=True)
    elif variant in ("orphan", "ambiguous", "committed"):
        real_publish = ga.publish
        stop = {"orphan": "intent.json", "ambiguous": "commit.json"}.get(variant)

        def cut(dir_fd, name, data, limit, **kwargs):
            if name == stop:
                raise OSError("cut")
            return real_publish(dir_fd, name, data, limit, **kwargs)

        monkeypatch.setattr(ga, "publish", cut)
        try:
            _admit(controller, project_id, work_plan(["VAL-A"]))
        except ToolError:
            pass
        monkeypatch.undo()
        if variant == "ambiguous":
            controller.store.save_state(project_id, MissionPlanning(mission_id="mission-001"))
        if variant == "committed":
            controller.store.save_state(project_id, MissionPlanning(mission_id="mission-001"))
        expected = "governed_admission_present"
    elif variant == "foreign_member":
        g.mkdir(parents=True)
        (g / "stray").write_text("x")
        expected = "governed_admission_unresolved"
    elif variant == "abandon_without_a":
        g.mkdir(parents=True)
        (g / "abandoned.json").write_text("{}")
        expected = "governed_admission_unresolved"
    elif variant == "abandoned":
        _admit(controller, project_id, work_plan(["VAL-A"]))
        controller.abandon_governance(project_id, "mission-001", {
            "schema": "unrest.governed-abandon-request.v1", "idempotency_key": "ab"})
        controller.store.save_state(project_id, MissionPlanning(mission_id="mission-001"))
    if expected is None:
        envelope = controller.submit_plan(project_id, work_plan(["VAL-A"]))
        assert isinstance(envelope.state, MissionRunning)
    else:
        before = tree_snapshot(controller.store.bucket_root(project_id))
        assert _codes(controller.submit_plan, project_id, work_plan(["VAL-A"])).code == expected
        assert tree_snapshot(controller.store.bucket_root(project_id)) == before


def test_val16_runtime_executor_projects_private_code(tmp_path):
    from unrest_harness import runtime_executor

    controller, project_id, mission_id = governed_project(tmp_path)
    controller.store.save_state(project_id, MissionPlanning(mission_id=mission_id))
    before = tree_snapshot(controller.store.bucket_root(project_id))
    with pytest.raises(ToolError) as caught:
        runtime_executor._invoke(controller, "submit_plan", {
            "project_id": project_id, "task_list": work_plan(["VAL-A"]).model_dump(mode="json")})
    failure = runtime_executor._payload(caught.value)[runtime_executor.EXECUTOR_FAILURE_KEY]
    assert failure["public_error"]["error"]["code"] == "invalid_argument"
    assert failure["private_tool_error"]["code"] == "governed_admission_present"
    assert tree_snapshot(controller.store.bucket_root(project_id)) == before
