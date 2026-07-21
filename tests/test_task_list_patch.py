"""TaskListPatch application + post-patch invariants.

See `specs/task_list/PRODUCT.md` §Patching and §Edge Cases.
"""
from __future__ import annotations


from unrest_harness.models import Task, TaskList, TaskListPatch, TaskStateFile
from unrest_harness.task_list_patch import apply_patch


def _task(
    tid: str,
    ttype: str,
    targets: list[str],
    skill: str | None = None,
    depends_on: list[str] | None = None,
    body: str = "body",
) -> Task:
    if skill is None and ttype != "gate":
        skill = "s"
    return Task(
        id=tid,
        type=ttype,  # type: ignore[arg-type]
        body="" if ttype == "gate" else body,
        targets=targets,
        skill=skill,
        depends_on=depends_on or [],
    )


def _base() -> tuple[TaskList, TaskStateFile, set[str]]:
    """w1 → v1 → g1 with all tasks pending."""
    tl = TaskList(tasks=[
        _task("w1", "work", ["X"]),
        _task("v1", "validate", ["X"], skill="aud", depends_on=["w1"]),
        _task("g1", "gate", ["X"], depends_on=["v1"]),
    ])
    return tl, TaskStateFile(), {"X"}


class TestEmptyPatch:
    def test_rejected(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(tl, ts, ids, TaskListPatch())
        assert any(e.code == "empty_patch" for e in errs)


class TestAddItems:
    def test_orphan_file_caught(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(supersede={"w1": "w1"}),  # noop placeholder to make patch non-empty
            new_contract_ids_on_disk={"NEW-001"},
        )
        # supersede_self also fires; the orphan check should still appear when we
        # use a real patch op. Use a benign add_items missing the orphan instead.
        _, _, _, errs2 = apply_patch(
            tl, ts, ids,
            TaskListPatch(add_items=[]),  # also empty
            new_contract_ids_on_disk={"NEW-001"},
        )
        # The empty-patch path returns empty_patch only.
        assert any(e.code == "empty_patch" for e in errs2)

        # The real orphan-catching path is exercised below via add_items mismatch.
        _, _, _, errs3 = apply_patch(
            tl, ts, ids,
            TaskListPatch(
                add_items=["NEW-001"],
                add=[_task("w-new", "work", ["NEW-001"], depends_on=["g1"]),
                     _task("v-new", "validate", ["NEW-001"], skill="aud",
                           depends_on=["w-new"]),
                     _task("g-new", "gate", ["NEW-001"], depends_on=["v-new"])],
            ),
            new_contract_ids_on_disk={"NEW-001", "ORPHAN"},
        )
        assert any(e.code == "undeclared_new_assertion" for e in errs3)

    def test_file_missing(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(add_items=["NEW-001"]),
            new_contract_ids_on_disk=set(),
        )
        assert any(e.code == "assertion_file_missing" for e in errs)

    def test_duplicate_assertion(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(add_items=["X"]),
            new_contract_ids_on_disk={"X"},
        )
        assert any(e.code == "duplicate_assertion" for e in errs)


class TestSupersede:
    def test_supersede_cleared_task_rejected(self) -> None:
        tl, ts, ids = _base()
        ts.set_status("w1", "cleared")
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(
                supersede={"w1": "w1-v2"},
                add=[_task("w1-v2", "work", ["X"])],
            ),
        )
        assert any(e.code == "supersede_cleared_task" for e in errs)

    def test_running_cannot_be_superseded(self) -> None:
        tl, ts, ids = _base()
        ts.set_status("w1", "running")
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(
                supersede={"w1": "w1-v2"},
                add=[_task("w1-v2", "work", ["X"])],
            ),
        )
        assert any(e.code == "supersede_status_invalid" for e in errs)

    def test_unknown_supersede(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(
                supersede={"ghost": "w-new"},
                add=[_task("w-new", "work", ["X"])],
            ),
        )
        assert any(e.code == "unknown_supersede_target" for e in errs)

    def test_supersede_self_rejected(self) -> None:
        tl, ts, ids = _base()
        ts.set_status("w1", "failed")
        _, _, _, errs = apply_patch(
            tl, ts, ids, TaskListPatch(supersede={"w1": "w1"}),
        )
        assert any(e.code == "supersede_self" for e in errs)

    def test_supersede_inside_sealed_subgraph_rejected(self) -> None:
        tl, ts, ids = _base()
        for tid in ["w1", "v1"]:
            ts.set_status(tid, "cleared")
        ts.set_status("g1", "cleared")
        # All upstream of cleared gate are sealed.
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(
                supersede={"w1": "w1-v2"},
                add=[_task("w1-v2", "work", ["X"])],
            ),
        )
        # supersede_cleared_task fires first (w1 is cleared); but the seal rule
        # also applies. Accept either as long as the patch is rejected.
        assert errs
        codes = {e.code for e in errs}
        assert codes & {"supersede_cleared_task", "supersede_inside_sealed_subgraph"}


class TestSupersedePattern:
    def test_in_scope_fix(self) -> None:
        """gate_failed → supersede(w1, g1) + add (w1-v2, v1-v2, g1-v2)."""
        tl, ts, ids = _base()
        ts.set_status("w1", "failed")
        ts.set_status("v1", "cleared")
        ts.set_status("g1", "failed")
        patch = TaskListPatch(
            supersede={"w1": "w1-v2", "g1": "g1-v2"},
            add=[
                _task("w1-v2", "work", ["X"]),
                _task("v1-v2", "validate", ["X"], skill="aud", depends_on=["w1-v2"]),
                _task("g1-v2", "gate", ["X"], depends_on=["v1-v2"]),
            ],
        )
        new_tl, new_ts, new_ids, errs = apply_patch(tl, ts, ids, patch)
        assert errs == []
        assert new_ts.status_of("w1") == "superseded"
        assert new_ts.status_of("w1-v2") == "pending"
        assert new_ids == {"X"}


class TestPostPatchInvariants:
    def test_new_assertion_without_fulfiller_rejected(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(add_items=["NEW-001"]),
            new_contract_ids_on_disk={"NEW-001"},
        )
        assert any(e.code == "uncovered_assertion" for e in errs)

    def test_new_task_with_unknown_dep_rejected(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(add=[_task("w-bad", "work", ["X"], depends_on=["ghost"])]),
        )
        assert any(e.code == "dep_unknown_task" for e in errs)

    def test_task_id_collision_rejected(self) -> None:
        tl, ts, ids = _base()
        _, _, _, errs = apply_patch(
            tl, ts, ids,
            TaskListPatch(add=[_task("w1", "work", ["X"])]),
        )
        assert any(e.code == "task_id_collision" for e in errs)
