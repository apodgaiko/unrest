"""Executable durability matrix for the W-LEG whole-generation transaction."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import queue
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.envelope import project_supersession_lineage
from unrest_harness.models import (
    AttentionItemInternal,
    AttentionNeeded,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.patch_transaction import (
    INSTALL_ORDER,
    INTEGRITY_ERROR,
    UNSUPPORTED_BATCH,
    PatchTransaction,
    PatchTransactionError,
    TransactionTarget,
    recover_patch_transactions,
)
from unrest_harness.project_lock import ProjectMutationLock


PATHS = {
    "task_list": ".unrest-runtime/missions/mission-001/tasks.json",
    "task_state": ".unrest-runtime/missions/mission-001/task-state.json",
    "contract_state": ".unrest-runtime/missions/mission-001/contract-state.json",
    "supersession_lineage": ".unrest/missions/mission-001/supersession-lineage.json",
    "mission_seal": ".unrest/missions/mission-001/closeout.md",
    "project_record": ".unrest-runtime/project.json",
    "decision_record": ".unrest/decisions/001-patch.md",
    "attention_cursor": ".unrest-runtime/attention.json",
    "project_state": ".unrest-runtime/state.json",
}
CASES_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "legibility_v045"
    / "action-transaction-cases.v1.json"
)


class Crash(RuntimeError):
    pass


def _private_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _targets(root: Path, generation: str = "post") -> list[TransactionTarget]:
    result: list[TransactionTarget] = []
    for kind in INSTALL_ORDER:
        pre = None if kind in {"supersession_lineage", "decision_record"} else f"pre:{kind}\n".encode()
        post = None if kind == "attention_cursor" else f"{generation}:{kind}\n".encode()
        result.append(TransactionTarget.from_images(kind, PATHS[kind], pre, post))
    return result


def _seed(root: Path, targets: list[TransactionTarget]) -> None:
    _private_mkdir(root / ".unrest-runtime" / "missions" / "mission-001")
    _private_mkdir(root / ".unrest" / "missions" / "mission-001")
    _private_mkdir(root / ".unrest" / "decisions")
    for target in targets:
        if target.precondition == "absent":
            continue
        path = root / target.relative_path
        _private_mkdir(path.parent)
        path.write_bytes(f"pre:{target.kind}\n".encode())


def _condition(path: Path) -> str:
    if not path.exists():
        return "absent"
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _generation(root: Path, targets: list[TransactionTarget]) -> str:
    actual = [_condition(root / target.relative_path) for target in targets]
    if actual == [target.precondition for target in targets]:
        return "pre"
    if actual == [target.postcondition for target in targets]:
        return "post"
    return "mixed"


def _process_generation(root: Path) -> str:
    generations: set[str] = set()
    for kind in INSTALL_ORDER:
        body = (root / PATHS[kind]).read_text(encoding="utf-8")
        prefix = "generation:"
        suffix = f":{kind}\n"
        if not body.startswith(prefix) or not body.endswith(suffix):
            return "mixed"
        generations.add(body[len(prefix) : -len(suffix)])
    return next(iter(generations)) if len(generations) == 1 else "mixed"


def _process_targets(root: Path, pre: str, post: str) -> list[TransactionTarget]:
    return [
        TransactionTarget.from_images(
            kind,
            PATHS[kind],
            f"generation:{pre}:{kind}\n".encode(),
            f"generation:{post}:{kind}\n".encode(),
        )
        for kind in INSTALL_ORDER
    ]


def _mutator_process(
    root_text: str,
    action: str,
    attempted: object,
    acquired: object,
    partial: object,
    release: object,
    active: object,
    overlap: object,
    events: object,
) -> None:
    root = Path(root_text)
    attempted.set()  # type: ignore[attr-defined]
    events.put((action, "attempt", os.getpid()))  # type: ignore[attr-defined]
    lock = ProjectMutationLock(root / ".unrest-runtime" / "mutation.lock")
    assert lock.acquire(blocking=True)
    with active.get_lock():  # type: ignore[attr-defined]
        if active.value:  # type: ignore[attr-defined]
            overlap.value = 1  # type: ignore[attr-defined]
        active.value += 1  # type: ignore[attr-defined]
    acquired.set()  # type: ignore[attr-defined]
    events.put((action, "acquire", os.getpid()))  # type: ignore[attr-defined]
    try:
        pre = _process_generation(root)
        assert pre != "mixed"
        post = f"{pre}>{action}"

        def pause(event: str) -> None:
            if event == "after_target_install:task_list":
                partial.set()  # type: ignore[attr-defined]
                assert release.wait(10)  # type: ignore[attr-defined]

        PatchTransaction(
            root,
            "mission-001",
            f"decision-{action}",
            _process_targets(root, pre, post),
            fault_injector=pause,
        ).execute()
        events.put((action, "outcome", os.getpid(), pre, post))  # type: ignore[attr-defined]
    finally:
        with active.get_lock():  # type: ignore[attr-defined]
            active.value -= 1  # type: ignore[attr-defined]
        events.put((action, "release", os.getpid()))  # type: ignore[attr-defined]
        lock.release()


def _inspector_process(root_text: str, started: object, result: object) -> None:
    root = Path(root_text)
    started.set()  # type: ignore[attr-defined]
    lock = ProjectMutationLock(root / ".unrest-runtime" / "mutation.lock")
    assert lock.acquire(blocking=True)
    try:
        recover_patch_transactions(root)
        result.put((os.getpid(), _process_generation(root)))  # type: ignore[attr-defined]
    finally:
        lock.release()


def _labels() -> list[str]:
    labels: list[str] = []
    for kind in INSTALL_ORDER:
        if kind != "attention_cursor":
            labels.extend(
                [
                    f"before_post_image_write:{kind}",
                    f"after_post_image_write:{kind}",
                    f"before_post_image_fsync:{kind}",
                    f"after_post_image_fsync:{kind}",
                ]
            )
    labels.extend(
        [
            "before_post_images_directory_fsync",
            "after_post_images_directory_fsync",
            "before_manifest_write",
            "after_manifest_write",
            "before_manifest_fsync",
            "after_manifest_fsync",
            "before_staging_directory_fsync",
            "after_staging_directory_fsync",
            "before_commit_create",
            "after_commit_create",
            "before_commit_fsync",
            "after_commit_fsync",
            "before_commit_directory_fsync",
            "after_commit_directory_fsync",
        ]
    )
    for kind in INSTALL_ORDER:
        labels.extend(
            [
                f"before_target_install:{kind}",
                f"after_target_install:{kind}",
                f"before_target_directory_fsync:{kind}",
                f"after_target_directory_fsync:{kind}",
            ]
        )
    labels.extend(
        [
            "before_done_create",
            "after_done_create",
            "before_done_fsync",
            "after_done_fsync",
            "before_done_directory_fsync",
            "after_done_directory_fsync",
            "before_transaction_cleanup",
            "after_transaction_cleanup",
        ]
    )
    assert len(labels) == 90
    assert len(set(labels)) == 90
    return labels


def test_case_fixture_is_bound_to_executed_protocol() -> None:
    fixture = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    assert fixture["schema"] == "unrest.v045.product-transaction-cases.v1"
    assert fixture["install_order"] == list(INSTALL_ORDER)
    assert fixture["crash_label_count"] == len(_labels()) == 90
    assert fixture["process_case"] == {
        "inspectors": 2,
        "mutator_order": ["A", "B"],
        "mutators": 2,
    }


@pytest.mark.parametrize("label", _labels())
def test_every_declared_crash_boundary_recovers_one_complete_generation(
    tmp_path: Path, label: str
) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    _seed(root, targets)
    executed: list[str] = []

    def crash_at(event: str) -> None:
        executed.append(event)
        if event == label:
            raise Crash(event)

    transaction = PatchTransaction(
        root, "mission-001", "decision-001", targets, fault_injector=crash_at
    )
    with pytest.raises(Crash):
        transaction.execute()
    assert label in executed
    committed = (transaction.transaction_dir / "COMMIT").exists() or (
        _generation(root, targets) == "post"
    )
    recover_patch_transactions(root)
    assert _generation(root, targets) == ("post" if committed else "pre")
    assert not transaction.transaction_dir.exists()
    recover_patch_transactions(root)
    assert _generation(root, targets) == ("post" if committed else "pre")


def test_staging_modes_markers_and_cleanup_are_real(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    _seed(root, targets)
    transaction = PatchTransaction(root, "mission-001", "decision-001", targets)
    transaction.prepare()
    assert stat.S_IMODE(transaction.transaction_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(transaction.post_images_dir.stat().st_mode) == 0o700
    for image in transaction.post_images_dir.iterdir():
        assert stat.S_IMODE(image.stat().st_mode) == 0o700
    assert stat.S_IMODE((transaction.transaction_dir / "manifest.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((transaction.transaction_dir / "preconditions.json").stat().st_mode) == 0o600
    transaction.commit()
    assert (transaction.transaction_dir / "COMMIT").read_bytes() == b""
    assert stat.S_IMODE((transaction.transaction_dir / "COMMIT").stat().st_mode) == 0o600
    transaction.install()
    transaction.finish()
    assert _generation(root, targets) == "post"
    assert not transaction.transaction_dir.exists()


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_image",
        "unsafe_image_mode",
        "image_symlink",
        "manifest_mismatch",
        "third_state",
        "two_committed",
        "nonempty_commit",
        "unsafe_transaction_mode",
        "unexpected_staged_member",
    ),
)
def test_integrity_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    _seed(root, targets)
    transaction = PatchTransaction(root, "mission-001", "decision-001", targets)
    transaction.prepare()
    if mutation in {"third_state", "two_committed", "nonempty_commit"}:
        transaction.commit()
    image = transaction.post_images_dir / "task_list"
    if mutation == "missing_image":
        image.unlink()
    elif mutation == "unsafe_image_mode":
        image.chmod(0o600)
    elif mutation == "image_symlink":
        image.unlink()
        image.symlink_to("task_state")
    elif mutation == "manifest_mismatch":
        manifest = transaction.transaction_dir / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b"x")
    elif mutation == "third_state":
        (root / PATHS["task_list"]).write_bytes(b"third\n")
    elif mutation == "two_committed":
        second = transaction.transactions_root / "decision-002"
        _private_mkdir(second)
        (second / "COMMIT").write_bytes(b"")
    elif mutation == "nonempty_commit":
        (transaction.transaction_dir / "COMMIT").write_bytes(b"x")
    elif mutation == "unsafe_transaction_mode":
        transaction.transaction_dir.chmod(0o755)
    elif mutation == "unexpected_staged_member":
        (transaction.transaction_dir / "extra").write_bytes(b"")
    with pytest.raises(PatchTransactionError) as exc_info:
        recover_patch_transactions(root)
    assert exc_info.value.code == INTEGRITY_ERROR
    assert _generation(root, targets) in {"pre", "mixed"}


@pytest.mark.parametrize(
    "mutation",
    (
        "invalid_path",
        "missing_target_class",
        "invalid_order",
        "empty",
    ),
)
def test_invalid_batch_definitions_are_integrity_errors_before_staging(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    _seed(root, targets)
    live_before = {
        target.relative_path: (root / target.relative_path).read_bytes()
        for target in targets
        if (root / target.relative_path).exists()
    }
    if mutation == "invalid_path":
        targets[0] = TransactionTarget.from_images("task_list", "../escape", None, b"x")
    elif mutation == "missing_target_class":
        targets.pop()
    elif mutation == "invalid_order":
        targets.reverse()
    elif mutation == "empty":
        targets.clear()
    with pytest.raises(PatchTransactionError) as exc_info:
        PatchTransaction(root, "mission-001", "decision-001", targets)
    assert exc_info.value.code == INTEGRITY_ERROR
    assert not (root / ".unrest-runtime/missions/mission-001/patch-transactions").exists()
    assert {
        relative_path: (root / relative_path).read_bytes()
        for relative_path in live_before
    } == live_before


def _inventory(root: Path) -> list[tuple[str, int, str | None]]:
    return [
        (
            path.relative_to(root).as_posix(),
            path.lstat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
        for path in sorted(root.rglob("*"))
    ]


@pytest.mark.parametrize(
    "mutation", ("path", "kind", "object", "appended", "short_duplicate", "valid")
)
def test_new_batch_duplicates_are_unsupported_without_any_write(
    tmp_path: Path, mutation: str
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    # Preserve an existing staging tree as well as the live generation.
    staging = tmp_path / ".unrest-runtime/missions/mission-001/patch-transactions"
    _private_mkdir(staging / "unrelated")
    (staging / "unrelated/sentinel").write_bytes(b"unchanged")
    if mutation == "path":
        targets[-1] = replace(targets[-1], relative_path=targets[0].relative_path)
    elif mutation == "kind":
        targets[-1] = replace(targets[-1], kind=targets[0].kind)
    elif mutation == "object":
        targets[-1] = targets[0]
    elif mutation == "appended":
        targets.append(targets[0])
    elif mutation == "short_duplicate":
        targets = [targets[0], targets[0]]
    before = _inventory(tmp_path)
    if mutation == "valid":
        transaction = PatchTransaction(tmp_path, "mission-001", "decision-001", targets)
        assert transaction.targets == tuple(targets)
    else:
        with pytest.raises(PatchTransactionError) as exc_info:
            PatchTransaction(tmp_path, "mission-001", "decision-001", iter(targets))
        assert exc_info.value.code == UNSUPPORTED_BATCH
    assert _inventory(tmp_path) == before


@pytest.mark.parametrize("committed", (False, True))
@pytest.mark.parametrize("mutation", ("path", "kind", "object", "appended"))
def test_persisted_duplicates_remain_integrity_errors_without_any_write(
    tmp_path: Path, mutation: str, committed: bool
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    transaction = PatchTransaction(tmp_path, "mission-001", "decision-001", targets)
    transaction.prepare()
    if committed:
        transaction.commit()
    payload = json.loads(transaction.manifest_bytes())
    rows = payload["targets"]
    if mutation == "path":
        rows[-1]["path"] = rows[0]["path"]
    elif mutation == "kind":
        rows[-1]["kind"] = rows[0]["kind"]
        rows[-1]["post"] = rows[0]["post"]
    elif mutation == "object":
        rows[-1] = dict(rows[0])
    elif mutation == "appended":
        rows.append(dict(rows[0]))
    # Keep the two records consistent so a mismatch cannot mask the duplicate.
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    for name in ("manifest.json", "preconditions.json"):
        (transaction.transaction_dir / name).write_bytes(body)
    before = _inventory(tmp_path)
    with pytest.raises(PatchTransactionError) as exc_info:
        recover_patch_transactions(tmp_path)
    assert exc_info.value.code == INTEGRITY_ERROR
    if mutation == "path":
        cause = exc_info.value.__cause__
        assert isinstance(cause, PatchTransactionError)
        assert cause.code == UNSUPPORTED_BATCH
    assert _inventory(tmp_path) == before
    assert _generation(tmp_path, targets) == "pre"


@pytest.mark.parametrize(
    "mutation",
    ("bad_mission", "bad_transaction", "post_digest_mismatch", "malformed_precondition"),
)
def test_unsupported_batches_refuse_before_staging(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    mission_id = "mission-001"
    transaction_id = "decision-001"
    if mutation == "bad_mission":
        mission_id = "../mission"
    elif mutation == "bad_transaction":
        transaction_id = "../transaction"
    elif mutation == "malformed_precondition":
        targets[0] = replace(targets[0], precondition="not-a-condition")
    elif mutation == "post_digest_mismatch":
        target = targets[0]
        targets[0] = TransactionTarget(
            target.kind,
            target.relative_path,
            target.precondition,
            "sha256:" + "0" * 64,
            target.post_bytes,
        )
    with pytest.raises(PatchTransactionError) as exc_info:
        PatchTransaction(root, mission_id, transaction_id, targets)
    assert exc_info.value.code == UNSUPPORTED_BATCH
    assert not (root / ".unrest-runtime").exists()


def _config(home: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=Path(__file__).parents[1] / "src" / "unrest_harness" / "bundled",
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=1,
    )


def _controller(home: Path, workspace: Path) -> ProjectController:
    return ProjectController(
        _config(home),
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id, done=True, report="unused"
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )


def _work(node_id: str) -> Task:
    return Task(
        id=node_id,
        type="work",
        body="work",
        targets=["VAL-X"],
        skill="worker",
    )


def test_controller_patch_generation_persists_bounded_chain_and_cleans_journal(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = _controller(tmp_path / "home", workspace)
    store = controller.store
    record = store.create_project("transaction", workspace, project_id="project-1")
    record.current_mission_id = "mission-001"
    store.save_project(record)
    contract = store.ensure_contract_dir("project-1", "mission-001") / "VAL-X.md"
    contract.write_text(
        "# VAL-X\n\nSurface: library.\nNeeds: none.\nBehavior: x.\nEvidence: x.\n",
        encoding="utf-8",
    )
    store.save_task_list("project-1", "mission-001", TaskList(tasks=[_work("w1")]))
    task_state = TaskStateFile()
    task_state.set_status("w1", "failed")
    store.save_task_state("project-1", "mission-001", task_state)
    store.save_contract_state(
        "project-1",
        "mission-001",
        ContractStateFile(items={"VAL-X": ContractStateEntry()}),
    )
    item = AttentionItemInternal(
        id="attention-1",
        report="private failure detail",
        kind="node_failed",
        mission_id="mission-001",
        node_id="w1",
    )
    store.save_attention("project-1", [item])
    store.save_state("project-1", AttentionNeeded(items=[item]))

    envelope = controller.decide_attention(
        "project-1",
        [
            Decision(
                item_id="attention-1",
                action="patch",
                patch=TaskListPatch(
                    add=[_work("w2")], supersede={"w1": "w2"}
                ),
            )
        ],
    )

    assert envelope.state.state == "mission_running"
    assert [entry.model_dump() for entry in envelope.supersession_lineage] == [
        {
            "current": {"mission_id": "mission-001", "node_id": "w2"},
            "superseded": [{"mission_id": "mission-001", "node_id": "w1"}],
        }
    ]
    assert store.load_supersession_edges("project-1", "mission-001") == [
        {
            "new": {"mission_id": "mission-001", "node_id": "w2"},
            "old": {"mission_id": "mission-001", "node_id": "w1"},
        }
    ]
    assert store.load_attention("project-1") == []
    assert store.load_task_state("project-1", "mission-001").status_of("w1") == "superseded"
    assert store.load_task_state("project-1", "mission-001").status_of("w2") == "pending"
    assert list(store.decisions_dir("project-1").glob("*.md"))
    assert not list(store.patch_transactions_dir("project-1", "mission-001").iterdir())

    before = tuple(
        (path.relative_to(store.bucket_root("project-1")).as_posix(), path.read_bytes())
        for path in sorted(store.bucket_root("project-1").rglob("*"))
        if path.is_file()
    )
    restarted = _controller(tmp_path / "home", workspace)
    inspected = restarted.inspect_project("project-1")
    after = tuple(
        (path.relative_to(store.bucket_root("project-1")).as_posix(), path.read_bytes())
        for path in sorted(store.bucket_root("project-1").rglob("*"))
        if path.is_file()
    )
    assert inspected.supersession_lineage == envelope.supersession_lineage
    assert before == after

    chained_state = store.load_task_state("project-1", "mission-001")
    chained_state.set_status("w2", "failed")
    store.save_task_state("project-1", "mission-001", chained_state)
    chained_item = item.model_copy(
        update={"id": "attention-2", "node_id": "w2"}
    )
    store.save_attention("project-1", [chained_item])
    store.save_state("project-1", AttentionNeeded(items=[chained_item]))
    chained = restarted.decide_attention(
        "project-1",
        [
            Decision(
                item_id="attention-2",
                action="patch",
                patch=TaskListPatch(
                    add=[_work("w3")], supersede={"w2": "w3"}
                ),
            )
        ],
    )
    assert [entry.model_dump() for entry in chained.supersession_lineage] == [
        {
            "current": {"mission_id": "mission-001", "node_id": "w3"},
            "superseded": [
                {"mission_id": "mission-001", "node_id": "w2"},
                {"mission_id": "mission-001", "node_id": "w1"},
            ],
        }
    ]


def test_mixed_patch_and_next_mission_installs_all_outer_effects_together(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = _controller(tmp_path / "home", workspace)
    store = controller.store
    record = store.create_project("mixed", workspace, project_id="project-1")
    record.current_mission_id = "mission-001"
    store.save_project(record)
    contract = store.ensure_contract_dir("project-1", "mission-001") / "VAL-X.md"
    contract.write_text(
        "# VAL-X\n\nSurface: library.\nNeeds: none.\nBehavior: x.\nEvidence: x.\n",
        encoding="utf-8",
    )
    store.save_task_list("project-1", "mission-001", TaskList(tasks=[_work("w1")]))
    task_state = TaskStateFile()
    task_state.set_status("w1", "failed")
    store.save_task_state("project-1", "mission-001", task_state)
    store.save_contract_state(
        "project-1",
        "mission-001",
        ContractStateFile(items={"VAL-X": ContractStateEntry()}),
    )
    failed = AttentionItemInternal(
        id="attention-node",
        report="private node detail",
        kind="node_failed",
        mission_id="mission-001",
        node_id="w1",
    )
    review = AttentionItemInternal(
        id="attention-review",
        report="private review detail",
        kind="terminal_review",
        mission_id="mission-001",
        terminal_review_id="review-spawn-1",
    )
    store.save_attention("project-1", [failed, review])
    store.save_state("project-1", AttentionNeeded(items=[failed, review]))

    envelope = controller.decide_attention(
        "project-1",
        [
            Decision(
                item_id="attention-node",
                action="patch",
                patch=TaskListPatch(
                    add=[_work("w2")], supersede={"w1": "w2"}
                ),
            ),
            Decision(item_id="attention-review", action="next_mission"),
        ],
    )

    assert envelope.state.state == "mission_planning"
    assert envelope.state.mission_id == "mission-002"
    assert store.load_project("project-1").current_mission_id == "mission-002"
    closeout = store.mission_dir("project-1", "mission-001") / "closeout.md"
    assert "done_with_acknowledged_gaps" in closeout.read_text(encoding="utf-8")
    assert store.load_task_state("project-1", "mission-001").status_of("w1") == "superseded"
    assert store.load_task_state("project-1", "mission-001").status_of("w2") == "pending"
    assert store.load_attention("project-1") == []
    assert len(list(store.decisions_dir("project-1").glob("*.md"))) == 1
    assert not list(store.patch_transactions_dir("project-1", "mission-001").iterdir())


def test_lineage_projection_preserves_authored_current_and_accepted_edge_order() -> None:
    task_list = TaskList(tasks=[_work("old-a"), _work("old-b"), _work("current")])
    task_state = TaskStateFile()
    task_state.set_status("old-a", "superseded")
    task_state.set_status("old-b", "superseded")
    edges = [
        {
            "new": {"mission_id": "mission-001", "node_id": "middle"},
            "old": {"mission_id": "mission-001", "node_id": "old-a"},
        },
        {
            "new": {"mission_id": "mission-001", "node_id": "middle"},
            "old": {"mission_id": "mission-001", "node_id": "old-b"},
        },
        {
            "new": {"mission_id": "mission-001", "node_id": "current"},
            "old": {"mission_id": "mission-001", "node_id": "middle"},
        },
    ]
    projected = project_supersession_lineage(
        "mission-001", task_list, task_state, edges
    )
    assert [entry.model_dump() for entry in projected] == [
        {
            "current": {"mission_id": "mission-001", "node_id": "current"},
            "superseded": [
                {"mission_id": "mission-001", "node_id": "middle"},
                {"mission_id": "mission-001", "node_id": "old-a"},
                {"mission_id": "mission-001", "node_id": "old-b"},
            ],
        }
    ]


def test_lineage_places_immediate_predecessors_before_older_ancestors() -> None:
    task_list = TaskList(tasks=[_work("current")])
    task_state = TaskStateFile()
    edges = [
        {
            "new": {"mission_id": "mission-001", "node_id": "mid-a"},
            "old": {"mission_id": "mission-001", "node_id": "old-x"},
        },
        {
            "new": {"mission_id": "mission-001", "node_id": "current"},
            "old": {"mission_id": "mission-001", "node_id": "mid-a"},
        },
        {
            "new": {"mission_id": "mission-001", "node_id": "current"},
            "old": {"mission_id": "mission-001", "node_id": "mid-b"},
        },
    ]

    projected = project_supersession_lineage(
        "mission-001", task_list, task_state, edges
    )

    assert [row.node_id for row in projected[0].superseded] == [
        "mid-a",
        "mid-b",
        "old-x",
    ]


def test_manifestless_recovery_refuses_unproven_mutated_live_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    targets = _targets(root)
    _seed(root, targets)

    def crash_before_manifest(label: str) -> None:
        if label == "before_manifest_write":
            raise Crash(label)

    transaction = PatchTransaction(
        root,
        "mission-001",
        "decision-001",
        targets,
        fault_injector=crash_before_manifest,
    )
    with pytest.raises(Crash):
        transaction.execute()
    (root / PATHS["task_list"]).write_bytes(b"third-state\n")

    with pytest.raises(PatchTransactionError) as exc_info:
        recover_patch_transactions(root)

    assert exc_info.value.code == INTEGRITY_ERROR
    assert transaction.transaction_dir.exists()
    assert (root / PATHS["task_list"]).read_bytes() == b"third-state\n"


@pytest.mark.parametrize(
    "mutation",
    ("extra_root", "extra_edge", "malformed_identity", "duplicate", "cycle", "overflow"),
)
def test_lineage_file_is_closed_bounded_and_acyclic(
    tmp_path: Path, mutation: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = _controller(tmp_path / "home", workspace)
    record = controller.store.create_project(
        "lineage", workspace, project_id="project-1"
    )
    record.current_mission_id = "mission-001"
    controller.store.save_project(record)
    path = controller.store.supersession_lineage_path("project-1", "mission-001")
    path.parent.mkdir(parents=True, exist_ok=True)
    edges = [
        {
            "new": {"mission_id": "mission-001", "node_id": f"n{index + 1}"},
            "old": {"mission_id": "mission-001", "node_id": f"n{index}"},
        }
        for index in range(257 if mutation == "overflow" else 1)
    ]
    payload: dict[str, object] = {
        "schema": "unrest.v045.supersession-lineage.v1",
        "edges": edges,
    }
    if mutation == "extra_root":
        payload["extra"] = True
    elif mutation == "extra_edge":
        edges[0]["extra"] = {}  # type: ignore[index]
    elif mutation == "malformed_identity":
        edges[0]["old"] = {"mission_id": "mission-001"}  # type: ignore[index]
    elif mutation == "duplicate":
        edges.append(edges[0])
    elif mutation == "cycle":
        edges.append(
            {
                "new": {"mission_id": "mission-001", "node_id": "n0"},
                "old": {"mission_id": "mission-001", "node_id": "n1"},
            }
        )
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid supersession lineage"):
        controller.store.load_supersession_edges("project-1", "mission-001")


def test_edge_257_is_refused_before_any_decision_mutation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    controller = _controller(tmp_path / "home", workspace)
    store = controller.store
    record = store.create_project("overflow", workspace, project_id="project-1")
    record.current_mission_id = "mission-001"
    store.save_project(record)
    contract = store.ensure_contract_dir("project-1", "mission-001") / "VAL-X.md"
    contract.write_text(
        "# VAL-X\n\nSurface: library.\nNeeds: none.\nBehavior: x.\nEvidence: x.\n",
        encoding="utf-8",
    )
    store.save_task_list("project-1", "mission-001", TaskList(tasks=[_work("w1")]))
    task_state = TaskStateFile()
    task_state.set_status("w1", "failed")
    store.save_task_state("project-1", "mission-001", task_state)
    store.save_contract_state(
        "project-1",
        "mission-001",
        ContractStateFile(items={"VAL-X": ContractStateEntry()}),
    )
    item = AttentionItemInternal(
        id="attention-1",
        report="private",
        kind="node_failed",
        mission_id="mission-001",
        node_id="w1",
    )
    store.save_attention("project-1", [item])
    store.save_state("project-1", AttentionNeeded(items=[item]))
    edges = [
        {
            "new": {"mission_id": "mission-001", "node_id": f"n{index + 1}"},
            "old": {"mission_id": "mission-001", "node_id": f"n{index}"},
        }
        for index in range(256)
    ]
    lineage = store.supersession_lineage_path("project-1", "mission-001")
    lineage.parent.mkdir(parents=True, exist_ok=True)
    lineage.write_bytes(store.render_supersession_lineage(edges))
    controller.inspect_project("project-1")  # materialize the lock before snapshot
    before = tuple(
        (path.relative_to(store.bucket_root("project-1")).as_posix(), path.read_bytes())
        for path in sorted(store.bucket_root("project-1").rglob("*"))
        if path.is_file()
    )

    with pytest.raises(ToolError) as exc_info:
        controller.decide_attention(
            "project-1",
            [
                Decision(
                    item_id="attention-1",
                    action="patch",
                    patch=TaskListPatch(
                        add=[_work("w2")], supersede={"w1": "w2"}
                    ),
                )
            ],
        )

    assert exc_info.value.code == "lineage_limit_exceeded"
    after = tuple(
        (path.relative_to(store.bucket_root("project-1")).as_posix(), path.read_bytes())
        for path in sorted(store.bucket_root("project-1").rglob("*"))
        if path.is_file()
    )
    assert after == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock transaction contract")
def test_two_mutators_and_two_inspectors_are_process_linearizable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    _private_mkdir(root)
    _private_mkdir(root / ".unrest-runtime")
    for kind in INSTALL_ORDER:
        path = root / PATHS[kind]
        _private_mkdir(path.parent)
        path.write_text(f"generation:g0:{kind}\n", encoding="utf-8")

    context = multiprocessing.get_context("spawn")
    active = context.Value("i", 0)
    overlap = context.Value("i", 0)
    events = context.Queue()
    controls = [
        (context.Event(), context.Event(), context.Event(), context.Event())
        for _ in range(2)
    ]
    mutators = [
        context.Process(
            target=_mutator_process,
            args=(
                str(root),
                action,
                *controls[index],
                active,
                overlap,
                events,
            ),
        )
        for index, action in enumerate(("A", "B"))
    ]
    mutators[0].start()
    assert controls[0][2].wait(10)
    mutators[1].start()
    assert controls[1][0].wait(10)
    assert not controls[1][1].wait(0.05)
    controls[0][3].set()
    assert controls[1][2].wait(10)

    inspector_results = context.Queue()
    inspector_starts = [context.Event(), context.Event()]
    inspectors = [
        context.Process(
            target=_inspector_process,
            args=(str(root), inspector_starts[index], inspector_results),
        )
        for index in range(2)
    ]
    for index, inspector in enumerate(inspectors):
        inspector.start()
        assert inspector_starts[index].wait(10)
    controls[1][3].set()
    for process in (*mutators, *inspectors):
        process.join(10)
        assert process.exitcode == 0

    recorded: list[tuple[object, ...]] = []
    while True:
        try:
            recorded.append(events.get_nowait())
        except queue.Empty:
            break
    acquired = [row[0] for row in recorded if row[1] == "acquire"]
    outcomes = [row for row in recorded if row[1] == "outcome"]
    observations = [inspector_results.get(timeout=2) for _ in inspectors]
    assert acquired == ["A", "B"]
    assert [(row[3], row[4]) for row in outcomes] == [
        ("g0", "g0>A"),
        ("g0>A", "g0>A>B"),
    ]
    assert overlap.value == 0
    assert len({row[2] for row in recorded}) == 2
    assert len({pid for pid, _ in observations}) == 2
    assert {generation for _, generation in observations} == {"g0>A>B"}
    assert _process_generation(root) == "g0>A>B"
    recover_patch_transactions(root)
    recover_patch_transactions(root)
    assert _process_generation(root) == "g0>A>B"
    snapshot = {
        kind: hashlib.sha256((root / PATHS[kind]).read_bytes()).hexdigest()
        for kind in INSTALL_ORDER
    }
    print(
        "WLEG_PROCESS_EVIDENCE="
        + json.dumps(
            {
                "events": recorded,
                "final_generation": "g0>A>B",
                "final_snapshot": snapshot,
                "inspectors": observations,
                "overlap": overlap.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


@pytest.mark.parametrize("timing", ["stable", "late", "supported"])
def test_rename_capability_temporal_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timing: str,
) -> None:
    import errno

    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    before = [_condition(tmp_path / target.relative_path) for target in targets]
    events: list[tuple[str, bool]] = []
    enabled = timing == "stable"
    real_replace = os.replace
    real_fsync = os.fsync
    tx_dir = tmp_path / ".unrest-runtime/missions/mission-001/patch-transactions/rename"

    def replace_call(src: object, dst: object, **kwargs: object) -> None:
        committed = (tx_dir / "COMMIT").exists()
        events.append(("replace", committed))
        if enabled:
            raise OSError(errno.ENOTSUP, "injected rename capability")
        if kwargs:
            source_fd = kwargs["src_dir_fd"]
            destination_fd = kwargs["dst_dir_fd"]
            assert isinstance(source_fd, int) and isinstance(destination_fd, int)
            assert os.fstat(source_fd).st_ino != os.fstat(destination_fd).st_ino
            assert os.fstat(source_fd).st_dev == os.fstat(destination_fd).st_dev
            assert not tx_dir.exists()
        real_replace(src, dst, **kwargs)  # type: ignore[arg-type]

    def fsync_call(fd: int) -> None:
        events.append(("directory_fsync" if stat.S_ISDIR(os.fstat(fd).st_mode)
                       else "file_fsync", (tx_dir / "COMMIT").exists()))
        real_fsync(fd)

    def boundary(label: str) -> None:
        nonlocal enabled
        events.append((label, (tx_dir / "COMMIT").exists()))
        if label == "after_commit_directory_fsync" and timing == "late":
            enabled = True

    monkeypatch.setattr(os, "replace", replace_call)
    monkeypatch.setattr(os, "fsync", fsync_call)
    transaction = PatchTransaction(
        tmp_path, "mission-001", "rename", targets, fault_injector=boundary,
    )
    assert events == []  # The stable fault is already installed during construction.
    if timing == "supported":
        transaction.execute()
        assert _generation(tmp_path, targets) == "post"
    else:
        with pytest.raises(PatchTransactionError) as caught:
            transaction.execute()
        assert caught.value.code == (UNSUPPORTED_BATCH if timing == "stable" else INTEGRITY_ERROR)
        assert [_condition(tmp_path / target.relative_path) for target in targets] == before
    replacements = [committed for label, committed in events if label == "replace"]
    assert replacements[:1] == [False]
    assert not _probe_files(tmp_path)
    if timing == "stable":
        assert replacements == [False]
        assert not transaction.transactions_root.exists()
        assert not any(label.startswith("before_post_image") for label, _ in events)
    else:
        assert replacements[:2] == [False, False]
        first_prepare = next(i for i, (label, _) in enumerate(events)
                             if label.startswith("before_post_image"))
        assert sum(label == "replace" for label, _ in events[:first_prepare]) == 2
        assert sum(label == "file_fsync" for label, _ in events[:first_prepare]) >= 4
        assert sum(label == "directory_fsync" for label, _ in events[:first_prepare]) >= 6
        if timing == "late":
            assert replacements == [False, False, True]
            assert (tx_dir / "COMMIT").exists()
            enabled = False
            # Existing journals recover even if new admission is unavailable.
            import unrest_harness.patch_transaction as module

            def forbidden_probe(root: Path) -> None:
                raise AssertionError("recovery must not probe")

            monkeypatch.setattr(module, "_probe_rename_support", forbidden_probe)
            recover_patch_transactions(tmp_path)
        assert _generation(tmp_path, targets) == "post"
    recovered = [_condition(tmp_path / target.relative_path) for target in targets]
    recover_patch_transactions(tmp_path)
    assert [_condition(tmp_path / target.relative_path) for target in targets] == recovered
    assert not tx_dir.exists()


@pytest.mark.parametrize("operation,failure_call", [
    *((operation, count) for operation in ("write", "replace", "read") for count in (1, 2)),
    *(("open", count) for count in range(1, 5)),
    *(("close", count) for count in range(1, 5)),
    *(("lseek", count) for count in (1, 2)),
    *(("fsync", count) for count in range(1, 12)),
    ("unlink", 1),
])
def test_probe_io_failures_refuse_before_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, failure_call: int,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    real = getattr(os, operation)
    calls = 0

    def fail_once(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            if operation == "close":
                real(*args, **kwargs)
            raise OSError("injected probe operation failure")
        return real(*args, **kwargs)

    transaction = PatchTransaction(tmp_path, "mission-001", "probe-failure", targets)
    monkeypatch.setattr(os, operation, fail_once)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert calls >= failure_call
    assert _generation(tmp_path, targets) == "pre"
    assert not transaction.transactions_root.exists()
    residue = _probe_files(tmp_path)
    if operation == "unlink":
        # Cleanup itself was denied: residue is truthful and never a journal.
        recover_patch_transactions(tmp_path)
        assert residue == _probe_files(tmp_path)
    else:
        assert not residue


@pytest.mark.parametrize("fault", ["short_write", "wrong_bytes", "noop_rename", "copy_rename"])
def test_probe_verifies_real_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    if fault == "short_write":
        monkeypatch.setattr(os, "write", lambda *args: 0)
    elif fault == "wrong_bytes":
        monkeypatch.setattr(os, "read", lambda *args: b"wrong")
    elif fault == "noop_rename":
        monkeypatch.setattr(os, "replace", lambda *args, **kwargs: None)
    else:
        def copy_rename(src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
            os.link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

        monkeypatch.setattr(os, "replace", copy_rename)
    transaction = PatchTransaction(tmp_path, "mission-001", "probe-verification", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert _generation(tmp_path, targets) == "pre"
    assert not transaction.transactions_root.exists()
    assert not _probe_files(tmp_path)


@pytest.mark.parametrize("competitor", ["file", "symlink", "directory"])
def test_probe_never_adopts_competing_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, competitor: str,
) -> None:
    import unrest_harness.patch_transaction as module

    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    monkeypatch.setattr(module.secrets, "token_hex", lambda count: "collision")
    path = tmp_path / ".unrest-rename-probe-collision-source"
    victim = tmp_path / "unrelated"
    victim.write_bytes(b"unrelated-canary")
    if competitor == "file":
        path.write_bytes(b"competing-canary")
    elif competitor == "symlink":
        path.symlink_to(victim)
    else:
        path.mkdir()
    original = path.lstat()
    transaction = PatchTransaction(tmp_path, "mission-001", "collision", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert path.lstat() == original
    assert victim.read_bytes() == b"unrelated-canary"
    assert not transaction.transactions_root.exists()
    assert _generation(tmp_path, targets) == "pre"


def test_probe_preserves_replaced_destination_and_private_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    real_replace = os.replace
    calls = 0
    victim = tmp_path / "unrelated"
    victim.write_bytes(b"private-body-canary")

    def competing_replace(src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
        nonlocal calls
        calls += 1
        assert stat.S_IMODE(os.stat(src, dir_fd=src_dir_fd).st_mode) == 0o600
        real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        os.unlink(dst, dir_fd=dst_dir_fd)
        os.symlink(victim, dst, dir_fd=dst_dir_fd)

    monkeypatch.setattr(os, "replace", competing_replace)
    transaction = PatchTransaction(tmp_path, "mission-001", "competitor", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert calls == 1
    assert victim.read_bytes() == b"private-body-canary"
    destination, = _probe_files(tmp_path)
    assert destination.is_symlink()
    assert not transaction.transactions_root.exists()
    assert _generation(tmp_path, targets) == "pre"
    recover_patch_transactions(tmp_path)
    assert destination.is_symlink()


def _interrupt_rename_probe(root: str) -> None:
    real_replace = os.replace

    def interrupt(*args: object, **kwargs: object) -> None:
        real_replace(*args, **kwargs)  # type: ignore[arg-type]
        os._exit(73)

    os.replace = interrupt  # type: ignore[assignment]
    PatchTransaction(Path(root), "mission-001", "interrupted-probe", _targets(Path(root))).execute()


def test_interrupted_probe_coexists_with_committed_recovery(tmp_path: Path) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    prior = PatchTransaction(tmp_path, "mission-001", "older-committed", targets)
    prior.prepare()
    prior.commit()
    process = multiprocessing.get_context("spawn").Process(
        target=_interrupt_rename_probe, args=(str(tmp_path),),
    )
    process.start()
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join()
    assert process.exitcode == 73
    residue, = _probe_files(tmp_path)
    inventory = (residue.lstat(), _condition(residue))
    assert _generation(tmp_path, targets) == "pre"
    assert (prior.transaction_dir / "COMMIT").exists()
    recover_patch_transactions(tmp_path)
    assert _generation(tmp_path, targets) == "post"
    recover_patch_transactions(tmp_path)
    assert inventory == (residue.lstat(), _condition(residue))
    assert not prior.transaction_dir.exists()


def test_probe_directory_replacement_is_not_cleaned_or_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    victim = tmp_path / "unrelated"
    victim.mkdir()
    (victim / "canary").write_bytes(b"not-probe-data")
    real_open = os.open
    swapped = False

    def swap_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if path == ".unrest-runtime" and not swapped:
            swapped = True
            (tmp_path / ".unrest-runtime").rename(tmp_path / "displaced-runtime")
            (tmp_path / ".unrest-runtime").symlink_to(victim, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", swap_open)
    transaction = PatchTransaction(tmp_path, "mission-001", "directory-swap", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert swapped
    assert (victim / "canary").read_bytes() == b"not-probe-data"
    assert (tmp_path / ".unrest-runtime").is_symlink()
    assert (tmp_path / "displaced-runtime").is_dir()
    assert not transaction.transactions_root.exists()
    (tmp_path / ".unrest-runtime").unlink()
    (tmp_path / "displaced-runtime").rename(tmp_path / ".unrest-runtime")
    assert _generation(tmp_path, targets) == "pre"


def test_probe_refuses_competing_overwrite_before_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    real_fsync = os.fsync
    real_replace = os.replace
    replacements = 0
    swapped = False

    def observe_replace(*args: object, **kwargs: object) -> None:
        nonlocal replacements
        replacements += 1
        real_replace(*args, **kwargs)  # type: ignore[arg-type]

    def substitute(fd: int) -> None:
        nonlocal swapped
        real_fsync(fd)
        if replacements == 1 and not swapped:
            swapped = True
            target, = _probe_files(tmp_path)
            target.unlink()
            target.write_bytes(b"competing-canary")

    monkeypatch.setattr(os, "fsync", substitute)
    monkeypatch.setattr(os, "replace", observe_replace)
    transaction = PatchTransaction(tmp_path, "mission-001", "overwrite-competitor", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert replacements == 1
    target, = _probe_files(tmp_path)
    assert target.read_bytes() == b"competing-canary"
    assert not transaction.transactions_root.exists()
    assert _generation(tmp_path, targets) == "pre"


def _probe_files(root: Path) -> list[Path]:
    return sorted([*root.glob(".unrest-rename-probe-*"),
                   *(root / ".unrest-runtime").glob(".unrest-rename-probe-*")])


@pytest.mark.parametrize("runtime_exists", [False, True])
def test_probe_borrows_only_existing_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_exists: bool,
) -> None:
    import unrest_harness.patch_transaction as module

    if runtime_exists:
        (tmp_path / ".unrest-runtime").mkdir(mode=0o755)
    parents = [tmp_path, *([tmp_path / ".unrest-runtime"] if runtime_exists else [])]
    identities = [(p.stat().st_dev, p.stat().st_ino, p.stat().st_mode) for p in parents]
    real_open, real_replace, real_unlink = os.open, os.replace, os.unlink
    replacements: list[bool] = []
    creations: list[int] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("probe must not mutate or enumerate directories")

    def opened(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and flags & os.O_NOFOLLOW
            assert isinstance(path, str) and path.startswith(".unrest-rename-probe-")
            assert "/" not in path
            assert kwargs["dir_fd"] in creations
        else:
            assert path in {str(tmp_path), ".unrest-runtime"}
            assert flags & os.O_DIRECTORY and flags & os.O_NOFOLLOW
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        creations.append(fd)
        return fd

    def replaced(src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
        source = os.stat(src, dir_fd=src_dir_fd, follow_symlinks=False)
        assert stat.S_ISREG(source.st_mode) and stat.S_IMODE(source.st_mode) == 0o600
        assert (os.fstat(src_dir_fd).st_ino != os.fstat(dst_dir_fd).st_ino) == runtime_exists
        assert os.fstat(src_dir_fd).st_dev == os.fstat(dst_dir_fd).st_dev
        try:
            os.stat(dst, dir_fd=dst_dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            overwrite = False
        else:
            overwrite = True
        replacements.append(overwrite)
        real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        with pytest.raises(FileNotFoundError):
            os.stat(src, dir_fd=src_dir_fd)
        assert os.stat(dst, dir_fd=dst_dir_fd).st_ino == source.st_ino

    def unlinked(path: str, *, dir_fd: int) -> None:
        assert path.startswith(".unrest-rename-probe-") and "/" not in path
        assert dir_fd in creations
        real_unlink(path, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        for operation in ("mkdir", "rmdir", "chmod", "fchmod", "listdir", "scandir"):
            patch.setattr(os, operation, forbidden)
        patch.setattr(os, "open", opened)
        patch.setattr(os, "replace", replaced)
        patch.setattr(os, "unlink", unlinked)
        module._probe_rename_support(tmp_path)
    assert replacements == [False, True]
    assert identities == [(p.stat().st_dev, p.stat().st_ino, p.stat().st_mode) for p in parents]
    assert not _probe_files(tmp_path)
    assert (tmp_path / ".unrest-runtime").exists() == runtime_exists
    for fd in creations:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("timing", ["supported", "stable", "late"])
def test_empty_project_admission_and_real_install_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timing: str,
) -> None:
    import errno

    targets = [TransactionTarget.from_images(kind, PATHS[kind], None, f"post:{kind}\n".encode())
               for kind in INSTALL_ORDER]
    real_replace = os.replace
    enabled = timing == "stable"
    moves: list[tuple[bool, bool]] = []
    events: list[str] = []

    def replaced(src: object, dst: object, **kwargs: object) -> None:
        probe = bool(kwargs)
        if probe:
            assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
            assert not (tmp_path / ".unrest-runtime").exists()
        else:
            assert Path(str(src)).parent != Path(str(dst)).parent
        moves.append((probe, enabled))
        if enabled:
            raise OSError(errno.ENOTSUP, "injected stable or late capability failure")
        real_replace(src, dst, **kwargs)  # type: ignore[arg-type]

    def boundary(label: str) -> None:
        nonlocal enabled
        events.append(label)
        if label == "after_commit_directory_fsync" and timing == "late":
            enabled = True

    monkeypatch.setattr(os, "replace", replaced)
    transaction = PatchTransaction(tmp_path, "mission-001", "empty", targets, fault_injector=boundary)
    assert moves == []
    if timing == "supported":
        transaction.execute()
    else:
        with pytest.raises(PatchTransactionError) as caught:
            transaction.execute()
        assert caught.value.code == (UNSUPPORTED_BATCH if timing == "stable" else INTEGRITY_ERROR)
        assert _generation(tmp_path, targets) == "pre"
    if timing == "stable":
        assert moves == [(True, True)] and events == []
        assert list(tmp_path.iterdir()) == []
    else:
        assert moves[:2] == [(True, False), (True, False)]
        assert any(not probe for probe, _ in moves)
        if timing == "late":
            assert (transaction.transaction_dir / "COMMIT").exists()
        enabled = False
        recover_patch_transactions(tmp_path)
        assert _generation(tmp_path, targets) == "post"
        snapshot = [_condition(tmp_path / t.relative_path) for t in targets]
        recover_patch_transactions(tmp_path)
        assert snapshot == [_condition(tmp_path / t.relative_path) for t in targets]
        assert not transaction.transaction_dir.exists()
    assert not _probe_files(tmp_path)


@pytest.mark.parametrize("competitor", ["file", "symlink", "mode"])
@pytest.mark.parametrize("observation", ["creation", "write", "rename", "read", "cleanup"])
def test_probe_observed_file_substitution_preserves_competitors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, competitor: str, observation: str,
) -> None:
    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    victim = tmp_path / "unrelated"
    victim.write_bytes(b"unrelated-canary")
    displaced = tmp_path / "displaced-owned"
    real_open, real_write, real_replace = os.open, os.write, os.replace
    real_read, real_fstat = os.read, os.fstat
    created: list[int] = []
    changed: Path | None = None
    original_inode: int | None = None
    reads = 0

    def substitute(path: Path) -> None:
        nonlocal changed, original_inode
        if changed is not None:
            return
        changed = path
        original_inode = path.lstat().st_ino
        if competitor == "mode":
            path.chmod(0o644)
        else:
            path.rename(displaced)
            if competitor == "symlink":
                path.symlink_to(victim)
            else:
                path.write_bytes(b"competing-canary")
                path.chmod(0o600)

    def opened(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if flags & os.O_CREAT:
            created.append(fd)
            if observation == "creation":
                substitute(tmp_path / str(path))
                # This is still the exclusively created inode, before product fstat.
                assert real_fstat(fd).st_ino == original_inode
                if competitor != "mode":
                    assert (tmp_path / str(path)).lstat().st_ino != real_fstat(fd).st_ino
        return fd

    def written(fd: int, body: object) -> int:
        result = real_write(fd, body)  # type: ignore[arg-type]
        if observation == "write":
            path, = _probe_files(tmp_path)
            substitute(path)
        return result

    def replaced(src: str, dst: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
        real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        if observation == "rename":
            substitute(tmp_path / ".unrest-runtime" / dst)

    def read(fd: int, size: int) -> bytes:
        nonlocal reads
        result = real_read(fd, size)
        reads += 1
        if observation == "read":
            path, = _probe_files(tmp_path)
            substitute(path)
        return result

    def fstat(fd: int) -> os.stat_result:
        if observation == "cleanup" and reads == 2 and fd in created:
            path, = _probe_files(tmp_path)
            substitute(path)
        return real_fstat(fd)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "write", written)
    monkeypatch.setattr(os, "replace", replaced)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "fstat", fstat)
    transaction = PatchTransaction(tmp_path, "mission-001", "custody", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert changed is not None and changed.lstat()
    assert victim.read_bytes() == b"unrelated-canary"
    if competitor == "file":
        assert changed.read_bytes() == b"competing-canary"
    elif competitor == "symlink":
        assert changed.is_symlink()
    else:
        assert stat.S_IMODE(changed.stat().st_mode) == 0o644
    if competitor != "mode":
        assert displaced.stat().st_ino == original_inode
        if observation == "creation":
            assert displaced.read_bytes() == b""  # No write through a lost name.
    assert _generation(tmp_path, targets) == "pre"
    assert not transaction.transactions_root.exists()
    monkeypatch.undo()
    snapshot = [(str(p), p.lstat(), _condition(p)) for p in _probe_files(tmp_path)]
    recover_patch_transactions(tmp_path)
    assert snapshot == [(str(p), p.lstat(), _condition(p)) for p in _probe_files(tmp_path)]
    for fd in created:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("parent", ["root", "runtime"])
def test_probe_borrowed_directory_substitution_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent: str,
) -> None:
    import unrest_harness.patch_transaction as module

    root = tmp_path / "project"
    root.mkdir()
    (root / ".unrest-runtime").mkdir()
    real_open = os.open
    displaced = tmp_path / "displaced"
    target = root if parent == "root" else root / ".unrest-runtime"
    swapped = False

    def opened(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if path == (str(root) if parent == "root" else ".unrest-runtime") and not swapped:
            swapped = True
            target.rename(displaced)
            target.mkdir(mode=0o700)
            (target / "canary").write_bytes(b"competitor")
        return fd

    monkeypatch.setattr(os, "open", opened)
    with pytest.raises(OSError):
        module._probe_rename_support(root)
    assert swapped
    assert (target / "canary").read_bytes() == b"competitor"
    assert displaced.is_dir()
    assert not _probe_files(root) and not _probe_files(displaced)


def test_probe_uncertain_close_is_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import unrest_harness.patch_transaction as module

    real_close = os.close
    closed: list[int] = []
    replacement: int | None = None

    def close(fd: int) -> None:
        nonlocal replacement
        assert fd not in closed
        closed.append(fd)
        real_close(fd)
        if replacement is None:
            replacement = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
            assert replacement == fd
            raise OSError("close released FD but reported failure")

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(OSError):
        module._probe_rename_support(tmp_path)
    assert replacement is not None
    assert stat.S_ISDIR(os.fstat(replacement).st_mode)
    real_close(replacement)
    assert len(closed) == 3  # Two created files and one borrowed root, each once.
    assert not _probe_files(tmp_path)


@pytest.mark.parametrize("operation", ["stat", "fstat"])
def test_probe_each_metadata_observation_failure_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    import unrest_harness.patch_transaction as module

    real = getattr(os, operation)
    real_probe = module._probe_rename_support
    calls = 0
    failure: int | None = None
    active = False

    def observed(*args: object, **kwargs: object) -> object:
        nonlocal calls
        if active:
            calls += 1
            if calls == failure:
                raise OSError("injected named metadata observation failure")
        return real(*args, **kwargs)

    def probe(root: Path) -> None:
        nonlocal active
        active = True
        try:
            real_probe(root)
        finally:
            active = False

    monkeypatch.setattr(os, operation, observed)
    monkeypatch.setattr(module, "_probe_rename_support", probe)
    control = tmp_path / "control"
    control.mkdir()
    (control / ".unrest-runtime").mkdir()
    probe(control)
    count = calls
    assert count > 0
    for point in range(1, count + 1):
        root = tmp_path / str(point)
        root.mkdir()
        targets = _targets(root)
        _seed(root, targets)
        transaction = PatchTransaction(root, "mission-001", "metadata", targets)
        calls, failure = 0, point
        with pytest.raises(PatchTransactionError) as caught:
            transaction.execute()
        assert calls >= point
        assert caught.value.code == UNSUPPORTED_BATCH
        assert _generation(root, targets) == "pre"
        assert not transaction.transactions_root.exists()
        residue = [(p, p.lstat(), _condition(p)) for p in _probe_files(root)]
        # An observation denied during cleanup cannot authorize deletion.
        recover_patch_transactions(root)
        assert residue == [(p, p.lstat(), _condition(p)) for p in _probe_files(root)]


def test_probe_partial_writes_are_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import unrest_harness.patch_transaction as module

    real_write = os.write
    writes = 0

    def partial(fd: int, body: bytes) -> int:
        nonlocal writes
        writes += 1
        return real_write(fd, body[:1])

    monkeypatch.setattr(os, "write", partial)
    module._probe_rename_support(tmp_path)
    assert writes == len(b"rename-probe-first\nrename-probe-second\n")
    assert not _probe_files(tmp_path)


@pytest.mark.parametrize("name", ["source", "destination"])
@pytest.mark.parametrize("competitor", ["file", "symlink", "directory"])
def test_probe_known_name_collision_preserves_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, competitor: str,
) -> None:
    import unrest_harness.patch_transaction as module

    targets = _targets(tmp_path)
    _seed(tmp_path, targets)
    monkeypatch.setattr(module.secrets, "token_hex", lambda count: "known")
    parent = tmp_path if name == "source" else tmp_path / ".unrest-runtime"
    path = parent / (".unrest-rename-probe-known-" + name)
    victim = tmp_path / "canary"
    victim.write_bytes(b"unrelated")
    if competitor == "file":
        path.write_bytes(b"competing")
    elif competitor == "symlink":
        path.symlink_to(victim)
    else:
        path.mkdir()
        (path / "unknown").write_bytes(b"competing")
    before = [(str(p.relative_to(tmp_path)), p.lstat().st_ino, p.lstat().st_mode,
               _condition(p) if p.is_file() else None) for p in sorted(tmp_path.rglob("*"))]
    transaction = PatchTransaction(tmp_path, "mission-001", "collision-known", targets)
    with pytest.raises(PatchTransactionError) as caught:
        transaction.execute()
    assert caught.value.code == UNSUPPORTED_BATCH
    assert before == [(str(p.relative_to(tmp_path)), p.lstat().st_ino, p.lstat().st_mode,
                       _condition(p) if p.is_file() else None) for p in sorted(tmp_path.rglob("*"))]
    assert _generation(tmp_path, targets) == "pre"
    assert not transaction.transactions_root.exists()
