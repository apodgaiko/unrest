"""Executable durability matrix for the W-LEG whole-generation transaction."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import queue
import stat
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
        "duplicate_path",
        "missing_target_class",
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
    elif mutation == "duplicate_path":
        targets[-1] = TransactionTarget.from_images(
            targets[-1].kind, targets[0].relative_path, b"pre\n", b"post\n"
        )
    elif mutation == "missing_target_class":
        targets.pop()
    with pytest.raises(PatchTransactionError) as exc_info:
        PatchTransaction(root, "mission-001", "decision-001", targets)
    assert exc_info.value.code == INTEGRITY_ERROR
    assert not (root / ".unrest-runtime/missions/mission-001/patch-transactions").exists()
    assert {
        relative_path: (root / relative_path).read_bytes()
        for relative_path in live_before
    } == live_before


@pytest.mark.parametrize(
    "mutation",
    ("bad_mission", "bad_transaction", "post_digest_mismatch"),
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
