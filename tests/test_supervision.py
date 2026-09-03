"""Executable proof for the W-owned sparse-supervision core."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    ActiveAttemptSnapshot,
    ContractStateEntry,
    ContractStateFile,
    Decision,
    MissionRunning,
    Task,
    TaskList,
    TaskListPatch,
    TaskStateFile,
    SteeringBinding,
    SteeringRequest,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore
from unrest_harness.supervision import (
    CheckpointEvaluation,
    CHECKPOINT_WAIT_SECONDS,
    SupervisionSnapshotError,
    SupervisionSteeringError,
    automatic_restart_count,
    binding_from_snapshot,
    evaluate_checkpoint_policy,
    initial_checkpoint_policy,
    load_policy_state,
    load_snapshot,
    load_supervision_receipts,
    inbox_path,
    recover_supervision,
    receipts_path,
    record_checkpoint_request,
    save_policy_state,
    save_snapshot,
    snapshot_path,
    steer_attempt as apply_steering,
    require_attempt_start_authority,
    wait_for_steering_action,
    terminal_snapshot,
)

NS = 1_000_000_000
TARGETS = ["FUT-V045-LEG-013", "FUT-V045-LEG-014"]
STEERING_TARGETS = ["FUT-V045-LEG-015", "FUT-V045-LEG-016"]
FIXTURE = Path(__file__).parent / "fixtures/legibility_v045/sparse-supervision.v1.json"
INT_REQUIREMENTS = (
    Path(__file__).parent
    / "fixtures/legibility_v045/int-v045-supervision-requirements.v1.json"
)


def _config(home: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=Path(__file__).parents[1] / "src/unrest_harness/bundled",
        harness_home=home,
        projects_dir=home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
    )


def _store(tmp_path: Path) -> ProjectStore:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    store = ProjectStore(_config(home))
    record = store.create_project("brief", workspace, project_id="project-1")
    record.current_mission_id = "mission-001"
    store.save_project(record)
    store.save_state("project-1", MissionRunning(mission_id="mission-001"))
    return store


def _snapshot(**updates: object) -> ActiveAttemptSnapshot:
    payload: dict[str, object] = {
        "attempt_id": "attempt-1",
        "blocker_code": None,
        "checkpoint_requests": 0,
        "checkpoint_sequence": 0,
        "completed_target_ids": [],
        "elapsed_nanoseconds": 0,
        "last_effect_sequence": 0,
        "mission_id": "mission-001",
        "node_id": "work-1",
        "phase": "active",
        "project_id": "project-1",
        "remaining_target_ids": TARGETS,
        "role": "worker",
        "scope_status": "in_scope",
        "supervision_status": "running",
        "terminal_review_id": None,
    }
    payload.update(updates)
    return ActiveAttemptSnapshot.model_validate(payload)


def _controller(store: ProjectStore) -> ProjectController:
    dispatcher = MockDispatcher(
        lambda request: WorkHandoff(
            node_id=request.task.id, done=True, report="unused"
        )
    )
    return ProjectController(
        store.config,
        dispatcher,
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        store=store,
    )


def _prepare_role_checkpoint(
    tmp_path: Path,
    role: Literal["worker", "validator", "terminal_reviewer"],
) -> tuple[ProjectStore, ProjectController, ActiveAttemptSnapshot, SteeringBinding]:
    store = _store(tmp_path)
    tasks = TaskList(
        tasks=[
            Task(
                id="work-1",
                type="work",
                body="private worker assignment",
                targets=STEERING_TARGETS,
                skill="worker",
            ),
            Task(
                id="validate-1",
                type="validate",
                body="private validator assignment",
                targets=STEERING_TARGETS,
                skill="validator",
            ),
        ]
    )
    store.save_task_list("project-1", "mission-001", tasks)
    task_state = TaskStateFile()
    node_id: str | None = "work-1"
    review_id: str | None = None
    attempt_id = "attempt-worker"
    if role == "validator":
        node_id = "validate-1"
        attempt_id = "attempt-validator"
    elif role == "terminal_reviewer":
        node_id = None
        review_id = "review-spawn-1"
        attempt_id = "attempt-reviewer"
    if node_id is not None:
        task_state.set_status(node_id, "running")
        task_state.set_last_attempt(node_id, attempt_id)
    store.save_task_state("project-1", "mission-001", task_state)
    store.save_contract_state(
        "project-1",
        "mission-001",
        ContractStateFile(
            items={target: ContractStateEntry() for target in STEERING_TARGETS}
        ),
    )
    controller = _controller(store)
    snapshot = _snapshot(
        attempt_id=attempt_id,
        node_id=node_id,
        terminal_review_id=review_id,
        role=role,
        checkpoint_sequence=1,
        elapsed_nanoseconds=900 * NS,
        phase="waiting_at_checkpoint",
        supervision_status="waiting",
        remaining_target_ids=STEERING_TARGETS,
    )
    binding = controller.report_supervision_checkpoint(snapshot)
    return store, controller, snapshot, binding


def _process_wait_for_steering(
    home: str,
    binding_payload: dict[str, object],
    ready: Any,
    result: Any,
) -> None:
    store = ProjectStore(_config(Path(home)))
    binding = SteeringBinding.model_validate(binding_payload)
    ready.put(os.getpid())
    outcome = wait_for_steering_action(store, binding, timeout_seconds=5)
    result.put((outcome.action, outcome.body, outcome.code))


def test_fixture_and_snapshot_schema_are_exact_closed_and_body_free() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    snapshot = _snapshot()
    assert list(snapshot.model_dump(mode="json")) == fixture["public_snapshot_fields"]
    assert len(snapshot.model_dump()) == 16
    with pytest.raises(ValidationError):
        ActiveAttemptSnapshot.model_validate(
            {**snapshot.model_dump(), "report": "PRIVATE REPORT"}
        )
    for field, value in (
        ("attempt_id", "prompt body"),
        ("project_id", "/private/path"),
        ("node_id", "credential=secret"),
    ):
        with pytest.raises(ValidationError):
            _snapshot(**{field: value})
    with pytest.raises(ValidationError):
        _snapshot(node_id=None, terminal_review_id=None)
    with pytest.raises(ValidationError):
        _snapshot(node_id="work-1", terminal_review_id="review-1")
    with pytest.raises(ValidationError):
        _snapshot(elapsed_nanoseconds=True)


def test_int_supervision_requirements_are_exact_path_specific_and_digest_backed() -> None:
    fixture_bytes = INT_REQUIREMENTS.read_bytes()
    payload = json.loads(fixture_bytes)
    rows = payload["requirements"]
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "1b7d60b287565f634fd100c128bfee8f45262a9cada2b771d8130620e022f37b"
    )
    assert payload["schema"] == "unrest.v045.w-leg-int-supervision-requirements.v1"
    assert len({row["path"] for row in rows}) == len(rows)
    assert all(row["operation"] == "modify" for row in rows)
    assert all(
        row["contract_ids"] == ["FUT-V045-LEG-015", "FUT-V045-LEG-016"]
        and row["requirement"]
        for row in rows
    )
    assert {row["path"] for row in rows} == {
        "docs/v03/v0.3.1/public-surface.v1.json",
        "src/unrest_harness/acp_runner.py",
        "src/unrest_harness/api.py",
        "src/unrest_harness/bundled/foundation/public-surface.v1.json",
        "src/unrest_harness/coordinator.py",
        "src/unrest_harness/public_schema.py",
        "src/unrest_harness/run_control.py",
        "src/unrest_harness/run_worker.py",
        "src/unrest_harness/server.py",
        "tests/test_distribution_check.py",
        "tests/test_run_control.py",
        "tests/test_server.py",
    }


def test_store_is_atomic_monotonic_and_retains_private_terminal_snapshot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = _snapshot()
    save_snapshot(store, first, assigned_target_ids=TARGETS)
    path = snapshot_path(store, "project-1", "mission-001", "attempt-1")
    assert set(json.loads(path.read_text())) == set(first.model_dump())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    progressed = _snapshot(
        checkpoint_sequence=1,
        elapsed_nanoseconds=30 * NS,
        last_effect_sequence=1,
        completed_target_ids=[TARGETS[0]],
        remaining_target_ids=[TARGETS[1]],
    )
    save_snapshot(store, progressed, assigned_target_ids=TARGETS)
    with pytest.raises(SupervisionSnapshotError, match="stale"):
        save_snapshot(store, first, assigned_target_ids=TARGETS)
    with pytest.raises(SupervisionSnapshotError, match="conflicts"):
        save_snapshot(
            store,
            progressed.model_copy(update={"scope_status": "uncertain"}),
            assigned_target_ids=TARGETS,
        )
    with pytest.raises(SupervisionSnapshotError, match="equal assigned"):
        save_snapshot(store, progressed, assigned_target_ids=[TARGETS[0]])

    terminal = terminal_snapshot(progressed)
    save_snapshot(store, terminal, assigned_target_ids=TARGETS)
    assert load_snapshot(store, "project-1", "mission-001", "attempt-1") == terminal


def test_legacy_absence_is_read_only_and_projection_orders_authored_attempts(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = store.bucket_root("project-1")
    before = sorted(path.relative_to(root) for path in root.rglob("*"))
    assert load_snapshot(store, "project-1", "mission-001", "missing") is None
    assert sorted(path.relative_to(root) for path in root.rglob("*")) == before

    tasks = TaskList(
        tasks=[
            Task(
                id="work-z",
                type="work",
                body="PRIVATE SOURCE BODY",
                targets=[TARGETS[0]],
                skill="worker",
            ),
            Task(
                id="validate-a",
                type="validate",
                body="PRIVATE VALIDATOR BODY",
                targets=TARGETS,
                skill="validator",
            ),
        ]
    )
    store.save_task_list("project-1", "mission-001", tasks)
    store.save_task_state("project-1", "mission-001", TaskStateFile())
    save_snapshot(
        store,
        _snapshot(
            attempt_id="validator-1",
            node_id="validate-a",
            role="validator",
        ),
        assigned_target_ids=TARGETS,
    )
    save_snapshot(
        store,
        _snapshot(
            attempt_id="worker-z",
            node_id="work-z",
            remaining_target_ids=[TARGETS[0]],
        ),
        assigned_target_ids=[TARGETS[0]],
    )
    save_snapshot(
        store,
        _snapshot(
            attempt_id="review-1",
            node_id=None,
            terminal_review_id="review-spawn-1",
            role="terminal_reviewer",
        ),
        assigned_target_ids=TARGETS,
    )

    envelope = _controller(store).inspect_project("project-1")
    assert [item.attempt_id for item in envelope.active_attempts] == [
        "worker-z",
        "validator-1",
        "review-1",
    ]
    encoded = envelope.model_dump_json()
    assert "PRIVATE SOURCE BODY" not in encoded
    assert "PRIVATE VALIDATOR BODY" not in encoded
    assert str(tmp_path) not in json.dumps(
        [item.model_dump(mode="json") for item in envelope.active_attempts]
    )

    save_snapshot(
        store,
        terminal_snapshot(
            _snapshot(
                attempt_id="worker-z",
                node_id="work-z",
                remaining_target_ids=[TARGETS[0]],
            )
        ),
        assigned_target_ids=[TARGETS[0]],
    )
    assert [
        item.attempt_id
        for item in _controller(store).inspect_project("project-1").active_attempts
    ] == ["validator-1", "review-1"]


def test_concurrent_writers_and_inspection_never_publish_a_partial_snapshot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    task = Task(
        id="work-1", type="work", body="body", targets=TARGETS, skill="worker"
    )
    store.save_task_list("project-1", "mission-001", TaskList(tasks=[task]))
    store.save_task_state("project-1", "mission-001", TaskStateFile())
    save_snapshot(store, _snapshot(), assigned_target_ids=TARGETS)

    candidates = [
        _snapshot(checkpoint_sequence=index, elapsed_nanoseconds=index * 30 * NS)
        for index in range(1, 17)
    ]

    def write(candidate: ActiveAttemptSnapshot) -> None:
        try:
            save_snapshot(store, candidate, assigned_target_ids=TARGETS)
        except SupervisionSnapshotError:
            pass

    with ThreadPoolExecutor(max_workers=5) as pool:
        writes = [pool.submit(write, candidate) for candidate in reversed(candidates)]
        reads = [
            pool.submit(_controller(store).inspect_project, "project-1")
            for _ in range(20)
        ]
        for future in writes:
            future.result()
        for future in reads:
            envelope = future.result()
            assert len(envelope.active_attempts) == 1
            assert len(envelope.active_attempts[0].model_dump()) == 16
    assert load_snapshot(
        store, "project-1", "mission-001", "attempt-1"
    ).checkpoint_sequence == 16  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("now", "due", "reason"),
    (
        (900 * NS - 1, False, "not_poll_tick"),
        (900 * NS, True, "normal_threshold"),
        (900 * NS + 1, False, "not_poll_tick"),
    ),
)
def test_first_checkpoint_floor_minus_exact_plus(
    now: int, due: bool, reason: str
) -> None:
    result = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=now),
        initial_checkpoint_policy(0),
        now_nanoseconds=now,
    )
    assert (result.checkpoint_due, result.reason, result.action) == (
        due,
        reason,
        "continue",
    )


@pytest.mark.parametrize("signal", ("blocker", "uncertain", "violation"))
def test_closed_early_signal_precedes_floor(signal: str) -> None:
    updates: dict[str, object] = {"elapsed_nanoseconds": 30 * NS}
    if signal == "blocker":
        updates["blocker_code"] = "authority_required"
    else:
        updates["scope_status"] = signal
    result = evaluate_checkpoint_policy(
        _snapshot(**updates), initial_checkpoint_policy(0), now_nanoseconds=30 * NS
    )
    assert result.checkpoint_due
    assert result.reason == "early_signal"
    assert result.action == "continue"


def test_request_at_900_effect_at_930_next_due_exactly_at_2130() -> None:
    initial = initial_checkpoint_policy(0)
    first_due = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=900 * NS),
        initial,
        now_nanoseconds=900 * NS,
    )
    after_request = record_checkpoint_request(first_due, now_nanoseconds=900 * NS)
    assert after_request.backoff_index == 0

    effect = _snapshot(elapsed_nanoseconds=930 * NS, last_effect_sequence=1)
    observed = evaluate_checkpoint_policy(
        effect, after_request, now_nanoseconds=930 * NS
    )
    assert observed.state.backoff_index == 1
    assert not observed.checkpoint_due
    equal_effect = evaluate_checkpoint_policy(
        effect, observed.state, now_nanoseconds=1530 * NS
    )
    assert equal_effect.state.backoff_index == 1
    assert not equal_effect.checkpoint_due
    assert equal_effect.reason == "silence_below_threshold"
    assert not evaluate_checkpoint_policy(
        effect, observed.state, now_nanoseconds=2130 * NS - 1
    ).checkpoint_due
    second_due = evaluate_checkpoint_policy(
        effect, observed.state, now_nanoseconds=2130 * NS
    )
    assert second_due.checkpoint_due
    assert second_due.reason == "normal_threshold"

    capped = record_checkpoint_request(second_due, now_nanoseconds=2130 * NS)
    cap_result = evaluate_checkpoint_policy(
        _snapshot(
            elapsed_nanoseconds=2160 * NS,
            last_effect_sequence=2,
            blocker_code="authority_required",
        ),
        capped,
        now_nanoseconds=2160 * NS,
    )
    assert cap_result.state.backoff_index == 2
    assert not cap_result.checkpoint_due
    assert cap_result.reason == "request_cap"


def test_off_tick_fresh_effect_preserves_policy_state_bytes() -> None:
    state = initial_checkpoint_policy(0)
    before = state.model_dump_json()
    result = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=31 * NS, last_effect_sequence=1),
        state,
        now_nanoseconds=31 * NS,
    )
    assert (result.checkpoint_due, result.reason, result.action) == (
        False,
        "not_poll_tick",
        "continue",
    )
    assert result.state.model_dump_json() == before
    assert state.model_dump_json() == before


def test_higher_effect_sequence_with_regressive_time_preserves_policy_bytes(
    tmp_path: Path,
) -> None:
    first = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=900 * NS),
        initial_checkpoint_policy(0),
        now_nanoseconds=900 * NS,
    )
    requested = record_checkpoint_request(first, now_nanoseconds=900 * NS)
    observed = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=930 * NS, last_effect_sequence=1),
        requested,
        now_nanoseconds=930 * NS,
    )
    store = _store(tmp_path)
    save_policy_state(
        store, "project-1", "mission-001", "attempt-1", observed.state
    )
    path = store.mission_runtime_dir(
        "project-1", "mission-001"
    ) / "supervision/attempt-1.policy.json"
    before = observed.state.model_dump_json()
    before_file = path.read_bytes()

    regressive = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=900 * NS, last_effect_sequence=2),
        observed.state,
        now_nanoseconds=960 * NS,
    )

    assert (regressive.checkpoint_due, regressive.reason, regressive.action) == (
        False,
        "regressive_effect_time",
        "continue",
    )
    assert regressive.state.model_dump_json() == before
    assert observed.state.model_dump_json() == before
    assert path.read_bytes() == before_file
    restarted = ProjectStore(_config(store.config.harness_home))
    assert load_policy_state(
        restarted, "project-1", "mission-001", "attempt-1"
    ) == observed.state

    later = evaluate_checkpoint_policy(
        _snapshot(elapsed_nanoseconds=990 * NS, last_effect_sequence=2),
        regressive.state,
        now_nanoseconds=990 * NS,
    )
    assert later.state.last_effect_sequence == 2
    assert later.state.last_effect_nanoseconds == 990 * NS
    assert later.state.backoff_index == 2


def test_silence_boundary_and_time_only_evaluation_have_no_runtime_effect(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    snapshot = _snapshot(elapsed_nanoseconds=900 * NS)
    save_snapshot(store, snapshot, assigned_target_ids=TARGETS)
    path = snapshot_path(store, "project-1", "mission-001", "attempt-1")
    before = path.read_bytes()
    state = record_checkpoint_request(
        evaluate_checkpoint_policy(snapshot, initial_checkpoint_policy(0), now_nanoseconds=900 * NS),
        now_nanoseconds=900 * NS,
    )
    for now, expected in (
        (1500 * NS - 1, False),
        (1500 * NS, True),
        (1500 * NS + 1, False),
    ):
        result = evaluate_checkpoint_policy(snapshot, state, now_nanoseconds=now)
        assert result.checkpoint_due is expected
        assert result.action == "continue"
    assert path.read_bytes() == before
    assert not (store.unrest_dir("project-1") / "supervision-receipts.json").exists()


def test_policy_restart_bytes_and_malformed_state_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    state = initial_checkpoint_policy(123, last_effect_sequence=4)
    save_policy_state(store, "project-1", "mission-001", "attempt-1", state)
    loaded = load_policy_state(store, "project-1", "mission-001", "attempt-1")
    assert loaded == state
    first_bytes = (
        store.mission_runtime_dir("project-1", "mission-001")
        / "supervision/attempt-1.policy.json"
    ).read_bytes()
    save_policy_state(store, "project-1", "mission-001", "attempt-1", loaded)  # type: ignore[arg-type]
    assert (
        store.mission_runtime_dir("project-1", "mission-001")
        / "supervision/attempt-1.policy.json"
    ).read_bytes() == first_bytes

    policy = (
        store.mission_runtime_dir("project-1", "mission-001")
        / "supervision/attempt-1.policy.json"
    )
    policy.write_text('{"checkpoint_requests":99}', encoding="utf-8")
    with pytest.raises(SupervisionSnapshotError, match="invalid checkpoint"):
        load_policy_state(store, "project-1", "mission-001", "attempt-1")


def test_corrupt_snapshot_fails_project_inspection_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    task = Task(
        id="work-1", type="work", body="body", targets=TARGETS, skill="worker"
    )
    store.save_task_list("project-1", "mission-001", TaskList(tasks=[task]))
    store.save_task_state("project-1", "mission-001", TaskStateFile())
    path = snapshot_path(store, "project-1", "mission-001", "attempt-1")
    path.parent.mkdir(parents=True)
    path.write_text('{"report":"PRIVATE"}', encoding="utf-8")
    with pytest.raises(ToolError) as error:
        _controller(store).inspect_project("project-1")
    assert error.value.code == "patch_transaction_integrity_error"
    assert "PRIVATE" not in str(error.value)


def test_record_request_refuses_a_non_due_evaluation() -> None:
    result = CheckpointEvaluation(
        checkpoint_due=False,
        reason="too_early",
        action="continue",
        state=initial_checkpoint_policy(0),
    )
    with pytest.raises(ValueError, match="not due"):
        record_checkpoint_request(result, now_nanoseconds=30 * NS)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _request(
    binding: SteeringBinding,
    action: Literal["continue", "nudge", "stop_for_attention"],
    *,
    body: str | None = None,
) -> SteeringRequest:
    return SteeringRequest(
        **binding.model_dump(), action=action, actor="orchestrator", body=body
    )


def test_exact_binding_replay_and_sixty_second_default_continue(
    tmp_path: Path,
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    for changed, code in (
        ({"checkpoint_sequence": 0}, "stale_checkpoint_binding"),
        ({"mission_id": "wrong-mission"}, "steering_binding_mismatch"),
        ({"node_id": "wrong-node"}, "steering_binding_mismatch"),
        ({"attempt_id": "wrong-attempt"}, "steering_binding_mismatch"),
    ):
        bad = binding.model_copy(update=changed)
        with pytest.raises(ToolError) as error:
            controller.steer_attempt(_request(bad, "continue"))
        assert error.value.code == code

    clock = _FakeClock()
    outcome = wait_for_steering_action(
        store,
        binding,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        poll_seconds=CHECKPOINT_WAIT_SECONDS,
    )
    assert (outcome.action, outcome.body, outcome.code) == (
        "continue",
        None,
        "timeout_continue",
    )
    assert clock.now == CHECKPOINT_WAIT_SECONDS
    rows = load_supervision_receipts(store, "project-1", "mission-001")
    assert len(rows) == 1
    assert rows[0].actor == "timeout_policy"
    with pytest.raises(ToolError) as replay:
        controller.steer_attempt(_request(binding, "continue"))
    assert replay.value.code == "steering_action_replayed"


@pytest.mark.parametrize("action", ("continue", "nudge"))
def test_reg_v045_leg_snapshot_004_unbound_refusal_bound_resume_and_finality(
    tmp_path: Path,
    action: Literal["continue", "nudge"],
) -> None:
    store, controller, first_waiting, first_binding = _prepare_role_checkpoint(
        tmp_path, "worker"
    )
    snapshot_file = snapshot_path(
        store, "project-1", "mission-001", first_binding.attempt_id
    )
    receipt_file = receipts_path(store, "project-1", "mission-001")
    inbox_file = inbox_path(store, first_binding)
    waiting_bytes = snapshot_file.read_bytes()
    with pytest.raises(SupervisionSnapshotError, match="durable steering authority"):
        save_snapshot(
            store,
            first_waiting.model_copy(
                update={"phase": "active", "supervision_status": "running"},
                deep=True,
            ),
            assigned_target_ids=STEERING_TARGETS,
        )
    assert snapshot_file.read_bytes() == waiting_bytes
    assert not receipt_file.exists()
    assert not inbox_file.exists()

    store = ProjectStore(_config(store.config.harness_home))
    controller = _controller(store)
    with pytest.raises(SupervisionSnapshotError, match="durable steering authority"):
        save_snapshot(
            store,
            first_waiting.model_copy(
                update={"phase": "active", "supervision_status": "running"},
                deep=True,
            ),
            assigned_target_ids=STEERING_TARGETS,
        )
    assert snapshot_file.read_bytes() == waiting_bytes
    assert not receipt_file.exists()
    assert not inbox_file.exists()

    controller.steer_attempt(_request(first_binding, "continue"))
    assert wait_for_steering_action(store, first_binding, timeout_seconds=0).action == (
        "continue"
    )
    first_active = load_snapshot(
        store, "project-1", "mission-001", first_binding.attempt_id
    )
    assert first_active == first_waiting.model_copy(
        update={"phase": "active", "supervision_status": "running"}, deep=True
    )
    first_active_bytes = snapshot_file.read_bytes()
    with pytest.raises(SupervisionSnapshotError, match="advance its sequence"):
        save_snapshot(
            store,
            first_waiting,
            assigned_target_ids=STEERING_TARGETS,
        )
    assert snapshot_file.read_bytes() == first_active_bytes

    second_waiting = first_active.model_copy(
        update={
            "checkpoint_sequence": 2,
            "elapsed_nanoseconds": 930 * NS,
            "last_effect_sequence": 1,
            "completed_target_ids": [STEERING_TARGETS[0]],
            "remaining_target_ids": [STEERING_TARGETS[1]],
            "phase": "waiting_at_checkpoint",
            "supervision_status": "waiting",
        },
        deep=True,
    )
    second_binding = controller.report_supervision_checkpoint(second_waiting)
    before_refusal = (snapshot_file.read_bytes(), receipt_file.read_bytes())
    wrong_binding = second_binding.model_copy(update={"node_id": "wrong-node"})
    with pytest.raises(ToolError) as unbound:
        controller.steer_attempt(_request(wrong_binding, action, body="private" if action == "nudge" else None))
    assert unbound.value.code == "steering_binding_mismatch"
    assert (snapshot_file.read_bytes(), receipt_file.read_bytes()) == before_refusal

    controller.steer_attempt(
        _request(
            second_binding,
            action,
            body="private bound nudge" if action == "nudge" else None,
        )
    )
    if action == "nudge":
        pending_bytes = (
            snapshot_file.read_bytes(),
            receipt_file.read_bytes(),
            inbox_path(store, second_binding).read_bytes(),
        )
        with pytest.raises(
            SupervisionSnapshotError, match="durable steering authority"
        ):
            save_snapshot(
                store,
                second_waiting.model_copy(
                    update={"phase": "active", "supervision_status": "running"},
                    deep=True,
                ),
                assigned_target_ids=STEERING_TARGETS,
            )
        assert (
            snapshot_file.read_bytes(),
            receipt_file.read_bytes(),
            inbox_path(store, second_binding).read_bytes(),
        ) == pending_bytes
    outcome = wait_for_steering_action(store, second_binding, timeout_seconds=0)
    assert outcome.action == action
    resumed = load_snapshot(
        store, "project-1", "mission-001", second_binding.attempt_id
    )
    assert resumed == second_waiting.model_copy(
        update={"phase": "active", "supervision_status": "running"}, deep=True
    )
    restarted = ProjectStore(_config(store.config.harness_home))
    assert load_snapshot(
        restarted, "project-1", "mission-001", second_binding.attempt_id
    ) == resumed

    third_waiting = resumed.model_copy(
        update={
            "checkpoint_sequence": 3,
            "elapsed_nanoseconds": 960 * NS,
            "last_effect_sequence": 2,
            "completed_target_ids": STEERING_TARGETS,
            "remaining_target_ids": [],
            "phase": "waiting_at_checkpoint",
            "supervision_status": "waiting",
        },
        deep=True,
    )
    third_binding = controller.report_supervision_checkpoint(third_waiting)
    controller.steer_attempt(_request(third_binding, "stop_for_attention"))
    stopping = load_snapshot(
        store, "project-1", "mission-001", third_binding.attempt_id
    )
    assert stopping is not None and stopping.phase == "stopping"
    stopping_bytes = snapshot_file.read_bytes()
    with pytest.raises(SupervisionSnapshotError, match="cannot roll back"):
        save_snapshot(
            store,
            stopping.model_copy(
                update={"phase": "active", "supervision_status": "running"}
            ),
            assigned_target_ids=STEERING_TARGETS,
        )
    assert snapshot_file.read_bytes() == stopping_bytes

    terminal = terminal_snapshot(stopping)
    save_snapshot(store, terminal, assigned_target_ids=STEERING_TARGETS)
    terminal_bytes = snapshot_file.read_bytes()
    with pytest.raises(SupervisionSnapshotError, match="cannot roll back"):
        save_snapshot(
            store,
            terminal.model_copy(
                update={
                    "phase": "waiting_at_checkpoint",
                    "supervision_status": "waiting",
                }
            ),
            assigned_target_ids=STEERING_TARGETS,
        )
    assert snapshot_file.read_bytes() == terminal_bytes


@pytest.mark.parametrize("role", ("worker", "validator", "terminal_reviewer"))
def test_parent_child_adapters_deliver_one_private_nudge(
    tmp_path: Path,
    role: Literal["worker", "validator", "terminal_reviewer"],
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, role)
    started = threading.Event()

    def child() -> object:
        started.set()
        return wait_for_steering_action(store, binding, timeout_seconds=2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = pool.submit(child)
        assert started.wait(timeout=1)
        pending = controller.steer_attempt(_request(binding, "nudge", body="private µ"))
        outcome = result.result(timeout=3)
    assert pending.code == "nudge_pending"
    assert outcome.action == "nudge"
    assert outcome.body == "private µ"
    path = inbox_path(store, binding)
    assert not path.exists()
    durable = (
        store.mission_dir("project-1", "mission-001")
        / "supervision-receipts.json"
    )
    encoded = durable.read_text(encoding="utf-8")
    assert "private" not in encoded
    assert "µ" not in encoded
    assert [row.delivery_status for row in load_supervision_receipts(
        store, "project-1", "mission-001"
    )] == ["pending", "delivered", "consumed"]


@pytest.mark.parametrize("role", ("worker", "validator", "terminal_reviewer"))
def test_independent_child_process_adapter_observes_bound_action(
    tmp_path: Path,
    role: Literal["worker", "validator", "terminal_reviewer"],
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, role)
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    result = context.Queue()
    process = context.Process(
        target=_process_wait_for_steering,
        args=(
            str(store.config.harness_home),
            binding.model_dump(mode="json"),
            ready,
            result,
        ),
    )
    process.start()
    try:
        child_pid = ready.get(timeout=5)
        assert child_pid != os.getpid()
        controller.steer_attempt(_request(binding, "continue"))
        assert result.get(timeout=5) == ("continue", None, "continued")
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)


def test_nudge_utf8_cap_second_nudge_and_private_modes(tmp_path: Path) -> None:
    store, controller, snapshot, binding = _prepare_role_checkpoint(tmp_path, "worker")
    body = "é" * 1024
    controller.steer_attempt(_request(binding, "nudge", body=body))
    path = inbox_path(store, binding)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert json.loads(path.read_text(encoding="utf-8"))["body"] == body
    assert wait_for_steering_action(store, binding, timeout_seconds=0).body == body

    next_snapshot = snapshot.model_copy(
        update={
            "checkpoint_sequence": 2,
            "elapsed_nanoseconds": 930 * NS,
            "phase": "waiting_at_checkpoint",
            "supervision_status": "waiting",
        }
    )
    next_binding = controller.report_supervision_checkpoint(next_snapshot)
    with pytest.raises(ToolError) as too_large:
        controller.steer_attempt(_request(next_binding, "nudge", body="é" * 1025))
    assert too_large.value.code == "nudge_too_large"
    with pytest.raises(ToolError) as second:
        controller.steer_attempt(_request(next_binding, "nudge", body="second"))
    assert second.value.code == "nudge_limit_exceeded"


class _CrashOnce:
    def __init__(self, label: str):
        self.label = label
        self.fired = False

    def __call__(self, label: str) -> None:
        if label == self.label and not self.fired:
            self.fired = True
            raise RuntimeError(label)


def test_crash_before_receipt_recovers_one_pending_delivery(tmp_path: Path) -> None:
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    crash = _CrashOnce("after_pending_inbox_fsync")
    with pytest.raises(RuntimeError, match="after_pending"):
        from unrest_harness.supervision import steer_attempt

        steer_attempt(store, _request(binding, "nudge", body="once"), fault=crash)
    assert load_supervision_receipts(store, "project-1", "mission-001") == []
    recover_supervision(store, "project-1", "mission-001")
    assert [row.code for row in load_supervision_receipts(
        store, "project-1", "mission-001"
    )] == ["nudge_pending"]
    assert wait_for_steering_action(store, binding, timeout_seconds=0).body == "once"


def test_crash_after_consumed_fsync_never_redelivers_body(tmp_path: Path) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "nudge", body="do-not-redeliver"))
    crash = _CrashOnce("after_consumed_inbox_fsync")
    with pytest.raises(RuntimeError, match="after_consumed"):
        wait_for_steering_action(store, binding, timeout_seconds=0, fault=crash)
    assert json.loads(inbox_path(store, binding).read_text())["state"] == "consumed"
    outcome = wait_for_steering_action(store, binding, timeout_seconds=0)
    assert (outcome.action, outcome.body, outcome.code) == (
        "continue",
        None,
        "nudge_already_consumed",
    )
    assert not inbox_path(store, binding).exists()
    durable = (
        store.mission_dir("project-1", "mission-001")
        / "supervision-receipts.json"
    ).read_text()
    assert "do-not-redeliver" not in durable


def test_crash_before_consumed_fsync_leaves_exactly_one_pending_delivery(
    tmp_path: Path,
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "nudge", body="deliver-on-retry"))
    crash = _CrashOnce("before_consumed_inbox_fsync")
    with pytest.raises(RuntimeError, match="before_consumed"):
        wait_for_steering_action(store, binding, timeout_seconds=0, fault=crash)
    assert json.loads(inbox_path(store, binding).read_text())["state"] == "pending"
    assert [row.delivery_status for row in load_supervision_receipts(
        store, "project-1", "mission-001"
    )] == ["pending", "delivered"]
    assert wait_for_steering_action(
        store, binding, timeout_seconds=0
    ).body == "deliver-on-retry"
    assert [row.delivery_status for row in load_supervision_receipts(
        store, "project-1", "mission-001"
    )] == ["pending", "delivered", "consumed"]


@pytest.mark.parametrize(
    ("role", "action", "body"),
    (
        ("worker", "nudge", "blocked body"),
        ("validator", "stop_for_attention", None),
        ("terminal_reviewer", "nudge", "review body"),
    ),
)
def test_unsupported_delivery_is_body_free_and_continues(
    tmp_path: Path,
    role: Literal["worker", "validator", "terminal_reviewer"],
    action: Literal["nudge", "stop_for_attention"],
    body: str | None,
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, role)
    receipt = controller.steer_attempt(
        _request(binding, action, body=body), delivery_supported=False
    )
    assert (receipt.delivery_status, receipt.code) == (
        "delivery_blocked",
        "delivery_blocked",
    )
    assert not inbox_path(store, binding).exists()
    outcome = wait_for_steering_action(store, binding, timeout_seconds=0)
    assert (outcome.action, outcome.body) == ("continue", None)
    durable = (
        store.mission_dir("project-1", "mission-001")
        / "supervision-receipts.json"
    ).read_text()
    assert body is None or body not in durable


def test_cooperative_stop_retains_private_state_and_requires_explicit_patch(
    tmp_path: Path,
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "stop_for_attention"))
    assert wait_for_steering_action(
        store, binding, timeout_seconds=0
    ).action == "stop_for_attention"
    envelope = controller.complete_cooperative_stop(
        binding, safe_handoff="PRIVATE STOP CANARY"
    )
    assert envelope.state.state == "attention_needed"
    assert envelope.active_attempts == []
    assert "PRIVATE STOP CANARY" not in envelope.model_dump_json()
    terminal = load_snapshot(store, "project-1", "mission-001", binding.attempt_id)
    assert terminal is not None and terminal.phase == "terminal"
    assert store.load_task_state(
        "project-1", "mission-001"
    ).status_of("work-1") == "failed"
    assert controller.complete_cooperative_stop(
        binding, safe_handoff="ignored replay"
    ).model_dump_json() == envelope.model_dump_json()

    contract_dir = store.ensure_contract_dir("project-1", "mission-001")
    for target in STEERING_TARGETS:
        (contract_dir / f"{target}.md").write_text(
            f"# {target}: fixture\n\nSurface: library.\nNeeds: none.\nBehavior: fixture.\nEvidence: fixture.\n"
        )
    attention_id = store.load_attention("project-1")[0].id
    replacement = Task(
        id="work-2",
        type="work",
        body="explicit replacement",
        targets=STEERING_TARGETS,
        skill="worker",
    )
    decided = controller.decide_attention(
        "project-1",
        [
            Decision(
                item_id=attention_id,
                action="patch",
                patch=TaskListPatch(
                    add=[replacement], supersede={"work-1": "work-2"}
                ),
            )
        ],
    )
    assert decided.state.state == "mission_running"
    assert decided.supersession_lineage[0].current.node_id == "work-2"
    assert decided.supersession_lineage[0].superseded[0].node_id == "work-1"
    assert load_snapshot(
        store, "project-1", "mission-001", binding.attempt_id
    ) == terminal


def test_cooperative_stop_restart_repairs_terminal_before_attention(
    tmp_path: Path,
) -> None:
    store, controller, snapshot, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "stop_for_attention"))
    stopping = load_snapshot(store, "project-1", "mission-001", binding.attempt_id)
    assert stopping is not None and stopping.phase == "stopping"
    save_snapshot(
        store,
        terminal_snapshot(stopping),
        assigned_target_ids=STEERING_TARGETS,
    )
    restarted = _controller(store)
    envelope = restarted.complete_cooperative_stop(
        binding, safe_handoff="PRIVATE RETAIN ME"
    )
    assert envelope.state.state == "attention_needed"
    assert envelope.active_attempts == []
    assert "PRIVATE RETAIN ME" not in envelope.model_dump_json()
    internal = store.load_attention("project-1")
    assert len(internal) == 1
    assert internal[0].report == "PRIVATE RETAIN ME"
    assert restarted.complete_cooperative_stop(
        binding, safe_handoff="replay"
    ).model_dump_json() == envelope.model_dump_json()
    assert store.load_attention("project-1")[0].report == "PRIVATE RETAIN ME"


def test_stopping_snapshot_rollback_refuses_without_poisoning_recovery(
    tmp_path: Path,
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "stop_for_attention"))
    stopping = load_snapshot(store, "project-1", "mission-001", binding.attempt_id)
    assert stopping is not None
    path = snapshot_path(store, "project-1", "mission-001", binding.attempt_id)
    before = path.read_bytes()

    rollback = stopping.model_copy(
        update={"phase": "active", "supervision_status": "running"}
    )
    with pytest.raises(SupervisionSnapshotError, match="cannot roll back"):
        save_snapshot(store, rollback, assigned_target_ids=STEERING_TARGETS)

    assert path.read_bytes() == before
    restarted = ProjectStore(_config(store.config.harness_home))
    recover_supervision(restarted, "project-1", "mission-001")
    recovered = load_snapshot(
        restarted, "project-1", "mission-001", binding.attempt_id
    )
    assert recovered == stopping


def test_attention_first_stop_crash_converges_all_later_state_cuts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "stop_for_attention"))
    original_save_attention = store.save_attention
    crashed = False

    def crash_after_attention(project_id: str, items: list[object]) -> None:
        nonlocal crashed
        original_save_attention(project_id, items)  # type: ignore[arg-type]
        if not crashed:
            crashed = True
            raise RuntimeError("after_save_attention")

    monkeypatch.setattr(store, "save_attention", crash_after_attention)
    with pytest.raises(RuntimeError, match="after_save_attention"):
        controller.complete_cooperative_stop(
            binding, safe_handoff="PRIVATE HANDOFF CUT"
        )
    monkeypatch.setattr(store, "save_attention", original_save_attention)

    assert store.load_state("project-1").state == "mission_running"
    assert store.load_task_state(
        "project-1", "mission-001"
    ).status_of("work-1") == "running"
    assert len(store.load_attention("project-1")) == 1

    restarted = _controller(store)
    envelope = restarted.complete_cooperative_stop(
        binding, safe_handoff="PRIVATE HANDOFF CUT"
    )
    assert envelope.state.state == "attention_needed"
    assert store.load_state("project-1").state == "attention_needed"
    assert store.load_task_state(
        "project-1", "mission-001"
    ).status_of("work-1") == "failed"
    assert len(store.load_attention("project-1")) == 1
    assert store.load_attention("project-1")[0].report == "PRIVATE HANDOFF CUT"
    assert "PRIVATE HANDOFF CUT" not in envelope.model_dump_json()

    duplicate = restarted.complete_cooperative_stop(
        binding, safe_handoff="ignored duplicate"
    )
    assert duplicate.model_dump_json() == envelope.model_dump_json()
    assert len(store.load_attention("project-1")) == 1


def test_task_state_first_stop_crash_converges_project_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "stop_for_attention"))
    original_save_task_state = store.save_task_state
    crashed = False

    def crash_after_task_state(
        project_id: str, mission_id: str, task_state: TaskStateFile
    ) -> None:
        nonlocal crashed
        original_save_task_state(project_id, mission_id, task_state)
        if not crashed:
            crashed = True
            raise RuntimeError("after_save_task_state")

    monkeypatch.setattr(store, "save_task_state", crash_after_task_state)
    with pytest.raises(RuntimeError, match="after_save_task_state"):
        controller.complete_cooperative_stop(
            binding, safe_handoff="PRIVATE TASK CUT"
        )
    monkeypatch.setattr(store, "save_task_state", original_save_task_state)

    assert store.load_state("project-1").state == "mission_running"
    assert store.load_task_state(
        "project-1", "mission-001"
    ).status_of("work-1") == "failed"
    assert len(store.load_attention("project-1")) == 1

    envelope = _controller(store).complete_cooperative_stop(
        binding, safe_handoff="ignored retry"
    )
    assert envelope.state.state == "attention_needed"
    assert store.load_state("project-1").state == "attention_needed"
    assert len(store.load_attention("project-1")) == 1
    assert store.load_attention("project-1")[0].report == "PRIVATE TASK CUT"
    assert "PRIVATE TASK CUT" not in envelope.model_dump_json()


def test_stop_receipt_crash_gap_converges_on_restart(tmp_path: Path) -> None:
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    crash = _CrashOnce("after_receipt_fsync:stop_requested")
    with pytest.raises(RuntimeError, match="after_receipt_fsync:stop_requested"):
        apply_steering(
            store,
            _request(binding, "stop_for_attention"),
            fault=crash,
        )

    waiting = load_snapshot(
        store, "project-1", "mission-001", binding.attempt_id
    )
    assert waiting is not None
    assert (waiting.phase, waiting.supervision_status) == (
        "waiting_at_checkpoint",
        "waiting",
    )
    assert [
        row.code
        for row in load_supervision_receipts(store, "project-1", "mission-001")
    ] == ["stop_requested"]

    restarted = _controller(store)
    assert wait_for_steering_action(
        store, binding, timeout_seconds=0
    ).action == "stop_for_attention"
    stopping = load_snapshot(
        store, "project-1", "mission-001", binding.attempt_id
    )
    assert stopping is not None
    assert (stopping.phase, stopping.supervision_status) == (
        "stopping",
        "stop_requested",
    )
    envelope = restarted.complete_cooperative_stop(
        binding, safe_handoff="PRIVATE CRASH-GAP HANDOFF"
    )
    assert envelope.state.state == "attention_needed"
    assert "PRIVATE CRASH-GAP HANDOFF" not in envelope.model_dump_json()
    terminal = load_snapshot(
        store, "project-1", "mission-001", binding.attempt_id
    )
    assert terminal is not None
    assert (terminal.phase, terminal.supervision_status) == ("terminal", "terminal")
    assert restarted.complete_cooperative_stop(
        binding, safe_handoff="ignored replay"
    ).model_dump_json() == envelope.model_dump_json()
    assert [
        row.code
        for row in load_supervision_receipts(store, "project-1", "mission-001")
    ] == ["stop_requested"]
    assert automatic_restart_count() == 0


def test_stop_completion_recovers_durable_receipt_without_prior_wait(
    tmp_path: Path,
) -> None:
    store, _, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    crash = _CrashOnce("after_receipt_fsync:stop_requested")
    with pytest.raises(RuntimeError, match="after_receipt_fsync:stop_requested"):
        apply_steering(
            store,
            _request(binding, "stop_for_attention"),
            fault=crash,
        )

    envelope = _controller(store).complete_cooperative_stop(
        binding, safe_handoff="PRIVATE DIRECT RECOVERY"
    )
    assert envelope.state.state == "attention_needed"
    assert "PRIVATE DIRECT RECOVERY" not in envelope.model_dump_json()
    terminal = load_snapshot(
        store, "project-1", "mission-001", binding.attempt_id
    )
    assert terminal is not None
    assert (terminal.phase, terminal.supervision_status) == ("terminal", "terminal")
    assert [
        row.code
        for row in load_supervision_receipts(store, "project-1", "mission-001")
    ] == ["stop_requested"]


def test_authority_guards_have_zero_restart_and_no_cancel_action() -> None:
    assert automatic_restart_count() == 0
    require_attempt_start_authority(
        role="worker",
        mutable_worker_active=False,
        replacement_requested=False,
        explicit_supersession=False,
        explicit_action=False,
        provider_attempts_remaining=1,
    )
    with pytest.raises(SupervisionSteeringError) as active:
        require_attempt_start_authority(
            role="worker",
            mutable_worker_active=True,
            replacement_requested=True,
            explicit_supersession=True,
            explicit_action=True,
            provider_attempts_remaining=1,
        )
    assert active.value.code == "mutable_worker_already_active"
    with pytest.raises(SupervisionSteeringError) as implicit:
        require_attempt_start_authority(
            role="worker",
            mutable_worker_active=False,
            replacement_requested=True,
            explicit_supersession=False,
            explicit_action=True,
            provider_attempts_remaining=1,
        )
    assert implicit.value.code == "explicit_supersession_required"
    for role in ("validator", "terminal_reviewer"):
        with pytest.raises(SupervisionSteeringError) as budget:
            require_attempt_start_authority(
                role=role,
                mutable_worker_active=False,
                replacement_requested=True,
                explicit_supersession=True,
                explicit_action=True,
                provider_attempts_remaining=0,
            )
        assert budget.value.code == "provider_budget_exhausted"
        with pytest.raises(SupervisionSteeringError) as implicit_role:
            require_attempt_start_authority(
                role=role,
                mutable_worker_active=False,
                replacement_requested=True,
                explicit_supersession=True,
                explicit_action=False,
                provider_attempts_remaining=1,
            )
        assert implicit_role.value.code == "explicit_attempt_action_required"
    with pytest.raises(ValidationError):
        SteeringRequest.model_validate(
            {
                "project_id": "project-1",
                "mission_id": "mission-001",
                "node_id": "work-1",
                "terminal_review_id": None,
                "attempt_id": "attempt-1",
                "checkpoint_sequence": 1,
                "action": "cancel_run",
                "actor": "orchestrator",
                "body": None,
            }
        )


def test_second_mutable_worker_and_mid_effect_steering_are_refused(
    tmp_path: Path,
) -> None:
    store, controller, snapshot, binding = _prepare_role_checkpoint(tmp_path, "worker")
    active = snapshot.model_copy(
        update={
            "attempt_id": "attempt-worker-2",
            "checkpoint_sequence": 2,
            "phase": "waiting_at_checkpoint",
            "supervision_status": "waiting",
        }
    )
    with pytest.raises(ToolError) as duplicate:
        controller.report_supervision_checkpoint(active)
    assert duplicate.value.code == "mutable_worker_already_active"

    # A request cannot act while the current atomic effect is in flight.
    controller.steer_attempt(_request(binding, "continue"))
    assert wait_for_steering_action(store, binding, timeout_seconds=0).action == (
        "continue"
    )
    in_flight = snapshot.model_copy(
        update={
            "checkpoint_sequence": 2,
            "elapsed_nanoseconds": snapshot.elapsed_nanoseconds + NS,
            "phase": "active",
            "supervision_status": "running",
        },
        deep=True,
    )
    save_snapshot(store, in_flight, assigned_target_ids=STEERING_TARGETS)
    in_flight_binding = binding_from_snapshot(in_flight)
    with pytest.raises(ToolError) as mid_effect:
        controller.steer_attempt(_request(in_flight_binding, "stop_for_attention"))
    assert mid_effect.value.code == "not_at_semantic_checkpoint"


def test_legacy_receipt_absence_is_read_only_and_rows_are_exact(tmp_path: Path) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    durable = (
        store.mission_dir("project-1", "mission-001")
        / "supervision-receipts.json"
    )
    before = sorted(
        path.relative_to(store.bucket_root("project-1"))
        for path in store.bucket_root("project-1").rglob("*")
    )
    assert load_supervision_receipts(store, "project-1", "mission-001") == []
    assert not durable.exists()
    assert sorted(
        path.relative_to(store.bucket_root("project-1"))
        for path in store.bucket_root("project-1").rglob("*")
    ) == before
    controller.steer_attempt(_request(binding, "continue"))
    payload = json.loads(durable.read_text())
    assert set(payload) == {"schema", "receipts"}
    assert payload["schema"] == "unrest.v045.supervision-receipts.v1"
    assert set(payload["receipts"][0]) == {
        "project_id",
        "mission_id",
        "node_id",
        "terminal_review_id",
        "attempt_id",
        "receipt_sequence",
        "checkpoint_sequence",
        "action",
        "actor",
        "body_byte_count",
        "body_sha256",
        "delivery_status",
        "code",
    }


@pytest.mark.parametrize(
    "mutation",
    (
        {"body": "PUBLIC LEAK"},
        {"receipt_sequence": 2},
        {"delivery_status": "consumed", "code": "nudge_consumed"},
        {"action": "retry"},
    ),
)
def test_receipt_mutation_attacks_fail_closed(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    store, controller, _, binding = _prepare_role_checkpoint(tmp_path, "worker")
    controller.steer_attempt(_request(binding, "nudge", body="private"))
    path = store.mission_dir("project-1", "mission-001") / "supervision-receipts.json"
    payload = json.loads(path.read_text())
    payload["receipts"][0].update(mutation)
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SupervisionSteeringError) as error:
        load_supervision_receipts(store, "project-1", "mission-001")
    assert error.value.code == "supervision_receipt_integrity_error"
