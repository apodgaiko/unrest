"""Body-free active-attempt storage and sparse checkpoint policy.

This module deliberately has no dispatcher, provider, cancellation, retry, or
restart dependency.  A due policy result is advisory: shared call sites owned
by INT-V045 may request a semantic checkpoint, but time itself performs no act.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Literal, Sequence, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import (
    ActiveAttemptSnapshot,
    NudgeInbox,
    SteeringBinding,
    SteeringRequest,
    SupervisionReceipt,
    SupervisionReceiptFile,
    TaskList,
)
from .project_lock import project_access_guard
from .storage import ProjectStore, atomic_write_json

POLL_NANOSECONDS = 30_000_000_000
FIRST_CHECKPOINT_NANOSECONDS = 900_000_000_000
SILENCE_NANOSECONDS = 600_000_000_000
BACKOFF_MULTIPLIERS = (1, 2, 4)
MAX_CHECKPOINT_REQUESTS = 2
CHECKPOINT_WAIT_SECONDS = 60
MAX_NUDGE_BYTES = 2048
MAX_NUDGES = 1
MAX_AUTOMATIC_RESTARTS = 0


class SupervisionSnapshotError(ValueError):
    """A runtime snapshot is invalid, stale, or conflicts with current truth."""


class SupervisionSteeringError(ValueError):
    """Stable body-free refusal for steering, recovery, or authority misuse."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SteeringOutcome:
    """Private child-side result; nudge body is never persisted elsewhere."""

    action: Literal["continue", "nudge", "stop_for_attention"]
    body: str | None
    code: str


class CheckpointPolicyState(BaseModel):
    """The complete body-free state needed for deterministic restart."""

    model_config = ConfigDict(extra="forbid")

    attempt_started_nanoseconds: int = Field(strict=True, ge=0)
    backoff_index: int = Field(strict=True, ge=0, le=2)
    checkpoint_requests: int = Field(strict=True, ge=0, le=MAX_CHECKPOINT_REQUESTS)
    last_effect_nanoseconds: int = Field(strict=True, ge=0)
    last_effect_sequence: int = Field(strict=True, ge=0)
    latest_request_nanoseconds: int | None = Field(default=None, strict=True, ge=0)


@dataclass(frozen=True)
class CheckpointEvaluation:
    """Pure advisory result; ``action`` is intentionally always continue."""

    checkpoint_due: bool
    reason: Literal[
        "early_signal",
        "normal_threshold",
        "not_poll_tick",
        "too_early",
        "silence_below_threshold",
        "request_cap",
        "invalid_monotonic_time",
        "regressive_effect_time",
    ]
    action: Literal["continue"]
    state: CheckpointPolicyState


def initial_checkpoint_policy(
    attempt_started_nanoseconds: int,
    *,
    last_effect_sequence: int = 0,
) -> CheckpointPolicyState:
    return CheckpointPolicyState(
        attempt_started_nanoseconds=attempt_started_nanoseconds,
        backoff_index=0,
        checkpoint_requests=0,
        last_effect_nanoseconds=attempt_started_nanoseconds,
        last_effect_sequence=last_effect_sequence,
        latest_request_nanoseconds=None,
    )


def evaluate_checkpoint_policy(
    snapshot: ActiveAttemptSnapshot,
    state: CheckpointPolicyState,
    *,
    now_nanoseconds: int,
) -> CheckpointEvaluation:
    """Evaluate one injected monotonic-clock observation without issuing work."""
    elapsed = now_nanoseconds - state.attempt_started_nanoseconds
    if elapsed < 0:
        return CheckpointEvaluation(
            False, "invalid_monotonic_time", "continue", state.model_copy(deep=True)
        )
    if elapsed % POLL_NANOSECONDS != 0:
        return CheckpointEvaluation(
            False, "not_poll_tick", "continue", state.model_copy(deep=True)
        )

    next_state = state.model_copy(deep=True)
    if snapshot.last_effect_sequence > state.last_effect_sequence:
        effect_time = state.attempt_started_nanoseconds + snapshot.elapsed_nanoseconds
        if effect_time > now_nanoseconds:
            return CheckpointEvaluation(
                False, "invalid_monotonic_time", "continue", state.model_copy(deep=True)
            )
        if effect_time < state.last_effect_nanoseconds:
            return CheckpointEvaluation(
                False, "regressive_effect_time", "continue", state.model_copy(deep=True)
            )
        next_state.last_effect_sequence = snapshot.last_effect_sequence
        next_state.last_effect_nanoseconds = effect_time
        next_state.backoff_index = min(2, state.backoff_index + 1)

    if next_state.checkpoint_requests >= MAX_CHECKPOINT_REQUESTS:
        return CheckpointEvaluation(False, "request_cap", "continue", next_state)

    early_signal = (
        snapshot.blocker_code is not None
        or snapshot.scope_status in {"uncertain", "violation"}
    )
    if early_signal:
        return CheckpointEvaluation(True, "early_signal", "continue", next_state)

    if elapsed < FIRST_CHECKPOINT_NANOSECONDS:
        return CheckpointEvaluation(False, "too_early", "continue", next_state)
    anchor = next_state.last_effect_nanoseconds
    if next_state.latest_request_nanoseconds is not None:
        anchor = max(anchor, next_state.latest_request_nanoseconds)
    required_silence = (
        SILENCE_NANOSECONDS * BACKOFF_MULTIPLIERS[next_state.backoff_index]
    )
    if now_nanoseconds - anchor < required_silence:
        return CheckpointEvaluation(
            False, "silence_below_threshold", "continue", next_state
        )
    return CheckpointEvaluation(True, "normal_threshold", "continue", next_state)


def record_checkpoint_request(
    evaluation: CheckpointEvaluation, *, now_nanoseconds: int
) -> CheckpointPolicyState:
    """Record an actually issued request; requests never advance backoff."""
    if not evaluation.checkpoint_due:
        raise ValueError("checkpoint request is not due")
    state = evaluation.state.model_copy(deep=True)
    if state.checkpoint_requests >= MAX_CHECKPOINT_REQUESTS:
        raise ValueError("checkpoint request cap reached")
    state.checkpoint_requests += 1
    state.latest_request_nanoseconds = now_nanoseconds
    return state


def supervision_runtime_dir(
    store: ProjectStore, project_id: str, mission_id: str
) -> Path:
    return store.mission_runtime_dir(project_id, mission_id) / "supervision"


def snapshot_path(
    store: ProjectStore, project_id: str, mission_id: str, attempt_id: str
) -> Path:
    _validate_path_identifier(attempt_id)
    return supervision_runtime_dir(store, project_id, mission_id) / f"{attempt_id}.json"


def policy_path(
    store: ProjectStore, project_id: str, mission_id: str, attempt_id: str
) -> Path:
    _validate_path_identifier(attempt_id)
    return supervision_runtime_dir(store, project_id, mission_id) / f"{attempt_id}.policy.json"


def load_snapshot(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    attempt_id: str,
) -> ActiveAttemptSnapshot | None:
    path = snapshot_path(store, project_id, mission_id, attempt_id)
    if not path.exists():
        return None
    _validate_private_file(path)
    try:
        snapshot = ActiveAttemptSnapshot.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise SupervisionSnapshotError("invalid active-attempt snapshot") from exc
    if (
        snapshot.project_id != project_id
        or snapshot.mission_id != mission_id
        or snapshot.attempt_id != attempt_id
    ):
        raise SupervisionSnapshotError("snapshot path identity mismatch")
    return snapshot


def save_snapshot(
    store: ProjectStore,
    snapshot: ActiveAttemptSnapshot,
    *,
    assigned_target_ids: Sequence[str],
) -> None:
    """Atomically compare and replace one snapshot under a per-attempt lock."""
    assigned = list(assigned_target_ids)
    _validate_target_partition(snapshot, assigned)
    if snapshot.checkpoint_requests > MAX_CHECKPOINT_REQUESTS:
        raise SupervisionSnapshotError("checkpoint request cap exceeded")
    path = snapshot_path(
        store, snapshot.project_id, snapshot.mission_id, snapshot.attempt_id
    )
    with _snapshot_lock(path):
        current = load_snapshot(
            store, snapshot.project_id, snapshot.mission_id, snapshot.attempt_id
        )
        if current is not None:
            _validate_monotonic_update(current, snapshot, assigned)
            if current == snapshot:
                return
            if (
                current.phase == "waiting_at_checkpoint"
                and (
                    snapshot.phase == "active"
                    or snapshot.supervision_status == "running"
                )
            ):
                _require_durable_resume_authority(store, current)
        atomic_write_json(
            path,
            snapshot.model_dump(mode="json"),
            trusted_root=store.bucket_root(snapshot.project_id),
            inventory=store.inventory,
            mode=0o600,
        )


def _require_durable_resume_authority(
    store: ProjectStore, snapshot: ActiveAttemptSnapshot
) -> None:
    """Refuse a waiting resume unless its exact steering outcome is durable."""
    binding = binding_from_snapshot(snapshot)
    rows = _binding_receipts(
        load_supervision_receipts(store, snapshot.project_id, snapshot.mission_id),
        binding,
    )
    if any(
        row.action == "continue" or row.delivery_status == "delivery_blocked"
        for row in rows
    ):
        return
    if any(
        row.action == "nudge" and row.delivery_status == "consumed" for row in rows
    ):
        return

    path = inbox_path(store, binding)
    if path.exists():
        inbox = _load_inbox(path)
        pending = next(
            (row for row in rows if row.action == "nudge" and row.delivery_status == "pending"),
            None,
        )
        if inbox.state == "consumed" and pending is not None:
            _require_inbox_receipt_identity(inbox, pending)
            return
    raise SupervisionSnapshotError(
        "waiting snapshot resume requires exact durable steering authority"
    )


def terminal_snapshot(snapshot: ActiveAttemptSnapshot) -> ActiveAttemptSnapshot:
    """Return the private terminal record retained until ordinary cleanup."""
    return snapshot.model_copy(
        update={"phase": "terminal", "supervision_status": "terminal"}, deep=True
    )


def load_project_active_attempts(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    task_list: TaskList,
) -> list[ActiveAttemptSnapshot]:
    """Read and order active snapshots without creating runtime state."""
    directory = supervision_runtime_dir(store, project_id, mission_id)
    if not directory.exists():
        return []
    directory_info = directory.lstat()
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_IMODE(
        directory_info.st_mode
    ) != 0o700:
        raise SupervisionSnapshotError("invalid supervision runtime directory")
    tasks = {task.id: task for task in task_list.tasks}
    order = {task.id: index for index, task in enumerate(task_list.tasks)}
    all_targets = _ordered_unique(
        target for task in task_list.tasks for target in task.targets
    )
    snapshots: list[ActiveAttemptSnapshot] = []
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith((".policy.json", ".inbox.json")):
            continue
        attempt_id = path.name.removesuffix(".json")
        snapshot = load_snapshot(store, project_id, mission_id, attempt_id)
        if snapshot is None:
            continue
        if snapshot.node_id is None:
            assigned = all_targets
        else:
            task = tasks.get(snapshot.node_id)
            if task is None:
                raise SupervisionSnapshotError("snapshot node is not an authored task")
            expected_role = "validator" if task.type == "validate" else "worker"
            if task.type == "gate" or snapshot.role != expected_role:
                raise SupervisionSnapshotError("snapshot role does not match authored task")
            assigned = task.targets
        _validate_target_partition(snapshot, assigned)
        if snapshot.phase != "terminal":
            snapshots.append(snapshot)
    return sorted(
        snapshots,
        key=lambda item: (
            1 if item.node_id is None else 0,
            order.get(item.node_id or "", len(order)),
            item.terminal_review_id or "",
        ),
    )


def load_policy_state(
    store: ProjectStore, project_id: str, mission_id: str, attempt_id: str
) -> CheckpointPolicyState | None:
    path = policy_path(store, project_id, mission_id, attempt_id)
    if not path.exists():
        return None
    _validate_private_file(path)
    try:
        return CheckpointPolicyState.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise SupervisionSnapshotError("invalid checkpoint policy state") from exc


def save_policy_state(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    attempt_id: str,
    state: CheckpointPolicyState,
) -> None:
    _ensure_private_supervision_dir(
        supervision_runtime_dir(store, project_id, mission_id)
    )
    atomic_write_json(
        policy_path(store, project_id, mission_id, attempt_id),
        state.model_dump(mode="json"),
        trusted_root=store.bucket_root(project_id),
        inventory=store.inventory,
        mode=0o600,
    )


def binding_from_snapshot(snapshot: ActiveAttemptSnapshot) -> SteeringBinding:
    return SteeringBinding(
        project_id=snapshot.project_id,
        mission_id=snapshot.mission_id,
        node_id=snapshot.node_id,
        terminal_review_id=snapshot.terminal_review_id,
        attempt_id=snapshot.attempt_id,
        checkpoint_sequence=snapshot.checkpoint_sequence,
    )


def inbox_path(
    store: ProjectStore, binding: SteeringBinding
) -> Path:
    _validate_path_identifier(binding.attempt_id)
    return (
        supervision_runtime_dir(store, binding.project_id, binding.mission_id)
        / f"{binding.attempt_id}.inbox.json"
    )


def receipts_path(
    store: ProjectStore, project_id: str, mission_id: str
) -> Path:
    return store.mission_dir(project_id, mission_id) / "supervision-receipts.json"


def report_supervision_checkpoint(
    store: ProjectStore,
    snapshot: ActiveAttemptSnapshot,
    *,
    assigned_target_ids: Sequence[str],
    project_guard: bool = True,
) -> SteeringBinding:
    """Publish one semantic checkpoint through the W-owned local adapter seam."""
    if snapshot.phase != "waiting_at_checkpoint" or snapshot.supervision_status != "waiting":
        raise SupervisionSteeringError("not_at_semantic_checkpoint")
    guard = (
        project_access_guard(store, snapshot.project_id)
        if project_guard
        else nullcontext()
    )
    with guard:
        recover_supervision(
            store,
            snapshot.project_id,
            snapshot.mission_id,
            project_guard=False,
        )
        if snapshot.role == "worker":
            directory = supervision_runtime_dir(
                store, snapshot.project_id, snapshot.mission_id
            )
            if directory.exists():
                for candidate in sorted(directory.glob("*.json")):
                    if candidate.name.endswith((".policy.json", ".inbox.json")):
                        continue
                    existing = load_snapshot(
                        store,
                        snapshot.project_id,
                        snapshot.mission_id,
                        candidate.stem,
                    )
                    if (
                        existing is not None
                        and existing.attempt_id != snapshot.attempt_id
                        and existing.node_id == snapshot.node_id
                        and existing.role == "worker"
                        and existing.phase != "terminal"
                    ):
                        raise SupervisionSteeringError(
                            "mutable_worker_already_active"
                        )
        save_snapshot(store, snapshot, assigned_target_ids=assigned_target_ids)
    return binding_from_snapshot(snapshot)


def load_supervision_receipts(
    store: ProjectStore, project_id: str, mission_id: str
) -> list[SupervisionReceipt]:
    """Load and validate the complete append-only transition history."""
    path = receipts_path(store, project_id, mission_id)
    if not path.exists():
        return []
    try:
        info = path.lstat()
    except OSError as exc:
        raise SupervisionSteeringError("supervision_receipt_integrity_error") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SupervisionSteeringError("supervision_receipt_integrity_error")
    try:
        payload = SupervisionReceiptFile.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise SupervisionSteeringError("supervision_receipt_integrity_error") from exc
    _validate_receipt_transitions(payload.receipts)
    return payload.receipts


def steer_attempt(
    store: ProjectStore,
    request: SteeringRequest,
    *,
    delivery_supported: bool = True,
    fault: Callable[[str], None] | None = None,
    project_guard: bool = True,
) -> SupervisionReceipt:
    """Accept exactly one action for the current bound semantic checkpoint."""
    binding = SteeringBinding.model_validate(
        request.model_dump(
            include={
                "project_id",
                "mission_id",
                "node_id",
                "terminal_review_id",
                "attempt_id",
                "checkpoint_sequence",
            }
        )
    )
    guard = (
        project_access_guard(store, request.project_id)
        if project_guard
        else nullcontext()
    )
    with guard:
        recover_supervision(
            store,
            request.project_id,
            request.mission_id,
            fault=fault,
            project_guard=False,
        )
        snapshot = _require_bound_snapshot(store, binding)
        receipts = load_supervision_receipts(
            store, request.project_id, request.mission_id
        )
        if _binding_receipts(receipts, binding):
            raise SupervisionSteeringError("steering_action_replayed")
        if snapshot.phase != "waiting_at_checkpoint" or snapshot.supervision_status != "waiting":
            raise SupervisionSteeringError("not_at_semantic_checkpoint")

        body_bytes = b""
        body_digest: str | None = None
        if request.action == "nudge":
            assert request.body is not None
            try:
                body_bytes = request.body.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise SupervisionSteeringError("invalid_nudge_utf8") from exc
            if len(body_bytes) > MAX_NUDGE_BYTES:
                raise SupervisionSteeringError("nudge_too_large")
            if any(
                receipt.action == "nudge"
                and receipt.delivery_status != "delivery_blocked"
                and receipt.attempt_id == binding.attempt_id
                and receipt.project_id == binding.project_id
                and receipt.mission_id == binding.mission_id
                for receipt in receipts
            ):
                raise SupervisionSteeringError("nudge_limit_exceeded")
            body_digest = hashlib.sha256(body_bytes).hexdigest()

        if not delivery_supported and request.action in {"nudge", "stop_for_attention"}:
            return _append_receipt(
                store,
                binding,
                action=request.action,
                actor=request.actor,
                body_byte_count=len(body_bytes),
                body_sha256=body_digest,
                delivery_status="delivery_blocked",
                code="delivery_blocked",
                fault=fault,
            )

        if request.action == "nudge":
            assert request.actor in {"orchestrator", "maintainer"}
            assert request.body is not None
            assert body_digest is not None
            inbox_actor = cast(
                Literal["orchestrator", "maintainer"], request.actor
            )
            inbox = NudgeInbox(
                **binding.model_dump(),
                actor=inbox_actor,
                body=request.body,
                body_byte_count=len(body_bytes),
                body_sha256=body_digest,
                state="pending",
            )
            _fault(fault, "before_pending_inbox_fsync")
            _atomic_write_json_fsynced(
                inbox_path(store, binding),
                inbox.model_dump(mode="json", by_alias=True),
                trusted_root=store.bucket_root(binding.project_id),
                mode=0o600,
                private_parent=True,
            )
            _fault(fault, "after_pending_inbox_fsync")
            return _append_receipt(
                store,
                binding,
                action="nudge",
                actor=request.actor,
                body_byte_count=len(body_bytes),
                body_sha256=body_digest,
                delivery_status="pending",
                code="nudge_pending",
                fault=fault,
            )

        receipt = _append_receipt(
            store,
            binding,
            action=request.action,
            actor=request.actor,
            body_byte_count=0,
            body_sha256=None,
            delivery_status="not_applicable",
            code="continued" if request.action == "continue" else "stop_requested",
            fault=fault,
        )
        if request.action == "stop_for_attention":
            save_snapshot(
                store,
                snapshot.model_copy(
                    update={"phase": "stopping", "supervision_status": "stop_requested"},
                    deep=True,
                ),
                assigned_target_ids=_assigned_targets_for_snapshot(store, snapshot),
            )
        return receipt


def wait_for_steering_action(
    store: ProjectStore,
    binding: SteeringBinding,
    *,
    timeout_seconds: float = CHECKPOINT_WAIT_SECONDS,
    poll_seconds: float = 0.05,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    fault: Callable[[str], None] | None = None,
    project_guard: bool = True,
) -> SteeringOutcome:
    """Wait no longer than 60 seconds, defaulting deterministically to continue."""
    if timeout_seconds < 0 or timeout_seconds > CHECKPOINT_WAIT_SECONDS:
        raise ValueError("checkpoint wait must be between zero and 60 seconds")
    if poll_seconds <= 0:
        raise ValueError("checkpoint poll must be positive")
    started = monotonic()
    deadline = started + timeout_seconds
    while True:
        guard = (
            project_access_guard(store, binding.project_id)
            if project_guard
            else nullcontext()
        )
        with guard:
            recover_supervision(
                store,
                binding.project_id,
                binding.mission_id,
                fault=fault,
                project_guard=False,
            )
            _require_current_or_stopping_checkpoint(store, binding)
            receipts = load_supervision_receipts(
                store, binding.project_id, binding.mission_id
            )
            rows = _binding_receipts(receipts, binding)
            if rows:
                first = rows[0]
                if first.delivery_status == "delivery_blocked":
                    _resume_after_continue(store, binding)
                    return SteeringOutcome("continue", None, "delivery_blocked")
                if first.action == "continue":
                    _resume_after_continue(store, binding)
                    return SteeringOutcome("continue", None, first.code)
                if first.action == "stop_for_attention":
                    return SteeringOutcome("stop_for_attention", None, first.code)
                return _consume_nudge_locked(store, binding, fault=fault)

            now = monotonic()
            if now >= deadline:
                _append_receipt(
                    store,
                    binding,
                    action="continue",
                    actor="timeout_policy",
                    body_byte_count=0,
                    body_sha256=None,
                    delivery_status="not_applicable",
                    code="timeout_continue",
                    fault=fault,
                )
                _resume_after_continue(store, binding)
                return SteeringOutcome("continue", None, "timeout_continue")
        remaining = max(0.0, deadline - monotonic())
        sleep(min(poll_seconds, remaining))


def recover_supervision(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    *,
    fault: Callable[[str], None] | None = None,
    project_guard: bool = True,
) -> None:
    """Repair receipt tails from private inbox truth without returning a body."""
    guard = project_access_guard(store, project_id) if project_guard else nullcontext()
    with guard:
        _recover_supervision_locked(
            store, project_id, mission_id, fault=fault
        )


def _recover_supervision_locked(
    store: ProjectStore,
    project_id: str,
    mission_id: str,
    *,
    fault: Callable[[str], None] | None,
) -> None:
    directory = supervision_runtime_dir(store, project_id, mission_id)
    receipts = load_supervision_receipts(store, project_id, mission_id)
    if not directory.exists():
        groups: dict[tuple[object, ...], list[SupervisionReceipt]] = {}
        for receipt in receipts:
            groups.setdefault(_binding_key(receipt), []).append(receipt)
        if any(
            rows[-1].action == "nudge"
            and rows[-1].delivery_status in {"pending", "delivered"}
            for rows in groups.values()
        ):
            raise SupervisionSteeringError("supervision_inbox_integrity_error")
        return
    try:
        directory_info = directory.lstat()
    except OSError as exc:
        raise SupervisionSteeringError("supervision_storage_integrity_error") from exc
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or stat.S_IMODE(directory_info.st_mode) != 0o700
    ):
        raise SupervisionSteeringError("supervision_storage_integrity_error")
    _recover_stop_receipts(store, receipts)
    inbox_bindings: set[tuple[object, ...]] = set()
    for path in sorted(directory.glob("*.inbox.json")):
        inbox = _load_inbox(path)
        binding = SteeringBinding.model_validate(
            inbox.model_dump(
                include={
                    "project_id",
                    "mission_id",
                    "node_id",
                    "terminal_review_id",
                    "attempt_id",
                    "checkpoint_sequence",
                }
            )
        )
        if binding.project_id != project_id or binding.mission_id != mission_id:
            raise SupervisionSteeringError("supervision_inbox_integrity_error")
        if path != inbox_path(store, binding):
            raise SupervisionSteeringError("supervision_inbox_integrity_error")
        _require_bound_snapshot(store, binding)
        inbox_bindings.add(_binding_key(binding))
        rows = _binding_receipts(receipts, binding)
        pending = next((row for row in rows if row.delivery_status == "pending"), None)
        if pending is None:
            pending = _append_receipt(
                store,
                binding,
                action="nudge",
                actor=inbox.actor,
                body_byte_count=inbox.body_byte_count,
                body_sha256=inbox.body_sha256,
                delivery_status="pending",
                code="nudge_pending",
                fault=fault,
            )
            receipts.append(pending)
            rows = _binding_receipts(receipts, binding)
        _require_inbox_receipt_identity(inbox, pending)
        consumed = next((row for row in rows if row.delivery_status == "consumed"), None)
        if inbox.state == "pending":
            if consumed is not None:
                raise SupervisionSteeringError("supervision_inbox_integrity_error")
            continue
        if consumed is None:
            _append_receipt(
                store,
                binding,
                action="nudge",
                actor=inbox.actor,
                body_byte_count=inbox.body_byte_count,
                body_sha256=inbox.body_sha256,
                delivery_status="consumed",
                code="nudge_consumed",
                fault=fault,
            )
        _remove_consumed_inbox(path, fault=fault)
    receipt_groups: dict[tuple[object, ...], list[SupervisionReceipt]] = {}
    for receipt in receipts:
        receipt_groups.setdefault(_binding_key(receipt), []).append(receipt)
    for key, rows in receipt_groups.items():
        if (
            rows[-1].action == "nudge"
            and rows[-1].delivery_status in {"pending", "delivered"}
            and key not in inbox_bindings
        ):
            raise SupervisionSteeringError("supervision_inbox_integrity_error")


def _recover_stop_receipts(
    store: ProjectStore, receipts: Sequence[SupervisionReceipt]
) -> None:
    """Converge the receipt-first stop transition after a process crash."""
    for receipt in receipts:
        if receipt.action != "stop_for_attention" or receipt.code != "stop_requested":
            continue
        binding = SteeringBinding.model_validate(
            receipt.model_dump(
                include={
                    "project_id",
                    "mission_id",
                    "node_id",
                    "terminal_review_id",
                    "attempt_id",
                    "checkpoint_sequence",
                }
            )
        )
        snapshot = _require_bound_snapshot(store, binding)
        if (snapshot.phase, snapshot.supervision_status) in {
            ("stopping", "stop_requested"),
            ("terminal", "terminal"),
        }:
            continue
        if (snapshot.phase, snapshot.supervision_status) != (
            "waiting_at_checkpoint",
            "waiting",
        ):
            raise SupervisionSteeringError("supervision_receipt_integrity_error")
        save_snapshot(
            store,
            snapshot.model_copy(
                update={"phase": "stopping", "supervision_status": "stop_requested"},
                deep=True,
            ),
            assigned_target_ids=_assigned_targets_for_snapshot(store, snapshot),
        )


def automatic_restart_count() -> Literal[0]:
    """There is deliberately no restart primitive in the supervision core."""
    return 0


def require_attempt_start_authority(
    *,
    role: Literal["worker", "validator", "terminal_reviewer"],
    mutable_worker_active: bool,
    replacement_requested: bool,
    explicit_supersession: bool,
    explicit_action: bool,
    provider_attempts_remaining: int,
) -> None:
    """Fail closed at the local INT composition seam; never starts an attempt."""
    if role == "worker" and mutable_worker_active:
        raise SupervisionSteeringError("mutable_worker_already_active")
    if role == "worker" and replacement_requested and not explicit_supersession:
        raise SupervisionSteeringError("explicit_supersession_required")
    if role in {"validator", "terminal_reviewer"}:
        if not explicit_action:
            raise SupervisionSteeringError("explicit_attempt_action_required")
        if provider_attempts_remaining <= 0:
            raise SupervisionSteeringError("provider_budget_exhausted")


def _require_current_checkpoint(
    store: ProjectStore, binding: SteeringBinding
) -> ActiveAttemptSnapshot:
    snapshot = _require_bound_snapshot(store, binding)
    if snapshot.phase != "waiting_at_checkpoint" or snapshot.supervision_status != "waiting":
        raise SupervisionSteeringError("not_at_semantic_checkpoint")
    return snapshot


def _require_bound_snapshot(
    store: ProjectStore, binding: SteeringBinding
) -> ActiveAttemptSnapshot:
    snapshot = load_snapshot(
        store, binding.project_id, binding.mission_id, binding.attempt_id
    )
    if snapshot is None:
        raise SupervisionSteeringError("steering_binding_mismatch")
    actual = binding_from_snapshot(snapshot)
    if actual.checkpoint_sequence != binding.checkpoint_sequence:
        raise SupervisionSteeringError("stale_checkpoint_binding")
    if actual != binding:
        raise SupervisionSteeringError("steering_binding_mismatch")
    return snapshot


def _require_current_or_stopping_checkpoint(
    store: ProjectStore, binding: SteeringBinding
) -> ActiveAttemptSnapshot:
    snapshot = load_snapshot(
        store, binding.project_id, binding.mission_id, binding.attempt_id
    )
    if snapshot is None:
        raise SupervisionSteeringError("steering_binding_mismatch")
    actual = binding_from_snapshot(snapshot)
    if actual.checkpoint_sequence != binding.checkpoint_sequence:
        raise SupervisionSteeringError("stale_checkpoint_binding")
    if actual != binding:
        raise SupervisionSteeringError("steering_binding_mismatch")
    valid_state = (
        (snapshot.phase, snapshot.supervision_status)
        in {("waiting_at_checkpoint", "waiting"), ("stopping", "stop_requested")}
    )
    if not valid_state:
        raise SupervisionSteeringError("not_at_semantic_checkpoint")
    return snapshot


def _assigned_targets_for_snapshot(
    store: ProjectStore, snapshot: ActiveAttemptSnapshot
) -> list[str]:
    task_list = store.load_task_list(
        snapshot.project_id, snapshot.mission_id
    )
    if snapshot.node_id is not None:
        task = next((item for item in task_list.tasks if item.id == snapshot.node_id), None)
        if task is None:
            raise SupervisionSteeringError("steering_binding_mismatch")
        return task.targets
    return _ordered_unique(
        target for task in task_list.tasks for target in task.targets
    )


def _resume_after_continue(store: ProjectStore, binding: SteeringBinding) -> None:
    snapshot = _require_current_or_stopping_checkpoint(store, binding)
    if snapshot.phase == "stopping":
        return
    save_snapshot(
        store,
        snapshot.model_copy(
            update={"phase": "active", "supervision_status": "running"}, deep=True
        ),
        assigned_target_ids=_assigned_targets_for_snapshot(store, snapshot),
    )


def _append_receipt(
    store: ProjectStore,
    binding: SteeringBinding,
    *,
    action: Literal["continue", "nudge", "stop_for_attention"],
    actor: Literal["orchestrator", "maintainer", "timeout_policy"],
    body_byte_count: int,
    body_sha256: str | None,
    delivery_status: Literal[
        "not_applicable", "pending", "delivered", "consumed", "delivery_blocked"
    ],
    code: Literal[
        "continued",
        "timeout_continue",
        "nudge_pending",
        "nudge_delivered",
        "nudge_consumed",
        "stop_requested",
        "delivery_blocked",
    ],
    fault: Callable[[str], None] | None,
) -> SupervisionReceipt:
    receipts = load_supervision_receipts(store, binding.project_id, binding.mission_id)
    receipt = SupervisionReceipt(
        **binding.model_dump(),
        receipt_sequence=len(receipts) + 1,
        action=action,
        actor=actor,
        body_byte_count=body_byte_count,
        body_sha256=body_sha256,
        delivery_status=delivery_status,
        code=code,
    )
    candidate = [*receipts, receipt]
    _validate_receipt_transitions(candidate)
    path = receipts_path(store, binding.project_id, binding.mission_id)
    _fault(fault, f"before_receipt_fsync:{code}")
    _atomic_write_json_fsynced(
        path,
        SupervisionReceiptFile(receipts=candidate).model_dump(
            mode="json", by_alias=True
        ),
        trusted_root=store.bucket_root(binding.project_id),
        mode=0o644,
        private_parent=False,
    )
    _fault(fault, f"after_receipt_fsync:{code}")
    return receipt


def _validate_receipt_transitions(receipts: Sequence[SupervisionReceipt]) -> None:
    groups: dict[tuple[object, ...], list[SupervisionReceipt]] = {}
    accepted_nudges: set[tuple[str, str, str]] = set()
    for expected, receipt in enumerate(receipts, start=1):
        if receipt.receipt_sequence != expected:
            raise SupervisionSteeringError("supervision_receipt_integrity_error")
        key = _binding_key(receipt)
        rows = groups.setdefault(key, [])
        if not rows:
            if receipt.action == "nudge" and receipt.delivery_status not in {
                "pending",
                "delivery_blocked",
            }:
                raise SupervisionSteeringError("supervision_receipt_integrity_error")
            if receipt.action != "nudge" and receipt.delivery_status not in {
                "not_applicable",
                "delivery_blocked",
            }:
                raise SupervisionSteeringError("supervision_receipt_integrity_error")
            if receipt.action == "nudge" and receipt.delivery_status == "pending":
                attempt_key = (
                    receipt.project_id,
                    receipt.mission_id,
                    receipt.attempt_id,
                )
                if attempt_key in accepted_nudges:
                    raise SupervisionSteeringError("supervision_receipt_integrity_error")
                accepted_nudges.add(attempt_key)
        else:
            first = rows[0]
            if first.delivery_status == "delivery_blocked" or first.action != "nudge":
                raise SupervisionSteeringError("supervision_receipt_integrity_error")
            expected_status = "delivered" if len(rows) == 1 else "consumed"
            if len(rows) > 2 or receipt.delivery_status != expected_status:
                raise SupervisionSteeringError("supervision_receipt_integrity_error")
            if (
                receipt.action != first.action
                or receipt.actor != first.actor
                or receipt.body_byte_count != first.body_byte_count
                or receipt.body_sha256 != first.body_sha256
            ):
                raise SupervisionSteeringError("supervision_receipt_integrity_error")
        rows.append(receipt)


def _binding_key(
    value: SteeringBinding | SupervisionReceipt | NudgeInbox,
) -> tuple[object, ...]:
    return (
        value.project_id,
        value.mission_id,
        value.node_id,
        value.terminal_review_id,
        value.attempt_id,
        value.checkpoint_sequence,
    )


def _binding_receipts(
    receipts: Sequence[SupervisionReceipt], binding: SteeringBinding
) -> list[SupervisionReceipt]:
    key = _binding_key(binding)
    return [receipt for receipt in receipts if _binding_key(receipt) == key]


def _load_inbox(path: Path) -> NudgeInbox:
    _validate_private_file(path)
    try:
        return NudgeInbox.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise SupervisionSteeringError("supervision_inbox_integrity_error") from exc


def _require_inbox_receipt_identity(
    inbox: NudgeInbox, receipt: SupervisionReceipt
) -> None:
    if (
        _binding_key(inbox) != _binding_key(receipt)
        or inbox.actor != receipt.actor
        or inbox.body_byte_count != receipt.body_byte_count
        or inbox.body_sha256 != receipt.body_sha256
    ):
        raise SupervisionSteeringError("supervision_inbox_integrity_error")


def _consume_nudge_locked(
    store: ProjectStore,
    binding: SteeringBinding,
    *,
    fault: Callable[[str], None] | None,
) -> SteeringOutcome:
    rows = _binding_receipts(
        load_supervision_receipts(store, binding.project_id, binding.mission_id),
        binding,
    )
    if any(row.delivery_status == "consumed" for row in rows):
        _resume_after_continue(store, binding)
        return SteeringOutcome("continue", None, "nudge_already_consumed")
    path = inbox_path(store, binding)
    if not path.exists():
        raise SupervisionSteeringError("supervision_inbox_integrity_error")
    inbox = _load_inbox(path)
    pending = next((row for row in rows if row.delivery_status == "pending"), None)
    if pending is None or inbox.state != "pending":
        raise SupervisionSteeringError("supervision_inbox_integrity_error")
    _require_inbox_receipt_identity(inbox, pending)
    delivered = next((row for row in rows if row.delivery_status == "delivered"), None)
    if delivered is None:
        _append_receipt(
            store,
            binding,
            action="nudge",
            actor=inbox.actor,
            body_byte_count=inbox.body_byte_count,
            body_sha256=inbox.body_sha256,
            delivery_status="delivered",
            code="nudge_delivered",
            fault=fault,
        )
    consumed_inbox = inbox.model_copy(update={"state": "consumed"}, deep=True)
    _fault(fault, "before_consumed_inbox_fsync")
    _atomic_write_json_fsynced(
        path,
        consumed_inbox.model_dump(mode="json", by_alias=True),
        trusted_root=store.bucket_root(binding.project_id),
        mode=0o600,
        private_parent=True,
    )
    _fault(fault, "after_consumed_inbox_fsync")
    _append_receipt(
        store,
        binding,
        action="nudge",
        actor=inbox.actor,
        body_byte_count=inbox.body_byte_count,
        body_sha256=inbox.body_sha256,
        delivery_status="consumed",
        code="nudge_consumed",
        fault=fault,
    )
    body = inbox.body
    _remove_consumed_inbox(path, fault=fault)
    _resume_after_continue(store, binding)
    return SteeringOutcome("nudge", body, "nudge_consumed")


def _remove_consumed_inbox(
    path: Path, *, fault: Callable[[str], None] | None
) -> None:
    _fault(fault, "before_consumed_inbox_cleanup")
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory_strict(path.parent)
    _fault(fault, "after_consumed_inbox_cleanup")


def _atomic_write_json_fsynced(
    path: Path,
    payload: object,
    *,
    trusted_root: Path,
    mode: int,
    private_parent: bool,
) -> None:
    root = Path(os.path.abspath(trusted_root))
    target = Path(os.path.abspath(path))
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise SupervisionSteeringError("supervision_storage_integrity_error") from exc
    if private_parent:
        _ensure_directory_chain(root, target.parent, final_mode=0o700)
    else:
        _ensure_directory_chain(root, target.parent, final_mode=None)
    if target.is_symlink():
        raise SupervisionSteeringError("supervision_storage_integrity_error")
    try:
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
    except OSError as exc:
        raise SupervisionSteeringError("supervision_storage_integrity_error") from exc
    if target_info is not None and not stat.S_ISREG(target_info.st_mode):
        raise SupervisionSteeringError("supervision_storage_integrity_error")
    content = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        replaced = True
        _fsync_directory_strict(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _fsync_directory_strict(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory_chain(
    root: Path, parent: Path, *, final_mode: int | None
) -> None:
    try:
        relative = parent.relative_to(root)
    except ValueError as exc:
        raise SupervisionSteeringError("supervision_storage_integrity_error") from exc
    candidate = root
    for index, part in enumerate(relative.parts):
        candidate /= part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            try:
                candidate.mkdir(mode=0o755)
                info = candidate.lstat()
                _fsync_directory_strict(candidate.parent)
            except OSError as exc:
                raise SupervisionSteeringError(
                    "supervision_storage_integrity_error"
                ) from exc
        except OSError as exc:
            raise SupervisionSteeringError("supervision_storage_integrity_error") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SupervisionSteeringError("supervision_storage_integrity_error")
        if final_mode is not None and index == len(relative.parts) - 1:
            os.chmod(candidate, final_mode)


def _fault(fault: Callable[[str], None] | None, label: str) -> None:
    if fault is not None:
        fault(label)


def _validate_target_partition(
    snapshot: ActiveAttemptSnapshot, assigned_target_ids: Sequence[str]
) -> None:
    assigned = list(assigned_target_ids)
    if len(set(assigned)) != len(assigned):
        raise SupervisionSnapshotError("assigned target ids must be unique")
    completed = snapshot.completed_target_ids
    remaining = snapshot.remaining_target_ids
    if set(completed) | set(remaining) != set(assigned):
        raise SupervisionSnapshotError("snapshot targets must equal assigned targets")
    if completed != [target for target in assigned if target in set(completed)]:
        raise SupervisionSnapshotError("completed targets are not in assigned order")
    if remaining != [target for target in assigned if target in set(remaining)]:
        raise SupervisionSnapshotError("remaining targets are not in assigned order")


def _validate_monotonic_update(
    current: ActiveAttemptSnapshot,
    candidate: ActiveAttemptSnapshot,
    assigned_target_ids: Sequence[str],
) -> None:
    immutable = (
        "attempt_id",
        "mission_id",
        "node_id",
        "project_id",
        "role",
        "terminal_review_id",
    )
    if any(getattr(current, name) != getattr(candidate, name) for name in immutable):
        raise SupervisionSnapshotError("snapshot identity conflicts with current record")
    if candidate.checkpoint_sequence < current.checkpoint_sequence:
        raise SupervisionSnapshotError("stale checkpoint sequence")
    if (
        current.phase == "active"
        and candidate.phase == "waiting_at_checkpoint"
        and candidate.checkpoint_sequence == current.checkpoint_sequence
    ):
        raise SupervisionSnapshotError("a new checkpoint must advance its sequence")
    if candidate.checkpoint_sequence == current.checkpoint_sequence and (
        candidate.blocker_code != current.blocker_code
        or candidate.scope_status != current.scope_status
    ):
        raise SupervisionSnapshotError("equal-sequence checkpoint content conflicts")
    monotonic_counts = (
        "elapsed_nanoseconds",
        "checkpoint_requests",
        "last_effect_sequence",
    )
    if any(
        getattr(candidate, name) < getattr(current, name) for name in monotonic_counts
    ):
        raise SupervisionSnapshotError("snapshot counters are not monotonic")
    if not set(current.completed_target_ids).issubset(candidate.completed_target_ids):
        raise SupervisionSnapshotError("completed targets cannot shrink")
    if not set(candidate.remaining_target_ids).issubset(current.remaining_target_ids):
        raise SupervisionSnapshotError("remaining targets cannot grow")
    phase_rank = {
        "active": 0,
        "waiting_at_checkpoint": 0,
        "stopping": 1,
        "terminal": 2,
    }
    status_rank = {
        "running": 0,
        "checkpoint_due": 0,
        "waiting": 0,
        "nudge_pending": 0,
        "stop_requested": 1,
        "terminal": 2,
    }
    if (
        phase_rank[candidate.phase] < phase_rank[current.phase]
        or status_rank[candidate.supervision_status]
        < status_rank[current.supervision_status]
    ):
        raise SupervisionSnapshotError("snapshot phase and status cannot roll back")
    _validate_target_partition(candidate, assigned_target_ids)


@contextmanager
def _snapshot_lock(path: Path) -> Iterator[None]:
    _ensure_private_supervision_dir(path.parent)
    lock_path = path.with_suffix(".lock")
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SupervisionSnapshotError("snapshot lock is not a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_path_identifier(value: str) -> None:
    if not value or value in {".", ".."} or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
        for character in value
    ):
        raise SupervisionSnapshotError("invalid supervision path identity")


def _ensure_private_supervision_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise SupervisionSnapshotError("supervision runtime path is not a directory")
    os.chmod(path, 0o700)


def _validate_private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise SupervisionSnapshotError("supervision runtime file is not private")


def _ordered_unique(values: Iterator[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


__all__ = [
    "BACKOFF_MULTIPLIERS",
    "CHECKPOINT_WAIT_SECONDS",
    "FIRST_CHECKPOINT_NANOSECONDS",
    "MAX_AUTOMATIC_RESTARTS",
    "MAX_CHECKPOINT_REQUESTS",
    "MAX_NUDGE_BYTES",
    "MAX_NUDGES",
    "POLL_NANOSECONDS",
    "SILENCE_NANOSECONDS",
    "CheckpointEvaluation",
    "CheckpointPolicyState",
    "SupervisionSnapshotError",
    "SupervisionSteeringError",
    "SteeringOutcome",
    "automatic_restart_count",
    "binding_from_snapshot",
    "evaluate_checkpoint_policy",
    "initial_checkpoint_policy",
    "load_policy_state",
    "load_project_active_attempts",
    "load_snapshot",
    "load_supervision_receipts",
    "inbox_path",
    "policy_path",
    "record_checkpoint_request",
    "recover_supervision",
    "report_supervision_checkpoint",
    "require_attempt_start_authority",
    "receipts_path",
    "save_policy_state",
    "save_snapshot",
    "snapshot_path",
    "supervision_runtime_dir",
    "steer_attempt",
    "terminal_snapshot",
    "wait_for_steering_action",
]
