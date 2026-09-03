"""ProjectController — routes the 7 orchestrator MCP tools.

See `specs/task_list/PRODUCT.md`. The controller owns:
- envelope construction
- decide_attention validation
- TaskListPatch application via task_list_patch.apply_patch()
- resume-from-disk on every tool call

The coordinator is constructed per-invocation; it has no in-memory state.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import VALID_REASONING_EFFORTS, HarnessConfig
from .coordinator import MissionCoordinator
from .dispatcher import NodeDispatcher, TerminalReviewer
from .attention import cooperative_stop
from .envelope import (
    EnvelopeDagMode,
    make_envelope,
    project_supersession_lineage,
    public_attention_items,
)
from .models import (
    AttentionItemInternal,
    AttentionFile,
    AttentionNeeded,
    ActiveAttemptSnapshot,
    Aborted,
    ContractStateFile,
    Decision,
    Draft,
    Envelope,
    MissionPlanning,
    MissionRunning,
    ProjectState,
    SteeringBinding,
    SteeringRequest,
    SupervisionReceipt,
    TaskList,
    TaskListPatch,
    TaskStateFile,
)
from .patch_transaction import (
    INSTALL_ORDER,
    INTEGRITY_ERROR,
    PatchTransaction,
    PatchTransactionError,
    TransactionTarget,
)
from .project_lock import ProjectLockError, project_access_guard, project_lock_path
from .storage import ProjectStore
from .storage import utc_now_iso
from .supervision import (
    SupervisionSnapshotError,
    SupervisionSteeringError,
    binding_from_snapshot,
    load_project_active_attempts,
    load_snapshot,
    load_supervision_receipts,
    recover_supervision,
    report_supervision_checkpoint,
    save_snapshot,
    steer_attempt as apply_steering,
    terminal_snapshot,
)
from .task_list_patch import apply_patch
from .task_validation import (
    ValidationError,
    parse_contract_dir,
    validate_task_list_submission,
)


MAX_ABORT_REASON_BYTES = 4096


@dataclass
class ToolError(Exception):
    code: str
    message: str
    details: list[ValidationError] | None = None

    def __str__(self) -> str:
        if self.details:
            tail = "; ".join(str(d) for d in self.details)
            return f"{self.code}: {self.message} ({tail})"
        return f"{self.code}: {self.message}"


class ProjectController:
    def __init__(
        self,
        config: HarnessConfig,
        dispatcher: NodeDispatcher,
        terminal_reviewer: TerminalReviewer,
        *,
        store: ProjectStore | None = None,
    ):
        self.config = config
        self.store = store or ProjectStore(config)
        self.dispatcher = dispatcher
        self.terminal_reviewer = terminal_reviewer

    def apply_accepted_point_plan(
        self,
        project_id: str,
        plan: object,
        issuer_proof: object,
    ) -> object:
        """Delegate one closed mutation plan to the store-owned authority."""

        return self.store.apply_accepted_point_plan(project_id, plan, issuer_proof)

    def local_grant_custodian(self, project_id: str, actor_id: str):
        """Bind an explicit local operator identity to immutable grant custody."""

        from .accepted_point_authority import HostGrantCustodian, _mint_local_host_actor

        repository = self.store.workspace_dir(project_id).resolve(strict=True)
        actor = _mint_local_host_actor(repository, actor_id)
        return HostGrantCustodian(repository, project_id, actor)

    # ------------------------------------------------------------------
    # Tool methods
    # ------------------------------------------------------------------

    def start_project(
        self,
        brief: str,
        workspace_dir: str,
        worker_model: str | None = None,
        worker_reasoning_effort: str | None = None,
    ) -> Envelope:
        if not brief.strip():
            raise ToolError("invalid_brief", "brief is empty")
        if worker_model is not None and not worker_model.strip():
            raise ToolError("invalid_worker_model", "worker_model is empty")
        worker_provider = self.config.for_role("worker").worker_provider.name
        if (worker_model is not None or worker_reasoning_effort is not None) and worker_provider != "codex":
            raise ToolError(
                "invalid_worker_override_provider",
                "worker model and project effort overrides require a Codex worker",
            )
        if (
            worker_reasoning_effort is not None
            and worker_reasoning_effort not in VALID_REASONING_EFFORTS
        ):
            raise ToolError(
                "invalid_worker_reasoning_effort",
                "worker_reasoning_effort must be one of: "
                + ", ".join(VALID_REASONING_EFFORTS),
            )
        record = self.store.create_project(
            brief,
            workspace_dir,
            worker_model=worker_model,
            worker_reasoning_effort=worker_reasoning_effort,
        )
        mission_id = self.store.generate_mission_id(1)
        record.current_mission_id = mission_id
        self.store.save_project(record)
        self.store.save_state(
            record.id, MissionPlanning(mission_id=mission_id)
        )
        return self._build_envelope(record.id, dag_mode="none")

    def submit_plan(self, project_id: str, task_list: TaskList) -> Envelope:
        with self._project_access(project_id):
            return self._submit_plan(project_id, task_list)

    def _submit_plan(self, project_id: str, task_list: TaskList) -> Envelope:
        state = self._require_state(project_id)
        if not isinstance(state, MissionPlanning):
            raise ToolError(
                "wrong_state",
                f"submit_plan requires MissionPlanning; got {state.state}",
            )
        mid = state.mission_id
        contract_dir = self.store.ensure_contract_dir(project_id, mid)
        ids, parse_errs = parse_contract_dir(contract_dir)
        if parse_errs:
            raise ToolError(
                "invalid_contract_dir",
                "contract directory invalid",
                details=parse_errs,
            )
        errs = validate_task_list_submission(ids, task_list)
        if errs:
            raise ToolError(
                "invalid_task_list", "task list validation failed", details=errs
            )

        self.store.save_task_list(project_id, mid, task_list)
        task_state = TaskStateFile()
        for task in task_list.tasks:
            task_state.set_status(task.id, "pending")
        self.store.save_task_state(project_id, mid, task_state)
        cs = ContractStateFile()
        for aid in ids:
            cs.items.setdefault(aid, _make_pending())
        self.store.save_contract_state(project_id, mid, cs)
        self.store.save_state(project_id, MissionRunning(mission_id=mid))
        return self._build_envelope(project_id, dag_mode="frontier")

    def advance_project(
        self,
        project_id: str,
        max_steps: int | None = None,
    ) -> Envelope:
        with self._project_access(project_id):
            return self._advance_project(project_id, max_steps)

    def _advance_project(
        self,
        project_id: str,
        max_steps: int | None = None,
    ) -> Envelope:
        self.store.sync_workspace_skill_surfaces(project_id)
        coordinator = MissionCoordinator(
            self.store, project_id, self.dispatcher, self.terminal_reviewer
        )
        steps = 0
        while True:
            result = coordinator.step()
            if result.kind in ("attention_needed", "terminal", "idle"):
                break
            steps += 1
            if max_steps is not None and steps >= max_steps:
                break
        self.store.sync_workspace_skill_surfaces(project_id)
        return self._build_envelope(project_id, dag_mode="frontier")

    def end_mission(
        self, project_id: str, deliverable_roots: list[str] | None = None
    ) -> Envelope:
        with self._project_access(project_id):
            return self._end_mission(project_id, deliverable_roots)

    def _end_mission(
        self, project_id: str, deliverable_roots: list[str] | None = None
    ) -> Envelope:
        state = self._require_state(project_id)
        if not isinstance(state, MissionRunning):
            raise ToolError(
                "wrong_state",
                f"end_mission requires MissionRunning; got {state.state}",
            )
        coordinator = MissionCoordinator(
            self.store, project_id, self.dispatcher, self.terminal_reviewer
        )
        try:
            resolved_roots = (
                None
                if deliverable_roots is None
                else self.store.resolve_terminal_review_roots(
                    project_id, state.mission_id, deliverable_roots
                )
            )
        except ValueError as exc:
            raise ToolError("invalid_deliverable_roots", str(exc)) from exc
        try:
            result = coordinator.close_mission(
                state.mission_id, deliverable_roots=resolved_roots
            )
        except ValueError as exc:
            raise ToolError("invalid_deliverable_roots", str(exc)) from exc
        if result.kind == "idle":
            raise ToolError(
                "mission_not_ready_to_close",
                result.detail or "mission still has runnable task work",
            )
        return self._build_envelope(project_id, dag_mode="none")

    def decide_attention(
        self,
        project_id: str,
        decisions: list[Decision],
    ) -> Envelope:
        with self._project_access(project_id):
            return self._decide_attention(project_id, decisions)

    def _decide_attention(
        self,
        project_id: str,
        decisions: list[Decision],
    ) -> Envelope:
        state = self._require_state(project_id)
        if not isinstance(state, AttentionNeeded):
            raise ToolError(
                "wrong_state",
                f"decide_attention requires AttentionNeeded; got {state.state}",
            )
        open_items = self.store.load_attention(project_id)
        validation_errs = self._validate_decisions(decisions, open_items)
        if validation_errs:
            raise ToolError(
                "invalid_decisions",
                "decision validation failed",
                details=validation_errs,
            )
        item_by_id = {it.id: it for it in open_items}
        if any(decision.action == "patch" for decision in decisions):
            return self._apply_transactional_decisions(
                project_id, decisions, open_items, item_by_id
            )
        next_state = self._apply_decisions(project_id, decisions, item_by_id)
        self.store.append_decision_record(project_id, decisions, open_items)
        self.store.clear_attention(project_id)
        self.store.save_state(project_id, next_state)
        return self._build_envelope(project_id, dag_mode="none")

    def inspect_project(self, project_id: str) -> Envelope:
        with self._project_access(project_id):
            return self._build_envelope(project_id, dag_mode="full")

    def report_supervision_checkpoint(
        self, snapshot: ActiveAttemptSnapshot
    ) -> SteeringBinding:
        """Local seam for INT-owned worker/validator/reviewer MCP adapters."""
        try:
            assigned = self._assigned_supervision_targets(snapshot)
            return report_supervision_checkpoint(
                self.store, snapshot, assigned_target_ids=assigned
            )
        except (SupervisionSnapshotError, SupervisionSteeringError) as exc:
            code = getattr(exc, "code", "invalid_supervision_snapshot")
            raise ToolError(code, "supervision checkpoint refused") from exc

    def steer_attempt(
        self,
        request: SteeringRequest,
        *,
        delivery_supported: bool = True,
    ) -> SupervisionReceipt:
        """Orchestrator-only local seam; shared transport remains INT-owned."""
        try:
            return apply_steering(
                self.store, request, delivery_supported=delivery_supported
            )
        except (SupervisionSnapshotError, SupervisionSteeringError) as exc:
            code = getattr(exc, "code", "invalid_supervision_snapshot")
            raise ToolError(code, "steering action refused") from exc

    def complete_cooperative_stop(
        self,
        binding: SteeringBinding,
        *,
        safe_handoff: str,
    ) -> Envelope:
        """Enter existing attention authority after a checkpoint stop handoff."""
        with self._project_access(binding.project_id):
            try:
                recover_supervision(
                    self.store, binding.project_id, binding.mission_id
                )
            except (SupervisionSnapshotError, SupervisionSteeringError) as exc:
                code = getattr(exc, "code", "invalid_supervision_snapshot")
                raise ToolError(code, "cooperative stop recovery refused") from exc
            snapshot = load_snapshot(
                self.store,
                binding.project_id,
                binding.mission_id,
                binding.attempt_id,
            )
            if snapshot is None or binding_from_snapshot(snapshot) != binding:
                raise ToolError(
                    "steering_binding_mismatch", "cooperative stop binding refused"
                )
            rows = [
                receipt
                for receipt in load_supervision_receipts(
                    self.store, binding.project_id, binding.mission_id
                )
                if (
                    receipt.project_id,
                    receipt.mission_id,
                    receipt.node_id,
                    receipt.terminal_review_id,
                    receipt.attempt_id,
                    receipt.checkpoint_sequence,
                )
                == (
                    binding.project_id,
                    binding.mission_id,
                    binding.node_id,
                    binding.terminal_review_id,
                    binding.attempt_id,
                    binding.checkpoint_sequence,
                )
            ]
            if len(rows) != 1 or rows[0].code != "stop_requested":
                raise ToolError(
                    "stop_handoff_integrity_error", "stop receipt is missing"
                )
            existing_attention = self.store.load_attention(binding.project_id)
            if snapshot.phase == "terminal":
                matching_attention = [
                    item
                    for item in existing_attention
                    if (
                        item.mission_id == binding.mission_id
                        and item.node_id == binding.node_id
                        and item.attempt_id == binding.attempt_id
                        and item.terminal_review_id == binding.terminal_review_id
                    )
                ]
                if len(matching_attention) > 1:
                    raise ToolError(
                        "stop_handoff_integrity_error",
                        "cooperative stop has duplicate attention",
                    )
                if not matching_attention:
                    existing_attention.append(cooperative_stop(snapshot, safe_handoff))
                    self.store.save_attention(binding.project_id, existing_attention)
                if snapshot.node_id is not None:
                    task_state = self.store.load_task_state(
                        binding.project_id, binding.mission_id
                    )
                    if task_state.status_of(snapshot.node_id) != "failed":
                        task_state.set_status(snapshot.node_id, "failed")
                        self.store.save_task_state(
                            binding.project_id, binding.mission_id, task_state
                        )
                self.store.save_state(
                    binding.project_id,
                    AttentionNeeded(items=public_attention_items(existing_attention)),
                )
                return self._build_envelope(binding.project_id, dag_mode="none")
            if (
                snapshot.phase != "stopping"
                or snapshot.supervision_status != "stop_requested"
            ):
                raise ToolError(
                    "stop_not_requested", "cooperative stop was not requested"
                )
            terminal = terminal_snapshot(snapshot)
            save_snapshot(
                self.store,
                terminal,
                assigned_target_ids=self._assigned_supervision_targets(snapshot),
            )
            item = cooperative_stop(terminal, safe_handoff)
            existing_attention.append(item)
            self.store.save_attention(binding.project_id, existing_attention)
            if snapshot.node_id is not None:
                task_state = self.store.load_task_state(
                    binding.project_id, binding.mission_id
                )
                task_state.set_status(snapshot.node_id, "failed")
                self.store.save_task_state(
                    binding.project_id, binding.mission_id, task_state
                )
            self.store.save_state(
                binding.project_id,
                AttentionNeeded(items=public_attention_items(existing_attention)),
            )
            return self._build_envelope(binding.project_id, dag_mode="none")

    def abort_project(self, project_id: str, reason: str) -> Envelope:
        with self._project_access(project_id):
            return self._abort_project(project_id, reason)

    def _abort_project(self, project_id: str, reason: str) -> Envelope:
        try:
            reason_bytes = reason.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ToolError(
                "invalid_abort_reason", "abort reason is not valid Unicode"
            ) from exc
        if not reason.strip():
            raise ToolError("invalid_abort_reason", "abort reason is empty")
        if len(reason_bytes) > MAX_ABORT_REASON_BYTES:
            raise ToolError(
                "abort_reason_too_large",
                f"abort reason exceeds {MAX_ABORT_REASON_BYTES} UTF-8 bytes",
            )
        record = self.store.load_project(project_id)
        state = self.store.load_state(project_id)
        mid = self._current_mission_id(record, state)
        if mid:
            try:
                self.store.seal_mission(
                    project_id, mid, status="aborted", body=reason
                )
            except FileNotFoundError:
                pass
        self.store.clear_attention(project_id)
        self.store.save_state(project_id, Aborted(reason=reason))
        return self._build_envelope(project_id, dag_mode="none")

    def _assigned_supervision_targets(
        self, snapshot: ActiveAttemptSnapshot
    ) -> list[str]:
        task_list = self.store.load_task_list(snapshot.project_id, snapshot.mission_id)
        if snapshot.node_id is not None:
            task = next(
                (item for item in task_list.tasks if item.id == snapshot.node_id), None
            )
            if task is None:
                raise SupervisionSteeringError("steering_binding_mismatch")
            expected_role = "validator" if task.type == "validate" else "worker"
            if task.type == "gate" or snapshot.role != expected_role:
                raise SupervisionSteeringError("steering_binding_mismatch")
            return task.targets
        targets: list[str] = []
        for task in task_list.tasks:
            for target in task.targets:
                if target not in targets:
                    targets.append(target)
        return targets

    def _apply_transactional_decisions(
        self,
        project_id: str,
        decisions: list[Decision],
        open_items: list[AttentionItemInternal],
        item_by_id: dict[str, AttentionItemInternal],
    ) -> Envelope:
        record = self.store.load_project(project_id)
        mission_ids = {item.mission_id for item in open_items}
        if len(mission_ids) != 1:
            raise ToolError(
                "patch_transaction_unsupported_batch",
                "decision batch spans multiple missions",
            )
        mission_id = next(iter(mission_ids))
        task_list = self.store.load_task_list(project_id, mission_id).model_copy(deep=True)
        task_state = self.store.load_task_state(project_id, mission_id).model_copy(deep=True)
        contract_state = self.store.load_contract_state(
            project_id, mission_id
        ).model_copy(deep=True)
        edges = self._extended_lineage(project_id, mission_id, decisions)
        next_state: ProjectState | None = None
        seal_bytes = self._read_optional(
            self.store.mission_dir(project_id, mission_id) / "closeout.md"
        )
        timestamp = utc_now_iso()

        for decision in decisions:
            item = item_by_id[decision.item_id]
            if decision.action == "patch":
                assert decision.patch is not None
                old_ids = set(contract_state.items)
                all_ids = set(
                    self.store.list_contract_assertions(project_id, mission_id)
                )
                patched, patched_state, patched_ids, errors = apply_patch(
                    task_list,
                    task_state,
                    old_ids,
                    decision.patch,
                    new_contract_ids_on_disk=all_ids - old_ids,
                )
                if errors:
                    raise ToolError(
                        "invalid_patch",
                        "patch validation failed",
                        details=errors,
                    )
                task_list, task_state = patched, patched_state
                for assertion_id in patched_ids - old_ids:
                    contract_state.items.setdefault(assertion_id, _make_pending())
                retired = set(decision.patch.supersede) | set(decision.patch.cancel)
                if (
                    item.kind in ("node_failed", "gate_failed")
                    and item.node_id
                    and item.node_id not in retired
                ):
                    task_state.set_status(item.node_id, "pending")
                next_state = MissionRunning(mission_id=mission_id)
            elif decision.action == "retry" and item.node_id:
                task_state.set_status(item.node_id, "pending")
                next_state = MissionRunning(mission_id=mission_id)
            elif decision.action == "continue":
                if item.kind in ("node_failed", "gate_failed") and item.node_id:
                    task_state.set_status(item.node_id, "cleared")
                    next_state = MissionRunning(mission_id=mission_id)
                elif item.kind != "terminal_review":
                    next_state = MissionRunning(mission_id=mission_id)
            elif decision.action == "abort":
                next_state = Aborted(reason=decision.justification or "aborted")
            elif decision.action == "next_mission":
                seal = self.store.render_mission_seal(
                    mission_id,
                    status="done_with_acknowledged_gaps",
                    body=(
                        "Sealed with gap(s) acknowledged via next_mission decision."
                    ),
                    timestamp=timestamp,
                )
                seal_bytes = self.store.render_text_bytes(seal)
                new_mission_id = self.store.generate_mission_id(
                    len(self.store.list_missions(project_id)) + 1
                )
                record.current_mission_id = new_mission_id
                next_state = MissionPlanning(mission_id=new_mission_id)

        if next_state is None:
            next_state = (
                MissionRunning(mission_id=record.current_mission_id)
                if record.current_mission_id
                else Draft()
            )

        number = self.store.next_decision_number(project_id)
        decision_path, decision_text = self.store.plan_decision_record(
            project_id,
            decisions,
            open_items,
            number=number,
            timestamp=timestamp,
        )
        if decision_path.exists():
            raise ToolError(INTEGRITY_ERROR, "decision record already exists")

        bucket = self.store.bucket_root(project_id)
        paths = {
            "task_list": self.store.mission_runtime_dir(project_id, mission_id)
            / "tasks.json",
            "task_state": self.store.mission_runtime_dir(project_id, mission_id)
            / "task-state.json",
            "contract_state": self.store.mission_runtime_dir(project_id, mission_id)
            / "contract-state.json",
            "supersession_lineage": self.store.supersession_lineage_path(
                project_id, mission_id
            ),
            "mission_seal": self.store.mission_dir(project_id, mission_id)
            / "closeout.md",
            "project_record": self.store.unrest_runtime_dir(project_id)
            / "project.json",
            "decision_record": decision_path,
            "attention_cursor": self.store.unrest_runtime_dir(project_id)
            / "attention.json",
            "project_state": self.store.unrest_runtime_dir(project_id) / "state.json",
        }
        post_images: dict[str, bytes | None] = {
            "task_list": self.store.render_json_bytes(task_list.model_dump(mode="json")),
            "task_state": self.store.render_json_bytes(task_state.model_dump(mode="json")),
            "contract_state": self.store.render_json_bytes(
                contract_state.model_dump(mode="json")
            ),
            "supersession_lineage": self.store.render_supersession_lineage(edges),
            "mission_seal": seal_bytes,
            "project_record": self.store.render_json_bytes(record.model_dump(mode="json")),
            "decision_record": self.store.render_text_bytes(decision_text),
            "attention_cursor": self.store.render_json_bytes(
                AttentionFile(items=[]).model_dump(mode="json")
            ),
            "project_state": self.store.render_json_bytes(
                next_state.model_dump(mode="json")
            ),
        }
        targets = [
            TransactionTarget.from_images(
                kind,
                paths[kind].relative_to(bucket).as_posix(),
                self._read_optional(paths[kind]),
                post_images[kind],
            )
            for kind in INSTALL_ORDER
        ]
        transaction = PatchTransaction(
            bucket,
            mission_id,
            f"decision-{number:03d}",
            targets,
        )
        transaction.execute()
        return self._build_envelope(project_id, dag_mode="none")

    def _extended_lineage(
        self, project_id: str, mission_id: str, decisions: list[Decision]
    ) -> list[dict[str, dict[str, str]]]:
        try:
            edges = self.store.load_supersession_edges(project_id, mission_id)
        except ValueError as exc:
            raise ToolError(INTEGRITY_ERROR, "invalid supersession lineage") from exc
        keys = {
            (
                edge["old"]["mission_id"],
                edge["old"]["node_id"],
                edge["new"]["mission_id"],
                edge["new"]["node_id"],
            )
            for edge in edges
        }
        for decision in decisions:
            if decision.action != "patch" or decision.patch is None:
                continue
            for old_id, new_id in decision.patch.supersede.items():
                key = (mission_id, old_id, mission_id, new_id)
                if key in keys:
                    raise ToolError("invalid_patch", "duplicate supersession edge")
                keys.add(key)
                edges.append(
                    {
                        "new": {"mission_id": mission_id, "node_id": new_id},
                        "old": {"mission_id": mission_id, "node_id": old_id},
                    }
                )
        if len(edges) > 256:
            raise ToolError(
                "lineage_limit_exceeded", "supersession lineage exceeds 256 edges"
            )
        self._validate_lineage_cycles(edges)
        return edges

    @staticmethod
    def _validate_lineage_cycles(
        edges: list[dict[str, dict[str, str]]],
    ) -> None:
        successors: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for edge in edges:
            old = edge["old"]
            new = edge["new"]
            old_key = (old["mission_id"], old["node_id"])
            new_key = (new["mission_id"], new["node_id"])
            successors.setdefault(old_key, []).append(new_key)
        visiting: set[tuple[str, str]] = set()
        visited: set[tuple[str, str]] = set()

        def visit(node: tuple[str, str]) -> None:
            if node in visiting:
                raise ToolError("invalid_patch", "cyclic supersession lineage")
            if node in visited:
                return
            visiting.add(node)
            for child in successors.get(node, []):
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for node in tuple(successors):
            visit(node)

    @staticmethod
    def _read_optional(path: Path) -> bytes | None:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    @contextmanager
    def _project_access(self, project_id: str) -> Iterator[None]:
        try:
            lock_path = project_lock_path(self.store, project_id)
            with project_access_guard(self.store, project_id):
                if lock_path is not None:
                    self.store.recover_patch_transactions(project_id)
                yield
        except PatchTransactionError as exc:
            raise ToolError(exc.code, "project transaction unavailable") from exc
        except ProjectLockError as exc:
            raise ToolError("project_lock_error", "project lock unavailable") from exc

    # ------------------------------------------------------------------
    # Decision pipeline
    # ------------------------------------------------------------------

    def _validate_decisions(
        self,
        decisions: list[Decision],
        open_items: list[AttentionItemInternal],
    ) -> list[ValidationError]:
        errs: list[ValidationError] = []
        item_ids = {it.id for it in open_items}
        decided_ids = {d.item_id for d in decisions}
        for missing in sorted(item_ids - decided_ids):
            errs.append(ValidationError("unresolved_attention_item", missing))
        for extra in sorted(decided_ids - item_ids):
            errs.append(ValidationError("unknown_attention_item", extra))
        seen: set[str] = set()
        for dec in decisions:
            if dec.item_id in seen:
                errs.append(
                    ValidationError("duplicate_decision", dec.item_id)
                )
            seen.add(dec.item_id)
        item_by_id = {it.id: it for it in open_items}
        for dec in decisions:
            it = item_by_id.get(dec.item_id)
            if it is None:
                continue
            if dec.action == "retry" and it.kind != "node_failed":
                errs.append(
                    ValidationError("invalid_action", "retry is only valid for node_failed")
                )
            if dec.action == "next_mission" and it.kind != "terminal_review":
                errs.append(
                    ValidationError(
                        "invalid_action",
                        "next_mission is only valid for runtime closure reports",
                    )
                )
            if dec.action == "patch":
                if dec.patch is None:
                    errs.append(
                        ValidationError(
                            "missing_patch",
                            f"item {dec.item_id} action=patch requires patch",
                        )
                    )
                elif dec.patch.is_empty:
                    errs.append(
                        ValidationError("empty_patch", dec.item_id)
                    )
        return errs

    def _apply_decisions(
        self,
        project_id: str,
        decisions: list[Decision],
        item_by_id: dict[str, AttentionItemInternal],
    ) -> ProjectState:
        next_state: ProjectState | None = None
        for dec in decisions:
            item = item_by_id[dec.item_id]
            outcome = self._apply_one(project_id, item, dec)
            if outcome is not None:
                next_state = outcome
        if next_state is not None:
            return next_state
        record = self.store.load_project(project_id)
        mid = record.current_mission_id
        if mid:
            return MissionRunning(mission_id=mid)
        return Draft()

    def _apply_one(
        self,
        project_id: str,
        item: AttentionItemInternal,
        decision: Decision,
    ) -> ProjectState | None:
        mid = item.mission_id
        kind = item.kind
        action = decision.action

        if action == "patch":
            assert decision.patch is not None
            self._apply_task_list_patch(project_id, mid, decision.patch)
            task_state = self.store.load_task_state(project_id, mid)
            # A task superseded or cancelled by this same patch is already
            # marked `superseded` by apply_patch — do not reset it to pending.
            retired_ids = (
                set(decision.patch.supersede.keys()) | set(decision.patch.cancel)
            )
            if kind in ("node_failed", "gate_failed") and item.node_id:
                if item.node_id not in retired_ids:
                    task_state.set_status(item.node_id, "pending")
            self.store.save_task_state(project_id, mid, task_state)
            return MissionRunning(mission_id=mid)

        if action == "retry" and item.node_id:
            ts = self.store.load_task_state(project_id, mid)
            ts.set_status(item.node_id, "pending")
            self.store.save_task_state(project_id, mid, ts)
            return MissionRunning(mission_id=mid)

        if action == "continue":
            if kind in ("node_failed", "gate_failed") and item.node_id:
                ts = self.store.load_task_state(project_id, mid)
                ts.set_status(item.node_id, "cleared")
                self.store.save_task_state(project_id, mid, ts)
                return MissionRunning(mission_id=mid)
            if kind == "terminal_review":
                return None
            return MissionRunning(mission_id=mid)

        if action == "abort":
            return Aborted(reason=decision.justification or "aborted")

        if action == "next_mission":
            return self._seal_and_plan_next(project_id, mid)

        return None

    def _seal_and_plan_next(self, project_id: str, mid: str) -> ProjectState:
        self.store.seal_mission(
            project_id,
            mid,
            status="done_with_acknowledged_gaps",
            body="Sealed with gap(s) acknowledged via next_mission decision.",
        )
        existing = self.store.list_missions(project_id)
        new_mid = self.store.generate_mission_id(len(existing) + 1)
        record = self.store.load_project(project_id)
        record.current_mission_id = new_mid
        self.store.save_project(record)
        return MissionPlanning(mission_id=new_mid)

    def _apply_task_list_patch(
        self, project_id: str, mid: str, patch: TaskListPatch
    ) -> None:
        tl = self.store.load_task_list(project_id, mid)
        task_state = self.store.load_task_state(project_id, mid)
        contract_state = self.store.load_contract_state(project_id, mid)
        old_ids = set(contract_state.items.keys())
        all_ids_on_disk = set(self.store.list_contract_assertions(project_id, mid))
        new_on_disk = all_ids_on_disk - old_ids

        patched_tl, patched_state, patched_ids, errs = apply_patch(
            tl,
            task_state,
            old_ids,
            patch,
            new_contract_ids_on_disk=new_on_disk,
        )
        if errs:
            raise ToolError(
                "invalid_patch", "patch validation failed", details=errs
            )
        self.store.save_task_list(project_id, mid, patched_tl)
        self.store.save_task_state(project_id, mid, patched_state)
        cs = self.store.load_contract_state(project_id, mid)
        for aid in patched_ids - old_ids:
            cs.items.setdefault(aid, _make_pending())
        self.store.save_contract_state(project_id, mid, cs)

    # ------------------------------------------------------------------
    # Envelope
    # ------------------------------------------------------------------

    def _build_envelope(
        self, project_id: str, *, dag_mode: EnvelopeDagMode = "summary"
    ) -> Envelope:
        record = self.store.load_project(project_id)
        state = self.store.load_state(project_id) or Draft()
        if isinstance(state, AttentionNeeded):
            state = AttentionNeeded(
                items=public_attention_items(self.store.load_attention(project_id))
            )
        tl: TaskList | None = None
        task_state: TaskStateFile | None = None
        lineage = []
        active_attempts = []
        mid = self._current_mission_id(record, state)
        if mid:
            try:
                tl = self.store.load_task_list(project_id, mid)
                task_state = self.store.load_task_state(project_id, mid)
            except FileNotFoundError:
                pass
            try:
                edges = self.store.load_supersession_edges(project_id, mid)
            except ValueError as exc:
                raise ToolError(INTEGRITY_ERROR, "invalid supersession lineage") from exc
            lineage = project_supersession_lineage(mid, tl, task_state, edges)
            if tl is not None:
                try:
                    active_attempts = load_project_active_attempts(
                        self.store, project_id, mid, tl
                    )
                except SupervisionSnapshotError as exc:
                    raise ToolError(
                        INTEGRITY_ERROR, "invalid active-attempt snapshot"
                    ) from exc
        project_root = str(self.store.unrest_dir(project_id))
        harness_root = str(self.store.bucket_root(project_id))
        envelope = make_envelope(
            project_id,
            state,
            project_root,
            harness_root,
            tl,
            task_state,
            dag_mode=dag_mode,
            supersession_lineage=lineage,
        )
        return envelope.model_copy(update={"active_attempts": active_attempts})

    @staticmethod
    def _current_mission_id(record, state) -> str | None:
        if isinstance(state, (MissionPlanning, MissionRunning)):
            return state.mission_id
        return record.current_mission_id

    def _require_state(self, project_id: str) -> ProjectState:
        state = self.store.load_state(project_id)
        if state is None:
            raise ToolError("not_found", f"project {project_id!r} has no state")
        return state


def _make_pending():
    from .models import ContractStateEntry
    return ContractStateEntry()


__all__ = ["ProjectController", "ToolError"]
