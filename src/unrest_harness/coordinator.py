"""MissionCoordinator — the state-machine kernel.

See `specs/task_list/PRODUCT.md` §Dispatch. One `step()` call advances
the state by at most one transition. The controller's `advance_project`
tool loops `step()` until a returnable condition.
"""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Literal

from . import attention as attn_factory
from .accepted_point_authority import (
    AcceptedPointAuthorityError,
    WorkspaceIntegrationPlan,
)
from .mutation_journal import request_fingerprint
from .capability_policy import redact_credential_values
from .dispatcher import (
    DispatchRequest,
    NodeDispatcher,
    NodeHandoff,
    TerminalReviewer,
)
from .models import (
    AttentionItemInternal,
    AttentionNeeded,
    Aborted,
    ContractStateEntry,
    Done,
    Draft,
    Failed,
    MissionPlanning,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    TerminalReviewConfig,
    TerminalReviewHandoff,
    ValidateHandoff,
    WorkHandoff,
)
from .storage import AttemptValidationError, ProjectStore, utc_now_filesafe
from .envelope import public_attention_items
from .task_validation import gates_in_order
from .workspaces import (
    HumanIntegrationGrant,
    ResourceBudget,
    WorkspaceError,
    WorkspaceManager,
)


_WRITES_LINE = re.compile(r"(?im)^writes:\s*(?P<paths>[^\n]+)$")
_MAX_GATE_REPORT_BYTES = 4096


# ---------------------------------------------------------------------------
# StepResult
# ---------------------------------------------------------------------------


StepKind = Literal["idle", "advanced", "attention_needed", "terminal"]


@dataclass(frozen=True)
class StepResult:
    kind: StepKind
    detail: str = ""

    @classmethod
    def idle(cls, detail: str = "") -> "StepResult":
        return cls("idle", detail)

    @classmethod
    def advanced(cls, detail: str = "") -> "StepResult":
        return cls("advanced", detail)

    @classmethod
    def attention_needed(cls, detail: str = "") -> "StepResult":
        return cls("attention_needed", detail)

    @classmethod
    def terminal(cls, detail: str = "") -> "StepResult":
        return cls("terminal", detail)


# ---------------------------------------------------------------------------
# MissionCoordinator
# ---------------------------------------------------------------------------


class MissionCoordinator:
    def __init__(
        self,
        store: ProjectStore,
        project_id: str,
        dispatcher: NodeDispatcher,
        terminal_reviewer: TerminalReviewer,
    ):
        self.store = store
        self.project_id = project_id
        self.dispatcher = dispatcher
        self.terminal_reviewer = terminal_reviewer

    # ------------------------------------------------------------------
    # The main step() kernel
    # ------------------------------------------------------------------

    def step(self) -> StepResult:
        # INVARIANT[ARCH-STATE-001]: One call returns after at most one
        # externally visible state transition.
        state = self.store.load_state(self.project_id)
        if state is None or isinstance(state, Draft):
            return StepResult.idle()
        if isinstance(state, MissionPlanning):
            return StepResult.idle()
        if isinstance(state, AttentionNeeded):
            return StepResult.attention_needed()
        if isinstance(state, (Done, Failed, Aborted)):
            return StepResult.terminal()
        if isinstance(state, MissionRunning):
            return self._step_mission(state.mission_id)
        return StepResult.idle()

    # ------------------------------------------------------------------
    # Mission inner loop
    # ------------------------------------------------------------------

    def _step_mission(self, mid: str) -> StepResult:
        try:
            tl = self.store.load_task_list(self.project_id, mid)
        except FileNotFoundError:
            self.store.save_state(
                self.project_id, Failed(reason=f"tasks.json missing for {mid}")
            )
            return StepResult.terminal("task_list missing")
        task_state = self.store.load_task_state(self.project_id, mid)
        contract_state = self.store.load_contract_state(self.project_id, mid)
        if not contract_state.items:
            for assertion in self.store.list_contract_assertions(self.project_id, mid):
                contract_state.items.setdefault(assertion, ContractStateEntry())
            self.store.save_contract_state(self.project_id, mid, contract_state)

        resume_result = self._reconcile_pending_attempts(mid, tl, task_state)
        if resume_result is not None:
            return resume_result

        gate_event = self._try_evaluate_a_gate(tl, task_state)
        if gate_event is not None:
            return self._apply_gate_event(mid, tl, task_state, gate_event)

        runnable = self._all_runnable_tasks(tl, task_state)
        if not runnable:
            return StepResult.idle("no runnable task work; call end_mission to request closure")

        selected = self._select_dispatch_tasks(tl, task_state, runnable)
        if len(selected) == 1:
            return self._dispatch_one(mid, selected[0])
        return self._dispatch_batch(mid, tl, task_state, selected)

    def _dispatch_one(self, mid: str, task: Task) -> StepResult:
        """Dispatch one work task or one validator."""
        self.store.refresh_inventory(os.environ)
        spawn_ts = utc_now_filesafe()
        task_state = self.store.load_task_state(self.project_id, mid)
        task_state.set_status(task.id, "running")
        task_state.set_last_attempt(task.id, spawn_ts)
        self.store.save_task_state(self.project_id, mid, task_state)

        request = DispatchRequest(
            project_id=self.project_id,
            mission_id=mid,
            task=task,
            spawn_ts=spawn_ts,
        )
        try:
            handoff = self.dispatcher.dispatch(request)
        except Exception as exc:  # noqa: BLE001
            synthetic = self._synthesize_handoff(
                task, self._bounded_dispatch_failure("Dispatcher crashed: ", exc)
            )
            self.store.save_attempt(
                self.project_id,
                mid,
                spawn_ts,
                task.id,
                synthetic,
            )
            return self._apply_handoff(mid, task, synthetic, spawn_ts)

        handoff = self._bind_dispatched_handoff(task, handoff, spawn_ts)
        self.store.save_attempt(self.project_id, mid, spawn_ts, task.id, handoff)
        return self._apply_handoff(mid, task, handoff, spawn_ts)

    # ------------------------------------------------------------------
    # Runnable selection (the only graph-shape-coupled code)
    # ------------------------------------------------------------------

    def _next_runnable_task(
        self, tl: TaskList, task_state: TaskStateFile
    ) -> Task | None:
        pending = self._all_runnable_tasks(tl, task_state)
        if not pending:
            return None
        return pending[0]

    def _all_runnable_tasks(
        self, tl: TaskList, task_state: TaskStateFile
    ) -> list[Task]:
        """Runnable = non-gate, pending, all deps cleared.

        `supersede` and `cancel` patches rewrite downstream `depends_on`
        in-place at patch time, so the runtime never sees a dep pointing at
        a retired task. The check is plain `status == cleared`.

        List order is preserved as a topological tie-break per spec G4.
        """
        runnable: list[Task] = []
        for task in tl.tasks:
            if task.type == "gate":
                continue
            if task_state.status_of(task.id) != "pending":
                continue
            if all(
                task_state.status_of(dep) == "cleared" for dep in task.depends_on
            ):
                runnable.append(task)
        return runnable

    @staticmethod
    def _validator_batch_for_pending_gate(
        tl: TaskList,
        task_state: TaskStateFile,
        runnable: list[Task],
    ) -> list[Task]:
        """Prefer a complete ready validator lane before starting more work."""
        by_id = {task.id: task for task in tl.tasks}
        runnable_validators = {
            task.id
            for task in runnable
            if task.type == "validate"
        }
        for gate in (task for task in tl.tasks if task.type == "gate"):
            if task_state.status_of(gate.id) != "pending":
                continue
            validator_dep_ids = [
                dep_id
                for dep_id in gate.depends_on
                if by_id.get(dep_id) is not None and by_id[dep_id].type == "validate"
            ]
            if not validator_dep_ids:
                continue
            deps_ready = True
            for dep_id in gate.depends_on:
                dep = by_id.get(dep_id)
                if dep is not None and dep.type == "validate":
                    deps_ready = (
                        task_state.status_of(dep_id) == "cleared"
                        or dep_id in runnable_validators
                    )
                else:
                    deps_ready = task_state.status_of(dep_id) == "cleared"
                if not deps_ready:
                    break
            if not deps_ready:
                continue
            validator_dep_set = set(runnable_validators).intersection(validator_dep_ids)
            return [
                task
                for task in runnable
                if task.id in validator_dep_set
            ]
        return []

    def _select_dispatch_tasks(
        self,
        tl: TaskList,
        task_state: TaskStateFile,
        runnable: list[Task],
    ) -> list[Task]:
        """Select one mutable task or a validator-only batch.

        A complete ready gate-validation lane retains priority over unrelated
        runnable work, subject to the same configured capacity ceiling.
        Otherwise the configured-capacity slice is considered in authored
        order. If that slice contains mutable work, only its first authored
        task is selected; validator-only slices retain batching.
        """
        capacity = max(1, self.store.config.max_parallel_nodes)
        validator_batch = self._validator_batch_for_pending_gate(
            tl, task_state, runnable
        )
        if validator_batch:
            return validator_batch[:capacity]

        candidate_batch = runnable[:capacity]
        work_batch = [task for task in candidate_batch if task.type == "work"]
        if work_batch:
            if len(work_batch) >= 2 and self._isolated_work_supported(work_batch):
                return work_batch
            # Shared-checkout work and tasks without explicit disjoint write
            # scopes preserve the v0.3.0 serial behavior.
            return candidate_batch[:1]
        return candidate_batch

    def _isolated_work_supported(self, batch: list[Task]) -> bool:
        if not bool(getattr(self.dispatcher, "supports_isolated_workspaces", False)):
            return False
        if any(not task.auto_merge for task in batch):
            return False
        scopes = [self._task_write_paths(task) for task in batch]
        if any(not scope for scope in scopes):
            return False
        flattened = [path for scope in scopes for path in scope]
        if any(
            self._paths_overlap(left, right)
            for index, left in enumerate(flattened)
            for right in flattened[index + 1 :]
        ):
            return False
        try:
            workspace = self.store.workspace_dir(self.project_id).resolve(strict=True)
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=workspace,
                check=True,
                capture_output=True,
                text=True,
            )
            return Path(result.stdout.strip()).resolve() == workspace
        except (FileNotFoundError, OSError, subprocess.CalledProcessError):
            return False

    @staticmethod
    def _task_write_paths(task: Task) -> tuple[str, ...]:
        match = _WRITES_LINE.search(task.body)
        if match is None:
            return ()
        paths = tuple(
            sorted(
                {
                    item.strip()
                    for item in match.group("paths").split(",")
                    if item.strip()
                }
            )
        )
        return paths

    @staticmethod
    def _paths_overlap(left: str, right: str) -> bool:
        return left == right or left.startswith(right + "/") or right.startswith(left + "/")

    def _dispatch_batch(
        self,
        mid: str,
        tl: TaskList,
        task_state: TaskStateFile,
        batch: list[Task],
    ) -> StepResult:
        if any(task.type == "work" for task in batch):
            if not all(task.type == "work" for task in batch):
                raise RuntimeError("mutable and validation work cannot share a batch")
            if len(batch) < 2 or not self._isolated_work_supported(batch):
                raise RuntimeError(
                    "mutable work batch requires isolated disjoint workspaces"
                )
            return self._dispatch_isolated_work_batch(mid, task_state, batch)

        self.store.refresh_inventory(os.environ)
        batch_attempts: list[_BatchAttempt] = []
        for index, task in enumerate(batch):
            spawn_ts = self._batch_spawn_ts(index)
            task_state.set_status(task.id, "running")
            task_state.set_last_attempt(task.id, spawn_ts)
            batch_attempts.append(
                _BatchAttempt(task=task, spawn_ts=spawn_ts)
            )
        self.store.save_task_state(self.project_id, mid, task_state)

        requests = [
            DispatchRequest(
                project_id=self.project_id,
                mission_id=mid,
                task=attempt.task,
                spawn_ts=attempt.spawn_ts,
            )
            for attempt in batch_attempts
        ]
        handoffs = self._dispatch_requests(requests)

        attention: list[AttentionItemInternal] = []
        for attempt in sorted(batch_attempts, key=lambda item: item.task.id):
            handoff = self._bind_dispatched_handoff(
                attempt.task, handoffs[attempt.task.id], attempt.spawn_ts
            )
            self.store.save_attempt(
                self.project_id,
                mid,
                attempt.spawn_ts,
                attempt.task.id,
                handoff,
            )
            attention.extend(
                self._apply_handoff_collect(mid, attempt.task, handoff, attempt.spawn_ts)
            )

        if attention:
            self._raise_attention(attention)
            return StepResult.attention_needed("batch_attention")
        return StepResult.advanced(
            "batch cleared: " + ", ".join(attempt.task.id for attempt in batch_attempts)
        )

    def _dispatch_isolated_work_batch(
        self,
        mid: str,
        task_state: TaskStateFile,
        batch: list[Task],
    ) -> StepResult:
        """Dispatch explicit disjoint scopes in T1 worktrees, then integrate.

        ``Writes: path, ...`` in each task body is the plan-authorized scope.
        Missing, malformed, overlapping, dirty-parent, or non-Git admission
        preserves the legacy serial path and makes no isolation claim.
        """

        repository = self.store.workspace_dir(self.project_id).resolve(strict=True)
        manager: WorkspaceManager
        leases: dict[str, Any] = {}
        try:
            manager = WorkspaceManager(
                repository,
                custody_root_id=f"mission:{self.project_id}:{mid}",
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            policy_bytes = (
                self.store.config.bundled_dir
                / "policies"
                / "role-capabilities.v1.json"
            ).read_bytes()
            policy_digest = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
            batch_attempts: list[_BatchAttempt] = []
            for index, task in enumerate(batch):
                spawn_ts = self._batch_spawn_ts(index)
                lease = manager.lease_workspace(
                    base_revision=base,
                    owner_id=(
                        f"mission-task:{self.project_id}:{mid}:"
                        f"{task.id}:{spawn_ts}"
                    ),
                    declared_write_paths=self._task_write_paths(task),
                    capability_policy_digest=policy_digest,
                    duration_seconds=max(
                        60, self.store.config.terminal_review_timeout_seconds
                    ),
                    lease_id=f"lease:{self._lease_token(mid, task.id, spawn_ts)}",
                    resource_budget=ResourceBudget(max_processes=0),
                )
                leases[task.id] = lease
                batch_attempts.append(_BatchAttempt(task=task, spawn_ts=spawn_ts))
        except (OSError, subprocess.CalledProcessError, WorkspaceError):
            for lease in leases.values():
                try:
                    manager.cancel_workspace(lease.lease_id)
                    manager.cleanup_workspace(lease.lease_id)
                except (UnboundLocalError, WorkspaceError):
                    pass
            return self._dispatch_one(mid, batch[0])

        self.store.refresh_inventory(os.environ)
        for attempt in batch_attempts:
            task_state.set_status(attempt.task.id, "running")
            task_state.set_last_attempt(attempt.task.id, attempt.spawn_ts)
        self.store.save_task_state(self.project_id, mid, task_state)

        requests = [
            DispatchRequest(
                project_id=self.project_id,
                mission_id=mid,
                task=attempt.task,
                spawn_ts=attempt.spawn_ts,
                cwd=leases[attempt.task.id].worktree_path,
            )
            for attempt in batch_attempts
        ]
        handoffs = self._dispatch_requests(requests)
        batch_error: str | None = None
        grants: list[HumanIntegrationGrant] = []
        bound_handoffs: dict[str, NodeHandoff] = {}
        for attempt in sorted(batch_attempts, key=lambda item: item.task.id):
            handoff = self._bind_dispatched_handoff(
                attempt.task, handoffs[attempt.task.id], attempt.spawn_ts
            )
            bound_handoffs[attempt.task.id] = handoff
            if not handoff.done:
                batch_error = "A parallel worker failed; batch integration was withheld."
                continue
            try:
                returned = manager.return_workspace(leases[attempt.task.id].lease_id)
                if returned.patch_digest is not None:
                    grants.append(
                        HumanIntegrationGrant(
                            grant_id=(
                                f"mission-grant:{mid}:{attempt.task.id}:"
                                f"{attempt.spawn_ts}"
                            ),
                            authorized_by="mission-plan-parent-authority",
                            lease_id=leases[attempt.task.id].lease_id,
                            patch_digest=returned.patch_digest,
                            expected_parent_revision=base,
                        )
                    )
            except WorkspaceError as exc:
                batch_error = f"Workspace return failed: {exc.code}"

        if batch_error is None and grants:
            try:
                ordered_grants = tuple(sorted(grants, key=lambda item: item.lease_id))
                integration_request = {
                    "grant_ids": [item.grant_id for item in ordered_grants],
                    "lease_ids": [item.lease_id for item in ordered_grants],
                    "mission_id": mid,
                    "project_id": self.project_id,
                    "validation_policy": "git_index_check",
                }
                plan = WorkspaceIntegrationPlan(
                    tuple(item.lease_id for item in ordered_grants),
                    tuple(item.grant_id for item in ordered_grants),
                    request_fingerprint(integration_request),
                    validation_policy="git_index_check",
                )
                issuer_proof = self.store.mission_grant_proof(
                    self.project_id,
                    mid,
                    plan,
                )
                self.store.apply_accepted_point_plan(
                    self.project_id,
                    plan,
                    issuer_proof,
                )
            except (AcceptedPointAuthorityError, WorkspaceError) as exc:
                batch_error = f"Workspace integration failed: {exc.code}"

        for lease in leases.values():
            try:
                latest = manager.inspect_workspace(lease.lease_id)
                if latest.state == "active":
                    manager.cancel_workspace(lease.lease_id)
                cleanup = manager.cleanup_workspace(lease.lease_id)
                if cleanup.outcome != "released" and batch_error is None:
                    batch_error = "Workspace cleanup requires attention."
            except WorkspaceError:
                if batch_error is None:
                    batch_error = "Workspace cleanup requires attention."

        attention: list[AttentionItemInternal] = []
        for attempt in sorted(batch_attempts, key=lambda item: item.task.id):
            handoff = bound_handoffs[attempt.task.id]
            if batch_error is not None and handoff.done:
                handoff = WorkHandoff(
                    node_id=attempt.task.id,
                    attempt_id=attempt.spawn_ts,
                    done=False,
                    report=batch_error,
                    request_attention=False,
                )
            self.store.save_attempt(
                self.project_id,
                mid,
                attempt.spawn_ts,
                attempt.task.id,
                handoff,
            )
            attention.extend(
                self._apply_handoff_collect(
                    mid, attempt.task, handoff, attempt.spawn_ts
                )
            )
        if attention:
            self._raise_attention(attention)
            return StepResult.attention_needed("isolated_batch_attention")
        return StepResult.advanced(
            "isolated batch cleared: "
            + ", ".join(attempt.task.id for attempt in batch_attempts)
        )

    @staticmethod
    def _validate_integration_tree(worktree: Path) -> bool:
        return (
            subprocess.run(
                ["git", "diff", "--cached", "--check"],
                cwd=worktree,
                check=False,
                capture_output=True,
            ).returncode
            == 0
        )

    @staticmethod
    def _lease_token(mid: str, task_id: str, spawn_ts: str) -> str:
        return hashlib.sha256(
            f"{mid}\0{task_id}\0{spawn_ts}".encode("utf-8")
        ).hexdigest()[:24]

    def _dispatch_requests(
        self,
        requests: list[DispatchRequest],
    ) -> dict[str, NodeHandoff]:
        if not requests:
            return {}

        batch_method = getattr(self.dispatcher, "dispatch_batch", None)
        if callable(batch_method):
            try:
                handoffs = batch_method(requests)
                if len(handoffs) != len(requests):
                    raise RuntimeError(
                        f"dispatch_batch returned {len(handoffs)} handoff(s) for "
                        f"{len(requests)} request(s)"
                    )
                return {
                    request.task.id: handoff
                    for request, handoff in zip(requests, handoffs, strict=True)
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    request.task.id: self._synthesize_handoff(
                        request.task,
                        self._bounded_dispatch_failure(
                            "Dispatcher batch crashed: ", exc
                        ),
                    )
                    for request in requests
                }

        def _run(request: DispatchRequest) -> tuple[str, NodeHandoff]:
            try:
                return request.task.id, self.dispatcher.dispatch(request)
            except Exception as exc:  # noqa: BLE001
                return (
                    request.task.id,
                    self._synthesize_handoff(
                        request.task,
                        self._bounded_dispatch_failure("Dispatcher crashed: ", exc),
                    ),
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests)) as pool:
            return dict(pool.map(_run, requests))

    def _bounded_dispatch_failure(self, prefix: str, exc: Exception) -> str:
        cause = redact_credential_values(str(exc), self.store.inventory)
        return f"{prefix}{cause}"[:2000]

    @staticmethod
    def _batch_spawn_ts(index: int) -> str:
        return f"{utc_now_filesafe()}-{index:04d}"

    def _apply_handoff(
        self,
        mid: str,
        task: Task,
        handoff: NodeHandoff,
        spawn_ts: str,
    ) -> StepResult:
        attention = self._apply_handoff_collect(mid, task, handoff, spawn_ts)
        if attention:
            self._raise_attention(attention)
            return StepResult.attention_needed(attention[0].kind)
        return StepResult.advanced(f"{task.id} cleared")

    def _apply_handoff_collect(
        self,
        mid: str,
        task: Task,
        handoff: NodeHandoff,
        spawn_ts: str,
    ) -> list[AttentionItemInternal]:
        tl = self.store.load_task_list(self.project_id, mid)
        task_state = self.store.load_task_state(self.project_id, mid)
        contract_state = self.store.load_contract_state(self.project_id, mid)
        attention: list[AttentionItemInternal] = []

        if task.type == "work":
            if not handoff.done:
                task_state.set_status(task.id, "failed")
                self.store.save_task_state(self.project_id, mid, task_state)
                assert isinstance(handoff, WorkHandoff)
                return [attn_factory.node_failed(mid, task, handoff)]
            task_state.set_status(task.id, "cleared")
            self.store.save_task_state(self.project_id, mid, task_state)
        elif task.type == "validate":
            task_state.set_status(task.id, "cleared")
            self.store.save_task_state(self.project_id, mid, task_state)
            if isinstance(handoff, ValidateHandoff):
                for item in handoff.items:
                    entry = contract_state.items.setdefault(
                        item.item_id, ContractStateEntry()
                    )
                    if item.passed:
                        entry.status = "passed"
                    elif entry.status != "passed":
                        entry.status = "failed"
                self.store.save_contract_state(self.project_id, mid, contract_state)
                if self._validate_failure_needs_attention(tl, task_state, task, handoff):
                    attention.append(
                        attn_factory.node_attention(mid, task, handoff)
                    )

        if handoff.request_attention:
            attention.append(attn_factory.node_attention(mid, task, handoff))
        return attention

    def _synthesize_handoff(self, task: Task, report: str) -> NodeHandoff:
        if task.type == "validate":
            return ValidateHandoff(
                node_id=task.id,
                done=False,
                report=report,
                items=[],
                passed=False,
                request_attention=False,
            )
        return WorkHandoff(
            node_id=task.id,
            done=False,
            report=report,
            request_attention=False,
        )

    def _bind_dispatched_handoff(
        self, task: Task, handoff: NodeHandoff, spawn_ts: str
    ) -> NodeHandoff:
        if handoff.node_id != task.id:
            return self._synthesize_handoff(
                task, "Dispatcher returned a handoff for a different task."
            ).model_copy(update={"attempt_id": spawn_ts})
        if handoff.attempt_id is None:
            return self._synthesize_handoff(
                task, "Dispatcher returned a handoff with a null attempt identity."
            ).model_copy(update={"attempt_id": spawn_ts})
        if handoff.attempt_id != spawn_ts:
            return self._synthesize_handoff(
                task, "Dispatcher returned a handoff for a stale generation."
            ).model_copy(update={"attempt_id": spawn_ts})
        return handoff.model_copy(update={"attempt_id": spawn_ts})

    def close_mission(
        self, mid: str, *, deliverable_roots: list[str] | None = None
    ) -> StepResult:
        state = self.store.load_state(self.project_id)
        if not isinstance(state, MissionRunning):
            return StepResult.idle("close_mission requires mission_running")
        try:
            tl = self.store.load_task_list(self.project_id, mid)
        except FileNotFoundError:
            self.store.save_state(
                self.project_id, Failed(reason=f"tasks.json missing for {mid}")
            )
            return StepResult.terminal("task_list missing")

        task_state = self.store.load_task_state(self.project_id, mid)
        resume_result = self._reconcile_pending_attempts(mid, tl, task_state)
        if resume_result is not None:
            return resume_result

        gate_event = self._try_evaluate_a_gate(tl, task_state)
        if gate_event is not None:
            return StepResult.idle("mission has a ready gate; call advance_project first")

        task = self._next_runnable_task(tl, task_state)
        if task is not None:
            return StepResult.idle(
                f"mission has runnable task work ({task.id}); call advance_project first"
            )

        if deliverable_roots is not None:
            self.store.save_terminal_review_config(
                self.project_id,
                mid,
                TerminalReviewConfig(deliverable_roots=deliverable_roots),
            )
        return self._enter_terminal_review(mid)

    # ------------------------------------------------------------------
    # Gates
    # ------------------------------------------------------------------

    def _try_evaluate_a_gate(
        self, tl: TaskList, task_state: TaskStateFile
    ) -> "_GateEvent | None":
        for gate in gates_in_order(tl):
            if task_state.status_of(gate.id) != "pending":
                continue
            if not all(
                task_state.status_of(dep) == "cleared" for dep in gate.depends_on
            ):
                continue
            return _GateEvent(
                gate=gate,
                result=self._evaluate_gate(tl, task_state, gate),
            )
        return None

    def _evaluate_gate(
        self, tl: TaskList, task_state: TaskStateFile, gate: Task
    ) -> "_GateResult":
        """AND-semantics gate evaluation.

        For each gate target, every covering validator must report
        passed=True. Any single dissent blocks the gate. A validator
        "covers" a target when the validator task was authored with that
        target in `task.targets`; missing expected items count as passed=False.
        """
        mid = self._lookup_mid_for_state()
        current_by_target = self._current_validators_by_target(tl, task_state, gate)
        current_validator_ids = {
            validator_id
            for validators in current_by_target.values()
            for validator_id in validators
        }
        expected_by_validator = {
            task.id: [
                target
                for target in gate.targets
                if task.id in current_by_target[target]
            ]
            for task in tl.tasks
            if task.id in current_validator_ids
        }

        validator_verdicts: dict[str, dict[str, bool]] = {}
        attempt_paths: dict[str, str] = {}
        missing_items: dict[str, list[str]] = {}
        rejected_evidence: list[str] = []
        for v_task_id, expected in expected_by_validator.items():
            state_entry = task_state.tasks.get(v_task_id)
            generation = (
                state_entry.last_attempt if state_entry is not None else None
            )
            if generation is None:
                validator_verdicts[v_task_id] = {t: False for t in expected}
                missing_items[v_task_id] = list(expected)
                continue
            try:
                handoff = self.store.read_attempt(
                    self.project_id, mid, generation, v_task_id
                )
            except AttemptValidationError as exc:
                validator_verdicts[v_task_id] = {t: False for t in expected}
                missing_items[v_task_id] = list(expected)
                attempt_paths[v_task_id] = str(
                    self.store.attempt_path(
                        self.project_id, mid, generation, v_task_id
                    )
                )
                rejected_evidence.append(
                    f"validator evidence rejected for {v_task_id}: {exc}"
                )
                continue
            attempt_paths[v_task_id] = str(
                self.store.attempt_report_path(
                    self.project_id, mid, generation, v_task_id
                )
            )
            if not isinstance(handoff, ValidateHandoff):
                validator_verdicts[v_task_id] = {t: False for t in expected}
                missing_items[v_task_id] = list(expected)
                continue

            verdicts: dict[str, bool] = {}
            returned_ids: set[str] = set()
            for item in handoff.items:
                if item.item_id in expected:
                    if item.item_id in returned_ids:
                        verdicts[item.item_id] = False
                    else:
                        verdicts[item.item_id] = bool(item.passed)
                returned_ids.add(item.item_id)
            missing = [t for t in expected if t not in returned_ids]
            for t in missing:
                verdicts[t] = False
            if missing:
                missing_items[v_task_id] = missing
            validator_verdicts[v_task_id] = verdicts

        item_passed: dict[str, bool] = {}
        uncovered: list[str] = []
        for tgt in gate.targets:
            covering = [
                vid for vid, verds in validator_verdicts.items()
                if tgt in verds
            ]
            if not covering:
                uncovered.append(tgt)
                continue
            item_passed[tgt] = all(
                validator_verdicts[vid][tgt] for vid in covering
            )

        if uncovered:
            return _GateResult(
                cleared=False,
                reason=(
                    f"no validator covered item(s): {', '.join(uncovered)}"
                ),
                failed_items=uncovered,
                validator_verdicts=validator_verdicts,
                attempt_paths=attempt_paths,
                missing_items=missing_items,
            )
        if all(item_passed.values()) and not rejected_evidence:
            return _GateResult(
                cleared=True,
                validator_verdicts=validator_verdicts,
                attempt_paths=attempt_paths,
                missing_items=missing_items,
            )
        failed = [k for k, v in item_passed.items() if not v]
        dissent_detail: list[str] = []
        for tgt in failed:
            dissenters = [
                vid for vid, verds in validator_verdicts.items()
                if verds.get(tgt) is False and tgt not in missing_items.get(vid, [])
            ]
            omitters = [
                vid for vid, miss in missing_items.items() if tgt in miss
            ]
            parts: list[str] = []
            if dissenters:
                parts.append(f"dissent: {', '.join(dissenters)}")
            if omitters:
                parts.append(f"missing: {', '.join(omitters)}")
            dissent_detail.append(f"{tgt} ({'; '.join(parts)})")
        reason_parts: list[str] = []
        if rejected_evidence:
            reason_parts.append("; ".join(rejected_evidence))
        if dissent_detail:
            reason_parts.append(f"failed items: {', '.join(dissent_detail)}")
        return _GateResult(
            cleared=False,
            reason="; ".join(reason_parts)[:2000],
            failed_items=failed,
            validator_verdicts=validator_verdicts,
            attempt_paths=attempt_paths,
            missing_items=missing_items,
        )

    @staticmethod
    def _current_validators_by_target(
        tl: TaskList,
        task_state: TaskStateFile,
        gate: Task,
    ) -> dict[str, list[str]]:
        """Return each target's reachable, non-superseded validator maxima.

        Dependencies point from a task to its predecessors.  Currentness is
        therefore graph dominance in the opposite direction: a covering
        validator is historical for a target when another covering validator
        is reachable downstream from it on the way to this gate.  Authored
        task order is retained only as deterministic presentation order; it
        has no currentness authority.
        """
        by_id = {t.id: t for t in tl.tasks}
        reachable: set[str] = set()
        stack: list[str] = list(gate.depends_on)
        while stack:
            cur = stack.pop()
            if cur in reachable or cur not in by_id:
                continue
            reachable.add(cur)
            stack.extend(by_id[cur].depends_on)

        downstream: dict[str, list[str]] = {task.id: [] for task in tl.tasks}
        for task in tl.tasks:
            for dependency in task.depends_on:
                if dependency in downstream:
                    downstream[dependency].append(task.id)

        candidates: dict[str, set[str]] = {
            target: {
                task.id
                for task in tl.tasks
                if task.id in reachable
                and task.type == "validate"
                and target in task.targets
                and task_state.status_of(task.id) != "superseded"
            }
            for target in gate.targets
        }
        dominated: dict[str, set[str]] = {target: set() for target in gate.targets}
        for target, covering in candidates.items():
            for validator_id in covering:
                seen: set[str] = set()
                pending = list(downstream[validator_id])
                while pending:
                    current = pending.pop()
                    if current in seen or current == gate.id:
                        continue
                    seen.add(current)
                    if current in covering:
                        dominated[target].add(validator_id)
                        break
                    pending.extend(downstream.get(current, []))

        return {
            target: [
                task.id
                for task in tl.tasks
                if task.id in candidates[target]
                and task.id not in dominated[target]
            ]
            for target in gate.targets
        }

    def _validate_failure_needs_attention(
        self,
        tl: TaskList,
        task_state: TaskStateFile,
        task: Task,
        handoff: ValidateHandoff,
    ) -> bool:
        """Surface failed validation when no pending downstream gate will do it."""
        returned: dict[str, bool] = {
            item.item_id: bool(item.passed)
            for item in handoff.items
            if item.item_id in task.targets
        }
        targets_needing_attention = [
            target
            for target in task.targets
            if returned.get(target) is not True
        ]
        if not targets_needing_attention and handoff.passed:
            return False
        if not targets_needing_attention and not handoff.passed:
            targets_needing_attention = list(task.targets)

        return any(
            not self._has_pending_downstream_gate_covering(
                tl, task_state, task.id, target
            )
            for target in targets_needing_attention
        )

    @staticmethod
    def _has_pending_downstream_gate_covering(
        tl: TaskList,
        task_state: TaskStateFile,
        task_id: str,
        target: str,
    ) -> bool:
        by_id = {t.id: t for t in tl.tasks}
        adj: dict[str, list[str]] = {t.id: [] for t in tl.tasks}
        for task in tl.tasks:
            for dep in task.depends_on:
                if dep in adj:
                    adj[dep].append(task.id)

        seen: set[str] = set()
        stack = list(adj.get(task_id, []))
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            cur_task = by_id.get(cur)
            if cur_task is None:
                continue
            if (
                cur_task.type == "gate"
                and target in cur_task.targets
                and task_state.status_of(cur_task.id) == "pending"
            ):
                return True
            stack.extend(adj.get(cur, []))
        return False

    def _apply_gate_event(
        self,
        mid: str,
        tl: TaskList,
        task_state: TaskStateFile,
        event: "_GateEvent",
    ) -> StepResult:
        if event.result.cleared:
            task_state.set_status(event.gate.id, "cleared")
            self.store.save_task_state(self.project_id, mid, task_state)
            self._raise_attention(
                [
                    self._bounded_gate_attention(mid, event, cleared=True)
                ]
            )
            return StepResult.attention_needed("gate_checkpoint")
        else:
            task_state.set_status(event.gate.id, "failed")
            self.store.save_task_state(self.project_id, mid, task_state)
            self._raise_attention(
                [
                    self._bounded_gate_attention(mid, event, cleared=False)
                ]
            )
            return StepResult.attention_needed("gate_failed")

    @staticmethod
    def _bounded_gate_attention(
        mission_id: str,
        event: "_GateEvent",
        *,
        cleared: bool,
    ) -> AttentionItemInternal:
        """Render the existing gate formatter with a bounded public projection."""

        def render(
            gate: Task,
            verdicts: dict[str, dict[str, bool]],
            missing: dict[str, list[str]],
            reason: str,
            failed_items: list[str],
        ) -> AttentionItemInternal:
            if cleared:
                return attn_factory.gate_checkpoint(
                    mission_id,
                    gate,
                    validator_verdicts=verdicts,
                )
            return attn_factory.gate_failed(
                mission_id,
                gate,
                reason,
                failed_items=failed_items,
                validator_verdicts=verdicts,
                missing_items=missing,
            )

        result = event.result
        full = render(
            event.gate,
            result.validator_verdicts,
            result.missing_items,
            result.reason or "",
            result.failed_items or [],
        )
        if len(full.report.encode("utf-8")) < _MAX_GATE_REPORT_BYTES:
            return full

        targets = [
            target
            for target in event.gate.targets
            if len(target.encode("utf-8")) <= 128
        ][:8]
        gate_id = event.gate.id
        if len(gate_id.encode("utf-8")) > 128:
            gate_id = "gate-diagnostics-truncated"
        projected_gate = event.gate.model_copy(
            update={"id": gate_id, "targets": targets}
        )
        projected_verdicts: dict[str, dict[str, bool]] = {}
        for validator_id in sorted(result.validator_verdicts):
            if len(projected_verdicts) == 8:
                break
            if len(validator_id.encode("utf-8")) > 128:
                continue
            verdicts = {
                target: result.validator_verdicts[validator_id][target]
                for target in targets
                if target in result.validator_verdicts[validator_id]
            }
            if verdicts:
                projected_verdicts[validator_id] = verdicts
        projected_missing = {
            validator_id: [
                target
                for target in targets
                if target in result.missing_items.get(validator_id, [])
            ]
            for validator_id in projected_verdicts
        }
        bounded = render(
            projected_gate,
            projected_verdicts,
            projected_missing,
            "current validator evidence failed closed; public diagnostics truncated"
            if not cleared
            else "",
            [target for target in targets if target in (result.failed_items or [])],
        )
        if len(bounded.report.encode("utf-8")) < _MAX_GATE_REPORT_BYTES:
            return bounded

        minimal_gate = event.gate.model_copy(
            update={"id": "gate-diagnostics-truncated", "targets": []}
        )
        return render(
            minimal_gate,
            {},
            {},
            "current validator evidence failed closed; public diagnostics truncated"
            if not cleared
            else "",
            [],
        )

    # ------------------------------------------------------------------
    # Terminal review
    # ------------------------------------------------------------------

    def _enter_terminal_review(self, mid: str) -> StepResult:
        self.store.refresh_inventory(os.environ)
        config = self.store.load_terminal_review_config(self.project_id, mid)
        # Revalidate persisted roots immediately before dispatch. This is
        # preflight plus prompt policy for a trusted reviewer, not OS sandboxing.
        resolved_roots = self.store.resolve_terminal_review_roots(
            self.project_id, mid, config.deliverable_roots
        )
        if resolved_roots != config.deliverable_roots:
            self.store.save_terminal_review_config(
                self.project_id,
                mid,
                TerminalReviewConfig(deliverable_roots=resolved_roots),
            )
        spawn_ts = utc_now_filesafe()
        try:
            report = self.terminal_reviewer.review(self.project_id, mid, spawn_ts)
        except Exception as exc:  # noqa: BLE001
            report = TerminalReviewHandoff(
                done=False,
                report=(
                    "Terminal reviewer runtime failure; mission artifacts were "
                    "preserved and closure can be retried after resolving this "
                    f"attention item.\n\nError: {exc}"
                ),
            )
            self.store.save_terminal_review(self.project_id, mid, spawn_ts, report)
            self._raise_attention([attn_factory.terminal_review(mid, report)])
            return StepResult.attention_needed("terminal_review_crash")
        self.store.save_terminal_review(self.project_id, mid, spawn_ts, report)
        if report.done:
            self.store.seal_mission(
                self.project_id,
                mid,
                status="done",
                body=report.report or "Mission complete; terminal review clean.",
            )
            self.store.save_state(self.project_id, Done())
            return StepResult.terminal("done")
        self._raise_attention([attn_factory.terminal_review(mid, report)])
        return StepResult.attention_needed("terminal_review")

    # ------------------------------------------------------------------
    # Attention queue
    # ------------------------------------------------------------------

    def _raise_attention(self, items: list[AttentionItemInternal]) -> None:
        existing = self.store.load_attention(self.project_id)
        existing.extend(items)
        self.store.save_attention(self.project_id, existing)
        self.store.save_state(
            self.project_id,
            AttentionNeeded(items=public_attention_items(existing)),
        )

    # ------------------------------------------------------------------
    # Resume from disk
    # ------------------------------------------------------------------

    def _reconcile_pending_attempts(
        self, mid: str, tl: TaskList, task_state: TaskStateFile
    ) -> StepResult | None:
        attention: list[AttentionItemInternal] = []
        saw_running = False
        for task in tl.tasks:
            if task_state.status_of(task.id) != "running":
                continue
            saw_running = True
            entry = task_state.tasks.get(task.id)
            spawn_ts = entry.last_attempt if entry is not None else None
            if spawn_ts is None:
                spawn_ts = utc_now_filesafe()
                handoff = self._synthesize_handoff(
                    task,
                    "Coordinator resumed with a running task that has no dispatch generation.",
                )
                self.store.save_attempt(
                    self.project_id,
                    mid,
                    spawn_ts,
                    task.id,
                    handoff,
                )
                attention.extend(
                    self._apply_handoff_collect(mid, task, handoff, spawn_ts)
                )
                continue
            try:
                read_handoff = self.store.read_attempt(
                    self.project_id, mid, spawn_ts, task.id
                )
            except AttemptValidationError as exc:
                handoff = self._synthesize_handoff(
                    task,
                    "Coordinator rejected the persisted attempt: " + str(exc),
                )
                rejected_ts = f"{spawn_ts}-rejected"
                self.store.save_attempt(
                    self.project_id,
                    mid,
                    rejected_ts,
                    task.id,
                    handoff,
                )
                attention.extend(
                    self._apply_handoff_collect(mid, task, handoff, rejected_ts)
                )
                continue
            if read_handoff is None:
                handoff = self._synthesize_handoff(
                    task,
                    "Coordinator resumed with task marked running but no attempt "
                    "file was present for its current generation.",
                )
                self.store.save_attempt(
                    self.project_id, mid, spawn_ts, task.id, handoff
                )
                attention.extend(
                    self._apply_handoff_collect(mid, task, handoff, spawn_ts)
                )
                continue
            attention.extend(
                self._apply_handoff_collect(mid, task, read_handoff, spawn_ts)
            )
        if not saw_running:
            return None
        if attention:
            self._raise_attention(attention)
            return StepResult.attention_needed("resume_attention")
        return StepResult.advanced("reconciled pending attempts")

    # ------------------------------------------------------------------
    # Mission id helper
    # ------------------------------------------------------------------

    def _lookup_mid_for_state(self) -> str:
        state = self.store.load_state(self.project_id)
        if isinstance(state, (MissionRunning, MissionPlanning)):
            return state.mission_id
        missions = self.store.list_missions(self.project_id)
        if not missions:
            raise RuntimeError("no mission in this project")
        return missions[-1]


# ---------------------------------------------------------------------------
# Internal records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _BatchAttempt:
    task: Task
    spawn_ts: str


@dataclass(frozen=True)
class _GateResult:
    cleared: bool
    reason: str | None = None
    failed_items: list[str] | None = None
    validator_verdicts: dict[str, dict[str, bool]] = field(default_factory=dict)
    attempt_paths: dict[str, str] = field(default_factory=dict)
    missing_items: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class _GateEvent:
    gate: Task
    result: _GateResult


__all__ = ["MissionCoordinator", "StepResult"]
