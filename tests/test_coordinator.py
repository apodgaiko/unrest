"""Coordinator state-machine tests with the in-process mock dispatcher.

See `specs/task_list/PRODUCT.md` §Dispatch.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from unrest_harness.config import HarnessConfig
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.controller import MAX_ABORT_REASON_BYTES, ProjectController, ToolError
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    AttentionNeeded,
    Decision,
    MissionRunning,
    Task,
    TaskList,
    TaskListPatch,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "unrest_harness" / "bundled"
    return HarnessConfig(
        bundled_dir=bundled,
        harness_home=harness_home,
        projects_dir=harness_home / "projects",
        orchestrator_provider_name="claude",
        worker_provider_name="claude",
        worker_acp_command=None,
        validator_provider_name=None,
        validator_acp_command=None,
        terminal_reviewer_provider_name=None,
        terminal_reviewer_acp_command=None,
        max_parallel_nodes=1,
    )


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


def _simple_tl() -> TaskList:
    return TaskList(
        tasks=[
            _task("w1", "work", ["VAL-001"]),
            _task("v1", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["v1"]),
        ]
    )


def _validate_no_gate_tl() -> TaskList:
    return TaskList(
        tasks=[
            _task("w1", "work", ["VAL-001"]),
            _task("v1", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
        ]
    )


def _seed_project(
    controller: ProjectController,
    workspace: Path,
    *,
    brief: str = "Brief.",
    mission_id: str = "mission-001",
    assertion: str = "VAL-001",
) -> str:
    controller.start_project(brief, str(workspace))
    pid = controller.store.list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, mission_id)
    (contract_dir / f"{assertion}.md").write_text(
        f"# {assertion}\n\nStatement body.\n"
    )
    return pid


def _independent_frontier_oracle(
    controller: ProjectController,
    project_id: str,
    gate_id: str,
) -> dict[str, list[str]]:
    """Compute maxima from reloaded persistence without production traversal."""
    mission_id = "mission-001"
    task_list = controller.store.load_task_list(project_id, mission_id)
    task_state = controller.store.load_task_state(project_id, mission_id)
    by_id = {task.id: task for task in task_list.tasks}
    gate = by_id[gate_id]

    reachable: set[str] = set()
    pending = list(gate.depends_on)
    while pending:
        task_id = pending.pop()
        if task_id in reachable:
            continue
        reachable.add(task_id)
        pending.extend(by_id[task_id].depends_on)

    result: dict[str, list[str]] = {}
    for target in gate.targets:
        candidates = {
            task.id
            for task in task_list.tasks
            if task.id in reachable
            and task.type == "validate"
            and target in task.targets
            and task_state.status_of(task.id) != "superseded"
        }
        historical: set[str] = set()
        for downstream_id in candidates:
            upstream = list(by_id[downstream_id].depends_on)
            visited: set[str] = set()
            while upstream:
                task_id = upstream.pop()
                if task_id in visited:
                    continue
                visited.add(task_id)
                if task_id in candidates:
                    historical.add(task_id)
                upstream.extend(by_id[task_id].depends_on)
        result[target] = [
            task.id
            for task in task_list.tasks
            if task.id in candidates - historical
        ]
    return result


def _reloaded_gate_result(
    controller: ProjectController,
    project_id: str,
    gate_id: str = "g1",
):
    reloaded = ProjectController(
        controller.config,
        controller.dispatcher,
        controller.terminal_reviewer,
    )
    task_list = reloaded.store.load_task_list(project_id, "mission-001")
    task_state = reloaded.store.load_task_state(project_id, "mission-001")
    gate = next(task for task in task_list.tasks if task.id == gate_id)
    coordinator = MissionCoordinator(
        reloaded.store,
        project_id,
        reloaded.dispatcher,
        reloaded.terminal_reviewer,
    )
    return coordinator._evaluate_gate(task_list, task_state, gate)


def _frontier_identities(result: object) -> dict[str, list[str]]:
    verdicts = result.validator_verdicts  # type: ignore[attr-defined]
    targets = sorted({target for votes in verdicts.values() for target in votes})
    return {
        target: [node_id for node_id, votes in verdicts.items() if target in votes]
        for target in targets
    }


def _file_manifest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _fresh_frontier_probe(
    config: HarnessConfig,
    project_id: str,
    gate_id: str,
) -> bytes:
    script = (
        Path(__file__).parent
        / "fixtures"
        / "evidence_frontier_v045"
        / "replay.py"
    )
    return subprocess.run(
        [
            sys.executable,
            str(script),
            "gate",
            str(config.harness_home),
            project_id,
            gate_id,
        ],
        check=True,
        capture_output=True,
    ).stdout


def test_serial_dispatch_crash_is_bounded_and_redacted_in_reachable_sinks(
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = {
        "ANTHROPIC_API_KEY": "short-key",
        "ANTHROPIC_AUTH_TOKEN": "overlap-known-value",
        "CODEX_API_KEY": "known-value",
        "GLM_API_KEY": "known-value-suffix",
        "OPENAI_API_KEY": "colliding-known-value",
        "ZAI_API_KEY": "punctuation@known",
    }
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)

    def crash(_request: DispatchRequest) -> NodeHandoff:
        raise RuntimeError("|".join(credentials.values()) + "-" + "x" * 5000)

    controller = ProjectController(
        config,
        MockDispatcher(crash),
        MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
    )
    pid = _seed_project(controller, workspace)
    controller.submit_plan(pid, _simple_tl())
    controller.advance_project(pid, max_steps=1)

    attempt_path = next(controller.store.attempts_runtime_dir(pid, "mission-001").glob("*.json"))
    attempt = json.loads(attempt_path.read_text())
    assert len(attempt["report"]) <= 2000
    reachable = [
        attempt_path,
        next(controller.store.attempts_dir(pid, "mission-001").glob("*.md")),
        controller.store.unrest_runtime_dir(pid) / "attention.json",
        controller.store.unrest_runtime_dir(pid) / "state.json",
    ]
    for path in reachable:
        content = path.read_text()
        for value in credentials.values():
            assert value not in content


class TestHappyPath:
    def test_full_pipeline_to_done(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        dispatcher = MockDispatcher(responder)
        reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        controller = ProjectController(config, dispatcher, reviewer)

        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())

        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items and items[0].kind == "gate_checkpoint"

        env = controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        assert env.state.state in ("mission_running", "done")

        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "done"

    def test_advance_syncs_bucket_skill_to_real_host_dir_before_dispatch(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        codex_skills = workspace / ".codex" / "skills"
        codex_skills.mkdir(parents=True)
        (codex_skills / "user-skill" / "SKILL.md").parent.mkdir()
        (codex_skills / "user-skill" / "SKILL.md").write_text("# User skill\n")

        saw_synced_skill = False

        def responder(req: DispatchRequest) -> NodeHandoff:
            nonlocal saw_synced_skill
            saw_synced_skill = (
                codex_skills / "new-worker" / "SKILL.md"
            ).exists()
            return WorkHandoff(node_id=req.task.id, done=True, report="ok")

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        bucket_skill = (
            controller.store.unrest_dir(pid)
            / "skills"
            / "new-worker"
            / "SKILL.md"
        )
        bucket_skill.parent.mkdir(parents=True)
        bucket_skill.write_text("# New worker\n")

        controller.submit_plan(
            pid,
            TaskList(tasks=[_task("w1", "work", ["VAL-001"], skill="new-worker")]),
        )
        controller.advance_project(pid, max_steps=1)

        assert saw_synced_skill
        assert codex_skills.is_dir()
        assert not codex_skills.is_symlink()


class TestNodeFailedFlow:
    def test_work_failure_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_failed"
        assert "blocked" in items[0].report


class TestRequestAttentionRaisesNodeAttention:
    def test_request_attention_true_raises(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(
                node_id=req.task.id,
                done=True,
                report="finished",
                request_attention=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_attention"
        assert "finished" in items[0].report


class TestGateFailed:
    def test_validator_failing_raises_gate_failed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="found bug",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"

    @pytest.mark.parametrize(
        "invalid_kind", ("corrupt", "wrong-task", "stale-generation")
    )
    def test_invalid_gate_evidence_routes_to_attention_then_new_generation(
        self,
        config: HarnessConfig,
        workspace: Path,
        invalid_kind: str,
    ) -> None:
        def responder(request: DispatchRequest) -> NodeHandoff:
            return ValidateHandoff(
                node_id=request.task.id,
                attempt_id=request.spawn_ts,
                done=True,
                report="fresh validation",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "cleared")
        task_state.set_status("v1", "cleared")
        task_state.set_last_attempt("v1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        rejected = store.attempt_path(
            pid, "mission-001", generation, "v1"
        )
        rejected.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, object] = {
            "node_id": "v1",
            "attempt_id": generation,
            "done": True,
            "report": "forensic-sentinel-must-not-escape",
            "items": [{"item_id": "VAL-001", "passed": True}],
            "passed": True,
            "request_attention": False,
        }
        if invalid_kind == "corrupt":
            rejected.write_text("{forensic-sentinel-must-not-escape")
        else:
            if invalid_kind == "wrong-task":
                payload["node_id"] = "other-validator"
            else:
                payload["attempt_id"] = "2026-08-09T12-00-00Z"
            rejected.write_text(json.dumps(payload), encoding="utf-8")
        rejected_before = rejected.read_bytes()
        rejected_hash = hashlib.sha256(rejected_before).hexdigest()

        failed = controller.advance_project(pid, max_steps=1)

        assert failed.state.state == "attention_needed"
        attention = store.load_attention(pid)
        assert len(attention) == 1
        assert attention[0].kind == "gate_failed"
        assert "validator evidence rejected for v1" in attention[0].report
        assert len(attention[0].report.encode()) < 4096
        assert "forensic-sentinel" not in attention[0].report
        for sink in (
            store.unrest_runtime_dir(pid) / "attention.json",
            store.unrest_runtime_dir(pid) / "state.json",
        ):
            assert "forensic-sentinel" not in sink.read_text(encoding="utf-8")
        assert rejected.read_bytes() == rejected_before
        assert hashlib.sha256(rejected.read_bytes()).hexdigest() == rejected_hash

        replacement = TaskListPatch(
            supersede={"g1": "g1-v2"},
            add=[
                _task(
                    "v1-v2",
                    "validate",
                    ["VAL-001"],
                    skill="aud",
                    depends_on=["w1"],
                ),
                _task(
                    "g1-v2",
                    "gate",
                    ["VAL-001"],
                    depends_on=["v1-v2"],
                ),
            ],
        )
        controller.decide_attention(
            pid,
            [
                Decision(
                    item_id=attention[0].id,
                    action="patch",
                    patch=replacement,
                    justification="collect fresh validator evidence",
                )
            ],
        )
        recovered = controller.advance_project(pid)

        assert recovered.state.state == "attention_needed"
        final_attention = store.load_attention(pid)
        assert len(final_attention) == 1
        assert final_attention[0].kind == "gate_checkpoint"
        final_state = store.load_task_state(pid, "mission-001")
        assert final_state.status_of("g1-v2") == "cleared"
        new_generation = final_state.tasks["v1-v2"].last_attempt
        assert new_generation is not None and new_generation != generation
        assert rejected.read_bytes() == rejected_before
        assert hashlib.sha256(rejected.read_bytes()).hexdigest() == rejected_hash


class TestGateOptional:
    def test_validator_failure_without_downstream_gate_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="found bug",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _validate_no_gate_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "node_attention"
        assert "VAL-001: failed" in items[0].report


class TestValidatorDissentFailsGate:
    @staticmethod
    def _two_validator_tl() -> TaskList:
        return TaskList(
            tasks=[
                _task("w1", "work", ["VAL-001"]),
                _task("v-scrutiny", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
                _task("v-user-surface", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
                _task("g1", "gate", ["VAL-001"], depends_on=["v-scrutiny", "v-user-surface"]),
            ]
        )

    def test_dissent_raises_gate_failed_not_checkpoint(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            passed = req.task.id == "v-scrutiny"
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="scrutiny ok" if passed else "user-surface broken",
                items=[ValidationItem(item_id="VAL-001", passed=passed)],
                passed=passed,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"
        report = items[0].report
        assert "v-user-surface" in report
        assert "dissenting: VAL-001" in report
        assert "v-scrutiny: 1/1 passed" in report

    def test_all_validators_pass_clears_with_explicit_summary(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_checkpoint"
        report = items[0].report
        assert "v-scrutiny: 1/1 passed" in report
        assert "v-user-surface: 1/1 passed" in report

    def test_validator_omitting_items_fails_gate(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            if req.task.id == "v-scrutiny":
                return ValidateHandoff(
                    node_id=req.task.id,
                    done=True,
                    report="scrutiny ok",
                    items=[ValidationItem(item_id="VAL-001", passed=True)],
                    passed=True,
                )
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="ran but rendered no verdict",
                items=[],
                passed=False,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, self._two_validator_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_failed"
        report = items[0].report
        assert "v-user-surface" in report
        assert "missing: VAL-001" in report


class TestCurrentEvidenceFrontier:
    @staticmethod
    def _run_graph(
        config: HarnessConfig,
        workspace: Path,
        tasks: list[Task],
        validator_items: dict[str, list[ValidationItem]],
        assertions: tuple[str, ...] = ("VAL-001",),
    ) -> tuple[ProjectController, str]:
        def responder(request: DispatchRequest) -> NodeHandoff:
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="work")
            items = validator_items[request.task.id]
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report=(
                    f"private-report-canary-{request.task.id} "
                    "/private/validator/report-canary-never-public"
                ),
                items=items,
                passed=all(item.passed for item in items),
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        controller.start_project("frontier", str(workspace))
        project_id = controller.store.list_projects()[0].id
        contract_dir = controller.store.ensure_contract_dir(project_id, "mission-001")
        for assertion in assertions:
            (contract_dir / f"{assertion}.md").write_text(f"# {assertion}\n")
        controller.submit_plan(project_id, TaskList(tasks=tasks))
        envelope = controller.advance_project(project_id)
        assert envelope.state.state == "attention_needed"
        return controller, project_id

    @pytest.mark.parametrize(
        ("tasks", "items", "expected", "cleared"),
        [
            (
                [
                    _task("w", "work", ["VAL-001"]),
                    _task("v", "validate", ["VAL-001"], depends_on=["w"]),
                    _task("g1", "gate", ["VAL-001"], depends_on=["v"]),
                ],
                {"v": [ValidationItem(item_id="VAL-001", passed=True)]},
                {"VAL-001": ["v"]},
                True,
            ),
            (
                [
                    _task("w", "work", ["VAL-001"]),
                    _task("old", "validate", ["VAL-001"], depends_on=["w"]),
                    _task("new", "validate", ["VAL-001"], depends_on=["old"]),
                    _task("g1", "gate", ["VAL-001"], depends_on=["new"]),
                ],
                {
                    "old": [ValidationItem(item_id="VAL-001", passed=False)],
                    "new": [ValidationItem(item_id="VAL-001", passed=True)],
                },
                {"VAL-001": ["new"]},
                True,
            ),
            (
                [
                    _task("w", "work", ["VAL-001"]),
                    _task("root", "validate", ["VAL-001"], depends_on=["w"]),
                    _task("left", "validate", ["VAL-001"], depends_on=["root"]),
                    _task("right", "validate", ["VAL-001"], depends_on=["root"]),
                    _task("g1", "gate", ["VAL-001"], depends_on=["left", "right"]),
                ],
                {
                    "root": [ValidationItem(item_id="VAL-001", passed=False)],
                    "left": [ValidationItem(item_id="VAL-001", passed=True)],
                    "right": [ValidationItem(item_id="VAL-001", passed=False)],
                },
                {"VAL-001": ["left", "right"]},
                False,
            ),
        ],
        ids=("direct", "transitive-replacement", "diamond-incomparable"),
    )
    def test_persisted_graph_frontier_matches_independent_oracle(
        self,
        config: HarnessConfig,
        workspace: Path,
        tasks: list[Task],
        items: dict[str, list[ValidationItem]],
        expected: dict[str, list[str]],
        cleared: bool,
    ) -> None:
        controller, project_id = self._run_graph(config, workspace, tasks, items)

        oracle = _independent_frontier_oracle(controller, project_id, "g1")
        result = _reloaded_gate_result(controller, project_id)
        actual = {
            target: [
                validator_id
                for validator_id, verdicts in result.validator_verdicts.items()
                if target in verdicts
            ]
            for target in expected
        }

        assert oracle == expected
        assert actual == oracle
        assert result.cleared is cleared

    def test_separate_persisted_independent_lanes_match_reloaded_oracle(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("north", "validate", ["VAL-001"], depends_on=["w"]),
            _task("south", "validate", ["VAL-001"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["north", "south"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {
                "north": [ValidationItem(item_id="VAL-001", passed=True)],
                "south": [ValidationItem(item_id="VAL-001", passed=True)],
            },
        )

        oracle = _independent_frontier_oracle(controller, project_id, "g1")
        result = _reloaded_gate_result(controller, project_id)

        assert oracle == {"VAL-001": ["north", "south"]}
        assert _frontier_identities(result) == oracle
        assert result.cleared is True

    def test_overlapping_targets_retire_only_overlap_and_ignore_unexpected_vote(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-A", "VAL-B"]),
            _task("old", "validate", ["VAL-A", "VAL-B"], depends_on=["w"]),
            _task("repair", "validate", ["VAL-A"], depends_on=["old"]),
            _task("g1", "gate", ["VAL-A", "VAL-B"], depends_on=["repair"]),
        ]
        items = {
            "old": [
                ValidationItem(item_id="VAL-A", passed=False),
                ValidationItem(item_id="VAL-B", passed=True),
            ],
            "repair": [
                ValidationItem(item_id="VAL-A", passed=True),
                ValidationItem(item_id="VAL-B", passed=False),
            ],
        }
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            items,
            assertions=("VAL-A", "VAL-B"),
        )

        result = _reloaded_gate_result(controller, project_id)

        assert _independent_frontier_oracle(controller, project_id, "g1") == {
            "VAL-A": ["repair"],
            "VAL-B": ["old"],
        }
        assert result.validator_verdicts == {
            "repair": {"VAL-A": True},
            "old": {"VAL-B": True},
        }
        assert result.cleared is True

    def test_patch_replacement_combines_overlap_history_and_incomparable_dissent(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-A", "VAL-B"]),
            _task(
                "old",
                "validate",
                ["VAL-A", "VAL-B"],
                depends_on=["w"],
            ),
            _task("peer", "validate", ["VAL-A"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-A", "VAL-B"], depends_on=["old", "peer"]),
        ]
        items = {
            "old": [
                ValidationItem(item_id="VAL-A", passed=False),
                ValidationItem(item_id="VAL-B", passed=True),
            ],
            "peer": [ValidationItem(item_id="VAL-A", passed=False)],
            "repair": [ValidationItem(item_id="VAL-A", passed=True)],
        }
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            items,
            assertions=("VAL-A", "VAL-B"),
        )
        before_oracle = _independent_frontier_oracle(controller, project_id, "g1")
        before_result = _reloaded_gate_result(controller, project_id)
        old_attempt = controller.store.list_attempts(
            project_id, "mission-001", node_id="old"
        )[0]
        old_report = controller.store.attempt_report_path(
            project_id, "mission-001", old_attempt.spawn_ts, "old"
        )
        retained = {
            old_attempt.path: old_attempt.path.read_bytes(),
            old_report: old_report.read_bytes(),
        }
        attention = controller.store.load_attention(project_id)
        assert attention[0].kind == "gate_failed"

        controller.decide_attention(
            project_id,
            [
                Decision(
                    item_id=attention[0].id,
                    action="patch",
                    justification="replace only the old VAL-A lane",
                    patch=TaskListPatch(
                        add=[
                            _task(
                                "repair",
                                "validate",
                                ["VAL-A"],
                                depends_on=["old"],
                            ),
                            _task(
                                "g2",
                                "gate",
                                ["VAL-A", "VAL-B"],
                                depends_on=["repair", "peer"],
                            ),
                        ],
                        supersede={"g1": "g2"},
                    ),
                )
            ],
        )
        controller.advance_project(project_id)
        after_oracle = _independent_frontier_oracle(controller, project_id, "g2")
        after_result = _reloaded_gate_result(controller, project_id, "g2")

        assert before_oracle == {"VAL-A": ["old", "peer"], "VAL-B": ["old"]}
        assert before_result.validator_verdicts == {
            "old": {"VAL-A": False, "VAL-B": True},
            "peer": {"VAL-A": False},
        }
        assert after_oracle == {
            "VAL-A": ["peer", "repair"],
            "VAL-B": ["old"],
        }
        assert _frontier_identities(after_result) == after_oracle
        assert after_result.validator_verdicts == {
            "old": {"VAL-B": True},
            "peer": {"VAL-A": False},
            "repair": {"VAL-A": True},
        }
        assert after_result.cleared is False
        assert {path: path.read_bytes() for path in retained} == retained

    def test_omitted_expected_item_fails_closed_in_isolation(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("complete", "validate", ["VAL-001"], depends_on=["w"]),
            _task("omits", "validate", ["VAL-001"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["complete", "omits"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {
                "complete": [ValidationItem(item_id="VAL-001", passed=True)],
                "omits": [],
            },
        )

        result = _reloaded_gate_result(controller, project_id)

        assert result.cleared is False
        assert result.validator_verdicts == {
            "complete": {"VAL-001": True},
            "omits": {"VAL-001": False},
        }
        assert result.missing_items == {"omits": ["VAL-001"]}

    def test_missing_generation_fails_closed_in_isolation(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("complete", "validate", ["VAL-001"], depends_on=["w"]),
            _task("missing", "validate", ["VAL-001"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["complete", "missing"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {
                "complete": [ValidationItem(item_id="VAL-001", passed=True)],
                "missing": [ValidationItem(item_id="VAL-001", passed=True)],
            },
        )
        task_state = controller.store.load_task_state(project_id, "mission-001")
        task_state.tasks["missing"].last_attempt = None
        controller.store.save_task_state(project_id, "mission-001", task_state)

        result = _reloaded_gate_result(controller, project_id)

        assert result.cleared is False
        assert result.validator_verdicts == {
            "complete": {"VAL-001": True},
            "missing": {"VAL-001": False},
        }
        assert result.missing_items == {"missing": ["VAL-001"]}

    def test_frontier_reconstructs_byte_identically_in_fresh_interpreters(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("old", "validate", ["VAL-001"], depends_on=["w"]),
            _task("left", "validate", ["VAL-001"], depends_on=["old"]),
            _task("right", "validate", ["VAL-001"], depends_on=["old"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["left", "right"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {
                validator: [ValidationItem(item_id="VAL-001", passed=validator != "right")]
                for validator in ("old", "left", "right")
            },
        )
        script = """
import json, sys
from pathlib import Path
from unrest_harness.config import HarnessConfig
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import TerminalReviewHandoff, WorkHandoff
from unrest_harness.storage import ProjectStore
home, project_id = Path(sys.argv[1]), sys.argv[2]
config = HarnessConfig(
    bundled_dir=Path.cwd() / 'src' / 'unrest_harness' / 'bundled',
    harness_home=home,
    projects_dir=home / 'projects',
    orchestrator_provider_name='claude',
    worker_provider_name='claude',
    worker_acp_command=None,
    validator_provider_name=None,
    validator_acp_command=None,
    terminal_reviewer_provider_name=None,
    terminal_reviewer_acp_command=None,
)
store = ProjectStore(config)
dispatcher = MockDispatcher(lambda request: WorkHandoff(node_id=request.task.id, done=True))
reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True))
task_list = store.load_task_list(project_id, 'mission-001')
task_state = store.load_task_state(project_id, 'mission-001')
gate = next(task for task in task_list.tasks if task.id == 'g1')
result = MissionCoordinator(store, project_id, dispatcher, reviewer)._evaluate_gate(task_list, task_state, gate)
print(json.dumps({'cleared': result.cleared, 'matrix': result.validator_verdicts}, sort_keys=True, separators=(',', ':')))
"""
        command = [sys.executable, "-c", script, str(config.harness_home), project_id]

        first = subprocess.run(command, check=True, capture_output=True).stdout
        second = subprocess.run(command, check=True, capture_output=True).stdout

        assert first == second
        assert json.loads(first) == {
            "cleared": False,
            "matrix": {
                "left": {"VAL-001": True},
                "right": {"VAL-001": False},
            },
        }

    def test_last_attempt_wins_over_lexical_time_and_mtime(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("validator", "validate", ["VAL-001"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["validator"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {"validator": [ValidationItem(item_id="VAL-001", passed=True)]},
        )
        store = controller.store
        state = store.load_task_state(project_id, "mission-001")
        selected = state.tasks["validator"].last_attempt
        assert selected is not None
        misleading = "9999-12-31T23-59-59Z"
        store.save_attempt(
            project_id,
            "mission-001",
            misleading,
            "validator",
            ValidateHandoff(
                node_id="validator",
                done=True,
                report="chronology must not vote",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            ),
        )
        selected_path = store.attempt_path(
            project_id, "mission-001", selected, "validator"
        )
        misleading_path = store.attempt_path(
            project_id, "mission-001", misleading, "validator"
        )
        os.utime(selected_path, (2_000_000_000, 2_000_000_000))
        os.utime(misleading_path, (1, 1))

        result = _reloaded_gate_result(controller, project_id)

        assert result.cleared is True
        assert result.validator_verdicts == {"validator": {"VAL-001": True}}

    def test_multiple_validator_generations_ignore_lexical_and_mtime_cues(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        tasks = [
            _task("w", "work", ["VAL-001"]),
            _task("alpha", "validate", ["VAL-001"], depends_on=["w"]),
            _task("beta", "validate", ["VAL-001"], depends_on=["w"]),
            _task("g1", "gate", ["VAL-001"], depends_on=["alpha", "beta"]),
        ]
        controller, project_id = self._run_graph(
            config,
            workspace,
            tasks,
            {
                "alpha": [ValidationItem(item_id="VAL-001", passed=True)],
                "beta": [ValidationItem(item_id="VAL-001", passed=True)],
            },
        )
        store = controller.store
        state = store.load_task_state(project_id, "mission-001")
        selected = {
            validator: state.tasks[validator].last_attempt
            for validator in ("alpha", "beta")
        }
        assert all(selected.values())
        for index, validator in enumerate(("alpha", "beta")):
            misleading = f"999{index}-12-31T23-59-59Z"
            store.save_attempt(
                project_id,
                "mission-001",
                misleading,
                validator,
                ValidateHandoff(
                    node_id=validator,
                    done=True,
                    report=f"misleading-{validator}",
                    items=[ValidationItem(item_id="VAL-001", passed=False)],
                    passed=False,
                ),
            )
            selected_path = store.attempt_path(
                project_id,
                "mission-001",
                str(selected[validator]),
                validator,
            )
            misleading_path = store.attempt_path(
                project_id, "mission-001", misleading, validator
            )
            os.utime(selected_path, (2_000_000_000 - index, 2_000_000_000 - index))
            os.utime(misleading_path, (1 + index, 1 + index))

        chosen = _reloaded_gate_result(controller, project_id)
        assert _independent_frontier_oracle(controller, project_id, "g1") == {
            "VAL-001": ["alpha", "beta"]
        }
        assert chosen.cleared is True
        assert chosen.validator_verdicts == {
            "alpha": {"VAL-001": True},
            "beta": {"VAL-001": True},
        }
        assert {
            validator: Path(chosen.attempt_paths[validator]).name.split("__", 1)[0]
            for validator in ("alpha", "beta")
        } == selected

        alpha_path = store.attempt_path(
            project_id, "mission-001", str(selected["alpha"]), "alpha"
        )
        original = alpha_path.read_bytes()
        payload = json.loads(original)
        payload["node_id"] = "beta"
        alpha_path.write_text(json.dumps(payload))
        cross_task = _reloaded_gate_result(controller, project_id)
        assert cross_task.cleared is False
        assert "attempt node_id does not match running task" in (cross_task.reason or "")

        payload = json.loads(original)
        payload["attempt_id"] = "1900-01-01T00-00-00Z"
        alpha_path.write_text(json.dumps(payload))
        stale = _reloaded_gate_result(controller, project_id)
        assert stale.cleared is False
        assert "attempt_id does not match running generation" in (stale.reason or "")
        alpha_path.write_bytes(original)

    def test_uncovered_target_fails_closed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller, project_id = self._run_graph(
            config,
            workspace,
            [
                _task("w", "work", ["VAL-A", "VAL-B"]),
                _task("validator", "validate", ["VAL-A"], depends_on=["w"]),
                _task("g1", "gate", ["VAL-A", "VAL-B"], depends_on=["validator"]),
            ],
            {"validator": [ValidationItem(item_id="VAL-A", passed=True)]},
            assertions=("VAL-A", "VAL-B"),
        )

        result = _reloaded_gate_result(controller, project_id)

        assert result.cleared is False
        assert result.failed_items == ["VAL-B"]
        assert result.reason == "no validator covered item(s): VAL-B"

    @pytest.mark.parametrize("cleared", (True, False), ids=("cleared", "failed"))
    def test_large_current_matrix_has_bounded_public_and_persisted_attention(
        self, config: HarnessConfig, workspace: Path, cleared: bool
    ) -> None:
        validator_ids = [f"validator-{index:03d}" for index in range(96)]
        tasks = [_task("w", "work", ["VAL-001"])]
        tasks.extend(
            _task(validator, "validate", ["VAL-001"], depends_on=["w"])
            for validator in validator_ids
        )
        tasks.append(_task("g1", "gate", ["VAL-001"], depends_on=validator_ids))
        private_canary = "/private/validator/report-canary-never-public"
        items = {
            validator: [
                ValidationItem(
                    item_id="VAL-001",
                    passed=cleared or validator != validator_ids[-1],
                )
            ]
            for validator in validator_ids
        }

        controller, project_id = self._run_graph(
            config, workspace, tasks, items
        )
        attention = controller.store.load_attention(project_id)
        envelope = controller.inspect_project(project_id)
        assert isinstance(envelope.state, AttentionNeeded)
        sinks = {
            "public_envelope": json.dumps(envelope.model_dump(mode="json")),
            "attention": (
                controller.store.unrest_runtime_dir(project_id) / "attention.json"
            ).read_text(),
            "state": (
                controller.store.unrest_runtime_dir(project_id) / "state.json"
            ).read_text(),
        }
        result = _reloaded_gate_result(controller, project_id)

        assert len(result.validator_verdicts) == len(validator_ids)
        assert result.cleared is cleared
        assert len(attention) == 1
        persisted_lengths = [len(item.report.encode("utf-8")) for item in attention]
        public_lengths = [
            len(item.report.encode("utf-8")) for item in envelope.state.items
        ]
        assert max(persisted_lengths) < 4096
        assert max(public_lengths) < 4096
        assert all(len(text.encode("utf-8")) > 0 for text in sinks.values())
        for text in sinks.values():
            assert private_canary not in text
            assert "private-report-canary" not in text

    def test_pending_malformed_evidence_bounds_all_public_sinks(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        canary = "LONG-REPORT-CANARY-" + "x" * 6000 + " /private/secret/path"

        def responder(request: DispatchRequest) -> NodeHandoff:
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="work")
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report=canary,
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        project_id = _seed_project(controller, workspace)
        controller.submit_plan(project_id, _simple_tl())
        controller.advance_project(project_id, max_steps=2)
        state = controller.store.load_task_state(project_id, "mission-001")
        generation = state.tasks["v1"].last_attempt
        assert generation is not None
        assert state.status_of("g1") == "pending"
        attempt = controller.store.attempt_path(
            project_id, "mission-001", generation, "v1"
        )
        attempt.write_text('{"report":"' + canary)

        envelope = controller.advance_project(project_id)
        assert isinstance(envelope.state, AttentionNeeded)
        attention = controller.store.load_attention(project_id)
        sinks = (
            json.dumps(envelope.model_dump(mode="json")),
            (controller.store.unrest_runtime_dir(project_id) / "attention.json").read_text(),
            (controller.store.unrest_runtime_dir(project_id) / "state.json").read_text(),
            (
                controller.store.mission_runtime_dir(project_id, "mission-001")
                / "task-state.json"
            ).read_text(),
        )
        assert attention[0].kind == "gate_failed"
        assert len(attention[0].report.encode("utf-8")) < 4096
        assert all(
            len(item.report.encode("utf-8")) < 4096 for item in envelope.state.items
        )
        assert all("LONG-REPORT-CANARY" not in text for text in sinks)
        assert all("/private/secret/path" not in text for text in sinks)

    def test_invalid_cycle_rejects_before_persistence_and_cleared_gate_stays_sealed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id, done=True, report=""
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        project_id = _seed_project(controller, workspace)
        state_path = controller.store.unrest_runtime_dir(project_id) / "state.json"
        state_before = state_path.read_bytes()
        with pytest.raises(ToolError) as cycle_error:
            controller.submit_plan(
                project_id,
                TaskList(
                    tasks=[
                        _task("w", "work", ["VAL-001"], depends_on=["v"]),
                        _task("v", "validate", ["VAL-001"], depends_on=["w"]),
                        _task("g1", "gate", ["VAL-001"], depends_on=["v"]),
                    ]
                ),
            )
        assert cycle_error.value.code == "invalid_task_list"
        assert "cycle_detected" in str(cycle_error.value.details)
        assert state_path.read_bytes() == state_before
        with pytest.raises(ToolError) as missing_error:
            controller.submit_plan(
                project_id,
                TaskList(
                    tasks=[
                        _task("w", "work", ["VAL-001"]),
                        _task(
                            "v",
                            "validate",
                            ["VAL-001"],
                            depends_on=["absent"],
                        ),
                        _task("g1", "gate", ["VAL-001"], depends_on=["v"]),
                    ]
                ),
            )
        assert missing_error.value.code == "invalid_task_list"
        assert "dep_unknown_task" in str(missing_error.value.details)
        assert state_path.read_bytes() == state_before
        assert not (
            controller.store.mission_runtime_dir(project_id, "mission-001")
            / "tasks.json"
        ).exists()

        controller = ProjectController(
            config,
            MockDispatcher(
                lambda request: (
                    WorkHandoff(node_id=request.task.id, done=True, report="ok")
                    if request.task.type == "work"
                    else ValidateHandoff(
                        node_id=request.task.id,
                        done=True,
                        report="ok",
                        items=[ValidationItem(item_id="VAL-001", passed=True)],
                        passed=True,
                    )
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        controller.submit_plan(project_id, _simple_tl())
        controller.advance_project(project_id)
        attention = controller.store.load_attention(project_id)
        assert attention[0].kind == "gate_checkpoint", attention[0].report
        assert (
            controller.store.load_task_state(project_id, "mission-001").status_of("g1")
            == "cleared"
        )
        protected_paths = [
            controller.store.mission_runtime_dir(project_id, "mission-001")
            / "tasks.json",
            controller.store.mission_runtime_dir(project_id, "mission-001")
            / "task-state.json",
            controller.store.unrest_runtime_dir(project_id) / "attention.json",
            controller.store.unrest_runtime_dir(project_id) / "state.json",
        ]
        attempt_history = [
            path
            for record in controller.store.list_attempts(project_id, "mission-001")
            for path in (
                record.path,
                controller.store.attempt_report_path(
                    project_id, "mission-001", record.spawn_ts, record.node_id
                ),
            )
        ]
        before = {
            str(path): path.read_bytes() for path in protected_paths + attempt_history
        }

        with pytest.raises(ToolError) as sealed_error:
            controller.decide_attention(
                project_id,
                [
                    Decision(
                        item_id=attention[0].id,
                        action="patch",
                        patch=TaskListPatch(
                            add=[
                                _task(
                                    "g2",
                                    "gate",
                                    ["VAL-001"],
                                    depends_on=["v1"],
                                )
                            ],
                            supersede={"g1": "g2"},
                        ),
                    )
                ],
            )
        assert sealed_error.value.code == "invalid_patch"
        assert before == {
            str(path): path.read_bytes() for path in protected_paths + attempt_history
        }

        replay_script = (
            Path(__file__).parent
            / "fixtures"
            / "evidence_frontier_v045"
            / "replay.py"
        )
        fresh = subprocess.run(
            [
                sys.executable,
                str(replay_script),
                "sealed-patch",
                str(config.harness_home),
                project_id,
            ],
            check=True,
            capture_output=True,
        )
        fresh_result = json.loads(fresh.stdout)
        assert fresh_result["accepted"] is False
        assert fresh_result["code"] == "invalid_patch"
        ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        ).inspect_project(project_id)
        assert before == {
            str(path): path.read_bytes() for path in protected_paths + attempt_history
        }

    @pytest.mark.parametrize("retire_operation", ("supersede", "cancel"))
    def test_normal_patch_retirement_excludes_residually_reachable_validator(
        self,
        config: HarnessConfig,
        workspace: Path,
        retire_operation: str,
    ) -> None:
        def responder(request: DispatchRequest) -> NodeHandoff:
            if request.task.id == "work-old":
                return WorkHandoff(
                    node_id=request.task.id,
                    done=False,
                    report="replace this work",
                )
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="work")
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        project_id = _seed_project(controller, workspace)
        controller.submit_plan(
            project_id,
            TaskList(
                tasks=[
                    _task("work-old", "work", ["VAL-001"]),
                    _task(
                        "validator-retired",
                        "validate",
                        ["VAL-001"],
                        depends_on=["work-old"],
                    ),
                    _task(
                        "validator-keep",
                        "validate",
                        ["VAL-001"],
                        depends_on=["work-old"],
                    ),
                    _task(
                        "g1",
                        "gate",
                        ["VAL-001"],
                        depends_on=["validator-retired", "validator-keep"],
                    ),
                ]
            ),
        )
        controller.advance_project(project_id)
        attention = controller.store.load_attention(project_id)
        additions = [_task("work-new", "work", ["VAL-001"])]
        supersede = {"work-old": "work-new"}
        cancel: list[str] = []
        if retire_operation == "supersede":
            additions.append(
                _task(
                    "validator-new",
                    "validate",
                    ["VAL-001"],
                    depends_on=["work-new"],
                )
            )
            supersede["validator-retired"] = "validator-new"
        else:
            cancel = ["validator-retired"]
        old_attempt = controller.store.list_attempts(
            project_id, "mission-001", node_id="work-old"
        )[0].path
        old_attempt_digest = hashlib.sha256(old_attempt.read_bytes()).hexdigest()

        controller.decide_attention(
            project_id,
            [
                Decision(
                    item_id=attention[0].id,
                    action="patch",
                    patch=TaskListPatch(
                        add=additions,
                        supersede=supersede,
                        cancel=cancel,
                    ),
                )
            ],
        )
        controller.advance_project(project_id)
        task_list = controller.store.load_task_list(project_id, "mission-001")
        gate = next(task for task in task_list.tasks if task.id == "g1")
        # Residual reachability is a persistence control: status, not edge
        # disappearance, excludes a retired validator from the vote.
        if "validator-retired" not in gate.depends_on:
            gate.depends_on.append("validator-retired")
            controller.store.save_task_list(project_id, "mission-001", task_list)

        oracle = _independent_frontier_oracle(controller, project_id, "g1")
        result = _reloaded_gate_result(controller, project_id)
        task_state = controller.store.load_task_state(project_id, "mission-001")

        assert task_state.status_of("validator-retired") == "superseded"
        assert "validator-retired" not in oracle["VAL-001"]
        assert "validator-retired" not in result.validator_verdicts
        assert hashlib.sha256(old_attempt.read_bytes()).hexdigest() == old_attempt_digest

    def test_historical_validator_attempt_decision_and_regression_bytes_are_immutable(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(request: DispatchRequest) -> NodeHandoff:
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="work")
            passed = request.task.id == "new"
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report=f"attempt-body-canary-{request.task.id}",
                items=[ValidationItem(item_id="VAL-001", passed=passed)],
                passed=passed,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        project_id = _seed_project(controller, workspace)
        controller.submit_plan(
            project_id,
            TaskList(
                tasks=[
                    _task("w", "work", ["VAL-001"]),
                    _task("old", "validate", ["VAL-001"], depends_on=["w"]),
                    _task("new", "validate", ["VAL-001"], depends_on=["old"]),
                    _task("g1", "gate", ["VAL-001"], depends_on=["new"]),
                ]
            ),
        )
        controller.advance_project(project_id, max_steps=2)
        old_attempt = controller.store.list_attempts(
            project_id, "mission-001", node_id="old"
        )[0]
        old_markdown = controller.store.attempt_report_path(
            project_id, "mission-001", old_attempt.spawn_ts, "old"
        )
        regression = controller.store.regression_path(
            project_id, "mission-001", "VAL-001"
        )
        regression.parent.mkdir(parents=True, exist_ok=True)
        regression.write_text("# Regression ledger\n\n## Existing\nbody-canary\n")
        decision = controller.store.append_decision_record(
            project_id,
            [Decision(item_id="historical-control", action="continue")],
            [],
            summary="pre-existing-control",
        )
        immutable_paths = [old_attempt.path, old_markdown, regression, decision]
        immutable_manifest = {
            str(path.relative_to(controller.store.bucket_root(project_id))): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in immutable_paths
        }
        active_mutation_allowlist = {
            ".unrest-runtime/missions/mission-001/task-state.json",
            ".unrest-runtime/missions/mission-001/contract-state.json",
            ".unrest-runtime/attention.json",
            ".unrest-runtime/state.json",
        }
        before_files = {
            str(path.relative_to(controller.store.bucket_root(project_id))): path.read_bytes()
            for path in controller.store.bucket_root(project_id).rglob("*")
            if path.is_file()
        }

        controller.advance_project(project_id)
        attention = controller.store.load_attention(project_id)
        reloaded_result = _reloaded_gate_result(controller, project_id)
        after_manifest = {
            str(path.relative_to(controller.store.bucket_root(project_id))): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in immutable_paths
        }
        persisted_attention = (
            controller.store.unrest_runtime_dir(project_id) / "attention.json"
        ).read_text()
        changed_existing = {
            relative
            for relative, content in before_files.items()
            if (controller.store.bucket_root(project_id) / relative).read_bytes()
            != content
        }

        assert immutable_manifest == after_manifest
        assert changed_existing <= active_mutation_allowlist
        assert reloaded_result.validator_verdicts == {"new": {"VAL-001": True}}
        assert attention[0].kind == "gate_checkpoint"
        assert "attempt-body-canary-old" not in persisted_attention
        assert "attempt-body-canary-new" not in persisted_attention

    @pytest.mark.parametrize("operation", ("supersede", "cancel"))
    def test_retirement_history_and_fresh_replay_are_closed_and_exact(
        self,
        config: HarnessConfig,
        workspace: Path,
        operation: str,
    ) -> None:
        reports = {
            "old": "FAILED-BODY-CANARY /private/old/report",
            "keep": "SUCCESS-BODY-CANARY /private/keep/report",
            "new": "NEW-BODY-CANARY /private/new/report",
        }

        def responder(request: DispatchRequest) -> NodeHandoff:
            if request.task.id == "work-old":
                return WorkHandoff(
                    node_id=request.task.id,
                    done=False,
                    report="replace this work",
                )
            if request.task.type == "work":
                return WorkHandoff(node_id=request.task.id, done=True, report="work")
            return ValidateHandoff(
                node_id=request.task.id,
                done=True,
                report=reports[request.task.id],
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        project_id = _seed_project(controller, workspace)
        initial_tasks = [
            _task("work-old", "work", ["VAL-001"]),
            _task(
                "old", "validate", ["VAL-001"], depends_on=["work-old"]
            ),
            _task(
                "keep", "validate", ["VAL-001"], depends_on=["work-old"]
            ),
            _task("g1", "gate", ["VAL-001"], depends_on=["old", "keep"]),
        ]
        controller.submit_plan(project_id, TaskList(tasks=initial_tasks))
        controller.advance_project(project_id)
        attention = controller.store.load_attention(project_id)
        assert attention[0].kind == "node_failed"

        store = controller.store
        mission_id = "mission-001"
        valid_generation = "2001-01-01T00-00-00Z"
        invalid_generation = "2000-01-01T00-00-00Z"
        store.save_attempt(
            project_id,
            mission_id,
            valid_generation,
            "old",
            ValidateHandoff(
                node_id="old",
                done=True,
                report=reports["old"],
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            ),
        )
        before_state = store.load_task_state(project_id, mission_id)
        work_old_generation = before_state.tasks["work-old"].last_attempt
        before_state.set_last_attempt("old", valid_generation)
        store.save_task_state(project_id, mission_id, before_state)
        store.save_attempt(
            project_id,
            mission_id,
            invalid_generation,
            "old",
            ValidateHandoff(
                node_id="old",
                done=True,
                report="INVALID-BODY-CANARY /private/invalid/report",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            ),
        )
        invalid_json = store.attempt_path(
            project_id, mission_id, invalid_generation, "old"
        )
        invalid_payload = json.loads(invalid_json.read_text())
        invalid_payload["attempt_id"] = "1999-01-01T00-00-00Z"
        invalid_json.write_text(json.dumps(invalid_payload))

        regression = store.regression_path(project_id, mission_id, "VAL-001")
        regression.parent.mkdir(parents=True, exist_ok=True)
        regression.write_text("# Regression ledger\n\n## Existing\nREGRESSION-CANARY\n")
        decision = store.append_decision_record(
            project_id,
            [Decision(item_id="history-control", action="continue")],
            [],
            summary="pre-existing decision",
        )
        valid_json = store.attempt_path(
            project_id, mission_id, valid_generation, "old"
        )
        valid_markdown = store.attempt_report_path(
            project_id, mission_id, valid_generation, "old"
        )
        invalid_markdown = store.attempt_report_path(
            project_id, mission_id, invalid_generation, "old"
        )
        closed_paths = (
            valid_json,
            valid_markdown,
            invalid_json,
            invalid_markdown,
            decision,
            regression,
        )
        root = store.bucket_root(project_id)
        closed_manifest = {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in closed_paths
        }

        assert [
            (record.spawn_ts, record.node_id)
            for record in store.list_attempts(project_id, mission_id, node_id="old")
        ] == [(invalid_generation, "old"), (valid_generation, "old")]
        assert store.read_attempt(
            project_id, mission_id, valid_generation, "old"
        ) == ValidateHandoff(
            node_id="old",
            attempt_id=valid_generation,
            done=True,
            report=reports["old"],
            items=[ValidationItem(item_id="VAL-001", passed=False)],
            passed=False,
        )
        with pytest.raises(ValueError, match="running generation"):
            store.read_attempt(project_id, mission_id, invalid_generation, "old")
        assert valid_markdown.read_text().startswith("---\nnode_id: old\n")
        assert invalid_markdown.read_text().startswith("---\nnode_id: old\n")
        assert decision in sorted(store.decisions_dir(project_id).glob("*.md"))
        assert store.next_decision_number(project_id) == 2
        assert store.regression_entry_count(project_id, mission_id, "VAL-001") == 1
        assert regression == store.regression_path(project_id, mission_id, "VAL-001")

        before_tasks = store.load_task_list(project_id, mission_id)
        before_state = store.load_task_state(project_id, mission_id)
        assert before_tasks == TaskList(tasks=initial_tasks)
        assert before_state.model_dump(mode="json") == {
            "tasks": {
                "work-old": {"status": "failed", "last_attempt": work_old_generation},
                "old": {"status": "pending", "last_attempt": valid_generation},
                "keep": {"status": "pending", "last_attempt": None},
                "g1": {"status": "pending", "last_attempt": None},
            }
        }
        before_all = _file_manifest(root)

        additions = [_task("work-new", "work", ["VAL-001"])]
        supersede = {"work-old": "work-new"}
        cancel: list[str] = []
        if operation == "supersede":
            additions.append(
                _task("new", "validate", ["VAL-001"], depends_on=["work-new"])
            )
            supersede["old"] = "new"
        else:
            cancel = ["old"]
        controller.decide_attention(
            project_id,
            [
                Decision(
                    item_id=attention[0].id,
                    action="patch",
                    justification=f"normal {operation} repair",
                    patch=TaskListPatch(
                        add=additions,
                        supersede=supersede,
                        cancel=cancel,
                    ),
                )
            ],
        )
        controller.advance_project(project_id)

        after_tasks = store.load_task_list(project_id, mission_id)
        after_state = store.load_task_state(project_id, mission_id)
        expected_tasks = [
            _task("work-old", "work", ["VAL-001"]),
            _task("old", "validate", ["VAL-001"], depends_on=["work-new"]),
            _task("keep", "validate", ["VAL-001"], depends_on=["work-new"]),
            _task(
                "g1",
                "gate",
                ["VAL-001"],
                depends_on=(["new", "keep"] if operation == "supersede" else ["keep"]),
            ),
            _task("work-new", "work", ["VAL-001"]),
        ]
        if operation == "supersede":
            expected_tasks.append(
                _task("new", "validate", ["VAL-001"], depends_on=["work-new"])
            )
        assert after_tasks == TaskList(tasks=expected_tasks)
        assert after_state.status_of("work-old") == "superseded"
        assert after_state.status_of("old") == "superseded"
        assert after_state.status_of("work-new") == "cleared"
        assert after_state.status_of("keep") == "cleared"
        assert after_state.status_of("g1") == "cleared"
        work_new_generation = after_state.tasks["work-new"].last_attempt
        keep_generation = after_state.tasks["keep"].last_attempt
        assert work_new_generation is not None
        assert keep_generation is not None
        if operation == "supersede":
            assert after_state.status_of("new") == "cleared"
        expected_after_state = {
            "tasks": {
                "work-old": {
                    "status": "superseded",
                    "last_attempt": work_old_generation,
                },
                "old": {
                    "status": "superseded",
                    "last_attempt": valid_generation,
                },
                "keep": {"status": "cleared", "last_attempt": keep_generation},
                "g1": {"status": "cleared", "last_attempt": None},
                "work-new": {
                    "status": "cleared",
                    "last_attempt": work_new_generation,
                },
            }
        }
        if operation == "supersede":
            new_generation = after_state.tasks["new"].last_attempt
            assert new_generation is not None
            expected_after_state["tasks"]["new"] = {
                "status": "cleared",
                "last_attempt": new_generation,
            }
        assert after_state.model_dump(mode="json") == expected_after_state

        active_validator = "new" if operation == "supersede" else "keep"
        store.save_attempt(
            project_id,
            mission_id,
            "9999-12-31T23-59-59Z",
            active_validator,
            ValidateHandoff(
                node_id=active_validator,
                done=True,
                report="misleading restart generation",
                items=[ValidationItem(item_id="VAL-001", passed=False)],
                passed=False,
            ),
        )
        assert {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in closed_paths
        } == closed_manifest

        gate = next(task for task in after_tasks.tasks if task.id == "g1")
        exact_rewrite = list(gate.depends_on)
        gate.depends_on.append("old")
        store.save_task_list(project_id, mission_id, after_tasks)
        result = _reloaded_gate_result(controller, project_id)
        oracle = _independent_frontier_oracle(controller, project_id, "g1")
        expected_frontier = (
            {"VAL-001": ["keep", "new"]}
            if operation == "supersede"
            else {"VAL-001": ["keep"]}
        )
        assert exact_rewrite == (
            ["new", "keep"] if operation == "supersede" else ["keep"]
        )
        assert oracle == expected_frontier
        assert _frontier_identities(result) == oracle
        assert "old" not in result.validator_verdicts
        assert result.cleared is True

        successful_generation = after_state.tasks["keep"].last_attempt
        assert successful_generation is not None
        successful = store.read_attempt(
            project_id, mission_id, successful_generation, "keep"
        )
        assert successful is not None and successful.report == reports["keep"]

        after_all = _file_manifest(root)
        active_mutation_allowlist = {
            ".unrest-runtime/attention.json",
            ".unrest-runtime/state.json",
            f".unrest-runtime/missions/{mission_id}/tasks.json",
            f".unrest-runtime/missions/{mission_id}/task-state.json",
            f".unrest-runtime/missions/{mission_id}/contract-state.json",
            f".unrest/missions/{mission_id}/supersession-lineage.json",
        }
        active_mutation_allowlist.update(
            relative
            for relative in after_all
            if relative.startswith(f".unrest-runtime/missions/{mission_id}/attempts/")
            or relative.startswith(f".unrest/missions/{mission_id}/attempts/")
            or relative.startswith(".unrest/decisions/")
        )
        changed_paths = {
            path
            for path in set(before_all) | set(after_all)
            if before_all.get(path) != after_all.get(path)
        }
        assert changed_paths <= active_mutation_allowlist
        assert not changed_paths & set(closed_manifest)

        public_sinks = (
            json.dumps(controller.inspect_project(project_id).model_dump(mode="json")),
            (store.unrest_runtime_dir(project_id) / "attention.json").read_text(),
            (store.unrest_runtime_dir(project_id) / "state.json").read_text(),
        )
        for canary in (
            "FAILED-BODY-CANARY",
            "SUCCESS-BODY-CANARY",
            "INVALID-BODY-CANARY",
            "/private/old/report",
            "/private/keep/report",
            "/private/invalid/report",
        ):
            assert all(canary not in sink for sink in public_sinks)

        before_replay = _file_manifest(root)
        first = _fresh_frontier_probe(config, project_id, "g1")
        second = _fresh_frontier_probe(config, project_id, "g1")
        replay = json.loads(first)
        assert first == second
        assert replay["oracle"] == expected_frontier
        assert {
            target: [
                node_id
                for node_id, votes in replay["matrix"].items()
                if target in votes
            ]
            for target in replay["oracle"]
        } == replay["oracle"]
        assert replay["cleared"] is True
        assert replay["statuses"]["old"] == "superseded"
        assert _file_manifest(root) == before_replay
        assert set(_file_manifest(root)) - set(before_replay) == set()
        assert {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in closed_paths
        } == closed_manifest


class TestSubmitPlanValidation:
    def test_contract_less_plan_rejected(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda req: WorkHandoff(node_id=req.task.id, done=True, report="ok")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        # Seed the project but author no contract assertion files.
        controller.start_project("Brief.", str(workspace))
        pid = controller.store.list_projects()[0].id

        with pytest.raises(ToolError) as exc:
            controller.submit_plan(pid, TaskList(tasks=[_task("w1", "work", [])]))
        assert exc.value.code == "invalid_task_list"
        assert any("empty_contract" in str(d) for d in (exc.value.details or []))

        state = controller.store.load_state(pid)
        assert state is not None and state.state == "mission_planning"


class TestDecideAttentionValidation:
    def test_atomic_rejection(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        with pytest.raises(ToolError) as exc:
            controller.decide_attention(
                pid,
                [Decision(item_id=items[0].id, action="next_mission")],
            )
        assert exc.value.code == "invalid_decisions"

    def test_missing_decision_rejected(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            return WorkHandoff(node_id=req.task.id, done=False, report="blocked")

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        with pytest.raises(ToolError) as exc:
            controller.decide_attention(pid, [])
        assert any(
            "unresolved_attention_item" in str(d) for d in (exc.value.details or [])
        )


class TestTerminalReview:
    def test_clean_review_to_done(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        responses: list[NodeHandoff] = [
            WorkHandoff(node_id="w1", done=True, report=""),
            ValidateHandoff(
                node_id="v1",
                done=True,
                report="",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            ),
        ]
        gen = iter(responses)

        def responder(req: DispatchRequest) -> NodeHandoff:
            return next(gen)

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "done"

    def test_terminal_review_report_raises_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        reviewer = MockTerminalReviewer(
            TerminalReviewHandoff(
                done=False,
                report=(
                    "Terminal review found a blocking gap.\n"
                    "- brief_reference: brief quote\n"
                    "- description: missing endpoint"
                ),
            )
        )
        controller = ProjectController(config, MockDispatcher(responder), reviewer)
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        env = controller.end_mission(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "terminal_review"
        assert "missing endpoint" in items[0].report


class TestDecideAttentionPatchAddItems:
    """Regression: decide_attention(patch) with add_items must source
    old_ids from contract-state, not from disk listing."""

    def test_add_items_through_decide_attention_succeeds(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config, MockDispatcher(responder), MockTerminalReviewer(TerminalReviewHandoff(done=True, report=""))
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert items[0].kind == "gate_checkpoint"

        contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
        (contract_dir / "NEW-001.md").write_text("# NEW-001\n\nNew assertion.\n")

        # Patch declaring NEW-001 + supporting tasks. The new gate depends on
        # g1 transitively via the new work task (which depends on g1).
        patch = TaskListPatch(
            add_items=["NEW-001"],
            add=[
                _task("w2", "work", ["NEW-001"], depends_on=["g1"]),
                _task("v2", "validate", ["NEW-001"], skill="aud", depends_on=["w2"]),
                _task("g2", "gate", ["NEW-001"], depends_on=["v2"]),
            ],
        )
        env2 = controller.decide_attention(
            pid,
            [Decision(item_id=items[0].id, action="patch", patch=patch)],
        )
        assert env2.state.state == "mission_running"


class TestEnvelopeProjectId:
    def test_envelope_carries_project_id(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config, MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        env = controller.inspect_project(pid)
        assert env.projectId == pid
        env2 = controller.inspect_project(env.projectId)
        assert env2.projectId == env.projectId

    def test_tool_specific_dag_modes(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        def responder(req: DispatchRequest) -> NodeHandoff:
            if req.task.type == "work":
                return WorkHandoff(node_id=req.task.id, done=True, report="ok")
            return ValidateHandoff(
                node_id=req.task.id,
                done=True,
                report="audited",
                items=[ValidationItem(item_id="VAL-001", passed=True)],
                passed=True,
            )

        controller = ProjectController(
            config,
            MockDispatcher(responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        start = controller.start_project("Brief.", str(workspace))
        assert start.dag is None
        pid = start.projectId
        contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
        (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nStatement body.\n")

        submitted = controller.submit_plan(pid, _simple_tl())
        assert submitted.dag is not None
        assert "    w1  [work:s]  pending  → VAL-001  ← (root)" in submitted.dag
        assert "focus-subgraph" not in submitted.dag

        inspected = controller.inspect_project(pid)
        assert inspected.dag is not None
        assert "    w1" in inspected.dag
        assert "    v1" in inspected.dag
        assert "    g1" in inspected.dag
        assert "focus-subgraph" not in inspected.dag

        advanced = controller.advance_project(pid, max_steps=1)
        assert advanced.dag is not None
        assert "focus-subgraph" not in advanced.dag

        attention = controller.advance_project(pid)
        assert attention.state.state == "attention_needed"
        assert attention.dag is not None
        assert "focus-subgraph" not in attention.dag
        items = controller.store.load_attention(pid)

        decided = controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        assert decided.dag is None

        controller.advance_project(pid)
        ended = controller.end_mission(pid)
        assert ended.dag is None


class TestAbortProject:
    def test_aborts(self, config: HarnessConfig, workspace: Path) -> None:
        controller = ProjectController(
            config, MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.abort_project(pid, "user requested")
        assert env.state.state == "aborted"
        assert env.dag is None

    @pytest.mark.parametrize(
        "reason",
        (
            "a" * (MAX_ABORT_REASON_BYTES - 1),
            "a" * MAX_ABORT_REASON_BYTES,
            "🚀" * (MAX_ABORT_REASON_BYTES // 4),
        ),
        ids=("boundary-minus-one", "boundary", "unicode-byte-boundary"),
    )
    def test_abort_reason_utf8_boundary_persists_and_reloads_exactly(
        self, config: HarnessConfig, workspace: Path, reason: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)

        env = controller.abort_project(pid, reason)
        reloaded = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        ).inspect_project(pid)
        closeout = controller.store.mission_dir(pid, "mission-001") / "closeout.md"

        assert env.state.reason == reason  # type: ignore[union-attr]
        assert reloaded.state == env.state
        assert closeout.read_text().endswith(reason + "\n")
        assert len(env.state.reason.encode()) <= MAX_ABORT_REASON_BYTES  # type: ignore[union-attr]

    @pytest.mark.parametrize("active", (False, True), ids=("planning", "active"))
    @pytest.mark.parametrize(
        "reason",
        ("a" * (MAX_ABORT_REASON_BYTES + 1), "x" * 200_000),
        ids=("boundary-plus-one", "two-hundred-thousand"),
    )
    def test_oversized_abort_is_rejected_before_any_terminal_write(
        self, config: HarnessConfig, workspace: Path, active: bool, reason: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        if active:
            controller.submit_plan(pid, _simple_tl())
        state_path = controller.store.unrest_runtime_dir(pid) / "state.json"
        before = state_path.read_bytes()
        closeout = controller.store.mission_dir(pid, "mission-001") / "closeout.md"

        with pytest.raises(ToolError, match="4096 UTF-8 bytes") as exc_info:
            controller.abort_project(pid, reason)

        assert len(str(exc_info.value).encode()) < 256
        assert state_path.read_bytes() == before
        assert not closeout.exists()

    def test_abort_rejects_unencodable_unicode_before_writes(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        state_path = controller.store.unrest_runtime_dir(pid) / "state.json"
        before = state_path.read_bytes()

        with pytest.raises(ToolError, match="not valid Unicode"):
            controller.abort_project(pid, "\ud800")

        assert state_path.read_bytes() == before


class TestResume:
    def test_resume_picks_up_attempt_landed_while_down(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")),
        )
        pid = _seed_project(controller, workspace)
        store = controller.store
        controller.submit_plan(pid, _simple_tl())

        ts = store.load_task_state(pid, "mission-001")
        ts.set_status("w1", "running")
        ts.set_last_attempt("w1", "2026-01-01T00-00-00Z")
        store.save_task_state(pid, "mission-001", ts)
        store.save_attempt(
            pid,
            "mission-001",
            "2026-01-01T00-00-00Z",
            "w1",
            WorkHandoff(node_id="w1", done=True, report="landed"),
        )
        store.save_state(pid, MissionRunning(mission_id="mission-001"))
        controller.advance_project(pid)
        ts = store.load_task_state(pid, "mission-001")
        assert ts.status_of("w1") == "cleared"

    @pytest.mark.parametrize(
        "case",
        (
            "malformed_json",
            "wrong_task",
            "stale_generation",
            "replayed_success",
            "null_attempt_id",
            "missing_done",
        ),
    )
    def test_invalid_attempt_provenance_fails_closed_and_is_idempotent(
        self, config: HarnessConfig, workspace: Path, case: str
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "running")
        task_state.set_last_attempt("w1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        expected = store.attempt_path(pid, "mission-001", generation, "w1")
        expected.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "node_id": "w1",
            "attempt_id": generation,
            "done": True,
            "report": "must not be replayed",
            "request_attention": False,
        }
        if case == "malformed_json":
            expected.write_text("{")
        elif case == "wrong_task":
            payload["node_id"] = "other-task"
            expected.write_text(json.dumps(payload))
        elif case == "stale_generation":
            payload["attempt_id"] = "2026-08-09T12-00-00Z"
            expected.write_text(json.dumps(payload))
        elif case == "replayed_success":
            old = store.attempt_path(
                pid, "mission-001", "2026-08-09T12-00-00Z", "w1"
            )
            payload["attempt_id"] = "2026-08-09T12-00-00Z"
            old.write_text(json.dumps(payload))
        elif case == "null_attempt_id":
            payload["attempt_id"] = None
            expected.write_text(json.dumps(payload))
        else:
            payload.pop("done")
            expected.write_text(json.dumps(payload))

        restarted = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        )
        result = restarted.advance_project(pid, max_steps=1)

        assert result.state.state == "attention_needed"
        assert store.load_task_state(pid, "mission-001").status_of("w1") == "failed"
        attention = store.load_attention(pid)
        assert len(attention) == 1
        assert len(attention[0].report.encode()) < 4096
        observed = {
            "state": (store.unrest_runtime_dir(pid) / "state.json").read_bytes(),
            "tasks": (
                store.mission_runtime_dir(pid, "mission-001") / "task-state.json"
            ).read_bytes(),
            "attention": (
                store.unrest_runtime_dir(pid) / "attention.json"
            ).read_bytes(),
            "attempts": tuple(
                (path.name, path.read_bytes())
                for path in sorted(
                    store.attempts_runtime_dir(pid, "mission-001").glob("*.json")
                )
            ),
        }

        repeated = restarted.advance_project(pid, max_steps=1)
        assert repeated.state.state == "attention_needed"
        assert observed["state"] == (
            store.unrest_runtime_dir(pid) / "state.json"
        ).read_bytes()
        assert observed["tasks"] == (
            store.mission_runtime_dir(pid, "mission-001") / "task-state.json"
        ).read_bytes()
        assert observed["attention"] == (
            store.unrest_runtime_dir(pid) / "attention.json"
        ).read_bytes()
        assert observed["attempts"] == tuple(
            (path.name, path.read_bytes())
            for path in sorted(
                store.attempts_runtime_dir(pid, "mission-001").glob("*.json")
            )
        )

    def test_valid_current_generation_attempt_resumes_once(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda r: WorkHandoff(node_id=r.task.id, done=True, report="")
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        store = controller.store
        generation = "2026-08-10T12-00-00Z"
        task_state = store.load_task_state(pid, "mission-001")
        task_state.set_status("w1", "running")
        task_state.set_last_attempt("w1", generation)
        store.save_task_state(pid, "mission-001", task_state)
        store.save_attempt(
            pid,
            "mission-001",
            generation,
            "w1",
            WorkHandoff(node_id="w1", done=True, report="current"),
        )

        restarted = ProjectController(
            config, controller.dispatcher, controller.terminal_reviewer
        )
        restarted.advance_project(pid, max_steps=1)
        attempts_before = tuple(store.list_attempts(pid, "mission-001", node_id="w1"))

        assert store.load_task_state(pid, "mission-001").status_of("w1") == "cleared"
        assert store.load_attention(pid) == []
        assert tuple(store.list_attempts(pid, "mission-001", node_id="w1")) == attempts_before

    def test_dispatched_explicit_null_attempt_id_fails_closed(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(
                lambda request: WorkHandoff(
                    node_id=request.task.id,
                    attempt_id=None,
                    done=True,
                    report="explicit null must not bind",
                )
            ),
            MockTerminalReviewer(TerminalReviewHandoff(done=True)),
        )
        pid = _seed_project(controller, workspace)
        controller.submit_plan(pid, _simple_tl())

        result = controller.advance_project(pid, max_steps=1)

        assert result.state.state == "attention_needed"
        attempt = controller.store.list_attempts(
            pid, "mission-001", node_id="w1"
        )[0]
        persisted = json.loads(attempt.path.read_text(encoding="utf-8"))
        assert persisted["done"] is False
        assert persisted["attempt_id"] == attempt.spawn_ts
        assert "null attempt identity" in persisted["report"]
