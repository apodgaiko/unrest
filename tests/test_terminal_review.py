"""Terminal review wiring tests — drive a mission to drain + verify outcomes.

See docs/v5/10-implementation-plan.md §2 Phase 7.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
import unrest_harness.acp_runner as acp_runner_module

from unrest_harness.acp_runner import ACPTerminalReviewer, ACPNodeRunner
from unrest_harness.assets import AssetLoader
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import (
    DispatchRequest,
    MockDispatcher,
    MockTerminalReviewer,
    NodeHandoff,
)
from unrest_harness.models import (
    Decision,
    Task,
    TaskList,
    TerminalReviewConfig,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore


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


def _task(tid: str, ttype: str, targets: list[str], skill: str | None = None,
          depends_on: list[str] | None = None) -> Task:
    if skill is None and ttype != "gate":
        skill = "s"
    return Task(
        id=tid,
        type=ttype,  # type: ignore[arg-type]
        body="" if ttype == "gate" else "b",
        targets=targets,
        skill=skill,
        depends_on=depends_on or [],
    )


def _simple_tl() -> TaskList:
    return TaskList(tasks=[
        _task("w1", "work", ["VAL-001"]),
        _task("v1", "validate", ["VAL-001"], skill="aud", depends_on=["w1"]),
        _task("g1", "gate", ["VAL-001"], depends_on=["v1"]),
    ])


def _start_and_seed_contract(
    controller: ProjectController, workspace: Path
) -> str:
    """Run start_project, then seed mission-001 contract VAL-001 inside the bucket."""
    controller.start_project("brief", str(workspace))
    pid = controller.store.list_projects()[0].id
    contract_dir = controller.store.ensure_contract_dir(pid, "mission-001")
    (contract_dir / "VAL-001.md").write_text("# VAL-001\n\nstatement\n")
    return pid


def _responder(req: DispatchRequest) -> NodeHandoff:
    if req.task.type == "work":
        return WorkHandoff(node_id=req.task.id, done=True, report="")
    return ValidateHandoff(
        node_id=req.task.id,
        done=True,
        report="",
        items=[ValidationItem(item_id="VAL-001", passed=True)],
        passed=True,
    )


def _advance_to_closure(controller: ProjectController, pid: str) -> None:
    controller.submit_plan(pid, _simple_tl())
    env = controller.advance_project(pid)
    assert env.state.state == "attention_needed"
    items = controller.store.load_attention(pid)
    controller.decide_attention(
        pid, [Decision(item_id=items[0].id, action="continue")]
    )
    env = controller.advance_project(pid)
    assert env.state.state == "mission_running"


def _resume_after_terminal_gap(controller: ProjectController, pid: str) -> None:
    items = controller.store.load_attention(pid)
    assert len(items) == 1
    assert items[0].kind == "terminal_review"
    env = controller.decide_attention(
        pid, [Decision(item_id=items[0].id, action="continue")]
    )
    assert env.state.state == "mission_running"


@dataclass(frozen=True)
class _ReviewerInput:
    deliverable_roots: list[str]
    prompt: str
    contents_read: dict[str, str]


class _ScriptedRecordingReviewer:
    """Render the real reviewer prompt and read only its declared file roots."""

    def __init__(
        self,
        config: HarnessConfig,
        *,
        expected_report: Path | None = None,
        expected_content: str = "",
        succeed_when_visible: bool = True,
    ) -> None:
        self.store = ProjectStore(config)
        self.runner = ACPNodeRunner(config, AssetLoader(config))
        self.expected_report = expected_report
        self.expected_content = expected_content
        self.succeed_when_visible = succeed_when_visible
        self.inputs: list[_ReviewerInput] = []

    def review(
        self, project_id: str, mission_id: str, spawn_ts: str
    ) -> TerminalReviewHandoff:
        del spawn_ts
        roots = self.store.load_terminal_review_config(
            project_id, mission_id
        ).deliverable_roots
        prompt = self.runner._render_terminal_reviewer_prompts(
            project_bucket=str(self.store.unrest_dir(project_id)),
            workspace_dir=str(self.store.workspace_dir(project_id)),
            deliverable_roots=roots,
        )
        contents = {
            root: Path(root).read_text(encoding="utf-8")
            for root in roots
            if Path(root).is_file()
        }
        self.inputs.append(
            _ReviewerInput(
                deliverable_roots=list(roots),
                prompt=prompt,
                contents_read=contents,
            )
        )
        expected_root = (
            str(self.expected_report.resolve())
            if self.expected_report is not None
            else None
        )
        visible = (
            expected_root is not None
            and contents.get(expected_root) == self.expected_content
        )
        if visible and self.succeed_when_visible:
            return TerminalReviewHandoff(
                done=True, report="Declared final report content verified."
            )
        return TerminalReviewHandoff(
            done=False,
            report="GAP-ARTIFACT-NOT-VISIBLE: final report is not authorized.",
        )


class TestCleanReview:
    def test_clean_review_seals_done(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        controller = ProjectController(
            config,
            MockDispatcher(_responder),
            MockTerminalReviewer(TerminalReviewHandoff(done=True, report="all clear")),
        )
        pid = _start_and_seed_contract(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        # First advance: gate_checkpoint
        env = controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        report = controller.store.mission_dir(pid, "mission-001") / "evidence" / "report.md"
        report.parent.mkdir(parents=True)
        report.write_text("final report")
        env = controller.end_mission(pid, [str(report)])
        assert env.state.state == "done"
        review_config = controller.store.load_terminal_review_config(
            pid, "mission-001"
        )
        assert review_config.deliverable_roots == [str(report.resolve())]
        # Closeout written
        closeout = controller.store.mission_dir(pid, "mission-001") / "closeout.md"
        assert closeout.exists()
        assert "status: done" in closeout.read_text()


class TestTerminalReviewerFailure:
    def test_illegal_environment_name_is_recoverable_attention_before_any_work(
        self,
        config: HarnessConfig,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canary = "CANARY=ILLEGAL_ENVIRONMENT_NAME"
        rejected_config = replace(
            config,
            terminal_reviewer_acp_command=sys.executable,
        )
        reviewer = ACPTerminalReviewer(rejected_config)
        actual_build_launch_plan = acp_runner_module.build_launch_plan

        def illegal_environment_build_launch_plan(command, *, cwd, environment):
            copied_environment = dict(environment)
            copied_environment[canary] = "CANARY-VALUE"
            return actual_build_launch_plan(
                command,
                cwd=cwd,
                environment=copied_environment,
            )

        async def forbidden_mcp(**kwargs):
            raise AssertionError("reviewer MCP startup must not be reached")

        async def forbidden_spawn(*args, **kwargs):
            raise AssertionError("adapter spawn must not be reached")

        class ForbiddenClient:
            def __init__(self, *args, **kwargs) -> None:
                raise AssertionError("ACPClient construction must not be reached")

        monkeypatch.setattr(
            reviewer.runner, "_start_terminal_reviewer_mcp", forbidden_mcp
        )
        monkeypatch.setattr(
            "unrest_harness.acp_runner.build_launch_plan",
            illegal_environment_build_launch_plan,
        )
        monkeypatch.setattr("unrest_harness.acp_runner.spawn_launch", forbidden_spawn)
        monkeypatch.setattr("unrest_harness.acp_runner.ACPClient", ForbiddenClient)
        controller = ProjectController(
            rejected_config,
            MockDispatcher(_responder),
            reviewer,
        )
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        env = controller.end_mission(pid)

        assert env.state.state == "attention_needed"
        reloaded = ProjectStore(rejected_config)
        items = reloaded.load_attention(pid)
        assert len(items) == 1
        assert items[0].kind == "terminal_review"
        assert items[0].report == "ACP adapter launch rejected: invalid_command"
        persisted_reviews = list(
            reloaded.terminal_reviews_dir(pid, "mission-001").glob("*.md")
        )
        assert len(persisted_reviews) == 1
        persisted = persisted_reviews[0].read_text(encoding="utf-8")
        assert "done: false" in persisted
        assert "ACP adapter launch rejected: invalid_command" in persisted
        assert "CANARY" not in persisted
        assert not (
            reloaded.mission_dir(pid, "mission-001") / "closeout.md"
        ).exists()

    @pytest.mark.parametrize(
        "field",
        ["argv0", "later_argv", "cwd", "env_key", "env_value", "path"],
    )
    @pytest.mark.parametrize("malformation", ["nul", "unencodable"])
    def test_malformed_os_launch_string_is_recoverable_attention(
        self,
        config: HarnessConfig,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
        malformation: str,
    ) -> None:
        malformed = "CANARY\0VALUE" if malformation == "nul" else "\ud800"
        try:
            os.fsencode(malformed)
        except UnicodeError:
            pass
        else:
            if malformation == "unencodable":
                pytest.skip("host filesystem encoding accepts the unpaired surrogate")

        command = sys.executable
        if field == "argv0":
            command = malformed
        elif field == "later_argv":
            command = f"{command} '{malformed}'"
        rejected_config = replace(config, terminal_reviewer_acp_command=command)
        reviewer = ACPTerminalReviewer(rejected_config)
        actual_build_launch_plan = acp_runner_module.build_launch_plan

        def malformed_build_launch_plan(command, *, cwd, environment):
            copied_environment = dict(environment)
            if field == "cwd":
                cwd = malformed
            elif field == "env_key":
                copied_environment[malformed] = "value"
            elif field == "env_value":
                copied_environment["MALFORMED_VALUE"] = malformed
            elif field == "path":
                copied_environment["PATH"] = malformed
            return actual_build_launch_plan(
                command,
                cwd=cwd,
                environment=copied_environment,
            )

        async def forbidden_mcp(**kwargs):
            raise AssertionError("reviewer MCP startup must not be reached")

        async def forbidden_spawn(*args, **kwargs):
            raise AssertionError("adapter spawn must not be reached")

        class ForbiddenClient:
            def __init__(self, *args, **kwargs) -> None:
                raise AssertionError("ACPClient construction must not be reached")

        monkeypatch.setattr(
            reviewer.runner, "_start_terminal_reviewer_mcp", forbidden_mcp
        )
        monkeypatch.setattr(
            "unrest_harness.acp_runner.build_launch_plan",
            malformed_build_launch_plan,
        )
        monkeypatch.setattr("unrest_harness.acp_runner.spawn_launch", forbidden_spawn)
        monkeypatch.setattr("unrest_harness.acp_runner.ACPClient", ForbiddenClient)
        controller = ProjectController(
            rejected_config,
            MockDispatcher(_responder),
            reviewer,
        )
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        env = controller.end_mission(pid)

        assert env.state.state == "attention_needed"
        reloaded = ProjectStore(rejected_config)
        items = reloaded.load_attention(pid)
        assert len(items) == 1
        assert items[0].kind == "terminal_review"
        assert items[0].report == "ACP adapter launch rejected: invalid_command"
        persisted_reviews = list(
            reloaded.terminal_reviews_dir(pid, "mission-001").glob("*.md")
        )
        assert len(persisted_reviews) == 1
        persisted = persisted_reviews[0].read_text(encoding="utf-8")
        assert "done: false" in persisted
        assert "ACP adapter launch rejected: invalid_command" in persisted
        assert "CANARY" not in persisted
        assert not (
            reloaded.mission_dir(pid, "mission-001") / "closeout.md"
        ).exists()

    def test_preflight_rejection_persists_safe_recoverable_attention(
        self,
        config: HarnessConfig,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canary = "CANARY-terminal-command-path-env-secret-prompt-stderr-body"
        rejected_config = replace(
            config,
            terminal_reviewer_acp_command=f"./{canary}",
        )
        monkeypatch.setenv("PATH", canary)
        monkeypatch.setenv("OPENAI_API_KEY", canary)
        reviewer = ACPTerminalReviewer(rejected_config)

        async def forbidden_mcp(**kwargs):
            raise AssertionError("reviewer MCP startup must not be reached")

        class ForbiddenClient:
            def __init__(self, *args, **kwargs) -> None:
                raise AssertionError("ACPClient construction must not be reached")

        monkeypatch.setattr(
            reviewer.runner, "_start_terminal_reviewer_mcp", forbidden_mcp
        )
        monkeypatch.setattr("unrest_harness.acp_runner.ACPClient", ForbiddenClient)
        controller = ProjectController(
            rejected_config,
            MockDispatcher(_responder),
            reviewer,
        )
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        env = controller.end_mission(pid)

        assert env.state.state == "attention_needed"
        reloaded = ProjectStore(rejected_config)
        items = reloaded.load_attention(pid)
        assert len(items) == 1
        assert items[0].kind == "terminal_review"
        assert items[0].report == "ACP adapter launch rejected: missing"
        persisted_reviews = list(
            reloaded.terminal_reviews_dir(pid, "mission-001").glob("*.md")
        )
        assert len(persisted_reviews) == 1
        persisted = persisted_reviews[0].read_text(encoding="utf-8")
        assert "done: false" in persisted
        assert "ACP adapter launch rejected: missing" in persisted
        assert canary not in persisted
        assert not (
            reloaded.mission_dir(pid, "mission-001") / "closeout.md"
        ).exists()

    def test_production_timeout_handoff_is_persisted_and_does_not_seal(
        self,
        config: HarnessConfig,
        workspace: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        reviewer = ACPTerminalReviewer(config)

        async def timed_out(*args, **kwargs) -> TerminalReviewHandoff:
            return TerminalReviewHandoff(
                done=False,
                report=(
                    "Terminal review timed out after 900 seconds. The ACP reviewer "
                    "and its MCP server were stopped; closure was not sealed."
                ),
            )

        monkeypatch.setattr(reviewer.runner, "run_terminal_review", timed_out)
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        env = controller.end_mission(pid)

        assert env.state.state == "attention_needed"
        assert not (
            controller.store.mission_dir(pid, "mission-001") / "closeout.md"
        ).exists()
        reviews = list(
            controller.store.terminal_reviews_dir(pid, "mission-001").glob("*.md")
        )
        assert len(reviews) == 1
        persisted = reviews[0].read_text(encoding="utf-8")
        assert "done: false" in persisted
        assert "timed out after 900 seconds" in persisted

    def test_runtime_failure_is_recoverable_attention(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        class FailingReviewer:
            def review(
                self, project_id: str, mission_id: str, spawn_ts: str
            ) -> TerminalReviewHandoff:
                raise RuntimeError("reviewer exited without a handoff")

        controller = ProjectController(config, MockDispatcher(_responder), FailingReviewer())
        pid = _start_and_seed_contract(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        controller.advance_project(pid)
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        controller.advance_project(pid)

        env = controller.end_mission(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        assert len(items) == 1
        assert items[0].kind == "terminal_review"
        assert "reviewer exited without a handoff" in items[0].report
        reviews = list(controller.store.terminal_reviews_dir(pid, "mission-001").iterdir())
        assert len(reviews) == 1
        assert "runtime failure" in reviews[0].read_text(encoding="utf-8")

        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        controller.terminal_reviewer = MockTerminalReviewer(
            TerminalReviewHandoff(done=True, report="retry clean")
        )
        env = controller.end_mission(pid)
        assert env.state.state == "done"


class TestDeclaredRootClosure:
    def test_report_is_invisible_without_root_then_visible_with_exact_root(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        report_content = "release-status: complete\n"
        reviewer = _ScriptedRecordingReviewer(
            config,
            expected_content=report_content,
        )
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        report = (
            controller.store.mission_dir(pid, "mission-001")
            / "evidence"
            / "final"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text(report_content, encoding="utf-8")
        reviewer.expected_report = report

        mission = controller.store.mission_dir(pid, "mission-001")
        process_history = {
            mission / "mission.md": "mission-charter-sentinel",
            mission / "contract" / "VAL-001.md": "contract-sentinel",
            mission / "attempts" / "prior-worker.md": "worker-report-sentinel",
            mission / "regressions" / "VAL-001.md": "validator-report-sentinel",
            mission / "terminal-reviews" / "prior.md": "prior-review-sentinel",
            mission / "closeout.md": "closeout-history-sentinel",
            controller.store.unrest_dir(pid) / "decisions" / "prior.md": (
                "decision-sentinel"
            ),
            controller.store.unrest_dir(pid) / "MEMORY.md": "mission-memory-sentinel",
            controller.store.unrest_dir(pid) / "AGENTS.md": (
                "agent-guidance-sentinel"
            ),
            controller.store.mission_runtime_dir(pid, "mission-001")
            / "private-cursor.json": "runtime-cursor-sentinel",
            controller.store.unrest_dir(pid)
            / "skills"
            / "private-provider"
            / "SKILL.md": "provider-control-sentinel",
        }
        for path, content in process_history.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        env = controller.end_mission(pid)
        assert env.state.state == "attention_needed"
        assert reviewer.inputs[0].deliverable_roots == []
        assert reviewer.inputs[0].contents_read == {}
        state = controller.store.load_state(pid)
        assert state is not None
        assert state.state != "done"

        _resume_after_terminal_gap(controller, pid)
        env = controller.end_mission(pid, [str(report)])
        assert env.state.state == "done"

        canonical_report = str(report.resolve())
        declared_input = reviewer.inputs[1]
        assert declared_input.deliverable_roots == [canonical_report]
        assert declared_input.contents_read == {canonical_report: report_content}
        assert canonical_report in declared_input.prompt
        persisted = controller.store.load_terminal_review_config(pid, "mission-001")
        assert persisted.deliverable_roots == [canonical_report]
        state = controller.store.load_state(pid)
        assert state is not None
        assert state.state == "done"

        for reviewer_input in reviewer.inputs:
            for path, sentinel in process_history.items():
                assert str(path.resolve()) not in reviewer_input.prompt
                assert sentinel not in reviewer_input.prompt

    def test_aliased_allowed_bases_are_canonicalized_on_retry(
        self, config: HarnessConfig, tmp_path: Path
    ) -> None:
        physical_root = tmp_path / "physical"
        physical_root.mkdir()
        aliased_root = tmp_path / "aliased"
        aliased_root.symlink_to(physical_root, target_is_directory=True)
        harness_home = aliased_root / "harness-home"
        aliased_config = replace(
            config,
            harness_home=harness_home,
            projects_dir=harness_home / "projects",
        )
        workspace = aliased_root / "workspace"
        workspace.mkdir()
        report_content = "release-status: complete\n"
        reviewer = _ScriptedRecordingReviewer(
            aliased_config,
            expected_content=report_content,
        )
        controller = ProjectController(
            aliased_config, MockDispatcher(_responder), reviewer
        )
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        report = (
            controller.store.mission_dir(pid, "mission-001")
            / "evidence"
            / "final"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text(report_content, encoding="utf-8")
        reviewer.expected_report = report
        product = workspace / "product.md"
        product.write_text("product", encoding="utf-8")

        first = controller.end_mission(pid, None)
        assert first.state.state == "attention_needed"
        assert reviewer.inputs[0].deliverable_roots == []
        _resume_after_terminal_gap(controller, pid)

        second = controller.end_mission(pid, [str(product), str(report)])
        expected_roots = sorted([str(product.resolve()), str(report.resolve())])
        assert second.state.state == "done"
        assert reviewer.inputs[1].deliverable_roots == expected_roots
        assert reviewer.inputs[1].contents_read == {
            str(product.resolve()): "product",
            str(report.resolve()): report_content,
        }
        assert controller.store.load_terminal_review_config(
            pid, "mission-001"
        ).deliverable_roots == expected_roots

    def test_none_clear_and_replace_persist_across_failed_review_retries(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        reviewer = _ScriptedRecordingReviewer(
            config, succeed_when_visible=False
        )
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        evidence = controller.store.mission_dir(pid, "mission-001") / "evidence"
        report_a = evidence / "a.md"
        report_b = evidence / "b.md"
        evidence.mkdir(parents=True)
        report_a.write_text("a", encoding="utf-8")
        report_b.write_text("b", encoding="utf-8")
        config_path = controller.store.terminal_review_config_path(
            pid, "mission-001"
        )

        controller.end_mission(pid, None)
        assert reviewer.inputs[-1].deliverable_roots == []
        assert not config_path.exists()

        _resume_after_terminal_gap(controller, pid)
        controller.end_mission(
            pid, [str(report_b), str(report_a), str(report_b)]
        )
        replaced = sorted([str(report_a.resolve()), str(report_b.resolve())])
        assert reviewer.inputs[-1].deliverable_roots == replaced
        assert controller.store.load_terminal_review_config(
            pid, "mission-001"
        ).deliverable_roots == replaced

        _resume_after_terminal_gap(controller, pid)
        controller.end_mission(pid, None)
        assert reviewer.inputs[-1].deliverable_roots == replaced

        _resume_after_terminal_gap(controller, pid)
        controller.end_mission(pid, [])
        assert reviewer.inputs[-1].deliverable_roots == []
        assert controller.store.load_terminal_review_config(
            pid, "mission-001"
        ).deliverable_roots == []

        _resume_after_terminal_gap(controller, pid)
        controller.end_mission(pid, None)
        assert reviewer.inputs[-1].deliverable_roots == []

    def test_invalid_new_roots_block_reviewer_dispatch(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        reviewer = _ScriptedRecordingReviewer(config)
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        mission = controller.store.mission_dir(pid, "mission-001")
        evidence = mission / "evidence"
        escaping = evidence / "escaping"
        broken = evidence / "broken"
        escaping.mkdir(parents=True)
        broken.mkdir(parents=True)
        (escaping / "contract-link").symlink_to(mission / "contract")
        (broken / "missing-link").symlink_to(evidence / "does-not-exist")
        product = workspace / "product.md"
        product.write_text("product", encoding="utf-8")
        direct_escape = evidence / "direct-escape"
        direct_escape.symlink_to(product)
        control_path = evidence / "bad\nname.md"
        control_path.write_text("bad", encoding="utf-8")
        mission_md = mission / "mission.md"
        mission_md.write_text("mission", encoding="utf-8")
        workspace_git = workspace / ".git"
        workspace_git.mkdir()

        invalid_roots = [
            evidence / "missing.md",
            control_path,
            escaping,
            broken,
            direct_escape,
            mission_md,
            mission,
            workspace_git,
            workspace,
        ]
        for invalid_root in invalid_roots:
            with pytest.raises(ToolError) as exc_info:
                controller.end_mission(pid, [str(invalid_root)])
            assert exc_info.value.code == "invalid_deliverable_roots"
        assert reviewer.inputs == []

    def test_invalid_persisted_root_blocks_coordinator_dispatch(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        reviewer = _ScriptedRecordingReviewer(config)
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        _advance_to_closure(controller, pid)

        report = (
            controller.store.mission_dir(pid, "mission-001")
            / "evidence"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text("report", encoding="utf-8")
        resolved = controller.store.resolve_terminal_review_roots(
            pid, "mission-001", [str(report)]
        )
        controller.store.save_terminal_review_config(
            pid,
            "mission-001",
            TerminalReviewConfig(deliverable_roots=resolved),
        )
        report.unlink()

        with pytest.raises(ToolError) as exc_info:
            controller.end_mission(pid, None)
        assert exc_info.value.code == "invalid_deliverable_roots"
        assert reviewer.inputs == []


class TestGapsTransition:
    def test_terminal_review_report_then_next_mission_seals(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
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
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        controller.end_mission(pid)
        review_dir = controller.store.terminal_reviews_dir(pid, "mission-001")
        assert review_dir.exists() and any(review_dir.iterdir())
        # Resolve via next_mission
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="next_mission")]
        )
        # mission-002 should be the new current mission
        record = ProjectStore(config).load_project(pid)
        assert record.current_mission_id == "mission-002"


class TestAbortRoundtripFromTerminalReview:
    def test_abort_via_decision(
        self, config: HarnessConfig, workspace: Path
    ) -> None:
        reviewer = MockTerminalReviewer(
            TerminalReviewHandoff(done=False, report="blocking gap: x\nbrief: y")
        )
        controller = ProjectController(config, MockDispatcher(_responder), reviewer)
        pid = _start_and_seed_contract(controller, workspace)
        controller.submit_plan(pid, _simple_tl())
        env = controller.advance_project(pid)
        assert env.state.state == "attention_needed"
        items = controller.store.load_attention(pid)
        controller.decide_attention(
            pid, [Decision(item_id=items[0].id, action="continue")]
        )
        env = controller.advance_project(pid)
        assert env.state.state == "mission_running"
        controller.end_mission(pid)
        items = controller.store.load_attention(pid)
        env = controller.decide_attention(
            pid,
            [
                Decision(
                    item_id=items[0].id,
                    action="abort",
                    justification="user decision",
                )
            ],
        )
        assert env.state.state == "aborted"
