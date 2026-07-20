from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from textual.widgets import Static

from zenith_harness.cli import cli
from zenith_harness.config import HarnessConfig
from zenith_harness.live import build_live_snapshot
from zenith_harness.live_dashboard import build_dashboard_view_model
from zenith_harness.models import (
    AttentionItemInternal,
    ContractStateEntry,
    ContractStateFile,
    Done,
    Failed,
    MissionRunning,
    Task,
    TaskList,
    TaskStateFile,
    WorkHandoff,
)
from zenith_harness.storage import ProjectStore
from zenith_harness.textual_dashboard import ZenithDashboardApp


@pytest.fixture
def config(harness_home: Path) -> HarnessConfig:
    bundled = Path(__file__).resolve().parents[1] / "src" / "zenith_harness" / "bundled"
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
    )


@pytest.fixture
def store(config: HarnessConfig) -> ProjectStore:
    return ProjectStore(config)


def _seed_dashboard_project(
    store: ProjectStore,
    workspace: Path,
    *,
    project_id: str,
    state: object,
    work_status: str = "running",
    validate_status: str = "pending",
    attention: bool = False,
    attempt_report: str | None = None,
    attention_report: str | None = None,
    evidence_text: str = "dashboard evidence line\n",
) -> None:
    record = store.create_project("dashboard", workspace, project_id=project_id)
    record.current_mission_id = "mission-001"
    store.save_project(record)
    store.save_state(project_id, state)  # type: ignore[arg-type]
    store.save_task_list(
        project_id,
        "mission-001",
        TaskList(
            tasks=[
                Task(
                    id="w1",
                    type="work",
                    body="Implement dashboard core with selected task context.",
                    targets=["VAL-DASHBOARD-001", "VAL-DETAIL-004"],
                    skill="engineering-mission-playbook",
                ),
                Task(
                    id="v1",
                    type="validate",
                    body="Validate dashboard through Textual pilot.",
                    targets=["VAL-DASHBOARD-001"],
                    skill="user-testing-validator",
                    depends_on=["w1"],
                ),
            ]
        ),
    )
    task_state = TaskStateFile()
    task_state.set_status("w1", work_status)  # type: ignore[arg-type]
    task_state.set_status("v1", validate_status)  # type: ignore[arg-type]
    store.save_task_state(project_id, "mission-001", task_state)
    contract_dir = store.ensure_contract_dir(project_id, "mission-001")
    (contract_dir / "VAL-DASHBOARD-001.md").write_text("# VAL-DASHBOARD-001\n", encoding="utf-8")
    store.save_contract_state(
        project_id,
        "mission-001",
        ContractStateFile(
            items={"VAL-DASHBOARD-001": ContractStateEntry(status="pending")}
        ),
    )
    store.save_attempt(
        project_id,
        "mission-001",
        "2026-01-01T00-00-00Z",
        "w1",
        WorkHandoff(
            node_id="w1",
            done=False,
            request_attention=attention,
            report=attempt_report
            or (
                "## Summary\nDashboard distinctive summary.\n\n"
                "## Verification\nPilot exercised distinctive verification.\n\n"
                "## Risks Or Blockers\nNone for fixture.\n"
            ),
        ),
    )
    evidence_dir = store.mission_dir(project_id, "mission-001") / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "dashboard-evidence.txt").write_text(evidence_text, encoding="utf-8")
    if attention:
        store.save_attention(
            project_id,
            [
                AttentionItemInternal(
                    id="att-dashboard",
                    kind="node_attention",
                    mission_id="mission-001",
                    node_id="w1",
                    report=attention_report
                    or "Attention distinctive report for dashboard validation.",
                )
            ],
        )


def _touch_project(store: ProjectStore, project_id: str, mtime: float) -> None:
    for path in store.bucket_root(project_id).rglob("*"):
        if path.is_file():
            os.utime(path, (mtime, mtime))


def _file_mtimes(root: Path) -> dict[Path, int]:
    return {path: path.stat().st_mtime_ns for path in root.rglob("*") if path.is_file()}


def test_fleet_prioritizes_urgent_running_pinned_and_latest_remaining(
    store: ProjectStore,
    config: HarnessConfig,
    tmp_path: Path,
) -> None:
    projects = [
        ("urgent", MissionRunning(mission_id="mission-001"), True, 100, "running"),
        ("failed-flow", Failed(reason="boom"), False, 390, "failed"),
        ("fresh-running", MissionRunning(mission_id="mission-001"), False, 380, "running"),
        ("stale-running", MissionRunning(mission_id="mission-001"), False, 100, "running"),
        ("pinned-done", Done(), False, 50, "cleared"),
        ("done-1", Done(), False, 370, "cleared"),
        ("done-2", Done(), False, 360, "cleared"),
        ("done-3", Done(), False, 350, "cleared"),
        ("done-4", Done(), False, 340, "cleared"),
        ("done-5", Done(), False, 330, "cleared"),
        ("done-6", Done(), False, 320, "cleared"),
    ]
    for project_id, state, attention, mtime, work_status in projects:
        workspace = tmp_path / project_id
        workspace.mkdir()
        _seed_dashboard_project(
            store,
            workspace,
            project_id=project_id,
            state=state,
            attention=attention,
            work_status=work_status,
        )
        _touch_project(store, project_id, mtime)

    snapshot = build_live_snapshot(config=config)
    model = build_dashboard_view_model(
        snapshot,
        pinned_project_ids={"pinned-done"},
        selected_project_id="fresh-running",
        now=400.0,
    )

    by_id = {flow.id: flow for flow in model.flows}
    assert by_id["urgent"].status == "urgent attention"
    assert by_id["failed-flow"].status == "failed"
    assert by_id["fresh-running"].status == "running"
    assert by_id["stale-running"].status == "stale running"
    assert by_id["done-1"].status == "done"
    assert by_id["pinned-done"].is_pinned
    visible_ids = [flow.id for flow in model.visible_flows]
    assert visible_ids[:4] == ["urgent", "failed-flow", "stale-running", "fresh-running"]
    assert "pinned-done" in visible_ids
    assert {"done-1", "done-2", "done-3", "done-4", "done-5"}.issubset(visible_ids)
    assert "done-6" not in visible_ids
    intervention = model.render_intervention()
    assert "INTERVENTION [CRIT] NEEDS INPUT: 3 risk flow(s)" in intervention
    assert "ASK 1 | FAIL 1 | LONG 0 | STALE 1 | RUN 2 | DONE 7" in intervention
    assert "1. [ASK] ! urgent age=5m00s attention=1" in intervention
    assert "2. [FAIL] x failed-flow age=10s failed_tasks=1" in intervention
    assert "3. [STALE] ~ stale-running age=5m00s stale" in intervention
    fleet = model.render_fleet()
    assert "[ASK] ! urgent" in fleet
    assert "[FAIL] x failed-flow" in fleet
    assert "[STALE] ~ stale-running" in fleet
    assert "mix W1/V1/G0 R1/F0/P1" in fleet
    assert "sig att=1 run=1 pend=1 attempts=1" in fleet
    full = build_dashboard_view_model(snapshot, show_full_list=True, now=400.0)
    assert len(full.visible_flows) == len(projects)


def test_long_running_flow_is_visibly_distinct_from_stale(
    store: ProjectStore,
    config: HarnessConfig,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "longcase"
    workspace.mkdir()
    _seed_dashboard_project(
        store,
        workspace,
        project_id="longcase",
        state=MissionRunning(mission_id="mission-001"),
    )
    _touch_project(store, "longcase", 1)

    snapshot = build_live_snapshot(config=config)
    model = build_dashboard_view_model(snapshot, selected_project_id="longcase", now=1000.0)
    flow = model.flows[0]

    assert flow.is_stale is True
    assert flow.is_long_running is True
    assert flow.status == "long running"
    assert flow.status_chip == "[LONG]"
    assert "long" in flow.signals
    assert "stale" not in flow.signals
    assert "[LONG] > longcase" in model.render_fleet()
    assert "long-running" in model.render_intervention()


def test_detail_output_attention_aggregation_consumption_and_actions(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
) -> None:
    _seed_dashboard_project(
        store,
        workspace,
        project_id="detail-project",
        state=MissionRunning(mission_id="mission-001"),
        attention=True,
        evidence_text="evidence distinctive raw line\n",
    )
    _touch_project(store, "detail-project", 100)
    snapshot = build_live_snapshot(config=config)

    compact = build_dashboard_view_model(
        snapshot,
        selected_project_id="detail-project",
        selected_task_id="w1",
        now=120.0,
    )
    rendered_detail = compact.render_detail()
    assert "[ASK] ! action=USER INPUT" in rendered_detail
    assert "Progress [----------] 0/2 cleared | run=1 fail=0 pend=1 attempts=1" in rendered_detail
    assert "[RUN] > w1 work/running | skill=engineering-mission-playbook | targets=2" in rendered_detail
    assert "Task id: w1" in rendered_detail
    assert "Type/status: work/running" in rendered_detail
    assert "Skill: engineering-mission-playbook" in rendered_detail
    assert "Targets: VAL-DASHBOARD-001, VAL-DETAIL-004" in rendered_detail
    assert "Context:" in rendered_detail
    assert "selected task context" in rendered_detail
    assert "dashboard-evidence.txt" in rendered_detail

    rendered_output = compact.render_output()
    assert "Agent Output - compact" in rendered_output
    assert "Dashboard distinctive summary" in rendered_output
    assert "Pilot exercised distinctive verification" in rendered_output
    assert "evidence distinctive raw line" in rendered_output

    expanded = build_dashboard_view_model(
        snapshot,
        selected_project_id="detail-project",
        selected_task_id="w1",
        now=120.0,
        output_full=True,
        attention_expanded=True,
    )
    assert "Agent Output - full/tail" in expanded.render_output()
    assert "## Report" in expanded.render_output()
    assert "att-dashboard" in expanded.render_attention()
    assert "kind=node_attention" in expanded.render_attention()
    assert "Full report:" in expanded.render_attention()
    assert "Task types: work=1, validate=1, gate=0" in expanded.render_aggregation()
    assert "Progress: [----------]" in expanded.render_aggregation()
    assert "engineering-mission-playbook=1" in expanded.render_aggregation()
    assert "Tool calls: future telemetry" in expanded.render_aggregation()
    assert "Tokens: coming soon" in expanded.render_consumption()
    assert "Cost: coming soon" in expanded.render_consumption()
    assert "Age: last activity 20s | stale=no" in expanded.render_consumption()
    assert "Pressure: attention=1 failed=0 running=1 attempts=1" in expanded.render_consumption()
    assert "preview future" in expanded.render_actions()
    assert "No dashboard key executes actions" in expanded.render_actions()


def test_output_and_attention_default_truncate_while_expansion_preserves_tail(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
) -> None:
    long_summary = "\n".join(f"summary line {index}" for index in range(30))
    long_attention = "\n".join(f"attention line {index}" for index in range(35))
    _seed_dashboard_project(
        store,
        workspace,
        project_id="long-output",
        state=MissionRunning(mission_id="mission-001"),
        attention=True,
        attempt_report=(
            "## Summary\n"
            f"{long_summary}\n\n"
            "## Verification\n"
            "verification sentinel\n\n"
            "## Risks Or Blockers\n"
            "none\n"
        ),
        attention_report=f"{long_attention}\nattention FINAL_SENTINEL",
        evidence_text="\n".join(f"evidence line {index}" for index in range(20)),
    )
    _touch_project(store, "long-output", 100)
    snapshot = build_live_snapshot(config=config)

    compact = build_dashboard_view_model(
        snapshot,
        selected_project_id="long-output",
        selected_task_id="w1",
        now=500.0,
    )
    output_lines = compact.output.lines
    attention_lines = compact.attention.lines

    assert len(output_lines) == 16
    assert output_lines[-1] == "... press o for full/tail output"
    assert "summary line 29" not in compact.render_output()
    assert len(attention_lines) <= 6
    assert "FINAL_SENTINEL" not in compact.render_attention()

    expanded = build_dashboard_view_model(
        snapshot,
        selected_project_id="long-output",
        selected_task_id="w1",
        now=500.0,
        output_full=True,
        attention_expanded=True,
    )

    assert "summary line 29" in expanded.render_output()
    assert "attention FINAL_SENTINEL" in expanded.render_attention()


@pytest.mark.asyncio
async def test_textual_app_constructs_and_interactions_do_not_mutate_project_files(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    tmp_path: Path,
) -> None:
    second = tmp_path / "second"
    second.mkdir()
    _seed_dashboard_project(
        store,
        workspace,
        project_id="first",
        state=MissionRunning(mission_id="mission-001"),
    )
    _seed_dashboard_project(
        store,
        second,
        project_id="second",
        state=MissionRunning(mission_id="mission-001"),
    )
    _touch_project(store, "first", 100)
    _touch_project(store, "second", 200)
    before = _file_mtimes(config.projects_dir)

    def snapshot():
        return build_live_snapshot(config=config)

    app = ZenithDashboardApp(
        snapshot_provider=snapshot,
        refresh_interval=None,
        now_provider=lambda: 250.0,
    )
    async with app.run_test() as pilot:
        assert app.model is not None
        intervention = app.query_one("#intervention", Static)
        assert "INTERVENTION" in str(intervention.render())
        assert app.selected_project_id == "second"
        await pilot.press("j")
        assert app.selected_project_id == "first"
        await pilot.press("n")
        assert app.selected_task_id == "v1"
        await pilot.press("p")
        assert "first" in app.pinned_project_ids
        await pilot.press("f")
        assert app.show_full_list is True
        await pilot.press("o")
        assert app.output_full is True
        await pilot.press("a")
        assert app.attention_expanded is True
        await pilot.press("q")

    assert _file_mtimes(config.projects_dir) == before


def test_live_dashboard_cli_invokes_textual_app(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_dashboard_project(
        store,
        workspace,
        project_id="cli-project",
        state=MissionRunning(mission_id="mission-001"),
    )
    ran: dict[str, int] = {}

    def fake_run(self: ZenithDashboardApp) -> None:
        ran["project_count"] = self.snapshot_provider().project_count

    monkeypatch.setattr(ZenithDashboardApp, "run", fake_run)
    result = CliRunner().invoke(
        cli,
        [
            "live",
            "--dashboard",
            "--projects-dir",
            str(config.projects_dir),
            "--interval",
            "0.1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert ran == {"project_count": 1}


def test_live_watch_mode_still_renders_until_keyboard_interrupt(
    store: ProjectStore,
    config: HarnessConfig,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_dashboard_project(
        store,
        workspace,
        project_id="watch-project",
        state=MissionRunning(mission_id="mission-001"),
    )

    def stop_after_first_render(_delay: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("zenith_harness.cli.time.sleep", stop_after_first_render)
    result = CliRunner().invoke(
        cli,
        [
            "live",
            "--projects-dir",
            str(config.projects_dir),
            "--interval",
            "0.1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "watch-project" in result.output
