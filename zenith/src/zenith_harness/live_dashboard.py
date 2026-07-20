"""Dashboard view-models for read-only Zenith live snapshots."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable

from .live import AttentionSnapshot, LiveSnapshot, ProjectSnapshot, RecentFile, TaskSnapshot

STALE_AFTER_SECONDS = 180
LONG_RUNNING_SECONDS = 15 * 60
TERMINAL_STATES = {"done", "failed", "aborted"}
ACTIVE_STATES = {"mission_planning", "mission_running", "attention_needed"}
IMPORTANT_SECTIONS = {
    "summary",
    "implemented",
    "left undone",
    "contract targets",
    "verification",
    "tests",
    "evidence",
    "discovered issues",
    "risks or blockers",
    "risks",
    "items",
}


@dataclass(frozen=True)
class InterventionView:
    severity: str
    needs_intervention: bool
    lines: list[str]


@dataclass(frozen=True)
class FlowView:
    id: str
    short_id: str
    state: str
    mission_id: str | None
    mission_label: str
    workspace: str
    attention_count: int
    status: str
    status_chip: str
    status_glyph: str
    severity: str
    severity_rank: int
    is_urgent: bool
    is_failed: bool
    is_active: bool
    is_stale: bool
    is_long_running: bool
    is_pinned: bool
    is_selected: bool
    last_activity_at: str | None
    last_activity_age_seconds: int | None
    age_label: str
    progress_bar: str
    progress_label: str
    task_mix: str
    signals: tuple[str, ...]
    attempt_count: int
    running_tasks: int
    failed_tasks: int
    pending_tasks: int
    task_summary: str


@dataclass(frozen=True)
class TaskView:
    id: str
    type: str
    status: str
    status_chip: str
    status_glyph: str
    skill: str
    targets: str
    target_count: int
    dependencies: str
    context: str
    is_selected: bool


@dataclass(frozen=True)
class DetailView:
    project_id: str | None
    mission_id: str | None
    state: str
    flow_status: str
    tasks: list[TaskView]
    selected_task: TaskView | None
    recent_attempts: list[str]
    recent_evidence: list[str]
    lines: list[str]


@dataclass(frozen=True)
class OutputView:
    compact_lines: list[str]
    full_lines: list[str]
    showing_full: bool

    @property
    def lines(self) -> list[str]:
        return self.full_lines if self.showing_full else self.compact_lines


@dataclass(frozen=True)
class AttentionView:
    lines: list[str]
    has_attention: bool
    expanded: bool


@dataclass(frozen=True)
class AggregationView:
    lines: list[str]


@dataclass(frozen=True)
class ConsumptionView:
    lines: list[str]


@dataclass(frozen=True)
class ActionsView:
    lines: list[str]
    preview_only: bool = True


@dataclass(frozen=True)
class DashboardViewModel:
    generated_at: str
    projects_dir: str
    selected_project_id: str | None
    selected_task_id: str | None
    show_full_list: bool
    intervention: InterventionView
    flows: list[FlowView]
    visible_flows: list[FlowView]
    detail: DetailView
    output: OutputView
    attention: AttentionView
    aggregation: AggregationView
    consumption: ConsumptionView
    actions: ActionsView

    def render_intervention(self) -> str:
        return "\n".join(self.intervention.lines)

    def render_fleet(self) -> str:
        title = "Fleet - full list" if self.show_full_list else "Fleet - priority view"
        lines = [
            title,
            f"Projects {len(self.flows)} | Visible {len(self.visible_flows)} | Sorted by risk",
        ]
        if not self.visible_flows:
            lines.append("No Zenith projects found.")
            return "\n".join(lines)
        for index, flow in enumerate(self.visible_flows, start=1):
            marker = ">" if flow.is_selected else " "
            lines.append(
                f"{marker}{index:02d} {flow.status_chip} {flow.status_glyph} "
                f"{flow.short_id:<18} age={flow.age_label:<7} {flow.progress_bar} "
                f"{flow.progress_label:<13} mix {flow.task_mix}"
            )
            lines.append(
                f"    sig {' '.join(flow.signals)} | mission={flow.mission_label}"
            )
        return "\n".join(lines)

    def render_detail(self) -> str:
        return "\n".join(self.detail.lines)

    def render_tasks(self) -> str:
        if not self.detail.tasks:
            return "Tasks\nNo task list for selected flow."
        lines = ["Tasks"]
        for index, task in enumerate(self.detail.tasks, start=1):
            marker = ">" if task.is_selected else " "
            lines.append(
                f"{marker}{index:02d} {task.status_chip} {task.status_glyph} "
                f"{task.id:<8} {task.type}/{task.status} "
                f"targets={task.target_count} skill={task.skill}"
            )
        return "\n".join(lines)

    def render_output(self) -> str:
        title = "Agent Output - full/tail" if self.output.showing_full else "Agent Output - compact"
        return "\n".join([title, *self.output.lines])

    def render_attention(self) -> str:
        title = "Attention - expanded" if self.attention.expanded else "Attention"
        return "\n".join([title, *self.attention.lines])

    def render_aggregation(self) -> str:
        return "\n".join(["Aggregation", *self.aggregation.lines])

    def render_consumption(self) -> str:
        return "\n".join(["Consumption", *self.consumption.lines])

    def render_actions(self) -> str:
        return "\n".join(["Actions - preview only", *self.actions.lines])


def build_dashboard_view_model(
    snapshot: LiveSnapshot,
    *,
    pinned_project_ids: Iterable[str] = (),
    selected_project_id: str | None = None,
    selected_task_id: str | None = None,
    now: datetime | float | int | None = None,
    show_full_list: bool = False,
    output_full: bool = False,
    attention_expanded: bool = False,
) -> DashboardViewModel:
    """Build a read-only dashboard view-model from a live snapshot."""
    pinned = set(pinned_project_ids)
    now_ts = _timestamp(now) if now is not None else _snapshot_timestamp(snapshot)
    selected_project_id = _select_project_id(snapshot, selected_project_id)
    project_by_id = {project.id: project for project in snapshot.projects}
    if selected_project_id not in project_by_id:
        selected_project_id = snapshot.selected_project_id
    if selected_project_id not in project_by_id and snapshot.projects:
        selected_project_id = snapshot.projects[0].id

    flows = [
        _flow_view(
            project,
            now_ts=now_ts,
            is_pinned=project.id in pinned,
            is_selected=project.id == selected_project_id,
        )
        for project in snapshot.projects
    ]
    flows.sort(key=_flow_sort_key)
    visible_flows = _visible_flows(flows, selected_project_id, show_full_list=show_full_list)
    selected_project = project_by_id.get(selected_project_id or "")
    selected_flow = next((flow for flow in flows if flow.id == selected_project_id), None)
    detail = _detail_view(selected_project, selected_flow, selected_task_id)
    selected_task_id = detail.selected_task.id if detail.selected_task else None
    output = _output_view(selected_project, selected_task_id, output_full=output_full)
    attention = _attention_view(
        selected_project,
        selected_task_id,
        expanded=attention_expanded,
    )
    aggregation = _aggregation_view(selected_project)
    consumption = _consumption_view(snapshot, selected_project, now_ts=now_ts)
    actions = _actions_view(selected_project, selected_task_id)
    intervention = _intervention_view(flows, snapshot)
    return DashboardViewModel(
        generated_at=snapshot.generated_at,
        projects_dir=snapshot.projects_dir,
        selected_project_id=selected_project_id,
        selected_task_id=selected_task_id,
        show_full_list=show_full_list,
        intervention=intervention,
        flows=flows,
        visible_flows=visible_flows,
        detail=detail,
        output=output,
        attention=attention,
        aggregation=aggregation,
        consumption=consumption,
        actions=actions,
    )


def _flow_view(
    project: ProjectSnapshot,
    *,
    now_ts: float,
    is_pinned: bool,
    is_selected: bool,
) -> FlowView:
    task_counts = project.mission.task_state_counts if project.mission else {}
    contract_counts = project.mission.contract_state_counts if project.mission else {}
    running_tasks = task_counts.get("running", 0)
    failed_tasks = task_counts.get("failed", 0)
    pending_tasks = task_counts.get("pending", 0)
    cleared_tasks = task_counts.get("cleared", 0)
    task_count = project.mission.task_count if project.mission else 0
    attempt_count = len(project.mission.recent_attempts) if project.mission else 0
    is_urgent = project.attention_count > 0 or project.state == "attention_needed"
    is_failed = (
        project.state == "failed"
        or failed_tasks > 0
        or contract_counts.get("failed", 0) > 0
    )
    is_active = project.state in ACTIVE_STATES
    age = None
    if project.last_activity_mtime > 0:
        age = max(0, int(now_ts - project.last_activity_mtime))
    is_stale = is_active and not is_urgent and age is not None and age >= STALE_AFTER_SECONDS
    is_long_running = is_active and age is not None and age >= LONG_RUNNING_SECONDS
    status = _flow_status(
        project,
        is_urgent=is_urgent,
        is_failed=is_failed,
        is_active=is_active,
        is_stale=is_stale,
        is_long_running=is_long_running,
    )
    severity, severity_rank = _flow_severity(
        project,
        is_urgent=is_urgent,
        is_failed=is_failed,
        is_active=is_active,
        is_stale=is_stale,
        is_long_running=is_long_running,
    )
    progress_bar = _progress_bar(cleared_tasks, task_count)
    progress_label = f"{cleared_tasks}/{task_count} cleared" if task_count else "0/0 tasks"
    task_mix = _task_mix(project)
    signals = _flow_signals(
        project,
        is_pinned=is_pinned,
        is_urgent=is_urgent,
        is_failed=is_failed,
        is_stale=is_stale,
        is_long_running=is_long_running,
        attempt_count=attempt_count,
        running_tasks=running_tasks,
        failed_tasks=failed_tasks,
        pending_tasks=pending_tasks,
    )
    return FlowView(
        id=project.id,
        short_id=_short_id(project.id),
        state=project.state,
        mission_id=project.current_mission_id,
        mission_label=_short_id(project.current_mission_id or "-", limit=14),
        workspace=project.workspace,
        attention_count=project.attention_count,
        status=status,
        status_chip=_status_chip(status),
        status_glyph=_status_glyph(status),
        severity=severity,
        severity_rank=severity_rank,
        is_urgent=is_urgent,
        is_failed=is_failed,
        is_active=is_active,
        is_stale=is_stale,
        is_long_running=is_long_running,
        is_pinned=is_pinned,
        is_selected=is_selected,
        last_activity_at=project.last_activity_at or None,
        last_activity_age_seconds=age,
        age_label=_age_label(age),
        progress_bar=progress_bar,
        progress_label=progress_label,
        task_mix=task_mix,
        signals=signals,
        attempt_count=attempt_count,
        running_tasks=running_tasks,
        failed_tasks=failed_tasks,
        pending_tasks=pending_tasks,
        task_summary=_task_summary(project),
    )


def _flow_status(
    project: ProjectSnapshot,
    *,
    is_urgent: bool,
    is_failed: bool,
    is_active: bool,
    is_stale: bool,
    is_long_running: bool,
) -> str:
    if is_urgent:
        return "urgent attention"
    if is_failed:
        return "failed"
    if project.state == "done":
        return "done"
    if project.state == "aborted":
        return "aborted"
    if is_long_running:
        return "long running"
    if is_stale:
        return "stale running"
    if is_active:
        return "running"
    return project.state


def _flow_severity(
    project: ProjectSnapshot,
    *,
    is_urgent: bool,
    is_failed: bool,
    is_active: bool,
    is_stale: bool,
    is_long_running: bool,
) -> tuple[str, int]:
    if is_urgent:
        return "CRIT", 0
    if is_failed:
        return "CRIT", 1
    if is_stale or is_long_running:
        return "WARN", 2
    if project.state == "aborted":
        return "WARN", 3
    if is_active:
        return "LIVE", 4
    if project.state == "done":
        return "OK", 5
    return "IDLE", 6


def _flow_sort_key(flow: FlowView) -> tuple[int, int, int, int, str]:
    age = flow.last_activity_age_seconds or 0
    age_sort = -age if flow.severity_rank <= 2 else age
    return (
        flow.severity_rank,
        0 if flow.is_pinned else 1,
        0 if flow.is_selected else 1,
        age_sort,
        flow.id,
    )


def _visible_flows(
    flows: list[FlowView],
    selected_project_id: str | None,
    *,
    show_full_list: bool,
) -> list[FlowView]:
    if show_full_list:
        return list(flows)
    visible: list[FlowView] = []
    visible_ids: set[str] = set()

    def add_matching(predicate) -> None:
        for flow in flows:
            if predicate(flow) and flow.id not in visible_ids:
                visible.append(flow)
                visible_ids.add(flow.id)

    add_matching(lambda flow: flow.is_urgent)
    add_matching(lambda flow: flow.is_failed)
    add_matching(lambda flow: flow.is_stale or flow.is_long_running)
    add_matching(lambda flow: flow.is_active and not flow.is_urgent)
    add_matching(lambda flow: flow.is_pinned)
    if selected_project_id:
        add_matching(lambda flow: flow.id == selected_project_id)

    for flow in flows:
        if flow.id in visible_ids:
            continue
        visible.append(flow)
        visible_ids.add(flow.id)
        remaining_count = len(
            [
                item
                for item in visible
                if not item.is_urgent
                and not item.is_failed
                and not item.is_stale
                and not item.is_long_running
                and not item.is_active
                and not item.is_pinned
            ]
        )
        if remaining_count >= 5:
            break
    return visible


def _intervention_view(flows: list[FlowView], snapshot: LiveSnapshot) -> InterventionView:
    if not flows:
        return InterventionView(
            severity="OK",
            needs_intervention=False,
            lines=[
                "INTERVENTION [OK] no projects",
                f"Projects dir: {snapshot.projects_dir}",
            ],
        )

    attention_flows = [flow for flow in flows if flow.is_urgent]
    failed_flows = [flow for flow in flows if flow.is_failed and not flow.is_urgent]
    long_flows = [
        flow
        for flow in flows
        if flow.is_long_running and not flow.is_urgent and not flow.is_failed
    ]
    stale_flows = [
        flow
        for flow in flows
        if flow.is_stale
        and not flow.is_long_running
        and not flow.is_urgent
        and not flow.is_failed
    ]
    running_flows = [flow for flow in flows if flow.is_active and not flow.is_urgent]
    done_flows = [flow for flow in flows if flow.state == "done"]
    risk_flows = [*attention_flows, *failed_flows, *long_flows, *stale_flows]
    needs_intervention = bool(risk_flows)
    severity = risk_flows[0].severity if risk_flows else "OK"
    headline = "NEEDS INPUT" if attention_flows else "CHECK NOW" if risk_flows else "CLEAR"
    running_tasks = sum(flow.running_tasks for flow in flows)
    attempts = sum(flow.attempt_count for flow in flows)

    lines = [
        f"INTERVENTION [{severity}] {headline}: {len(risk_flows)} risk flow(s)",
        (
            f"ASK {len(attention_flows)} | FAIL {len(failed_flows)} | "
            f"LONG {len(long_flows)} | STALE {len(stale_flows)} | "
            f"RUN {len(running_flows)} | DONE {len(done_flows)} "
            f"| running tasks {running_tasks} | attempts {attempts}"
        ),
    ]
    if risk_flows:
        lines.append("Top risks")
        for index, flow in enumerate(risk_flows[:3], start=1):
            reason = _risk_reason(flow)
            lines.append(
                f"{index}. {flow.status_chip} {flow.status_glyph} {flow.short_id} "
                f"age={flow.age_label} {reason} {flow.progress_label}"
            )
    else:
        active = next((flow for flow in flows if flow.is_active), None)
        if active:
            lines.append(
                f"Watch {active.short_id}: {active.status_chip} "
                f"age={active.age_label} {active.progress_label}"
            )
        else:
            lines.append("No active intervention signals.")
    return InterventionView(
        severity=severity,
        needs_intervention=needs_intervention,
        lines=lines,
    )


def _risk_reason(flow: FlowView) -> str:
    if flow.is_urgent:
        return f"attention={flow.attention_count}"
    if flow.is_failed:
        return f"failed_tasks={flow.failed_tasks}"
    if flow.is_long_running:
        return "long-running"
    if flow.is_stale:
        return "stale"
    return flow.status


def _detail_view(
    project: ProjectSnapshot | None,
    flow: FlowView | None,
    selected_task_id: str | None,
) -> DetailView:
    if project is None:
        return DetailView(
            project_id=None,
            mission_id=None,
            state="none",
            flow_status="none",
            tasks=[],
            selected_task=None,
            recent_attempts=[],
            recent_evidence=[],
            lines=["Selected Flow", "No project selected."],
        )

    tasks = project.mission.tasks if project.mission else []
    selected_task = _select_task(tasks, selected_task_id)
    task_views = [_task_view(task, is_selected=task.id == (selected_task.id if selected_task else None)) for task in tasks]
    selected_task_view = next((task for task in task_views if task.is_selected), None)
    recent_attempts = _attempt_labels(project, selected_task_view.id if selected_task_view else None)
    recent_evidence = _file_labels(project.mission.recent_evidence if project.mission else [])
    mission = project.mission
    task_counts = mission.task_state_counts if mission else {}
    task_count = mission.task_count if mission else 0
    cleared = task_counts.get("cleared", 0)
    running = task_counts.get("running", 0)
    failed = task_counts.get("failed", 0)
    pending = task_counts.get("pending", 0)
    attempts = len(mission.recent_attempts) if mission else 0
    intervention = _detail_intervention_label(project, flow)
    lines = [
        "Selected Flow",
        (
            f"{flow.status_chip if flow else _status_chip(project.state)} "
            f"{flow.status_glyph if flow else _status_glyph(project.state)} "
            f"action={intervention} | state={project.state} | "
            f"status={flow.status if flow else project.state}"
        ),
        (
            f"Progress {_progress_bar(cleared, task_count)} {cleared}/{task_count} cleared | "
            f"run={running} fail={failed} pend={pending} attempts={attempts}"
        ),
        (
            f"Age {flow.age_label if flow else _age_label(None)} | "
            f"mission={project.current_mission_id or '-'} | project={project.id}"
        ),
        f"Workspace: {project.workspace}",
        f"Last activity: {project.last_activity_at or '-'}",
        f"Last activity path: {project.last_activity_path or '-'}",
    ]
    if selected_task_view:
        lines.extend(
            [
                "",
                "Selected Task",
                (
                    f"{selected_task_view.status_chip} {selected_task_view.status_glyph} "
                    f"{selected_task_view.id} {selected_task_view.type}/{selected_task_view.status} | "
                    f"skill={selected_task_view.skill} | targets={selected_task_view.target_count}"
                ),
                f"Task id: {selected_task_view.id}",
                f"Type/status: {selected_task_view.type}/{selected_task_view.status}",
                f"Skill: {selected_task_view.skill}",
                f"Targets: {selected_task_view.targets or '-'}",
                f"Dependencies: {selected_task_view.dependencies or '-'}",
                "Context:",
                selected_task_view.context or "-",
            ]
        )
    else:
        lines.extend(["", "Selected Task", "No tasks available."])
    if recent_attempts:
        lines.extend(["", "Recent attempts", *recent_attempts])
    if recent_evidence:
        lines.extend(["", "Recent evidence", *recent_evidence])
    return DetailView(
        project_id=project.id,
        mission_id=project.current_mission_id,
        state=project.state,
        flow_status=flow.status if flow else project.state,
        tasks=task_views,
        selected_task=selected_task_view,
        recent_attempts=recent_attempts,
        recent_evidence=recent_evidence,
        lines=lines,
    )


def _task_view(task: TaskSnapshot, *, is_selected: bool) -> TaskView:
    return TaskView(
        id=task.id,
        type=task.type,
        status=task.status,
        status_chip=_task_status_chip(task.status),
        status_glyph=_task_status_glyph(task.status),
        skill=task.skill or "-",
        targets=", ".join(task.targets),
        target_count=len(task.targets),
        dependencies=", ".join(task.depends_on),
        context=_truncate(task.body.strip(), 900),
        is_selected=is_selected,
    )


def _select_task(tasks: list[TaskSnapshot], selected_task_id: str | None) -> TaskSnapshot | None:
    if not tasks:
        return None
    for task in tasks:
        if task.id == selected_task_id:
            return task
    for task in tasks:
        if task.status == "running":
            return task
    return tasks[0]


def _output_view(
    project: ProjectSnapshot | None,
    selected_task_id: str | None,
    *,
    output_full: bool,
) -> OutputView:
    artifacts = _selected_artifacts(project, selected_task_id)
    if not artifacts:
        empty = ["No attempts, attention reports, or text evidence are available."]
        return OutputView(compact_lines=empty, full_lines=empty, showing_full=output_full)

    compact: list[str] = []
    for label, text in artifacts:
        sections = _extract_important_sections(text)
        if sections:
            compact.append(f"[{_artifact_kind(label)}] {_truncate(label, 72)}")
            compact.extend(sections)
    raw_tail = _raw_tail([text for _, text in artifacts], limit=5)
    if raw_tail:
        compact.extend(["[tail] recent raw lines", *raw_tail])
    if not compact:
        compact = ["[tail] recent raw lines", *_raw_tail([text for _, text in artifacts], limit=8)]
    compact = _limit_lines(compact, 16, footer="... press o for full/tail output")

    full: list[str] = []
    for label, text in artifacts:
        full.extend([f"[{_artifact_kind(label)}] {label}", _truncate(text.strip(), 5000), ""])
    return OutputView(
        compact_lines=compact,
        full_lines=[line for line in full if line != ""],
        showing_full=output_full,
    )


def _selected_artifacts(
    project: ProjectSnapshot | None,
    selected_task_id: str | None,
) -> list[tuple[str, str]]:
    if project is None or project.mission is None:
        return []
    attempts = project.mission.recent_attempts
    selected_attempts = [attempt for attempt in attempts if attempt.node_id == selected_task_id]
    chosen_attempts = selected_attempts or attempts
    artifacts: list[tuple[str, str]] = []
    for attempt in chosen_attempts[:3]:
        if attempt.text:
            label = f"attempt {attempt.name} node={attempt.node_id}"
            artifacts.append((label, attempt.text))
    for item in project.attention_items:
        if selected_task_id is None or item.node_id in {None, selected_task_id}:
            artifacts.append((f"attention {item.id}", item.report))
    for evidence in project.mission.recent_evidence[:3]:
        if evidence.text:
            artifacts.append((f"evidence {evidence.name}", evidence.text))
    return artifacts


def _extract_important_sections(text: str) -> list[str]:
    sections = _markdown_sections(text)
    lines: list[str] = []
    for heading, body in sections:
        if heading.lower().strip() not in IMPORTANT_SECTIONS:
            continue
        body_lines = [line.strip() for line in body.splitlines() if line.strip()]
        lines.append(f"## {heading}")
        lines.extend(_truncate(line, 180) for line in body_lines[:8])
    return lines[:35]


def _markdown_sections(text: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"^(#{1,3})\s+(.+?)\s*$", text, flags=re.MULTILINE))
    sections: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.append((match.group(2).strip(), text[start:end].strip()))
    return sections


def _raw_tail(texts: Iterable[str], *, limit: int) -> list[str]:
    lines: list[str] = []
    for text in texts:
        lines.extend(line.strip() for line in text.splitlines() if line.strip())
    return [_truncate(line, 200) for line in lines[-limit:]]


def _expanded_tail(text: str, *, limit: int) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return [_truncate(line, 500) for line in lines[-limit:]]


def _attention_view(
    project: ProjectSnapshot | None,
    selected_task_id: str | None,
    *,
    expanded: bool,
) -> AttentionView:
    if project is None or not project.attention_items:
        return AttentionView(lines=["No attention items for selected flow."], has_attention=False, expanded=expanded)
    lines: list[str] = []
    for item in project.attention_items:
        context = _attention_context(item)
        node = item.node_id or "-"
        lines.append(
            f"[ASK] {item.id} node={node} {context}: {_truncate(_one_line(item.report), 140)}"
        )
        if expanded and (selected_task_id is None or item.node_id in {None, selected_task_id}):
            lines.extend(["Full report:", *_expanded_tail(item.report, limit=24)])
    if not expanded:
        lines = _limit_lines(lines, 6, footer="... press a for full attention reports")
    return AttentionView(lines=lines, has_attention=True, expanded=expanded)


def _aggregation_view(project: ProjectSnapshot | None) -> AggregationView:
    if project is None or project.mission is None:
        return AggregationView(lines=["No mission task data available."])
    tasks = project.mission.tasks
    skill_counts: dict[str, int] = {}
    for task in tasks:
        skill = task.skill or "(none)"
        skill_counts[skill] = skill_counts.get(skill, 0) + 1
    lines = [
        f"Task types: {_format_counts(project.mission.task_type_counts)}",
        f"Task status: {_format_counts(project.mission.task_state_counts)}",
        f"Skills: {_format_counts(skill_counts)}",
        f"Progress: {_progress_bar(project.mission.task_state_counts.get('cleared', 0), len(tasks))}",
        "Tool calls: future telemetry, not available in snapshots.",
    ]
    return AggregationView(lines=lines)


def _consumption_view(
    snapshot: LiveSnapshot,
    project: ProjectSnapshot | None,
    *,
    now_ts: float,
) -> ConsumptionView:
    attempts = 0
    running_tasks = 0
    failed_tasks = 0
    attention_items = 0
    age = "-"
    stale = "no"
    if project and project.mission:
        attempts = len(project.mission.recent_attempts)
        running_tasks = project.mission.task_state_counts.get("running", 0)
        failed_tasks = project.mission.task_state_counts.get("failed", 0)
        attention_items = project.attention_count
        age_seconds = None
        if project.last_activity_mtime > 0:
            age_seconds = max(0, int(now_ts - project.last_activity_mtime))
        age = _age_label(age_seconds)
        stale = "yes" if age_seconds is not None and age_seconds >= STALE_AFTER_SECONDS else "no"
    lines = [
        "Tokens: coming soon",
        "Cost: coming soon",
        f"Age: last activity {age} | stale={stale}",
        (
            f"Pressure: attention={attention_items} failed={failed_tasks} "
            f"running={running_tasks} attempts={attempts}"
        ),
        f"Projects: {snapshot.project_count}",
    ]
    return ConsumptionView(lines=lines)


def _actions_view(project: ProjectSnapshot | None, selected_task_id: str | None) -> ActionsView:
    context = project.id if project else "no project"
    task = selected_task_id or "no task"
    lines = [
        f"Context: project={context} task={task}",
        "Continue: preview future decide_attention/advance action.",
        "Retry: preview future runtime retry for failed/transient node.",
        "Abort: preview future abort-project runtime action.",
        "Advance/end: preview future orchestrator runtime controls.",
        "No dashboard key executes actions or automates agent terminals.",
    ]
    return ActionsView(lines=lines)


def _attempt_labels(project: ProjectSnapshot, selected_task_id: str | None) -> list[str]:
    if project.mission is None:
        return []
    attempts = project.mission.recent_attempts
    selected = [attempt for attempt in attempts if attempt.node_id == selected_task_id]
    chosen = selected or attempts
    return [
        (
            f"- {attempt.node_id} {attempt.handoff_type or '-'} "
            f"done={attempt.done} passed={attempt.passed} attention={attempt.request_attention} "
            f"path={attempt.report_path or attempt.path}"
        )
        for attempt in chosen[:5]
    ]


def _file_labels(files: list[RecentFile]) -> list[str]:
    return [f"- {item.name} modified={item.modified_at} path={item.path}" for item in files[:5]]


def _task_summary(project: ProjectSnapshot) -> str:
    if project.mission is None:
        return "tasks=0 contracts=0"
    mission = project.mission
    return (
        f"tasks={mission.task_count} "
        f"types={_format_counts(mission.task_type_counts)} "
        f"status={_format_counts(mission.task_state_counts)}"
    )


def _detail_intervention_label(project: ProjectSnapshot, flow: FlowView | None) -> str:
    if flow is None:
        return "WATCH"
    if flow.is_urgent:
        return "USER INPUT"
    if flow.is_failed:
        return "FAILURE"
    if flow.is_stale:
        return "STALE"
    if flow.is_long_running:
        return "LONG RUN"
    if project.state == "done":
        return "CLEAR"
    if flow.is_active:
        return "MONITOR"
    return "WATCH"


def _status_chip(status: str) -> str:
    if "urgent" in status:
        return "[ASK]"
    if status == "failed":
        return "[FAIL]"
    if "stale" in status:
        return "[STALE]"
    if "long" in status:
        return "[LONG]"
    if status == "running":
        return "[RUN]"
    if status == "done":
        return "[DONE]"
    if status == "aborted":
        return "[STOP]"
    return "[IDLE]"


def _status_glyph(status: str) -> str:
    if "urgent" in status:
        return "!"
    if status == "failed":
        return "x"
    if "stale" in status:
        return "~"
    if "long" in status:
        return ">"
    if status == "running":
        return ">"
    if status == "done":
        return "*"
    if status == "aborted":
        return "!"
    return "-"


def _task_status_chip(status: str) -> str:
    if status == "failed":
        return "[FAIL]"
    if status == "running":
        return "[RUN]"
    if status == "cleared":
        return "[OK]"
    if status == "pending":
        return "[WAIT]"
    if status == "superseded":
        return "[SKIP]"
    return "[TASK]"


def _task_status_glyph(status: str) -> str:
    if status == "failed":
        return "x"
    if status == "running":
        return ">"
    if status == "cleared":
        return "*"
    if status == "pending":
        return "."
    if status == "superseded":
        return "-"
    return "?"


def _progress_bar(done: int, total: int, *, width: int = 10) -> str:
    if total <= 0:
        return "[" + "-" * width + "]"
    filled = round(width * max(0, min(done, total)) / total)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _task_mix(project: ProjectSnapshot) -> str:
    if project.mission is None:
        return "W0/V0/G0 R0/F0/P0"
    types = project.mission.task_type_counts
    states = project.mission.task_state_counts
    return (
        f"W{types.get('work', 0)}/V{types.get('validate', 0)}/G{types.get('gate', 0)} "
        f"R{states.get('running', 0)}/F{states.get('failed', 0)}/P{states.get('pending', 0)}"
    )


def _flow_signals(
    project: ProjectSnapshot,
    *,
    is_pinned: bool,
    is_urgent: bool,
    is_failed: bool,
    is_stale: bool,
    is_long_running: bool,
    attempt_count: int,
    running_tasks: int,
    failed_tasks: int,
    pending_tasks: int,
) -> tuple[str, ...]:
    signals: list[str] = []
    if is_pinned:
        signals.append("pin")
    if is_urgent:
        signals.append(f"att={project.attention_count}")
    if is_failed:
        signals.append(f"fail={failed_tasks}")
    if is_long_running:
        signals.append("long")
    elif is_stale:
        signals.append("stale")
    if running_tasks:
        signals.append(f"run={running_tasks}")
    if pending_tasks:
        signals.append(f"pend={pending_tasks}")
    if attempt_count:
        signals.append(f"attempts={attempt_count}")
    if not signals:
        signals.append("ok")
    return tuple(signals)


def _artifact_kind(label: str) -> str:
    return label.split(" ", 1)[0]


def _limit_lines(lines: list[str], limit: int, *, footer: str) -> list[str]:
    if len(lines) <= limit:
        return lines
    return [*lines[: max(0, limit - 1)], footer]


def _short_id(value: str, *, limit: int = 18) -> str:
    if len(value) <= limit:
        return value
    if limit <= 7:
        return value[:limit]
    head = max(1, limit - 7)
    return f"{value[:head]}...{value[-4:]}"


def _select_project_id(snapshot: LiveSnapshot, selected_project_id: str | None) -> str | None:
    return selected_project_id or snapshot.selected_project_id


def _snapshot_timestamp(snapshot: LiveSnapshot) -> float:
    try:
        return datetime.fromisoformat(snapshot.generated_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now(UTC).timestamp()


def _timestamp(value: datetime | float | int) -> float:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.timestamp()
    return float(value)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def _attention_context(item: AttentionSnapshot) -> str:
    parts = []
    if item.kind:
        parts.append(f"kind={item.kind}")
    if item.mission_id:
        parts.append(f"mission={item.mission_id}")
    if item.node_id:
        parts.append(f"node={item.node_id}")
    return "(" + ", ".join(parts) + ")" if parts else ""


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _age_label(age_seconds: int | None) -> str:
    if age_seconds is None:
        return "-"
    if age_seconds < 60:
        return f"{age_seconds}s"
    minutes, seconds = divmod(age_seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)].rstrip() + "..."
