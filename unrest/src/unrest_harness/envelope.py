"""Envelope renderer.

The envelope's `dag` field carries a text view of the task list (field name
kept for envelope-surface stability). Tool call sites choose whether to return
no DAG, a compact frontier view, or a full active task-list view.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable, Literal, Mapping

from .models import (
    AttentionItem,
    Envelope,
    ProjectState,
    Task,
    TaskList,
    TaskStateFile,
)

MAX_FRONTIER_ROWS = 12
MAX_GATE_ROWS = 8
MAX_FOCUS_ROWS = 9
MAX_INLINE_IDS = 3

DagRenderMode = Literal["summary", "frontier", "full"]
EnvelopeDagMode = Literal["none", "summary", "frontier", "full"]


def render_task_list(
    tl: TaskList | None,
    task_state: TaskStateFile | None,
    *,
    mode: DagRenderMode = "summary",
) -> str | None:
    """Compact text render. Returns None if `tl is None`."""
    if tl is None:
        return None
    if mode not in {"summary", "frontier", "full"}:
        raise ValueError("mode must be 'summary', 'frontier', or 'full'")

    statuses = {
        t.id: (task_state.status_of(t.id) if task_state else "pending")
        for t in tl.tasks
    }
    visible = [t for t in tl.tasks if statuses[t.id] != "superseded"]
    counter = Counter(statuses[t.id] for t in tl.tasks)
    header_parts = []
    for key in ("pending", "running", "cleared", "failed", "superseded"):
        if counter.get(key, 0):
            header_parts.append(f"{key}:{counter[key]}")
    header = f"Tasks — {len(tl.tasks)} total [{', '.join(header_parts)}]"

    preds = _predecessors_index(tl)
    succs = _successors_index(tl)
    ordered = _topological_order(visible, preds, statuses)
    if mode == "full":
        return _render_full(header, ordered, preds, statuses)
    if mode == "frontier":
        return _render_frontier(header, ordered, preds, statuses)
    return _render_summary(header, ordered, preds, succs, statuses)


# Back-compat alias for the few call sites that still spell "render_dag".
render_dag = render_task_list


def _render_full(
    header: str,
    ordered: list[Task],
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> str:
    lines = [header]
    lines.extend(_task_line(t, preds, statuses) for t in ordered)
    return "\n".join(lines)


def _render_summary(
    header: str,
    ordered: list[Task],
    preds: dict[str, list[str]],
    succs: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> str:
    ready, blocked, running, failed, gates, last_cleared = _collect_frontier(
        ordered, preds, statuses
    )
    lines = _frontier_header_lines(
        header, ready, blocked, running, failed, gates, statuses
    )

    rendered = 0
    rendered += _append_group(lines, "failed", failed, preds, statuses, rendered)
    rendered += _append_group(lines, "running", running, preds, statuses, rendered)
    rendered += _append_group(lines, "ready", ready, preds, statuses, rendered)

    omitted = len(failed) + len(running) + len(ready) - rendered
    if omitted > 0:
        lines.append(
            f"  ... {omitted} more frontier tasks omitted; read tasks.json for full list"
        )

    focus = _focus_subgraph(last_cleared, ordered, preds, succs, statuses)
    if focus:
        lines.append(
            f"  focus-subgraph around last-cleared:{last_cleared.id if last_cleared else '-'}:"
        )
        lines.extend(_task_line(t, preds, statuses) for t in focus)
    return "\n".join(lines)


def _render_frontier(
    header: str,
    ordered: list[Task],
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> str:
    ready, blocked, running, failed, gates, _ = _collect_frontier(
        ordered, preds, statuses
    )
    lines = _frontier_header_lines(
        header, ready, blocked, running, failed, gates, statuses
    )

    rendered = 0
    rendered += _append_group(lines, "failed", failed, preds, statuses, rendered)
    rendered += _append_group(lines, "running", running, preds, statuses, rendered)
    rendered += _append_group(lines, "ready", ready, preds, statuses, rendered)

    omitted = len(failed) + len(running) + len(ready) - rendered
    if omitted > 0:
        lines.append(
            f"  ... {omitted} more frontier tasks omitted; read tasks.json for full list"
        )
    return "\n".join(lines)


def _collect_frontier(
    ordered: list[Task],
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> tuple[list[Task], int, list[Task], list[Task], list[Task], Task | None]:
    ready: list[Task] = []
    blocked = 0
    running: list[Task] = []
    failed: list[Task] = []
    gates: list[Task] = []
    last_cleared: Task | None = None

    for task in ordered:
        status = statuses[task.id]
        if status == "failed":
            failed.append(task)
        elif status == "running":
            running.append(task)
        elif status == "pending":
            live_preds = [
                p for p in preds.get(task.id, []) if statuses.get(p) != "superseded"
            ]
            if all(statuses.get(p) == "cleared" for p in live_preds):
                ready.append(task)
            else:
                blocked += 1
        if task.type == "gate":
            gates.append(task)
        if status == "cleared":
            last_cleared = task
    return ready, blocked, running, failed, gates, last_cleared


def _frontier_header_lines(
    header: str,
    ready: list[Task],
    blocked: int,
    running: list[Task],
    failed: list[Task],
    gates: list[Task],
    statuses: Mapping[str, str],
) -> list[str]:
    lines = [header]
    lines.append(
        "  frontier: "
        f"failed:{len(failed)}, running:{len(running)}, "
        f"ready:{len(ready)}, blocked:{blocked}"
    )
    if gates:
        lines.append(
            f"  gates: {_summarize_statuses(gates, statuses, limit=MAX_GATE_ROWS)}"
        )
    return lines


def _topological_order(
    visible: list[Task],
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> list[Task]:
    """Kahn's algorithm with input list-order as tiebreaker.

    List order is the orchestrator's topological hint — preserve it when
    multiple tasks are simultaneously ready.
    """
    by_id = {t.id: t for t in visible}
    visible_ids = set(by_id)
    indeg: dict[str, int] = {}
    for tid in visible_ids:
        live_preds = [
            p for p in preds.get(tid, [])
            if p in visible_ids and statuses.get(p) != "superseded"
        ]
        indeg[tid] = len(live_preds)

    successors: dict[str, list[str]] = {tid: [] for tid in visible_ids}
    for tid, plist in preds.items():
        if tid not in visible_ids:
            continue
        for p in plist:
            if p in visible_ids and statuses.get(p) != "superseded":
                successors[p].append(tid)

    order_index = {t.id: i for i, t in enumerate(visible)}
    ready: list[tuple[int, str]] = [
        (order_index[tid], tid) for tid, d in indeg.items() if d == 0
    ]
    ready.sort()
    result: list[Task] = []
    while ready:
        _, tid = ready.pop(0)
        result.append(by_id[tid])
        for s in successors.get(tid, []):
            indeg[s] -= 1
            if indeg[s] == 0:
                ready.append((order_index[s], s))
                ready.sort()
    if len(result) < len(visible):
        emitted = {t.id for t in result}
        for t in visible:
            if t.id not in emitted:
                result.append(t)
    return result


def _predecessors_index(tl: TaskList) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {t.id: [] for t in tl.tasks}
    for task in tl.tasks:
        result[task.id] = list(task.depends_on)
    return result


def _successors_index(tl: TaskList) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {t.id: [] for t in tl.tasks}
    for task in tl.tasks:
        for dep in task.depends_on:
            result.setdefault(dep, []).append(task.id)
    return result


def _focus_subgraph(
    focus: Task | None,
    ordered: list[Task],
    preds: dict[str, list[str]],
    succs: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> list[Task]:
    if focus is None:
        return []
    by_id = {t.id: t for t in ordered}
    focus_ids: set[str] = {focus.id}
    focus_ids.update(
        p for p in preds.get(focus.id, []) if statuses.get(p) != "superseded"
    )
    focus_ids.update(
        s for s in succs.get(focus.id, []) if statuses.get(s) != "superseded"
    )

    for sid in list(succs.get(focus.id, [])):
        focus_ids.update(
            s for s in succs.get(sid, []) if statuses.get(s) != "superseded"
        )

    result = [t for t in ordered if t.id in focus_ids and t.id in by_id]
    if len(result) <= MAX_FOCUS_ROWS:
        return result
    focus_index = next((idx for idx, n in enumerate(result) if n.id == focus.id), 0)
    start = max(0, focus_index - MAX_FOCUS_ROWS // 2)
    end = start + MAX_FOCUS_ROWS
    if end > len(result):
        end = len(result)
        start = max(0, end - MAX_FOCUS_ROWS)
    return result[start:end]


def _append_group(
    lines: list[str],
    label: str,
    tasks: list[Task],
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
    rendered_so_far: int,
) -> int:
    if not tasks or rendered_so_far >= MAX_FRONTIER_ROWS:
        return 0
    remaining = MAX_FRONTIER_ROWS - rendered_so_far
    shown = tasks[:remaining]
    lines.append(f"  {label}:")
    lines.extend(_task_line(t, preds, statuses) for t in shown)
    return len(shown)


def _task_line(
    task: Task,
    preds: dict[str, list[str]],
    statuses: Mapping[str, str],
) -> str:
    type_label = f"[{task.type}:{task.skill}]" if task.type != "gate" else "[gate]"
    pred_ids = [p for p in preds.get(task.id, []) if statuses.get(p) != "superseded"]
    return (
        f"    {task.id}  {type_label}  {statuses[task.id]}  "
        f"→ {_summarize_ids(task.targets)}  ← {_summarize_ids(pred_ids, empty='(root)')}"
    )


def _summarize_ids(ids: list[str], *, empty: str = "-") -> str:
    if not ids:
        return empty
    if len(ids) <= MAX_INLINE_IDS:
        return ",".join(ids)
    shown = ",".join(ids[:MAX_INLINE_IDS])
    return f"{shown},+{len(ids) - MAX_INLINE_IDS}"


def _summarize_statuses(
    tasks: list[Task], statuses: Mapping[str, str], *, limit: int
) -> str:
    shown = [f"{t.id}:{statuses[t.id]}" for t in tasks[:limit]]
    if len(tasks) > limit:
        shown.append(f"+{len(tasks) - limit}")
    return ", ".join(shown)


def make_envelope(
    project_id: str,
    state: ProjectState,
    project_root: str,
    harness_root: str,
    task_list: TaskList | None = None,
    task_state: TaskStateFile | None = None,
    *,
    dag_mode: EnvelopeDagMode = "summary",
) -> Envelope:
    return Envelope(
        projectId=project_id,
        state=state,
        projectRoot=project_root,
        harnessRoot=harness_root,
        dag=(
            None
            if dag_mode == "none"
            else render_task_list(task_list, task_state, mode=dag_mode)
        ),
    )


def public_attention_items(items: Iterable["AttentionItemInternal"]) -> list[AttentionItem]:
    """Strip runtime metadata; public attention is only id + raw report."""
    return [AttentionItem(id=it.id, report=it.report) for it in items]


from .models import AttentionItemInternal  # noqa: E402


__all__ = [
    "render_task_list",
    "render_dag",
    "make_envelope",
    "public_attention_items",
    "DagRenderMode",
    "EnvelopeDagMode",
]
