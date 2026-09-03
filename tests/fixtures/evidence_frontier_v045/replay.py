"""Fresh-interpreter probes for the persisted evidence-frontier fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.coordinator import MissionCoordinator
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    Decision,
    Task,
    TaskListPatch,
    TerminalReviewHandoff,
    WorkHandoff,
)
from unrest_harness.storage import ProjectStore

MISSION_ID = "mission-001"


def _config(home: Path) -> HarnessConfig:
    return HarnessConfig(
        bundled_dir=Path.cwd() / "src" / "unrest_harness" / "bundled",
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


def _oracle(store: ProjectStore, project_id: str, gate_id: str) -> dict[str, list[str]]:
    """Compute graph maxima without calling coordinator traversal."""
    task_list = store.load_task_list(project_id, MISSION_ID)
    task_state = store.load_task_state(project_id, MISSION_ID)
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
        for task_id in candidates:
            upstream = list(by_id[task_id].depends_on)
            seen: set[str] = set()
            while upstream:
                upstream_id = upstream.pop()
                if upstream_id in seen:
                    continue
                seen.add(upstream_id)
                if upstream_id in candidates:
                    historical.add(upstream_id)
                upstream.extend(by_id[upstream_id].depends_on)
        result[target] = [
            task.id
            for task in task_list.tasks
            if task.id in candidates - historical
        ]
    return result


def _gate(home: Path, project_id: str, gate_id: str) -> dict[str, object]:
    store = ProjectStore(_config(home))
    task_list = store.load_task_list(project_id, MISSION_ID)
    task_state = store.load_task_state(project_id, MISSION_ID)
    gate = next(task for task in task_list.tasks if task.id == gate_id)
    dispatcher = MockDispatcher(
        lambda request: WorkHandoff(node_id=request.task.id, done=True, report="")
    )
    reviewer = MockTerminalReviewer(TerminalReviewHandoff(done=True))
    evaluated = MissionCoordinator(
        store, project_id, dispatcher, reviewer
    )._evaluate_gate(task_list, task_state, gate)
    return {
        "cleared": evaluated.cleared,
        "matrix": evaluated.validator_verdicts,
        "oracle": _oracle(store, project_id, gate_id),
        "statuses": {
            task.id: task_state.status_of(task.id) for task in task_list.tasks
        },
    }


def _sealed_patch(home: Path, project_id: str) -> dict[str, object]:
    config = _config(home)
    controller = ProjectController(
        config,
        MockDispatcher(
            lambda request: WorkHandoff(
                node_id=request.task.id, done=True, report=""
            )
        ),
        MockTerminalReviewer(TerminalReviewHandoff(done=True)),
    )
    attention = controller.store.load_attention(project_id)[0]
    replacement = Task(
        id="g2",
        type="gate",
        body="",
        targets=["VAL-001"],
        skill=None,
        depends_on=["v1"],
    )
    try:
        controller.decide_attention(
            project_id,
            [
                Decision(
                    item_id=attention.id,
                    action="patch",
                    patch=TaskListPatch(
                        add=[replacement], supersede={"g1": "g2"}
                    ),
                )
            ],
        )
    except ToolError as exc:
        return {"accepted": False, "code": exc.code, "message": str(exc)}
    return {"accepted": True}


def main() -> None:
    mode, home_arg, project_id, *rest = sys.argv[1:]
    home = Path(home_arg)
    if mode == "gate":
        result = _gate(home, project_id, rest[0])
    elif mode == "sealed-patch":
        result = _sealed_patch(home, project_id)
    else:
        raise SystemExit(f"unknown mode: {mode}")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
