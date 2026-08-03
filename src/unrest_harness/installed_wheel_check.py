"""Provider-independent installed-wheel lifecycle release check."""
from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path

from .config import HarnessConfig
from .controller import ProjectController
from .dispatcher import DispatchRequest, MockDispatcher, MockTerminalReviewer
from .models import (
    Decision,
    MissionPlanning,
    TaskList,
    TerminalReviewHandoff,
    ValidateHandoff,
    ValidationItem,
    WorkHandoff,
)


def _dispatcher(
    request: DispatchRequest,
) -> WorkHandoff | ValidateHandoff:
    if request.task.type == "validate":
        return ValidateHandoff(
            node_id=request.task.id,
            done=True,
            report="installed candidate validation passed",
            items=[ValidationItem(item_id="VAL-INSTALLED-001", passed=True)],
            passed=True,
        )
    return WorkHandoff(
        node_id=request.task.id,
        done=True,
        report="installed candidate work completed",
    )


def _controller(config: HarnessConfig) -> ProjectController:
    return ProjectController(
        config,
        MockDispatcher(_dispatcher),
        MockTerminalReviewer(
            TerminalReviewHandoff(
                done=True,
                report="installed candidate terminal review passed",
            )
        ),
    )


def run_installed_wheel_check() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="unrest-installed-wheel-") as raw_root:
        root = Path(raw_root)
        workspace = root / "unrelated-workspace"
        workspace.mkdir()
        discovered = HarnessConfig.discover()
        config = replace(
            discovered,
            harness_home=root / "home",
            projects_dir=root / "home" / "projects",
            max_parallel_nodes=1,
        )

        controller = _controller(config)
        started = controller.start_project(
            "Exercise the installed candidate lifecycle.",
            str(workspace),
        )
        project_id = started.projectId
        if not isinstance(started.state, MissionPlanning):
            raise RuntimeError("installed check did not enter mission planning")
        mission_id = started.state.mission_id
        contract_dir = controller.store.ensure_contract_dir(project_id, mission_id)
        (contract_dir / "VAL-INSTALLED-001.md").write_text(
            "# VAL-INSTALLED-001\n",
            encoding="utf-8",
        )
        controller.submit_plan(
            project_id,
            TaskList.model_validate(
                {
                    "tasks": [
                        {
                            "id": "w-installed",
                            "type": "work",
                            "body": "exercise installed work persistence",
                            "targets": ["VAL-INSTALLED-001"],
                            "skill": "installed-check",
                            "depends_on": [],
                        },
                        {
                            "id": "v-installed",
                            "type": "validate",
                            "body": "exercise installed validation persistence",
                            "targets": ["VAL-INSTALLED-001"],
                            "skill": "installed-check",
                            "depends_on": ["w-installed"],
                        },
                        {
                            "id": "g-installed",
                            "type": "gate",
                            "body": "",
                            "targets": ["VAL-INSTALLED-001"],
                            "skill": None,
                            "depends_on": ["v-installed"],
                        },
                    ]
                }
            ),
        )
        controller.advance_project(project_id)
        attention = controller.store.load_attention(project_id)
        if len(attention) != 1:
            raise RuntimeError("installed check did not reach the gate")
        controller.decide_attention(
            project_id,
            [Decision(item_id=attention[0].id, action="continue")],
        )
        controller.advance_project(project_id)

        restarted = _controller(config)
        report = (
            restarted.store.mission_dir(project_id, mission_id)
            / "evidence"
            / "installed-wheel"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text("installed candidate evidence\n", encoding="utf-8")
        restarted.end_mission(project_id, [str(report)])

        resumed = _controller(config)
        state = resumed.store.load_state(project_id)
        task_state = resumed.store.load_task_state(project_id, mission_id)
        attempts = resumed.store.list_attempts(project_id, mission_id)
        reviews = tuple(
            resumed.store.terminal_reviews_dir(project_id, mission_id).glob("*.md")
        )
        if state is None or state.state != "done":
            raise RuntimeError("installed check did not persist done state")
        if any(task_state.status_of(task_id) != "cleared" for task_id in (
            "w-installed",
            "v-installed",
            "g-installed",
        )):
            raise RuntimeError("installed check did not persist cleared tasks")
        if len(attempts) != 2 or len(reviews) != 1:
            raise RuntimeError("installed check did not persist attempts and review")
        return {
            "attempts": len(attempts),
            "mission_id": mission_id,
            "project_id": project_id,
            "restart_resume": True,
            "state": state.state,
            "terminal_reviews": len(reviews),
        }


def main() -> None:
    run_installed_wheel_check()


if __name__ == "__main__":
    main()
