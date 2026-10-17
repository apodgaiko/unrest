"""Create only the seed4605 and empty-home startup probe fixtures, without providers."""
from __future__ import annotations

import argparse
from pathlib import Path
import random

from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController
from unrest_harness.dispatcher import DispatchRequest, MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    Decision, Task, TaskList, TerminalReviewHandoff, ValidateHandoff, ValidationItem, WorkHandoff,
)


def respond(request: DispatchRequest) -> WorkHandoff | ValidateHandoff:
    if request.task.type == "work":
        return WorkHandoff(node_id=request.task.id, done=True, report="synthetic")
    return ValidateHandoff(node_id=request.task.id, done=True, report="synthetic",
                           items=[ValidationItem(item_id="VAL-STARTUP", passed=True)], passed=True)


def prepare(home: Path, probe_only: bool) -> None:
    config = HarnessConfig.discover()
    if config.harness_home != home:
        raise ValueError("UNREST_HOME must match explicit disposable home")
    controller = ProjectController(config, MockDispatcher(respond),
                                   MockTerminalReviewer(TerminalReviewHandoff(done=True, report="")))
    workspace = home.parent / "workspace"
    workspace.mkdir(exist_ok=True)
    identifiers = random.Random(4605).sample(range(10000), 10)
    for index in ([] if probe_only else identifiers) + [-1]:
        project_id = "startup-probe" if index == -1 else f"seed4605-{index:04d}"
        if (home / "projects" / project_id).exists():
            continue
        # Public creation with a deterministic storage ID; no candidate-derived oracle.
        controller.store.generate_project_id = lambda brief, pid=project_id: pid  # type: ignore[method-assign,misc]
        controller.start_project("Synthetic startup fixture", str(workspace))
        if index != -1:
            contract = controller.store.ensure_contract_dir(project_id, "mission-001")
            (contract / "VAL-STARTUP.md").write_text("# VAL-STARTUP\n\nSynthetic fixture.\n")
            skill = home / "projects" / project_id / ".unrest" / "skills" / "synthetic"
            skill.mkdir(parents=True, exist_ok=True)
            (skill / "SKILL.md").write_text("# Synthetic\n\nProvider-free fixture.\n")
            controller.submit_plan(project_id, TaskList(tasks=[
                Task(id="w", type="work", body="synthetic", skill="synthetic",
                     targets=["VAL-STARTUP"]),
                Task(id="v", type="validate", body="synthetic", skill="synthetic",
                     targets=["VAL-STARTUP"], depends_on=["w"]),
                Task(id="g", type="gate", body="", targets=["VAL-STARTUP"], depends_on=["v"]),
            ]))
            state = controller.advance_project(project_id)
            assert state.state.state == "attention_needed"
            attention = controller.store.load_attention(project_id)
            assert len(attention) == 1 and attention[0].kind == "gate_checkpoint"
            controller.decide_attention(project_id, [Decision(item_id=attention[0].id,
                                                             action="continue")])
            controller.advance_project(project_id)
            assert controller.end_mission(project_id).state.state == "done"
        controller.inspect_project(project_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--probe-only", action="store_true")
    args = parser.parse_args()
    prepare(args.home.resolve(), args.probe_only)
