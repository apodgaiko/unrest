"""Controlled RunControl executor; only disposable fixture backend is admitted."""

from dataclasses import replace
import asyncio
import hashlib
import json
import os
from pathlib import Path

import unrest_harness.approval_recovery as recovery
import unrest_harness.acp_runner as acp
from unrest_harness.assets import AssetLoader
from unrest_harness.models import Task
from unrest_harness.config import HarnessConfig
from unrest_harness.storage import ProjectStore


def execute(operation, arguments, context):
    assert operation == "advance_project"
    assert context.run_id and context.control.inspect_run(context.run_id).state == "running"
    root = Path(os.environ["CONTROLLED_RUN_ROOT"])
    store = ProjectStore(HarnessConfig(
        bundled_dir=Path(__file__).parents[2] / "src/unrest_harness/bundled",
        harness_home=root / "home", projects_dir=root / "home/projects",
        orchestrator_provider_name="codex", worker_provider_name="codex",
        worker_acp_command=None, validator_provider_name=None, validator_acp_command=None,
        terminal_reviewer_provider_name=None, terminal_reviewer_acp_command=None,
    ))
    native = Path(os.environ["CONTROLLED_RUN_NATIVE"])
    assert native.name == "controlled-backend"
    recovery.BACKEND_PINS = frozenset({hashlib.sha256(native.read_bytes()).hexdigest()})
    acp.verify_adapter = lambda *_: None
    original = recovery.ApprovalOwner.launch_environment

    async def launch(owner, environment):
        return await original(owner, dict(environment, CODEX_PATH=str(native)))

    recovery.ApprovalOwner.launch_environment = launch
    spawn = asyncio.create_subprocess_exec

    async def track_owned(*args, **kwargs):
        process = await spawn(*args, **kwargs)
        with Path(os.environ["CONTROLLED_RUN_TRACE"]).open("a") as stream:
            stream.write(
                json.dumps({"method": "controlled-owned-process", "pid": process.pid}) + "\n"
            )
        return process

    asyncio.create_subprocess_exec = track_owned
    config = replace(
        store.config,
        approval_recovery=True,
        worker_acp_command=os.environ["CONTROLLED_RUN_COMMAND"],
    )
    owner_context = recovery.RunApprovalContext(
        context.run_id, lambda: context.control.inspect_run(context.run_id).state == "running"
    )
    runner = acp.ACPNodeRunner(config, AssetLoader(config), owner_context)
    handoff = acp._run_coro_blocking(
        runner.run_node(
            "project",
            "mission-001",
            Task(id="w1", type="work", body="controlled", targets=[], skill="s"),
            "attempt-1",
            store,
        )
    )
    return {
        "projectId": "project",
        "projectRoot": str(store.workspace_dir("project")),
        "harnessRoot": str(store.bucket_root("project")),
        "state": {"state": "mission_running", "mission_id": "mission-001"},
        "next_action": "advance_project",
        "active_attempts": [],
        "supersession_lineage": [],
        "frontier": "Controlled completed" if handoff.done else "Controlled blocked",
        "dag": None,
    }
