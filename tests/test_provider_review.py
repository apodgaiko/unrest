"""Controlled subprocess proofs, not external Guardian reviewer decisions."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import pytest

from unrest_harness.acp_runner import ACPClient, ACPError, ACPNodeRunner
from unrest_harness.assets import AssetLoader
from unrest_harness.config import HarnessConfig
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.dispatcher import MockDispatcher, MockTerminalReviewer
from unrest_harness.models import (
    AttentionNeeded, Decision, MissionRunning, Task, TaskList, TaskListPatch,
    TaskStateFile, TerminalReviewHandoff, WorkHandoff,
)
from unrest_harness.provider_review import ProviderReviewCapture, ProviderReviewBlock, ReviewIdentity
from unrest_harness.storage import ProjectStore
from tests.test_acp_runner import _safe_policy

FIXTURE = Path(__file__).parent / "fixtures" / "approval_acp_process.py"
CANARY = "private-command-rationale-prompt-credential-CANARY"


def event(status="denied", *, update=False):
    completed = status != "inProgress"
    raw = {
        "threadId": "thread-1", "turnId": "turn-1", "reviewId": "review-1",
        "startedAtMs": 1, "targetItemId": None,
        "review": {"status": status, "riskLevel": "high", "userAuthorization": "low",
                   "rationale": CANARY},
        "action": {"type": "command", "source": "shell", "command": CANARY, "cwd": "/tmp"},
    }
    if completed:
        raw.update(completedAtMs=2, decisionSource="agent")
    payload = {
        "sessionUpdate": "tool_call_update" if update else "tool_call",
        "toolCallId": "guardian_assessment:review-1",
        "status": "in_progress" if not completed else (
            "completed" if status == "approved" else "failed"
        ),
        "rawOutput" if update else "rawInput": raw,
    }
    if not update:
        payload.update(kind="think", title="Guardian Review")
    return {"sessionId": "thread-1", "update": payload}


async def wire(tmp_path, events, capture, *, delay=0, raw_frame=None):
    scenario = tmp_path / "scenario.json"
    scenario.write_text(json.dumps({"events": events, "delay": delay, "raw_frame": raw_frame}))
    process = await asyncio.create_subprocess_exec(
        sys.executable, str(FIXTURE), str(scenario), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )

    async def failing_observer(_):
        raise RuntimeError("observer failure")

    client = ACPClient(process, str(tmp_path), policy=_safe_policy("codex"), terminal_environment={},
                       session_update_handler=failing_observer)
    try:
        await client.start()
        assert (await client.send_request("session/new", {}))["sessionId"] == "thread-1"
        client.provider_review = capture
        try:
            result = await asyncio.wait_for(client.send_request("session/prompt", {}), 2)
        except ACPError:
            result = None
        return result
    finally:
        await client.cleanup()
        assert process.returncode is not None
        assert not client._request_tasks


@pytest.mark.parametrize("status", ["denied", "approved", "timedOut", "aborted", "inProgress"])
@pytest.mark.parametrize("mapping", ["creation", "update"])
async def test_real_wire_status_and_pinned_mappings(tmp_path, status, mapping):
    records = []
    capture = ProviderReviewCapture("thread-1", records.append)
    events = ([event("inProgress")] if mapping == "update" else [])
    events.append(event(status, update=mapping == "update"))
    result = await wire(tmp_path, events, capture)
    if status == "denied":
        assert capture.blocked.reason == "denied"
        assert records == [ProviderReviewBlock("denied", ReviewIdentity("thread-1", "turn-1", "review-1"))]
        assert result is None
        assert CANARY not in repr(records)
    else:
        assert capture.blocked is None
        assert result == {"stopReason": "end_turn"}


@pytest.mark.parametrize("mutation", ["session", "thread", "review", "turn", "large", "status", "fields"])
async def test_real_wire_invalid_identity_is_blocked_not_authorized(tmp_path, mutation):
    item = event(update=True)
    raw = item["update"]["rawOutput"]
    if mutation == "session":
        item["sessionId"] = "wrong"
    elif mutation == "thread":
        raw["threadId"] = "wrong"
    elif mutation == "review":
        raw["reviewId"] = "wrong"
    elif mutation == "turn":
        raw["turnId"] = "wrong"
    elif mutation == "large":
        raw["reviewId"] = "x" * 129
    elif mutation == "status":
        raw["review"]["status"] = "unknown"
    else:
        raw["extra"] = CANARY
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    await wire(tmp_path, [event("inProgress"), item], capture)
    assert capture.blocked.reason == "invalid_context"


async def test_exact_guardian_objects_inside_ordinary_mcp_results_are_not_reviews(tmp_path):
    guardian = event()["update"]["rawInput"]
    events = [
        {"sessionId": "thread-1", "update": {
            "sessionUpdate": "tool_call", "toolCallId": "guardian_assessment:review-1",
            "kind": "other", "title": "Guardian Review",
            "rawInput": {"server": "example", "tool": "lookup", "arguments": guardian},
        }},
        {"sessionId": "thread-1", "update": {
            "sessionUpdate": "tool_call_update", "toolCallId": "guardian_assessment:review-1",
            "status": "failed", "rawOutput": {"result": guardian, "error": None},
        }},
        {"sessionId": "thread-1", "update": {
            "sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": json.dumps(guardian)},
        }},
    ]
    capture = ProviderReviewCapture("thread-1", lambda _: pytest.fail("unexpected record"))
    assert await wire(tmp_path, events, capture) == {"stopReason": "end_turn"}
    assert capture.blocked is None


def config_at(tmp_path, command=None):
    return HarnessConfig(
        bundled_dir=Path(__file__).parents[1] / "src/unrest_harness/bundled",
        harness_home=tmp_path / "home", projects_dir=tmp_path / "home/projects",
        orchestrator_provider_name="codex", worker_provider_name="codex",
        worker_acp_command=command, validator_provider_name=None, validator_acp_command=None,
        terminal_reviewer_provider_name=None, terminal_reviewer_acp_command=None,
    )


def setup_store(tmp_path, command=None):
    config = config_at(tmp_path, command)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = ProjectStore(config)
    record = store.create_project("controlled", str(workspace), project_id="project")
    record.current_mission_id = "mission-001"
    store.save_project(record)
    store.ensure_contract_dir("project", "mission-001")
    return store, config


def publish(store, block=ProviderReviewBlock("denied", ReviewIdentity("thread-1", "turn-1", "review-1"))):
    store.begin_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1")
    store.save_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1", block)


def test_durable_bounded_identity_and_restart_without_live_context(tmp_path):
    store, config = setup_store(tmp_path)
    publish(store)
    original = store.read_provider_review("project", "mission-001", "attempt-1", "w1")
    store.save_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1", original)
    durable, cursor = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    assert ".unrest" in durable.parts and ".unrest-runtime" in cursor.parts
    assert len(durable.read_bytes()) < 4096 and CANARY not in durable.read_text()
    assert json.loads(cursor.read_text())["resumable"] is False
    assert ProjectStore(config).read_provider_review("project", "mission-001", "attempt-1", "w1") == original
    with pytest.raises(ValueError, match="conflicts"):
        store.save_provider_review("project", "mission-001", "attempt-1", "w1", "wrong", original)
    with pytest.raises(ValueError, match="already exists"):
        store.begin_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1")


@pytest.mark.parametrize("damage", ["missing", "corrupt", "oversized", "wrong_attempt", "wrong_session"])
def test_restart_refuses_damaged_records(tmp_path, damage):
    store, config = setup_store(tmp_path)
    publish(store)
    durable, _ = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    if damage == "missing":
        durable.unlink()
    elif damage == "corrupt":
        durable.write_text("not json")
    elif damage == "oversized":
        durable.write_text("x" * 4097)
    else:
        value = json.loads(durable.read_text())
        value["attempt_id" if damage == "wrong_attempt" else "session_id"] = "wrong"
        durable.write_text(json.dumps(value))
    block = ProjectStore(config).read_provider_review("project", "mission-001", "attempt-1", "w1")
    assert block.reason in {"interrupted", "persistence_unavailable"}


@pytest.mark.parametrize("passing", [True, False])
async def test_runner_denial_overrides_handoff_and_reaps_owned_processes(tmp_path, monkeypatch, passing):
    scenario = tmp_path / "scenario.json"
    store, config = setup_store(tmp_path, f"{sys.executable} {FIXTURE} {scenario}")
    path = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    scenario.write_text(json.dumps({"events": [event()], "delay": 30,
                                    "handoff": str(path) if passing else None}))
    runner = ACPNodeRunner(config, AssetLoader(config))
    owned = []
    real_spawn = asyncio.create_subprocess_exec

    async def capture_spawn(*args, **kwargs):
        child = await real_spawn(*args, **kwargs)
        owned.append(child)
        return child

    async def stub_mcp(**kwargs):
        return await capture_spawn(sys.executable, "-c", "import time; time.sleep(30)")

    async def ready(*args, **kwargs):
        pass

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)
    monkeypatch.setattr(runner, "_start_worker_mcp_server", stub_mcp)
    monkeypatch.setattr(runner, "_wait_for_server_ready", ready)
    monkeypatch.setattr(runner, "_find_free_port", lambda: 0)
    task = Task(id="w1", type="work", body="controlled", targets=[], skill="s")
    handoff = await asyncio.wait_for(runner.run_node(
        "project", "mission-001", task, "attempt-1", store,
    ), 10)
    assert not handoff.done and handoff.request_attention
    assert "Review outcome: denied" in handoff.report
    assert "recovery is unavailable" in handoff.report and CANARY not in handoff.report
    assert len(owned) == 2 and all(child.returncode is not None for child in owned)
    assert store.provider_review_paths("project", "mission-001", "attempt-1", "w1")[1].exists()


async def test_duplicate_and_conflicting_reviews_are_monotone(tmp_path):
    records = []
    capture = ProviderReviewCapture("thread-1", records.append)
    await wire(tmp_path, [event(), event(), event("approved")], capture)
    assert capture.blocked.reason == "denied"
    assert len(records) == 1
    other = tmp_path / "conflict"
    other.mkdir()
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    await wire(other, [event("approved"), event("denied")], capture)
    assert capture.blocked.reason == "invalid_context"


async def test_write_failure_survives_swallowed_observer_and_restart(tmp_path, monkeypatch):
    store, config = setup_store(tmp_path)
    store.begin_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1")

    def broken(*args, **kwargs):
        raise OSError("private filesystem detail")

    monkeypatch.setattr(store, "save_provider_review", broken)
    capture = ProviderReviewCapture("thread-1", lambda block: store.save_provider_review(
        "project", "mission-001", "attempt-1", "w1", "thread-1", block,
    ))
    assert await wire(tmp_path, [event()], capture, delay=30) is None
    assert capture.blocked.reason == "persistence_unavailable"
    assert ProjectStore(config).read_provider_review(
        "project", "mission-001", "attempt-1", "w1"
    ).reason == "interrupted"


def controller_fixture(tmp_path):
    store, config = setup_store(tmp_path)
    store.save_task_list("project", "mission-001", TaskList(tasks=[
        Task(id="w1", type="work", body="controlled", targets=[], skill="s"),
    ]))
    state = TaskStateFile()
    state.set_status("w1", "running")
    state.set_last_attempt("w1", "attempt-1")
    store.save_task_state("project", "mission-001", state)
    store.save_state("project", MissionRunning(mission_id="mission-001"))
    calls = []

    def respond(request):
        calls.append(request.task.id)
        return WorkHandoff(node_id=request.task.id, done=True, report="independent repair")

    controller = ProjectController(config, MockDispatcher(respond),
                                   MockTerminalReviewer(TerminalReviewHandoff(done=True, report="ok")))
    return controller, store, calls


def test_controller_restart_passing_handoff_retry_continue_and_independent_repair(tmp_path):
    controller, store, calls = controller_fixture(tmp_path)
    publish(store)
    # Direct old worker file: restart must not accept this passing completion.
    path = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WorkHandoff(node_id="w1", attempt_id="attempt-1", done=True,
                               report=CANARY).model_dump_json())
    envelope = controller.advance_project("project", max_steps=1)
    assert isinstance(envelope.state, AttentionNeeded)
    item = envelope.state.items[0]
    assert "provider review blocked" in item.report
    assert CANARY not in envelope.model_dump_json()
    before = controller.inspect_project("project").model_dump_json()
    assert controller.inspect_project("project").model_dump_json() == before
    for action in ["continue", "retry"]:
        with pytest.raises(ToolError, match="prose consent"):
            controller.decide_attention("project", [Decision(item_id=item.id, action=action)])
    assert store.load_task_state("project", "mission-001").status_of("w1") == "failed"
    patch = TaskListPatch(add=[Task(id="repair", type="work", body="independent repair",
                                   targets=[], skill="s")])
    controller.decide_attention("project", [Decision(item_id=item.id, action="patch", patch=patch)])
    controller.advance_project("project", max_steps=1)
    assert calls == ["repair"]
    with pytest.raises(ToolError, match="Provider review blocked"):
        controller.end_mission("project")
    assert store.load_task_state("project", "mission-001").status_of("w1") == "failed"
    assert store.read_provider_review("project", "mission-001", "attempt-1", "w1").reason == "denied"


@pytest.mark.parametrize("cancel", [False, True])
def test_patch_cannot_retire_denied_node(tmp_path, cancel):
    controller, store, _ = controller_fixture(tmp_path)
    publish(store)
    envelope = controller.advance_project("project", max_steps=1)
    item = envelope.state.items[0]
    patch = TaskListPatch(
        add=[Task(id="repair", type="work", body="repair", targets=[], skill="s")],
        cancel=["w1"] if cancel else [], supersede={} if cancel else {"w1": "repair"},
    )
    with pytest.raises(ToolError, match="prose consent"):
        controller.decide_attention("project", [Decision(item_id=item.id, action="patch", patch=patch)])


@pytest.mark.parametrize("frame", ["{invalid json", "x" * 70000])
async def test_malformed_and_oversized_wire_never_become_success(tmp_path, frame):
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    await wire(tmp_path, [], capture, raw_frame=frame)
    assert capture.blocked.reason == "invalid_context"


async def test_credential_in_provider_identity_is_unavailable_not_copied(tmp_path):
    records = []
    item = event()
    item["update"]["rawInput"]["reviewId"] = "secret-canary"
    item["update"]["toolCallId"] = "guardian_assessment:secret-canary"
    capture = ProviderReviewCapture("thread-1", records.append, ("secret-canary",))
    await wire(tmp_path, [item], capture)
    assert records == [ProviderReviewBlock("invalid_context")]
    assert "secret-canary" not in repr(records)


async def test_cancellation_closes_owned_transport_and_keeps_record(tmp_path):
    records = []
    capture = ProviderReviewCapture("thread-1", records.append)
    running = asyncio.create_task(wire(tmp_path, [event("inProgress")], capture, delay=30))
    for _ in range(100):
        if capture._reviews:
            break
        await asyncio.sleep(.01)
    assert capture._reviews
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert capture.blocked is None and records == []


def test_steering_cannot_supply_prose_override(tmp_path):
    from unrest_harness.models import SteeringRequest

    controller, store, _ = controller_fixture(tmp_path)
    publish(store)
    for action in ("continue", "nudge"):
        request = SteeringRequest(
            project_id="project", mission_id="mission-001", node_id="w1",
            terminal_review_id=None, attempt_id="attempt-1", checkpoint_sequence=1,
            action=action, actor="maintainer", body="yes, approved" if action == "nudge" else None,
        )
        with pytest.raises(ToolError, match="prose consent"):
            controller.steer_attempt(request)


async def test_cli_and_actual_mcp_inspection_are_stable_private_and_schema_compatible(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from fastmcp import Client
    from unrest_harness.cli import cli
    from unrest_harness.server import create_orchestrator_server

    controller, store, _ = controller_fixture(tmp_path)
    publish(store)
    controller.advance_project("project", max_steps=1)
    monkeypatch.setattr(HarnessConfig, "discover", classmethod(lambda cls: store.config))
    result = CliRunner().invoke(cli, ["show-project", "project"])
    assert result.exit_code == 0, result.output
    assert "node=w1 attempt=attempt-1" in result.output
    assert "prose consent is not a provider override" in result.output
    assert CANARY not in result.output
    server = create_orchestrator_server(store.config, controller=controller)
    async with Client(server) as client:
        catalog = [tool.model_dump(mode="json") for tool in await client.list_tools()]
        first = await client.call_tool("inspect_project", {"project_id": "project"})
        second = await client.call_tool("inspect_project", {"project_id": "project"})
        assert first.data == second.data
        assert "provider review blocked" in json.dumps(first.data)
        assert CANARY not in json.dumps(first.data)
        assert catalog == [tool.model_dump(mode="json") for tool in await client.list_tools()]


def test_active_cursor_is_not_denial_for_steering_but_restart_does_not_resume(tmp_path):
    store, _ = setup_store(tmp_path)
    store.begin_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1")
    assert store.read_provider_review(
        "project", "mission-001", "attempt-1", "w1", allow_active=True
    ) is None
    assert store.read_provider_review(
        "project", "mission-001", "attempt-1", "w1"
    ).reason == "interrupted"
    block = ProviderReviewBlock("denied", ReviewIdentity("thread-1", "turn-1", "review-1"))
    store.save_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1", block)
    assert store.read_provider_review(
        "project", "mission-001", "attempt-1", "w1", allow_active=True
    ).reason == "denied"
    store.provider_review_paths("project", "mission-001", "attempt-1", "w1")[0].unlink()
    assert store.read_provider_review(
        "project", "mission-001", "attempt-1", "w1", allow_active=True
    ).reason == "interrupted"


def test_denial_does_not_hide_wrong_worker_handoff_identity(tmp_path):
    from unrest_harness.storage import AttemptValidationError

    store, _ = setup_store(tmp_path)
    publish(store)
    path = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WorkHandoff(node_id="w1", attempt_id="wrong", done=True, report="ok").model_dump_json())
    with pytest.raises(AttemptValidationError, match="generation"):
        store.read_attempt("project", "mission-001", "attempt-1", "w1")


@pytest.mark.parametrize("action", [
    {"type": "execve", "source": "unifiedExec", "program": "example", "argv": [], "cwd": "/tmp"},
    {"type": "writeStdin", "approvalId": "a", "processId": "p", "stdin": CANARY, "cwd": "/tmp"},
    {"type": "applyPatch", "cwd": "/tmp", "files": [CANARY]},
    {"type": "networkAccess", "target": CANARY, "host": "example.invalid", "protocol": "https", "port": 443},
    {"type": "mcpToolCall", "server": "s", "toolName": "t", "connectorId": None, "connectorName": None, "toolTitle": None},
    {"type": "requestPermissions", "reason": CANARY, "permissions": {"network": None, "fileSystem": None}},
])
async def test_schema_action_variants_do_not_persist_private_payloads(tmp_path, action):
    records = []
    capture = ProviderReviewCapture("thread-1", records.append)
    item = event()
    item["update"]["rawInput"]["action"] = action
    await wire(tmp_path, [item], capture)
    assert capture.blocked.reason == "denied"
    assert CANARY not in repr(records)


async def test_review_count_bound_and_malformed_action(tmp_path):
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    events = []
    for index in range(65):
        item = event("inProgress")
        item["update"]["toolCallId"] = f"guardian_assessment:review-{index}"
        item["update"]["rawInput"]["reviewId"] = f"review-{index}"
        events.append(item)
    await wire(tmp_path, events, capture)
    assert capture.blocked.reason == "invalid_context" and len(capture._reviews) == 64
    bad = event()
    bad["update"]["rawInput"]["action"] = {"type": "command"}
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    capture.consume(bad)
    assert capture.blocked.reason == "invalid_context"


def test_oversized_local_binding_refuses_before_record_or_prompt(tmp_path):
    store, _ = setup_store(tmp_path)
    with pytest.raises(ValueError, match="bound"):
        store.begin_provider_review("project", "mission-001", "attempt-1", "x" * 4000, "thread-1")
    paths = store.provider_review_paths("project", "mission-001", "attempt-1", "x" * 4000)
    assert all(not path.exists() for path in paths)
