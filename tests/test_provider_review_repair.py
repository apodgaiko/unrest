"""Controlled full-runner regressions for malformed envelopes and retained inspection."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import sys

from fastmcp import Client
import pytest

from unrest_harness.acp_runner import ACPNodeRunner
from unrest_harness.assets import AssetLoader
from unrest_harness.controller import ProjectController, ToolError
from unrest_harness.models import Decision, Task, TaskListPatch
from unrest_harness.provider_review import ProviderReviewCapture
from unrest_harness.server import create_orchestrator_server
from unrest_harness.storage import ProjectStore
from tests.test_provider_review import CANARY, FIXTURE, controller_fixture, event, wire


@pytest.mark.parametrize("mapping", ["creation", "update"])
@pytest.mark.parametrize("identity", ["missing", None, 12, {}, [], "", "wrong:review-1"])
async def test_malformed_outer_identity_blocks_on_managed_wire(tmp_path, mapping, identity):
    value = event(update=mapping == "update")
    if identity == "missing":
        value["update"].pop("toolCallId")
    else:
        value["update"]["toolCallId"] = identity
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    events = [event("inProgress")] if mapping == "update" else []
    assert await wire(tmp_path, [*events, value], capture) is None
    assert capture.blocked.reason == "invalid_context"
    assert capture.blocked.review is None


@pytest.mark.parametrize("field", ["kind", "title", "rawInput", "status"])
async def test_recognized_creation_missing_neighbor_field_blocks(tmp_path, field):
    value = event()
    value["update"].pop(field)
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    assert await wire(tmp_path, [value], capture) is None
    assert capture.blocked.reason == "invalid_context"


@pytest.mark.parametrize("registered", [False, True])
async def test_mcp_wrappers_and_prose_do_not_gain_review_provenance(tmp_path, registered):
    raw = event()["update"]["rawInput"]
    events = [event("inProgress")] if registered else []
    for call_id in (None, [], "wrong:review-1", "guardian_assessment:review-1"):
        for kind in ("tool_call", "tool_call_update"):
            events.append({"sessionId": "thread-1", "update": {
                "sessionUpdate": kind, "toolCallId": call_id,
                "kind": "other", "title": "Guardian Review", "status": "failed",
                "rawInput": {"server": "example", "tool": "lookup", "arguments": raw},
                "rawOutput": {"result": raw, "error": None},
            }})
    events += [None, {}, {"update": []}, {"update": {
        "sessionUpdate": "agent_message_chunk", "content": {"text": json.dumps(raw)},
    }}, {"update": {"sessionUpdate": "tool_call", "toolCallId": "guardian_assessment:review-1",
                   "kind": "other", "title": "ordinary", "rawInput": {"nested": raw}}}]
    capture = ProviderReviewCapture("thread-1", lambda _: pytest.fail("unexpected block"))
    assert await wire(tmp_path, events, capture) == {"stopReason": "end_turn"}
    assert capture.blocked is None


@pytest.mark.parametrize("case", ["valid", "missing", "wrong", "nonstring", "update_missing", "spoof"])
async def test_actual_runner_mcp_restart_and_retained_projection(tmp_path, monkeypatch, case):
    controller, store, calls = controller_fixture(tmp_path)
    scenario = tmp_path / "scenario.json"
    config = replace(store.config, worker_acp_command=f"{sys.executable} {FIXTURE} {scenario}")
    runner = ACPNodeRunner(config, AssetLoader(config))
    value = event(update=case == "update_missing")
    events = [event("inProgress")] if case == "update_missing" else []
    if case in ("missing", "update_missing"):
        value["update"].pop("toolCallId")
    elif case == "wrong":
        value["update"]["toolCallId"] = "wrong:review-1"
    elif case == "nonstring":
        value["update"]["toolCallId"] = []
    elif case == "spoof":
        value["update"]["kind"] = "other"
        value["update"]["rawInput"] = {"server": "example", "tool": "lookup",
                                         "arguments": value["update"]["rawInput"]}
    events.append(value)
    path = store.attempt_path("project", "mission-001", "attempt-1", "w1")
    scenario.write_text(json.dumps({"events": events, "handoff": str(path)}))
    owned = []
    spawn = asyncio.create_subprocess_exec

    async def record_spawn(*args, **kwargs):
        child = await spawn(*args, **kwargs)
        owned.append(child)
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", record_spawn)
    handoff = await asyncio.wait_for(runner.run_node(
        "project", "mission-001", Task(id="w1", type="work", body="controlled", targets=[], skill="s"),
        "attempt-1", store,
    ), 15)
    assert len(owned) == 2 and all(child.returncode is not None for child in owned)
    envelope = controller.advance_project("project", max_steps=1)
    if case == "spoof":
        assert handoff.done and not handoff.request_attention
        assert store.load_task_state("project", "mission-001").status_of("w1") == "cleared"
        assert ProjectStore(config).read_provider_review("project", "mission-001", "attempt-1", "w1") is None
        return
    assert not handoff.done and handoff.request_attention
    block = ProjectStore(config).read_provider_review("project", "mission-001", "attempt-1", "w1")
    assert block.reason == ("denied" if case == "valid" else "invalid_context")
    assert CANARY not in handoff.report
    assert store.load_task_state("project", "mission-001").status_of("w1") == "failed"
    durable, cursor = store.provider_review_paths("project", "mission-001", "attempt-1", "w1")
    original = (durable.read_bytes(), cursor.read_bytes())
    item = envelope.state.items[0]
    controller.decide_attention("project", [Decision(item_id=item.id, action="patch", patch=TaskListPatch(
        add=[Task(id="repair", type="work", body="independent", targets=[], skill="s")],
    ))])
    assert controller.inspect_project("project").next_action == "advance_project"
    controller.advance_project("project", max_steps=1)
    assert calls == ["repair"]
    previous = None
    for _ in range(2):
        restarted = ProjectController(config, controller.dispatcher, controller.terminal_reviewer)
        async with Client(create_orchestrator_server(config, controller=restarted)) as client:
            for _ in range(2):
                reply = (await client.call_tool("inspect_project", {"project_id": "project"})).data
                assert reply["state"]["state"] == "mission_running"
                assert reply["next_action"] == "none"
                assert "node=w1 attempt=attempt-1" in reply["frontier"]
                assert f"outcome={block.reason}" in reply["frontier"]
                assert "Native exact-action recovery is unavailable" in reply["frontier"]
                assert CANARY not in json.dumps(reply)
                assert previous is None or previous == reply
                previous = reply
        with pytest.raises(ToolError, match="Provider review blocked"):
            restarted.end_mission("project")
    assert (durable.read_bytes(), cursor.read_bytes()) == original


async def test_unregistered_update_blocks_and_denial_keeps_precedence(tmp_path):
    capture = ProviderReviewCapture("thread-1", lambda _: None)
    assert await wire(tmp_path, [event(update=True)], capture) is None
    assert capture.blocked.reason == "invalid_context"
    published = []
    capture = ProviderReviewCapture("thread-1", published.append)
    capture.consume(event())
    malformed = event()
    malformed["update"].pop("toolCallId")
    capture.consume(malformed)
    capture.consume(event("approved"))
    assert capture.blocked.reason == "denied" and len(published) == 1


def test_active_cursor_does_not_project_false_denial(tmp_path):
    controller, store, _ = controller_fixture(tmp_path)
    store.begin_provider_review("project", "mission-001", "attempt-1", "w1", "thread-1")
    envelope = controller.inspect_project("project")
    assert "provider-review:" not in envelope.frontier
    assert envelope.next_action == "advance_project"
