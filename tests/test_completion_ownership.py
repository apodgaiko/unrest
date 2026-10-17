"""Real role-process ownership races and process interruption at publication."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys

import pytest
from fastmcp import Client

from tests.test_server import _call_process_mcp, _http_server_process
from tests import test_server as helpers
from unrest_harness.models import Task, TaskList
from unrest_harness.storage import ProjectStore, atomic_write_json, publish_completion_json


config = helpers.config


async def _race(urls, arguments):
    async with Client(urls[0]) as first, Client(urls[1]) as second:
        results = await asyncio.gather(
            first.call_tool("end_node", arguments[0]),
            second.call_tool("end_node", arguments[1]),
        )
    return [result.structured_content for result in results]


@pytest.mark.parametrize("role,targets", [("work", []), ("work", ["VAL-A"]), ("validate", ["VAL-A"])])
@pytest.mark.parametrize("interleave", ["valid", "invalid", "exhausted", "both-invalid"])
def test_role_process_ownership(config, workspace, role, targets, interleave):
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"], cwd=workspace, check=True)
    store = ProjectStore(config)
    store.create_project("ownership", workspace, project_id="ownership")
    task = Task(id="node", type=role, targets=targets, body="check", skill="test")
    store.save_task_list("ownership", "mission-001", TaskList(tasks=[task]))
    path = store.attempt_path("ownership", "mission-001", "attempt", "node")
    env = {"UNREST_PROJECT_ID": "ownership", "UNREST_MISSION_ID": "mission-001", "UNREST_NODE_ID": "node", "UNREST_NODE_TYPE": role, "UNREST_HANDOFF_PATH": str(path)}
    mode = "validator" if role == "validate" else "worker"
    args = [{"done": True, "report": "first"}, {"done": False, "report": "second"}]
    if role == "validate":
        for index, arg in enumerate(args):
            arg.update(items=[{"item_id": "VAL-A", "passed": index == 0}], passed=index == 0)
    if interleave != "valid":
        args[1]["completion"] = {}
    if interleave == "both-invalid":
        args[0]["completion"] = {}
    with _http_server_process(config, workspace, mode=mode, role_environment=env) as (_, a), _http_server_process(config, workspace, mode=mode, role_environment=env) as (_, b):
        if interleave == "exhausted":
            refusal = _call_process_mcp(a, "end_node", args[1])
            assert refusal["code"] == "completion_refused"
            assert not path.exists()
        responses = asyncio.run(_race([a, b], args))
    assert sum(result.get("recorded") is True for result in responses) == 1
    saved = path.read_bytes()
    handoff = json.loads(saved)
    if interleave == "invalid":
        assert handoff["report"] == "first"
    if interleave == "both-invalid":
        assert handoff["done"] is False and handoff["request_attention"] is True
        assert any(result.get("code") == "completion_refused" for result in responses)
    markers = store.mission_runtime_dir("ownership", "mission-001") / "completion-refusals"
    assert not markers.exists() or not list(markers.glob("*.json"))
    with _http_server_process(config, workspace, mode=mode, role_environment=env) as (_, url):
        late = _call_process_mcp(url, "end_node", {**args[0], "completion": {}})
        assert late == {"recorded": False, "code": "completion_finalized"}
    assert path.read_bytes() == saved
    assert not markers.exists() or not list(markers.glob("*.json"))
    # A distinct attempt remains independently usable, even after exhaustion.
    other = store.attempt_path("ownership", "mission-001", "other", "node")
    with _http_server_process(config, workspace, mode=mode, role_environment={**env, "UNREST_HANDOFF_PATH": str(other)}) as (_, url):
        valid = {key: value for key, value in args[0].items() if key != "completion"}
        assert _call_process_mcp(url, "end_node", valid)["recorded"] is True
    assert path.read_bytes() == saved


@pytest.mark.parametrize("phase", ["before", "after"])
def test_interrupted_publication_and_lock_recovery(tmp_path, phase):
    path = tmp_path / "attempt.json"
    # Exit inside the actual primitive while holding the actual kernel lock.
    # Before-link interruption leaves only private bytes; after-link models a
    # lost response, with no opportunity for ordinary finally/cleanup handlers.
    script = r'''
import os, sys
from pathlib import Path
from unrest_harness.storage import completion_lock, publish_completion_json
path = Path(sys.argv[1])
link = os.link
def interrupted(source, destination):
    if sys.argv[2] == 'after':
        link(source, destination)
    os._exit(73)
os.link = interrupted
with completion_lock(path):
    publish_completion_json(path, {'report': 'first', 'done': True})
'''
    result = subprocess.run([sys.executable, "-c", script, str(path), phase], timeout=20)
    assert result.returncode == 73
    assert path.exists() is (phase == "after")
    retry = r'''
import sys
from unrest_harness.storage import completion_lock, publish_completion_json
with completion_lock(sys.argv[1]):
    print(publish_completion_json(sys.argv[1], {'report': 'second', 'done': False}))
'''
    result = subprocess.run([sys.executable, "-c", retry, str(path)], capture_output=True, text=True, timeout=20, check=True)
    assert result.stdout.strip() == ("False" if phase == "after" else "True")
    assert json.loads(path.read_bytes()) == {"report": "first" if phase == "after" else "second", "done": phase == "after"}


def test_publication_no_replace_preserves_generic_overwrite(tmp_path):
    path = tmp_path / "attempt.json"
    assert publish_completion_json(path, {"value": 1})
    saved = path.read_bytes()
    assert not publish_completion_json(path, {"value": 2})
    assert path.read_bytes() == saved
    atomic_write_json(path, {"value": 3}, trusted_root=tmp_path)
    assert json.loads(path.read_bytes()) == {"value": 3}
    link = tmp_path / "symlink.json"
    link.symlink_to(path)
    assert not publish_completion_json(link, {"value": 4})
    assert json.loads(path.read_bytes()) == {"value": 3}


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("role", ["work", "validate"])
def test_role_interrupted_publication(config, workspace, phase, role):
    import os

    from fastmcp.client.transports import StdioTransport

    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"], cwd=workspace, check=True)
    store = ProjectStore(config)
    store.create_project("crash", workspace, project_id="crash")
    store.save_task_list("crash", "mission-001", TaskList(tasks=[Task(id="node", type=role, targets=["VAL-A"], body="check", skill="test")]))
    path = store.attempt_path("crash", "mission-001", "attempt", "node")
    env = {key: value for key, value in os.environ.items() if not key.startswith("UNREST_")}
    env.update(UNREST_HOME=str(config.harness_home), UNREST_PROJECTS_DIR=str(config.projects_dir), UNREST_PROJECT_ID="crash", UNREST_MISSION_ID="mission-001", UNREST_NODE_ID="node", UNREST_NODE_TYPE=role, UNREST_HANDOFF_PATH=str(path))
    mode = "validator" if role == "validate" else "worker"
    args = {"done": True, "report": "published before lost response"}
    if role == "validate":
        args.update(items=[{"item_id": "VAL-A", "passed": True}], passed=True)
    script = f'''
import os
from unrest_harness.server import main
link = os.link
def interrupted(source, destination):
    if str(destination) == {str(path)!r}:
        if {phase!r} == 'after':
            link(source, destination)
        os._exit(73)
    return link(source, destination)
os.link = interrupted
main()
'''

    async def lost_response():
        transport = StdioTransport(command=sys.executable, args=["-c", script, "--mode", mode], env=env, cwd=str(workspace))
        async with Client(transport, timeout=20) as client:
            with pytest.raises(Exception):
                await client.call_tool("end_node", args)

    asyncio.run(lost_response())
    assert path.exists() is (phase == "after")
    saved = path.read_bytes() if path.exists() else None
    with _http_server_process(config, workspace, mode=mode, role_environment=env) as (_, url):
        result = _call_process_mcp(url, "end_node", args)
        if phase == "after":
            assert result == {"recorded": False, "code": "completion_finalized"}
            assert path.read_bytes() == saved
        else:
            assert result["recorded"] is True
    assert json.loads(path.read_bytes())["report"] == args["report"]
