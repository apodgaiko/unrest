"""First-use completion setup and interrupted consumed-quota recovery."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests import test_server as helpers
from unrest_harness import server
from unrest_harness.models import Task, TaskList
from unrest_harness.storage import ProjectStore, _prepare_atomic_write_destination

config = helpers.config


@pytest.mark.parametrize("branch", ["parent", "root"])
@pytest.mark.parametrize("competitor", ["directory", "symlink", "dangling", "file"])
def test_actual_competing_creator(tmp_path, monkeypatch, branch, competitor):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"preserved")
    root = tmp_path / "root" if branch == "root" else tmp_path
    competing = root if branch == "root" else root / "parent"
    target = competing / "child" / "result.json"
    original = Path.mkdir

    def competing_mkdir(path, *args, **kwargs):
        if path == competing:
            if competitor == "directory":
                original(path)
            elif competitor == "file":
                path.write_bytes(b"not a directory")
            else:
                path.symlink_to(outside if competitor == "symlink" else outside / "missing")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", competing_mkdir)
    kwargs = dict(create_parents=True, allowed_ancestor=tmp_path if branch == "root" else None)
    if competitor == "directory":
        assert _prepare_atomic_write_destination(target, root, **kwargs) == (target, target.parent)
    else:
        with pytest.raises(OSError, match="regular directory"):
            _prepare_atomic_write_destination(target, root, **kwargs)
    assert sentinel.read_bytes() == b"preserved"
    assert outside.stat().st_mode & 0o777 == 0o755
    assert sorted(p.name for p in outside.iterdir()) == ["sentinel"]


@pytest.mark.parametrize("operation", ["consume", "clear"])
@pytest.mark.parametrize("component", ["root", "intermediate", "refusals"])
@pytest.mark.parametrize("kind", ["symlink", "dangling", "file"])
def test_refusal_rejects_unsafe_parents(tmp_path, operation, component, kind):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    root = tmp_path / "bucket"
    path = root / ".unrest-runtime" / "completion-refusals" / "marker.json"
    bad = {"root": root, "intermediate": path.parent.parent, "refusals": path.parent}[component]
    bad.parent.mkdir(parents=True, exist_ok=True)
    if kind == "file":
        bad.write_bytes(b"file")
    else:
        bad.symlink_to(outside if kind == "symlink" else tmp_path / "missing")
    # Mirror the remaining relative suffix to detect traversed cleanup too.
    external = outside / path.relative_to(bad)
    external.parent.mkdir(parents=True, exist_ok=True)
    external.write_bytes(b"outside marker")
    orphan = external.parent / ".marker.json.orphan.tmp"
    orphan.write_bytes(b"outside temporary")
    before = {str(p.relative_to(outside)): (p.stat().st_mode, p.read_bytes() if p.is_file() else None) for p in [outside, *outside.rglob("*")]}
    if operation == "consume":
        with pytest.raises(OSError):
            server._consume_completion_refusal(path, project_id="p", mission_id="m", node_id="n", attempt_id="a")
    else:
        server._clear_completion_refusal(path)
    after = {str(p.relative_to(outside)): (p.stat().st_mode, p.read_bytes() if p.is_file() else None) for p in [outside, *outside.rglob("*")]}
    assert after == before


@pytest.mark.parametrize("phase", ["temporary", "before-replace", "after-replace"])
@pytest.mark.parametrize("kind", ["corrupt", "wrong-mode", "symlink"])
def test_consumed_marker_survives_recovery_interruption(tmp_path, phase, kind):
    path = tmp_path / "marker.json"
    sentinel = tmp_path / "outside"
    sentinel.write_bytes(b"preserved")
    args = dict(project_id="p", mission_id="m", node_id="n", attempt_id="a")
    if kind == "wrong-mode":
        assert server._consume_completion_refusal(path, **args)
        path.chmod(0o644)
    elif kind == "symlink":
        path.symlink_to(sentinel)
    else:
        path.write_bytes(b"corrupt")
    script = r'''
import os, sys, tempfile
from pathlib import Path
from unrest_harness.server import _consume_completion_refusal
phase = sys.argv[2]
replace = os.replace
mkstemp = tempfile.mkstemp
def interrupted_temp(*a, **kw):
    result = mkstemp(*a, **kw)
    os._exit(73)
def interrupted_replace(*a, **kw):
    if phase == 'after-replace': replace(*a, **kw)
    os._exit(73)
if phase == 'temporary': tempfile.mkstemp = interrupted_temp
else: os.replace = interrupted_replace
_consume_completion_refusal(Path(sys.argv[1]), project_id='p', mission_id='m', node_id='n', attempt_id='a')
'''
    result = subprocess.run([sys.executable, "-c", script, str(path), phase], timeout=20)
    assert result.returncode == 73
    assert os.path.lexists(path)
    assert server._consume_completion_refusal(path, **args) is False
    assert json.loads(path.read_bytes())["consumed"] is True
    assert path.stat().st_mode & 0o777 == 0o600
    assert sentinel.read_bytes() == b"preserved"
    assert not list(tmp_path.glob(".marker.json.*.tmp"))


@pytest.mark.parametrize("role,targets", [("work", []), ("work", ["VAL-A"]), ("validate", ["VAL-A"])])
@pytest.mark.parametrize("scenario", ["invalid-invalid", "valid-invalid", "valid-valid", "distinct"])
def test_real_roles_first_use(config, workspace, role, targets, scenario):
    subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"], cwd=workspace, check=True)
    store = ProjectStore(config)
    store.create_project("setup", workspace, project_id="setup")
    store.save_task_list("setup", "mission-001", TaskList(tasks=[Task(id="node", type=role, targets=targets, body="check", skill="test")]))
    path = store.attempt_path("setup", "mission-001", "attempt", "node")
    assert not path.parent.exists()
    barrier = workspace / "barrier"
    barrier.mkdir()
    script = f'''
import sys,time
from pathlib import Path
from unrest_harness.server import main
index=sys.argv.pop(1)
original=Path.mkdir
def synchronized(self,*a,**kw):
 if str(self)=={str(path.parent)!r}:
  (Path({str(barrier)!r})/index).touch()
  deadline=time.monotonic()+15
  while len(list(Path({str(barrier)!r}).iterdir()))<2:
   if time.monotonic()>deadline: raise RuntimeError('barrier timeout')
   time.sleep(.01)
 return original(self,*a,**kw)
Path.mkdir=synchronized
main()
'''
    env = {key: value for key, value in os.environ.items() if not key.startswith("UNREST_")}
    env.update(UNREST_HOME=str(config.harness_home), UNREST_PROJECTS_DIR=str(config.projects_dir), UNREST_PROJECT_ID="setup", UNREST_MISSION_ID="mission-001", UNREST_NODE_ID="node", UNREST_NODE_TYPE=role)
    mode = "validator" if role == "validate" else "worker"
    other = store.attempt_path("setup", "mission-001", "other", "node")

    async def call(index):
        destination = other if scenario == "distinct" and index == 1 else path
        transport = StdioTransport(command=sys.executable, args=["-c", script, str(index), "--mode", mode], env={**env, "UNREST_HANDOFF_PATH": str(destination)}, cwd=str(workspace))
        args = dict(done=index == 0, report=f"contender {index}")
        if role == "validate":
            args.update(items=[dict(item_id="VAL-A", passed=index == 0)], passed=index == 0)
        if scenario == "invalid-invalid" or scenario == "valid-invalid" and index == 1:
            args["completion"] = {}
        async with Client(transport, timeout=30) as client:
            return (await client.call_tool("end_node", args)).structured_content

    async def race():
        return await asyncio.gather(call(0), call(1))

    responses = asyncio.run(race())
    assert sum(r.get("recorded") is True for r in responses) == (2 if scenario == "distinct" else 1)
    handoff = json.loads(path.read_bytes())
    if scenario == "invalid-invalid":
        assert any(r.get("code") == "completion_refused" for r in responses)
        assert handoff["done"] is False and handoff["request_attention"] is True
    if scenario == "valid-invalid":
        assert handoff["report"] == "contender 0"
    if scenario == "distinct":
        assert json.loads(other.read_bytes())["report"] == "contender 1"


@pytest.mark.parametrize("boundary", ["root", "ancestor"])
@pytest.mark.parametrize("kind", ["missing", "symlink", "dangling", "file"])
def test_invalid_creation_boundary(tmp_path, boundary, kind):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    (outside / "sentinel").write_bytes(b"preserved")
    anchor = tmp_path / "anchor"
    if kind == "file":
        anchor.write_bytes(b"file")
    elif kind != "missing":
        anchor.symlink_to(outside if kind == "symlink" else tmp_path / "missing")
    root = anchor / "root" if boundary == "ancestor" else anchor
    with pytest.raises(OSError):
        _prepare_atomic_write_destination(root / "child" / "result.json", root, create_parents=True, allowed_ancestor=anchor if boundary == "ancestor" else None)
    assert (outside / "sentinel").read_bytes() == b"preserved"
    assert outside.stat().st_mode & 0o777 == 0o755
    assert sorted(p.name for p in outside.iterdir()) == ["sentinel"]


def test_process_dies_during_first_setup(tmp_path):
    root = tmp_path / "bucket"
    root.mkdir()
    path = root / ".unrest-runtime" / "attempts" / "result.json"
    script = r'''
import os, sys
from pathlib import Path
from unrest_harness.storage import completion_lock
original = Path.mkdir
def interrupted(self, *a, **kw):
    original(self, *a, **kw)
    os._exit(73)
Path.mkdir = interrupted
with completion_lock(sys.argv[1]): raise AssertionError('never reached')
'''
    result = subprocess.run([sys.executable, "-c", script, str(path)], timeout=20)
    assert result.returncode == 73
    assert not path.exists()
    from unrest_harness.storage import completion_lock, publish_completion_json

    with completion_lock(path):
        assert publish_completion_json(path, {"report": "restarted"})
    assert json.loads(path.read_bytes()) == {"report": "restarted"}
