"""Functional desktop observer checks, without scored startup measurements."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("desktop_fixture", ROOT / "tools/v046_desktop_fixture.py")
assert SPEC and SPEC.loader
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    manifest = tmp_path / "candidate.json"
    manifest.write_text('{"candidate": "functional-test-only"}\n')
    root = tmp_path / "desktop"
    setup = fixture.prepare(root, manifest)
    return root, setup


def test_preparation_is_disposable_and_strips_authority(prepared):
    root, setup = prepared
    assert os.environ["UNREST_HOME"] == str(root / "home")
    assert set(os.environ) - {"PYTEST_CURRENT_TEST"} == {"HOME", "PATH", "LANG", "UNREST_HOME", "UNREST_PROJECTS_DIR",
                               "PYTHONDONTWRITEBYTECODE"}
    assert setup["role"] == "orchestrator"
    assert setup["project_id"].startswith("desktop-probe-")
    assert setup["registration"]["args"][-1] == str(root)
    assert (root / "home/projects" / setup["project_id"]).is_dir()
    with pytest.raises(FileExistsError):
        fixture.prepare(root, root / "candidate-manifest.json")


@pytest.mark.parametrize("field", ["package", "launcher_sha256", "interpreter_sha256",
                                   "candidate_manifest_sha256", "registration"])
def test_changed_binding_refuses_before_server(prepared, monkeypatch, field):
    root, setup = prepared
    setup[field] = "changed"
    (root / "setup.json").write_text(json.dumps(setup))
    from unrest_harness import server

    monkeypatch.setattr(server, "main", lambda: pytest.fail("service must not start"))
    with pytest.raises(ValueError, match="identity changed"):
        fixture.serve(root)
    assert not list((root / "observations").iterdir())


def test_wire_forwarding_records_only_matching_metadata(tmp_path):
    raw = io.BytesIO()
    observer = fixture.ResponseObserver(raw, "unique-fixture", tmp_path)
    foreign = {"result": {"structuredContent": {"projectId": "private", "secret": "hidden"}}}
    expected = {"structuredContent": {"projectId": "unique-fixture", "state": {"state": "draft"}}}
    wire = b'not-json\n' + fixture.canonical(foreign) + b'\n'
    wire += fixture.canonical({"result": expected}) + b'\n'
    for byte in wire:
        observer.write(bytes([byte]))
    assert raw.getvalue() == wire
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    record = json.loads(files[0].read_text())
    assert record["result_sha256"] == fixture.sha(fixture.canonical(expected))
    assert "private" not in files[0].read_text()
    assert "hidden" not in files[0].read_text()


@pytest.mark.asyncio
async def test_actual_stdio_response_binds_fixture_process_and_candidate(prepared):
    root, setup = prepared
    registration = setup["registration"]
    params = StdioServerParameters(command=registration["command"], args=registration["args"])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            catalog = await session.list_tools()
            assert "inspect_project" in {tool.name for tool in catalog.tools}
            result = await session.call_tool("inspect_project", {"project_id": setup["project_id"]})
            assert not result.isError
            assert result.structuredContent["projectId"] == setup["project_id"]
    observation, = (root / "observations").iterdir()
    process = json.loads((observation / "process.json").read_text())
    response = json.loads((observation / "response-0001.json").read_text())
    exited = json.loads((observation / "exit.json").read_text())
    assert process["pid"] == response["pid"] == exited["pid"] != os.getpid()
    assert process["process_start"]
    assert process["package_sha256"] == setup["package"]["sha256"]
    assert process["candidate_manifest_sha256"] == setup["candidate_manifest_sha256"]
    assert response["structured_content_sha256"] == fixture.sha(
        fixture.canonical(result.structuredContent))
    assert process["registration_sha256"] == fixture.sha((root / "registration.json").read_bytes())
    assert process["server_module"] == str(Path(setup["package"]["path"]) / "server.py")
