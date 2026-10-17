"""Exercise the CLI through FastMCP's transport without external processes."""
from contextlib import asynccontextmanager
from pathlib import Path
import sys

import anyio
import fastmcp
from fastmcp.server.mixins import transport
from fastmcp.utilities import version_check
import httpx
from mcp import ClientSession
import pytest

from unrest_harness import server

ROLES = ("orchestrator", "worker", "validator", "terminal-reviewer")


@pytest.mark.parametrize("role", ROLES)
def test_stdio_skips_update_check_but_serves_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str,
) -> None:
    monkeypatch.setenv("UNREST_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(sys, "argv", ["unrest-server", "--mode", role])
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setattr(fastmcp.settings, "check_for_updates", "stable")
    monkeypatch.setattr(fastmcp.settings, "show_server_banner", True)
    requests = []

    def local_get(url, **kwargs):
        requests.append((url, kwargs))
        return httpx.Response(200, json={"releases": {"0.0.1": {}}},
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(version_check.httpx, "get", local_get)
    # Positive control: the real banner reaches the fresh-cache update path.
    transport.log_server_banner(fastmcp.FastMCP("control"))
    assert requests == [(version_check.PYPI_URL, {"timeout": 2.0})]
    version_check._get_cache_path().unlink()
    requests.clear()
    observed = []
    original_lifespan = fastmcp.FastMCP._lifespan_manager

    @asynccontextmanager
    async def lifespan(instance):
        observed.append("lifespan-enter")
        async with original_lifespan(instance):
            yield
        observed.append("lifespan-exit")

    @asynccontextmanager
    async def local_stdio():
        to_server, server_read = anyio.create_memory_object_stream(10)
        to_client, client_read = anyio.create_memory_object_stream(10)

        async def client():
            async with ClientSession(client_read, to_server) as session:
                await session.initialize()
                catalog = await session.list_tools()
                names = {tool.name for tool in catalog.tools}
                required = ("inspect_project" if role == "orchestrator" else
                            "submit_terminal_review" if role == "terminal-reviewer"
                            else "end_node")
                assert required in names
                await session.send_ping()
                observed.append("mcp-served")
            await to_server.aclose()

        async with anyio.create_task_group() as group:
            group.start_soon(client)
            async with server_read, to_client:
                yield server_read, to_client

    monkeypatch.setattr(fastmcp.FastMCP, "_lifespan_manager", lifespan)
    monkeypatch.setattr(transport, "stdio_server", local_stdio)
    server.main()
    assert observed == ["lifespan-enter", "mcp-served", "lifespan-exit"]
    assert requests == []
    assert not version_check._get_cache_path().exists()


@pytest.mark.parametrize("protocol", ("streamable-http", "sse"))
def test_http_keeps_transport_defaults(monkeypatch: pytest.MonkeyPatch, protocol: str):
    monkeypatch.setattr(sys, "argv", ["unrest-server", "--mode", "worker",
                                     "--transport", protocol, "--port", "12345"])
    calls = []

    async def http_run(self, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(fastmcp.settings, "show_server_banner", True)
    monkeypatch.setattr(fastmcp.FastMCP, "run_http_async", http_run)
    server.main()
    assert calls == [{"transport": protocol, "show_banner": True,
                      "host": "127.0.0.1", "port": 12345}]


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("invalid", ({"UNREST_CAPABILITY_POLICY_VERSION": "2"},
                                     {"UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS": "invalid"}))
def test_real_startup_rejection_is_bounded_and_body_free(tmp_path, role, invalid):
    import os
    import subprocess

    env = {"PATH": os.defpath, "HOME": str(tmp_path),
           "UNREST_HOME": str(tmp_path / "home"), **invalid}
    result = subprocess.run(
        [sys.executable, "-I", "-c", "from unrest_harness.server import main; main()",
         "--mode", role], env=env, cwd=tmp_path, input=b"", capture_output=True, timeout=10,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"unrest-server: startup configuration rejected\n"
