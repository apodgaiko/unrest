"""Private HTTP MCP factory, never registered in ordinary role catalogs.

The caller binds loopback only and owns server lifetime. No tool can grant a
turn, obtain a current capability, launch a process or execute candidate code.
Capabilities travel in arguments, not a static connection header. Transport
logging must remain disabled. This is a local research surface, not admission.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from mcp.types import CallToolResult, TextContent
from pydantic import StrictBool

from unrest_harness.experimental_lease import LeaseRefused, TurnBroker, TurnIdentity


class _Refusal(ToolResult):
    """Bounded MCP errors without dependency traceback/source/body logging."""

    def to_mcp_result(self) -> CallToolResult:
        return CallToolResult(content=self.content, isError=True)


def _refusal(error: Exception) -> _Refusal:
    code = str(error) if isinstance(error, LeaseRefused) else 'broker_unavailable'
    return _Refusal(content=[TextContent(type='text', text=code)])


def broker_server(broker: TurnBroker, connection_token: str) -> FastMCP:
    if len(connection_token) < 32:
        raise LeaseRefused('invalid_connection_token')
    server = FastMCP('experimental-turn-broker', auth=StaticTokenVerifier(tokens={
        connection_token: {'client_id': 'local-lane', 'scopes': []},
    }))

    def identity(value: dict[str, Any]) -> TurnIdentity:
        if type(value.get('scope')) is not list:
            raise LeaseRefused('invalid_identity')
        if type(value.get('targets', [])) is not list:
            raise LeaseRefused('invalid_identity')
        try:
            return TurnIdentity(**{**value, 'scope': tuple(value['scope']),
                                   'targets': tuple(value.get('targets', []))})
        except (TypeError, KeyError, ValueError):
            raise LeaseRefused('invalid_identity') from None

    @server.tool(output_schema=None)
    def replace_file(capability: str, turn: dict[str, Any], name: str, content: str) -> Any:
        """Replace one declared fixture file under this exact worker turn."""
        try:
            return broker.replace(capability, identity(turn), name, content)
        except Exception as error:
            return _refusal(error)

    @server.tool(output_schema=None)
    def complete_turn(capability: str, turn: dict[str, Any], candidate: str,
                      disposition: str, verdicts: dict[str, StrictBool] | None = None) -> Any:
        """Publish immutable experimental completion; never ordinary end_node."""
        try:
            return asdict(broker.complete(capability, identity(turn), candidate, disposition, verdicts))
        except Exception as error:
            return _refusal(error)

    return server
