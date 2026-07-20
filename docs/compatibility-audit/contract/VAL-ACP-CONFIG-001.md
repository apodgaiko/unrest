# VAL-ACP-CONFIG-001: Codex ACP receives supported configuration

Surface: subprocess environment.
Needs: controlled Codex provider and subprocess-boundary capture.
Behavior: The adapter command is unchanged; the spawned Codex ACP process gets
approval, sandbox, optional model, resolved effort, installed Codex path, and
agent mode through `CODEX_CONFIG`, `CODEX_PATH`, and `INITIAL_AGENT_MODE`.
Malformed or non-object `CODEX_CONFIG` fails closed with an explicit diagnostic.
No worker MCP server or ACP adapter process starts after that validation error.
Evidence: Helper edge tests plus a controlled executable shim capturing the
actual command and environment passed at the subprocess boundary, and a runtime
test that captures the caller-visible `CODEX_CONFIG` diagnostic while both the
worker-MCP and ACP process-start counters remain zero.
