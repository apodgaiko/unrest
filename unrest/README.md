# Unrest harness

> **No rest until proven.**

This directory contains the `unrest-harness` Python distribution: the `unrest`
CLI, `unrest-server` MCP entry point, orchestration runtime, bundled prompts and
skills, and tests.

From this directory:

```bash
uv sync --locked
uv run unrest --help
uv run unrest init --scope user --agent codex
```

Use `--agent claude` for Claude Code. For a repository-local installation or
Hermes, initialize project scope instead:

```bash
uv run unrest init --scope project --workspace-dir /path/to/project --agent hermes
```

After restarting a user-scoped host, start a mission with:

```text
/unrest <your mission>
```

Development checks:

```bash
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run pytest -q ../research/2026-07-production-log-mission/test_analyze_trace.py
uv build
```

See the [repository README](../README.md) for architecture, host setup, security,
research, and lineage. Licensed under the [Apache License 2.0](../LICENSE).
