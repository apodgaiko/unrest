# Unrest

> **No rest until proven.**

Unrest is a continuous-improvement harness for coding agents working on missions
that outlive a single context window. The common failure is not that an agent
cannot make progress; it is that the agent finds a plausible stopping point and
declares victory before the result is complete.

Unrest keeps an orchestrator alive around that tendency. It turns a broad
objective into durable mission state, dispatches focused workers, requires
independent validation, replans from evidence, and stops only after a fresh
terminal review can account for the requested outcome.

## Install

Requirements:

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)
- Node.js 22+ and `npm`
- Claude Code, Codex, or Hermes

Clone the repository and install the Python environment:

```bash
git clone https://github.com/OpenAIBot1/unrest.git
cd unrest/unrest
uv sync --locked
uv run unrest --help
```

Install the ACP adapter for the agents Unrest will dispatch:

```bash
npm install -g @agentclientprotocol/claude-agent-acp
npm install -g @agentclientprotocol/codex-acp
```

## Set up a host

User scope makes Unrest available from every workspace in Claude Code or Codex:

```bash
uv run unrest init --scope user --agent claude
uv run unrest init --scope user --agent codex
```

Run both commands if you use both hosts. The setup registers the `unrest` MCP
server and installs the `/unrest` skill and its managed assets. Existing model,
reasoning, sandbox, feature, and unrelated MCP settings are preserved. Restart
the host after setup, then run:

```text
/unrest <your mission>
```

Hermes and repository-local installations use project scope:

```bash
uv run unrest init --scope project --workspace-dir /path/to/project --agent claude
uv run unrest init --scope project --workspace-dir /path/to/project --agent codex
uv run unrest init --scope project --workspace-dir /path/to/project --agent hermes
```

Project scope is the default, so `--scope project` may be omitted. Start the
selected host in the initialized workspace and give it the generated
orchestrator prompt: `.claude/orchestrator_prompt.md`,
`.codex/orchestrator_prompt.md`, or `.hermes/orchestrator_prompt.md`.

## How it works

1. The orchestrator investigates the objective and writes durable mission scope.
2. Falsifiable contract assertions define what “done” means.
3. Workers implement bounded parts of the plan in isolated contexts.
4. Validators exercise the real product surface and record evidence.
5. Gates reconcile the evidence; failures trigger repair or replanning.
6. A fresh terminal reviewer checks the final deliverables before closure.

State that agents must resume from lives under `.unrest/`; runtime coordination
state lives under `.unrest-runtime/`. The MCP server and ACP adapters connect the
host orchestrator to worker and validator agents without treating chat history as
the source of truth.

Terminal review is bounded to 900 seconds by default. Set
`UNREST_TERMINAL_REVIEW_TIMEOUT_SECONDS` to a positive integer to change the
limit. A timeout stops the ACP reviewer and its MCP server, records a failed
review, and leaves the mission unsealed for retry.

## Why validation matters

Tests can be green while the requested behavior is absent, incomplete, or only
works in the worker's chosen example. Unrest separates implementation from
acceptance: validators are given explicit claims and evidence requirements, and
user-visible behavior is checked through its real surface. A failed validation
is information for the next iteration, not paperwork to route around.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`unrest/`](unrest/) | Python distribution, CLI, MCP server, bundled prompts and skills, tests |
| [`research/2026-07-production-log-mission/`](research/2026-07-production-log-mission/) | Reproducible case study of a historical long-running mission trace |
| [`docs/lineage.md`](docs/lineage.md) | Source lineage, imported baselines, and attribution |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Lint, types, tests, research test, build, and wheel smoke checks |

## Development

Run the same checks as CI from the Python project directory:

```bash
cd unrest
uv sync --locked
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run pytest -q ../research/2026-07-production-log-mission/test_analyze_trace.py
uv build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations.

## Research case study

The [July 2026 production-log mission case study](research/2026-07-production-log-mission/README.md)
reconstructs a pre-Unrest mission from frozen traces. It preserves the original
measurements and their uncertainty boundaries; it is not an Unrest benchmark or
a claim about current performance.

## Security

Coding agents can execute commands and modify files. Use a sandbox and credentials
appropriate to the mission, review requested permissions, and do not place secrets
in prompts or durable mission artifacts. Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

Declared terminal-review roots receive canonical preflight and are reinforced by
prompt policy for a trusted reviewer. They reduce accidental mission-history
exposure; they do not provide OS-level confinement or make an untrusted reviewer
safe.

## Lineage and license

Unrest is independently maintained by OpenAIBot1 and contains software derived
from an Apache-2.0-licensed upstream project. The complete attribution and import
history is in [docs/lineage.md](docs/lineage.md); no upstream endorsement is
implied. The software is licensed under the [Apache License 2.0](LICENSE).
