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
- Claude Code or Codex as the orchestrator host

Clone the repository and install the Python environment:

```bash
git clone https://github.com/apodgaiko/unrest.git
cd unrest
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

Fresh homes are supported: the managed `.claude` or `.codex` tree is created
only beneath the existing home directory after all destination paths pass the
same symlink and non-directory checks used by atomic persistence.

```text
/unrest <your mission>
```

Repository-local installations use project scope:

```bash
uv run unrest init --scope project --workspace-dir /path/to/project --agent claude
uv run unrest init --scope project --workspace-dir /path/to/project --agent codex
```

Project scope is the default, so `--scope project` may be omitted. Start the
selected host in the initialized workspace and give it the generated
orchestrator prompt: `.claude/orchestrator_prompt.md`,
or `.codex/orchestrator_prompt.md`. Initialization compares every bundled
provider asset with its packaged authoritative bytes and `0644` mode. Each
bounded asset group reports deterministic `created`, `repaired`, and `verified`
counts; repeated commands against unchanged state produce identical verified
output without rewriting exact assets. Corrupt, truncated, or wrong-mode
managed assets are atomically repaired without replacing unrelated host files.

## Inspect status

`unrest observe-project PROJECT_ID` prints a read-only project snapshot;
`unrest observe-project --all --strict --format json` emits the closed schema-v2
aggregate and exits nonzero if any project cannot be read. Schema v2 replaces
the former nested counts, task rows, attempt timing, anomaly bodies, shadow
scheduling, and detail aliases. Consumers must switch atomically: there is no
legacy output flag or version negotiation. Existing persisted project and
mission records remain schema version 1 and require no data migration.

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

## Safety and repository contracts

Unrest resolves a versioned capability policy before starting any MCP or ACP
role. The default `safe` profile limits filesystem, process, environment,
credential, and approval authority; unrestricted development access requires
the explicit `--unsafe-development-unrestricted` opt-in. Unsupported provider,
role, policy, or profile combinations fail closed before mission work starts.

The public `check-repository` development command performs the finite Lean Core
repository checks: required guidance and references, component ownership,
packaged runtime-policy loadability, and required CI lanes and commands. CI also
exercises the built wheel to prove packaged policy discovery and fail-closed
startup. The former governance/commit-message commands, generated historical
baseline, duplicate root schemas, and protected-surface policy are withdrawn in
v0.2 rather than compatibility-shimmed.

## Troubleshooting host setup

Initialization fails closed when a managed Claude path, including
`.claude/settings.json`, is a symlink, malformed, or not a regular file. Remove
or replace the unsafe filesystem entry yourself, then rerun `unrest init`; Unrest
does not follow the link or overwrite its target. Report the path kind and the
bounded error code, never credential values, environment dumps, settings file
bodies, prompts, or generated reports. The same value-free rule applies to bug
reports and release evidence.

## Why validation matters

Tests can be green while the requested behavior is absent, incomplete, or only
works in the worker's chosen example. Unrest separates implementation from
acceptance: validators are given explicit claims and evidence requirements, and
user-visible behavior is checked through its real surface. A failed validation
is information for the next iteration, not paperwork to route around.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/unrest_harness/` | CLI, MCP server, runtime, bundled prompts, skills, and provider definitions |
| `tests/` | Hermetic unit and integration tests plus opt-in live ACP smoke tests |
| [`docs/lineage.md`](docs/lineage.md) | Source lineage, imported baselines, and attribution |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Lint, types, tests, build, and installed-wheel smoke checks |

## Development

During a focused edit, run the narrow checks that exercise the changed behavior:

```bash
uv run pytest -q <focused-test-paths>
uv run ruff check <changed-product-paths>
uv run mypy <changed-typed-paths>
```

Run milestone checks from the repository root:

```bash
uv sync --locked
uv run ruff check .
uv run mypy src
uv run unrest check-repository
uv run pytest -q <milestone-test-paths>
```

Record why a focused check type is inapplicable when necessary. Before freezing
a release candidate, verify the Python and uv versions, run focused checks, and
prove in the intended execution lane that a tiny loopback socket can bind. None
of these preflights may invoke the full source suite. Freeze the resulting
tracked and untracked source binding, then run the full source suite exactly
once on Python 3.13 with `env -u CODEX_PATH uv run pytest -q`, retaining its raw
stdout, stderr, exit code, timing, environment metadata, and pre/post binding.
Do not rerun the suite after build. Python 3.11 and 3.12 run lightweight
compatibility checks. Changes to CLI entry points, bundled assets, package data,
or MCP surfaces additionally run `uv build`,
`uv run python tools/check_distribution.py dist`, and the installed-wheel
lifecycle from an unrelated working directory. The distribution check verifies
complete archive membership and bytes, safely extracts the sdist, and runs all
14 protected `tests/test_persistence_schema_v1.py` cases from the extracted
tree while proving the package module, test module, cwd, and effective
`sys.path` do not leak the checkout. This executable archive proof follows the
single full source-suite run and does not repeat it.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations.

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

Unrest is independently maintained by apodgaiko and contains software derived
from an Apache-2.0-licensed upstream project. Attribution and provenance are in
[docs/lineage.md](docs/lineage.md); no upstream endorsement is implied. The
software is licensed under the [Apache License 2.0](LICENSE).
