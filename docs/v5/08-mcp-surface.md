---
id: ARCH-MCP-001
status: active
applies_to:
  - src/unrest_harness/controller.py
  - src/unrest_harness/server.py
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_server.py
related_decisions: []
schema_version: 1
---

# MCP surface

## Purpose

Define the three structurally isolated MCP server modes, their tools, typed
handoffs, state preconditions, and error payloads.

## Public contract

`unrest-server` accepts `--mode orchestrator|worker|terminal-reviewer` and
`--transport stdio|streamable-http|sse`. Each mode constructs a separate
`FastMCP` instance and registers only its role's tools.

### Orchestrator mode

| Tool | Preconditions | Observable result |
| --- | --- | --- |
| `start_project` | Non-empty brief; existing absolute workspace; overrides valid for selected worker provider. | Creates project and `mission-001`; returns `mission_planning`. |
| `submit_plan` | `mission_planning`; contract files already written. | Validates and persists the task list; returns `mission_running`. |
| `advance_project` | Existing project, normally `mission_running`. | Blocks through dispatch steps until attention, terminal, idle, or `max_steps`. |
| `end_mission` | `mission_running`; no runnable work or ready gate. | Runs terminal review; returns `done` or attention. |
| `decide_attention` | `attention_needed`; one decision per open item. | Records decision and returns the next state. |
| `inspect_project` | Existing project. | Pure read with full textual task view. |
| `abort_project` | Existing project. | Preserves evidence, seals abort where possible, returns `aborted`. |

All successful calls return the typed envelope:

```json
{
  "projectId": "…",
  "state": {"state": "…"},
  "projectRoot": "…/.unrest",
  "harnessRoot": "…/<project-id>",
  "dag": "text task view or null"
}
```

Tool failures return:

```json
{
  "error": "stable_code",
  "message": "bounded explanation",
  "details": ["validation_code: detail"]
}
```

### Worker mode

Worker mode registers only `end_node`. Runtime configuration comes from:

- `UNREST_NODE_TYPE`
- `UNREST_NODE_ID`
- `UNREST_HANDOFF_PATH`

Work calls provide `done`, `report`, and optional `request_attention`.
Validation calls additionally provide one `items[]` verdict per assigned
target and aggregate `passed`. The tool atomically writes one strict JSON
handoff and returns an instruction to stop. Missing path or task ID is a hard
runtime error.

### Terminal-reviewer mode

Terminal-reviewer mode registers only `submit_terminal_review`. It reads
`UNREST_TERMINAL_REVIEW_PATH`, atomically writes `{done, report}`, and instructs
the reviewer to stop. `done=true` is a closure recommendation consumed by the
coordinator; the tool itself does not seal a mission.

## Invariants

- `ARCH-MCP-001`: tool authority is separated by server construction, not
  prompt convention.
- `SEC-MCP-001`: worker and reviewer modes cannot call orchestrator lifecycle
  tools through their server.
- `ARCH-STATE-001`: mutating orchestrator calls are serialized per project and
  execute blocking controller work in a thread.
- `COMPAT-ENVELOPE-001`: envelope field names and strict typed handoff fields
  are compatibility boundaries.

## Failure modes

- Wrong lifecycle state returns `wrong_state`.
- Invalid plans, patches, and decisions return stable top-level errors plus
  stable validation details.
- Invalid worker overrides fail before project creation.
- Missing worker/reviewer environment paths fail instead of inventing output.
- Exceptions in production dispatch/review are handled by the runtime as
  persisted failure evidence.

## Change protocol

Adding or changing a tool requires updates to this document, the server
registration tests, installed-wheel help/smoke checks, and the component map.
Do not expose orchestrator tools on worker or reviewer servers. Schema
incompatibility requires an ADR and explicit version/error behavior.

## Required verification

```bash
uv run pytest -q tests/test_server.py tests/test_models.py \
  tests/test_acp_runner.py
uv build
uv run python tools/check_distribution.py dist
```

For packaging changes, install the wheel and run `unrest-server --help` plus
`python -m unrest_harness --help` from an unrelated directory. These are
focused package checks; the full source suite runs only at the frozen-candidate
release checkpoint and is not repeated after build.

## Related decisions

No accepted repository ADR currently changes this surface.

## Known limitations

The approved base's provider configuration can implicitly select unrestricted
execution. This document records the MCP shape only; it does not bless that
behavior. The defect is classified in
[`BASE-CAPABILITY-DEFECT-001`](../../evals/baseline/fixtures/implicit-unrestricted-defaults.json)
and remains historical characterization.
