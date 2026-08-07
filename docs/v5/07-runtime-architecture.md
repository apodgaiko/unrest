---
id: ARCH-RUNTIME-001
status: active
applies_to:
  - src/unrest_harness/acp_runner.py
  - src/unrest_harness/controller.py
  - src/unrest_harness/coordinator.py
  - src/unrest_harness/dispatcher.py
  - src/unrest_harness/envelope.py
  - src/unrest_harness/runtime_observability.py
verified_by:
  - tests/test_acp_runner.py
  - tests/test_cli.py
  - tests/test_coordinator.py
  - tests/test_documentation_contract.py
  - tests/test_runtime_observability.py
  - tests/test_terminal_review.py
related_decisions: []
schema_version: 1
---

# Runtime architecture

## Purpose

Describe the current disk-resumable control loop from MCP request through
controller, coordinator, dispatcher, handoff, gate, attention, and terminal
review.

## Public contract

The orchestrator sees strict MCP payloads and an `Envelope` containing project
identity, state, durable/harness roots, and an optional textual task view.
Workers and terminal reviewers see disjoint one-tool MCP servers. Runtime truth
is reconstructed from persisted typed cursors for every controller call; an
in-memory coordinator is never authoritative.

## Invariants

- `ARCH-STATE-001`: one coordinator `step()` performs at most one externally
  visible state transition.
- `ARCH-DISPATCH-001`: a capacity slice containing work selects one authored
  task before persistence; only validator-only batches may run concurrently.
- `ARCH-TASK-001`: submission and patches preserve exact one-work-owner
  contract coverage.
- `ARCH-GATE-001`: gate results are derived from persisted validator handoffs,
  with missing evidence failing closed.
- `ARCH-MCP-001`: orchestrator, worker, and terminal-reviewer tool sets are
  structurally disjoint.
- `ARCH-CLOSURE-001`: runtime completion requires a fresh successful terminal
  review and a durable closeout.
- `ARCH-CONFIG-001`: bounded role/provider configuration is explicit and
  invalid values fail instead of being silently broadened.
- `ARCH-OBSERVE-001`: operator observation is a coherent, read-only projection
  of existing cursor facts; it never claims supervision or predicts completion.
## Components and data flow

```text
host orchestrator
  → FastMCP orchestrator tool
  → ProjectController (validation + envelope)
  → MissionCoordinator (one-step state machine)
  → NodeDispatcher / TerminalReviewer
  → ACP child + role-specific MCP child
  → typed JSON handoff in .unrest-runtime/
  → ProjectStore durable Markdown mirror
  → gate/attention/closure transition
```

`ProjectController` is the command boundary. It validates tool state, creates a
fresh coordinator per invocation, applies task-list patches, records decisions,
and builds envelopes. `MissionCoordinator` selects runnable tasks, persists
`running` before dispatch, applies typed handoffs, evaluates gates, reconciles
resumed attempts, and invokes terminal review. `ProjectStore` is the sole owner
of path conventions and normal persistence.

## State transitions

```text
start_project
  draft/absent → mission_planning

submit_plan
  mission_planning → mission_running

advance_project
  mission_running → mission_running
                  → attention_needed
                  → failed (missing task list)

decide_attention
  attention_needed → mission_running
                   → mission_planning (acknowledged gap / next mission)
                   → aborted

end_mission + successful terminal review
  mission_running → done
```

`advance_project` loops `step()` until attention, a terminal state, idle, or an
optional step limit. `end_mission` is a closure request, not a dispatch alias:
it refuses when work is runnable or a gate is ready.

## Dispatch and recovery

Before dispatch, task state records `running` and the spawn timestamp. A
dispatcher exception becomes a typed failed handoff. On a later invocation,
every `running` cursor is reconciled:

- a landed attempt is parsed and applied;
- no attempt produces a synthetic failure using the recorded spawn timestamp
  when available;
- all recovered attention is raised together.

Ready gate-validator lanes retain priority. Otherwise the coordinator considers
the authored runnable prefix up to configured capacity: a prefix containing
work selects only its first task, while a validator-only prefix may batch.
Selection happens before any task is marked `running`, so work never overlaps
work or validation through either dispatcher path. Batch handoffs are applied
in task-ID order for deterministic persistence even when dispatch completion
order differs.

Historical multiple-`running` state is a recovery input, not a scheduling
permission. The coordinator consumes landed attempts or persists synthetic
failures for missing attempts, returns that reconciliation transition, and only
performs fresh selection on a later step.

## Gates and attention

Gate evaluation considers every transitive upstream validate task that covers a
gate target. The latest persisted attempt per validator is the evidence.
Uncovered targets, absent attempts, wrong handoff types, omitted target items,
or a false verdict fail the gate. A successful gate becomes `cleared` and
raises a checkpoint; a failed gate becomes `failed` and raises failure
attention.

Public attention exposes only `{id, report}`. Runtime metadata stays in
`.unrest-runtime/`. Every open item must receive exactly one decision.
`retry` is restricted to transient `node_failed`; changed work and validation
gaps require a validated patch.

## Read-only runtime observation

`observe_project_runtime(...)` derives an immutable schema-version-1 snapshot
from the persisted project, state, task, contract, attention, and attempt
cursors. `unrest observe-project PROJECT_ID` exposes the compact text view;
`--format json` exposes the public JSON schema. `unrest observe-project --all`
uses one observation time, sorts projects, and preserves monitoring
completeness by returning bounded per-project failure records instead of
silently dropping malformed entries. Exactly one of `PROJECT_ID` and `--all`
is required. `--stale-after-seconds` is a positive diagnostic threshold and
defaults to 3600.

The version-1 JSON object has these stable top-level fields, in addition to the
version and identity fields: `persisted_state`, `derived_state`, `freshness`,
`progress`, `task_counts`, `assertion_counts`, `attention_counts`,
`gate_readiness`, `tasks`, `timings`, `anomalies`, and `shadow_scheduler`.
Task rows preserve authored order and include an ordinal, type, cursor status,
dependencies, blockers, runnable fact, attempt count, and current/latest
attempt identifiers. The `--all` object contains `schema_version`, one shared
`observed_at`, `projects`, and `failures`.

Before reading, every selected project and cursor path component is checked for
containment, regular type, and absence of symbolic links. The observer compares
one content capture with a post-read device/inode/size/mtime generation check
and retries a changing snapshot at most three times. It therefore returns a
stable coherent snapshot or a closed failure code such as `snapshot_changed`,
`malformed_cursor`, or `unsafe_cursor`; it does not present a mixed cross-file
read as authoritative. The operation creates no files and performs no
reconciliation, recovery, dispatch, gate evaluation, or attention decision.

The snapshot reports structural progress, task/status/type counts,
attention-kind counts, ready gates, per-task dependency and attempt facts,
anomalies, and one advisory shadow scheduler action. Active progress excludes
superseded tasks. It deliberately does not emit an effort percentage, ETA,
completion projection, or inferred supervision state.

Freshness fields are ages of named cursor or newest-input file modification
times. Active-attempt elapsed time comes from the filename-safe dispatch cursor
timestamp. Observed attempt duration is the attempt file modification time
minus its filename timestamp and is labelled `file_mtime`; it is historical
file metadata, not an estimate of remaining work. A stale-running label only
requests inspection: elapsed wall time cannot prove that a provider process is
dead. Shadow selection is checked against current coordinator selection in
tests, but never becomes scheduler input. Reports contain identifiers,
timestamps, structural facts, and closed codes, never task bodies, prompts,
handoff or attention reports, workspace paths, credentials, or unrelated
environment values.

The observation failure codebook is `invalid_format`, `invalid_project_id`,
`invalid_stale_threshold`, `malformed_cursor`, `project_not_found`,
`snapshot_changed`, `unsafe_cursor`, and `unsafe_project_path`. Runtime anomaly
codes are `mission_cursor_mismatch`, `failed_task_without_attention`,
`running_without_attempt_id`, `attempt_cursor_mismatch`,
`malformed_attempt_handoff`, `completed_attempt_unreconciled`, and
`stale_running_candidate`. Persisted state, derived state, shadow action, and
shadow reason are closed categorical fields rather than arbitrary display
strings.

## Deferred iteration-speed work

This change deliberately measures delay without changing runtime authority.
The postponed optimization inventory, activation gates, and risks are recorded
in the proposed [observe-before-optimizing decision](../decisions/ADR-0001-observe-before-optimizing.md).
Until a separate reviewed change activates an item, Unrest does not reuse
evidence, wake or dispatch itself from observer output, recover attempts
automatically, skip gates, or publish an ETA.

## Terminal review

The caller may persist canonical deliverable roots before closure. Immediately
before reviewer dispatch the runtime revalidates them. A successful typed
review writes its JSON/Markdown evidence, seals `closeout.md`, and enters
`done`. A false review or reviewer crash preserves evidence and opens attention
without sealing.

## Failure modes

- Missing `tasks.json` while running enters `failed`.
- Invalid submission or patch returns a stable `ToolError` without partial task
  state.
- Dispatcher and reviewer exceptions are converted to persisted typed failure
  artifacts.
- Invalid deliverable roots fail before terminal-review dispatch.
- Failed gates and incomplete work require explicit attention decisions.

## 9. Same-project operation serialization

Mutating orchestrator MCP calls acquire one in-process `asyncio.Lock` per
project. This prevents concurrent same-process tool calls from racing disk
cursors. `inspect_project` is read-only and does not take the lock.

The lock is not a distributed lock and does not make multiple server processes
safe against each other. Such concurrent same-project processes are outside the
current contract.

## Change protocol

State transition, task selection, gate, resume, terminal-review, or storage
boundary changes require an accepted ADR when compatibility changes, updates
to the task/storage specs and component registry, and focused recovery and
real-surface tests. Reclassify baseline observations explicitly.

## Required verification

```bash
uv run pytest -q tests/test_coordinator.py tests/test_coordinator_parallel.py \
  tests/test_runnable_selection.py tests/test_terminal_review.py \
  tests/test_server.py tests/test_acp_runner.py \
  tests/test_runtime_observability.py
```

At a completed implementation slice, also run the milestone checks in the root
`AGENTS.md`; do not treat this focused test list as a full-suite checkpoint.

## Related decisions

No accepted repository ADR currently changes this architecture.

## Known limitations

The approved base's overlapping-writer
[`BASE-SCHEDULER-DEFECT-001`](../../evals/baseline/fixtures/concurrent-writers.json)
fixture remains historical characterization only; current dispatch behavior is
governed by `ARCH-DISPATCH-001`.

Provider adapters at the approved base also select unrestricted modes
implicitly. That is the non-normative
[`BASE-CAPABILITY-DEFECT-001`](../../evals/baseline/fixtures/implicit-unrestricted-defaults.json)
observation.
