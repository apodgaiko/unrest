---
id: ARCH-RUNTIME-001
status: active
applies_to:
  - src/unrest_harness/acp_runner.py
  - src/unrest_harness/controller.py
  - src/unrest_harness/coordinator.py
  - src/unrest_harness/dispatcher.py
  - src/unrest_harness/envelope.py
verified_by:
  - tests/test_acp_runner.py
  - tests/test_coordinator.py
  - tests/test_documentation_contract.py
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
  tests/test_server.py tests/test_acp_runner.py
```

Also run the common repository gate.

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
