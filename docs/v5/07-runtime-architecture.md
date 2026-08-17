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
Workers, validators, and terminal reviewers see role-specific one-tool MCP
servers. Worker and validator modes share the strict `end_node` completion
implementation, but each of the four modes has its own server identity and
instructions. Runtime truth is reconstructed from persisted typed cursors for
every controller call; an in-memory coordinator is never authoritative.

## Invariants

- `ARCH-STATE-001`: one coordinator `step()` performs at most one externally
  visible state transition.
- `ARCH-DISPATCH-001`: a capacity slice containing work selects one authored
  task before persistence; only validator-only batches may run concurrently.
- `ARCH-TASK-001`: submission and patches preserve exact one-work-owner
  contract coverage.
- `ARCH-GATE-001`: gate results are derived from persisted validator handoffs,
  with missing evidence failing closed.
- `ARCH-MCP-001`: orchestrator, worker, validator, and terminal-reviewer modes
  are isolated by separate server construction. Worker and validator share
  only the strict `end_node` completion protocol, not role identity or
  authority.
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
of path conventions and normal persistence. Its atomic writer uses a unique
same-directory temporary file, fsyncs content before replacement, preserves an
existing regular target's mode, and removes rejected temporary generations.
Write, content-fsync, and replace failures reject while preserving the prior
generation. Parent-directory fsync is best effort after replacement: its
failure cannot roll back the visible target, so the call completes successfully
and restart observes the accepted new generation. Each write also carries a
lexical trusted persistence root. The root and every destination component
through the parent are checked with `lstat` before directory or temporary
creation and again before replacement; symlinks and other non-directories fail
closed at any nesting depth. Containment uses path components, and the writer
does not resolve a redirected destination and then write through it.

Initialization is the only caller that may supply an `allowed_ancestor` to the
atomic writer. This permits an absent managed `.claude`, `.codex`, or `.agents`
root to be created beneath an existing lexical workspace or user-home boundary.
The CLI preflights every initialization destination before its first write, and
both the boundary and every existing root/parent/target component must be a real
directory or regular file as appropriate; symlinks and non-directories are not
resolved or traversed. Calls without `allowed_ancestor` retain the normal rule
that their trusted persistence root must already exist, including all project
bucket persistence.

ACP batch dispatch uses an event-loop-local startup lock. The free-port probe,
role MCP child spawn, and readiness check serialize for contending nodes in one
batch, while completed event loops do not retain lock affinity or serialize a
later batch globally. Claude callers validate both managed settings targets
against the real workspace before reading them. Missing settings are created
atomically; exact legacy managed settings and current marked settings are the
only existing files Unrest migrates. Safe unmanaged settings remain unchanged,
and malformed, unsafe, or symlinked settings reject before any child spawn.

ACP `terminal/create` treats explicit JSON null for optional `args`, `env`, and
`outputByteLimit` exactly like omission. Non-null values retain strict list and
positive-integer validation, including rejection of booleans.

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

Spawn timestamps used by schema-v2 observation have the fixed ASCII UTC form
`YYYY-MM-DDTHH-MM-SSZ` with an optional `-NNNN` parallel suffix. Calendar and
clock fields must be valid; offsets, Unicode digit lookalikes, and other forms
are not accepted.

- only the exact `last_attempt` path is considered, and a landed handoff is
  applied only when its `node_id` and `attempt_id` match that task and dispatch
  generation;
- a missing, malformed, stale, replayed, or mismatched attempt produces a
  bounded synthetic failure rather than inferred success;
- all recovered attention is raised together.

Ready gate-validator lanes retain priority. Otherwise the coordinator considers
the authored runnable prefix up to configured capacity: a prefix containing
work selects only its first task, while a validator-only prefix may batch.
Selection happens before any task is marked `running`, so work never overlaps
work or validation through either dispatcher path. Batch handoffs are applied
in task-ID order for deterministic persistence even when dispatch completion
order differs.

Within a validator batch, each node keeps independent MCP child and drain
lifecycle state. Free-port selection, MCP spawn, and readiness confirmation are
serialized through one runner so a sibling cannot bind or be mistaken for the
selected endpoint. A pre-handoff exception becomes a per-node failed handoff
whose bounded, finite-inventory-redacted cause is written through the normal
attempt path; it is never converted into a cleared validation verdict.

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

`observe_project_runtime(...)` derives the closed schema-v2 status projection
from a coherent bounded capture of existing cursors. `unrest observe-project
PROJECT_ID` prints one deterministic key/value line; `--format json` prints
the same fields as a closed JSON object. `observe-project --all` uses one
observation time, orders projects bytewise by project ID, isolates each
project's closed failure, and emits only the wrapper fields `schema_version`,
`observed_at`, `projects`, and `failures`.

The project object fields, in order, are:

1. `schema_version` (the integer `2`);
2. `observed_at`, `project_id`, and nullable `mission_id`;
3. `persisted_state` and `derived_state`;
4. `attention_count`;
5. sorted unique bounded `running_task_ids`, `runnable_task_ids`, and
   `failed_task_ids`;
6. nullable `last_runtime_change_age_seconds`; and
7. sorted unique `codes`.

Derived state precedence is inconsistency, terminal, draft, planning, open
attention, active running/runnable work, then quiescent mission-running state.
The only diagnostic codes are `mission_cursor_mismatch`,
`failed_task_without_attention`, `running_without_attempt`,
`malformed_attempt`, and `stale_running_candidate`. Staleness is diagnostic
only; it never authorizes recovery or changes an active project to a
recovery-ready state.
`failed_task_without_attention` is an active-mission diagnostic: completed,
failed, and aborted project states retain failed task IDs but omit that stale
running-only anomaly.

The age is `observed_at - max(mtime)` across the current state, task,
attention, and contract cursors plus current-mission attempt and terminal-review
cursors. Future timestamps clamp to zero and values round half-even to three
decimal places. It is file-age metadata, not a heartbeat, liveness statement,
effort percentage, ETA, or completion prediction.

Capture accepts only a real immediate project directory and regular cursor
files. It rejects traversal, symbolic links, special files, oversized inputs,
and a generation that changes through all three bounded retries with one closed
failure code. Observation imports no coordinator or mutation path and performs
no persistence, dispatch, recovery, gate, attention, scheduler, or liveness
action.

For `--all`, non-strict mode exits zero when at least one project is readable;
strict mode exits nonzero when any failure exists. Empty roots exit zero in both
modes. All-failed roots exit nonzero in both modes. JSON failure objects contain
only bounded nullable `project_id` and a code from `invalid_project_id`,
`malformed_cursor`, `project_not_found`, `snapshot_changed`,
`unsafe_cursor`, or `unsafe_project_path`.

### Schema-v2 migration

Schema v2 is an approved hard cut, not a compatibility layer. The former
schema-v1 nested counts, task rows, attempt timing, anomaly bodies, shadow
scheduling, detail aliases, and alternate modes are removed. Consumers must
switch atomically to the schema-v2 fields above; there is no version
negotiation or legacy output flag. The observer remains non-persistent, so this
requires no cursor or project-data migration.

The CLI imports the status implementation only after `observe-project` is
selected (including its command help). Global help, initialization, ordinary
project operations, and MCP startup do not load it.

## Deferred iteration-speed work

This change reduces observation cost without changing runtime authority.
The postponed optimization inventory, activation gates, and risks are recorded
in the proposed [observe-before-optimizing decision](../decisions/ADR-0001-observe-before-optimizing.md).
Until a separate reviewed change activates an item, Unrest does not reuse
evidence, wake or dispatch itself from observer output, recover attempts
automatically, skip gates, or publish an ETA. The remaining multi-day issue is
external wake/checkpoint cadence around host automation, attention,
gate-checkpoint, and closure boundaries; this release makes no autonomous
dispatch, recovery, or elapsed-time-saving claim.

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

The approved base's overlapping-writer behavior remains historical
characterization only; current dispatch behavior is governed by
`ARCH-DISPATCH-001`.

Provider adapters at the approved base also selected unrestricted modes
implicitly. That remains a non-normative historical observation.
