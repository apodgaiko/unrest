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
  - src/unrest_harness/run_control.py
  - src/unrest_harness/runtime_executor.py
  - src/unrest_harness/workspaces.py
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

Experimental reuse/cohort dispatch and native approval recovery are disabled
by default. Genuine native approval, ACP live reuse and final-candidate timing
remain **UNVERIFIED** under the accepted 0.4.6 release risk. Controlled local
checks prove bounded local behavior; OS write isolation, transient-write
detection and comprehensive unknown-descendant termination remain unverified.
Ordinary dispatch, providers, persistence and supervision retain their existing
contracts. See the [release note](../release/lean-core-v0.4.6.md).

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
  task before persistence unless two or more work tasks declare explicit,
  pairwise-disjoint `Writes:` scopes and the production dispatcher proves a
  clean T1 Git-worktree admission. Validator-only batches remain concurrent.
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

Additive asynchronous Mission control follows one subordinate route:

```text
submit_run → durable RunControl admission → one process worker
           → runtime_executor → shared project mutation lock
           → ProjectController → MissionCoordinator/ProjectStore
```

Inquiry, workspace, identity/receipt, and evolution stores retain their own
typed lifecycle evidence but cannot write Mission state. Workspace integration
and evolution promotion reach the parent repository authority and never let a
child update the parent ref.

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

### Retained failure scheduling recovery

`advance_project` first validates retained provider-review origins and restores
stale pending blocked nodes to failed under ordinary project ownership, without
rewriting their originating records. Invalid or conflicting carriers refuse
before scheduling mutations; complete input validation precedes any status write.
Single and batch allocation/dispatch boundaries exclude retained blocks, while
independent work remains eligible and failed descendants remain blocked. Both
additive attention patch paths preserve the denial. A completed continuation
receipt does not permit fresh replay. The exact operator sequence and retention
limits are defined in [provider review denial capture](../architecture/provider-review-denial.md).

It then reconciles running attempts, evaluates ready gates,
and dispatches ready work in authored order. Only when none of those transitions
is available and no active supervision attempt remains does it look for a
failed work or validator task in the unsatisfied dependency ancestry of pending
tasks. A cleared dependency ends that search path. Unrelated failures and a
completed mission's idle state do not trigger recovery.

Recovery verifies the failed task's latest retained generation, handoff type,
node identity and incomplete result. Missing, malformed, stale or contradictory
evidence raises the existing attempt-validation error without inventing a
handoff. The first eligible failure in authored order becomes ordinary
`node_failed` attention for work or `node_attention` for validation. Its private
report explicitly identifies scheduling recovery and retains the original
failure report; routine public envelopes expose only the existing bounded
attention fields. Recovery never executes an attempt, reapplies completion,
or changes task, assertion or gate verdicts.

The project mutation lock covers discovery and publication. Attention is saved
before project state; after interruption, a fresh controller reuses an open
item with the same mission, task, generation and kind. Repeated advance while
attention is open is inert. A resolved event in decision history does not
suppress a still-stranded failure.

Operators use the existing `decide_attention` API and review the retained
failure before deciding. An authorized retirement patch must explicitly cancel
or supersede the failed task, preserve valid contract ownership, and leave
historical attempts and failed assertions intact. A work `node_failed` patch
that does not retire the task retains the existing retry behavior. Continuing
validator attention does not clear an incomplete validator; it may surface
again while it still blocks pending work. Accepted risk is not a passing
verdict. Provider-review restrictions on continuation, retry and retirement
remain authoritative; recovery provides no approval override or waiver.

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
the authored runnable prefix up to configured capacity. A work prefix runs
serially unless every selected work task has one explicit `Writes: path, ...`
line, the normalized scopes are pairwise disjoint, the dispatcher advertises
isolated-workspace support, each task has `auto_merge=true`, and the project is
a clean Git root. In that case
the parent leases distinct detached worktrees at one exact base, dispatches
with each request's own `cwd`, scope-checks identity-bound returned patches,
validates staged Git bytes, integrates the disjoint patch set serially, and
cleans only owned worktrees. Any scope escape, overlap, stale base, child
failure, integration failure, or unsettled cleanup becomes attention; conflict
does not change the parent. A missing declaration, non-Git root, unsupported
dispatcher, or admission failure preserves legacy serial behavior. T1 is Git
working-tree/index separation only, not process/network/credential/host
confinement. Batch handoffs are applied in task-ID order for deterministic
persistence even when dispatch completion order differs.

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

The five durable project mutations delegate directly to one controller-owned
boundary and request nonblocking OS-lock acquisition. Contention returns
`project_busy`, while lock-path or acquisition faults return
`project_lock_error`. Ordinary direct controller inspection uses the same
boundary in blocking/default mode. Standalone supervision admission instead
uses bounded acquisition as described below. Recovery
runs only after successful admission. Trusted same-operation nesting reuses the
admitted operation without reacquiring the lock, and different projects use
different locks.

The file is a stable rendezvous path, not a lease sentinel: ownership belongs
to the open file handle and the operating system releases it on close or
process exit. No deletion or operator cleanup is required. POSIX uses `flock`
and Windows uses a one-byte `msvcrt.locking` range. A shielded server task keeps
the controller call and its lock alive after caller cancellation until the
operation completes normally; the server adds no admission queue, lock, or
recovery boundary. MCP project inspection and attached run inspection remain
responsive through the trusted read-only live projection.

### Mission-shared supervision transactions

Checkpoint publication, steering, each role poll and standalone recovery own
one mission-wide OS lock at
`.unrest-runtime/missions/<mission>/supervision/.transaction`. This private,
extensionless regular file cannot alias a per-attempt snapshot lock. It stays
at the same inode across calls and restarts: never unlink or replace it to
recover ownership. Process death releases the open descriptor's `flock`.
Receipt history remains durable in `.unrest`; private inboxes, snapshots and
the ownership carrier remain runtime state.

Snapshot saves validate the lexical bucket root and directory chain before
creating directories or opening a carrier. Existing redirects, foreign-owned
or writable parents, and a nonprivate supervision directory refuse without
chmod normalization. Existing snapshot carriers must be single-link regular
files owned by the effective user with mode 0600; symlinks (including dangling
ones), hardlinks and nonregular files refuse before open. Opens use no-follow,
nonblocking and close-on-exec flags. Descriptor safety is checked before
locking; after acquisition the path, descriptor identity and safe state are
checked again before the snapshot body runs. Benign competing first creation
and restart reuse the same carrier. These checks apply to standalone saves
and nested transaction writes. They detect static unsafe paths and observable
carrier replacement, but do not provide hostile concurrent ancestor-swap
isolation or change the trusted-process exception.

Trusted `HarnessConfig` construction, including CLI and server discovery,
expands and resolves both persistence roots, so relative paths, home spellings
and aliases such as macOS `/var` select canonical roots before serving a project.
`dataclasses.replace` normalizes each explicitly changed root independently.
An immutable private established-root pair travels with replacements: unchanged
roots are never resolved again, including during role/provider changes or when
only the other root changes. This preserves refusal of later filesystem
redirects; it is not a boundary against Python callers forging private fields.
The pair adds no public configuration option or persisted field, and policy
cache identity and validation are unchanged. The packaged installed-wheel
checker resolves its newly created, owned temporary root before constructing
that configuration, including with the default macOS `TMPDIR`. Snapshot
acquisition never resolves a suspect root or carrier to make it acceptable.

Lock order is optional project admission, then supervision transaction, then
snapshot. Internal recovery uses the already-owned transaction and never
recursively acquires it. All receipt read/decide/append, inbox publication and
consumption, and corresponding checkpoint updates occur inside that boundary.
The role MCP and attached-run steering retain `project_guard=False`; this
bypasses only admission, allowing progress while a coordinator holds admission
and waits for a role. Transaction ownership ends before each polling sleep
and before provider work.

Ordinary handoff and terminal-review finalization acquire the mission transaction
and snapshot lock before rereading the attempt and publishing its terminal state.
Receipt recovery runs inside the transaction first, so a durable stop survives a
receipt-first crash. The fresh state determines cooperative-stop precedence;
provider denial still overrides a passing ordinary handoff. Terminal-review
success and runtime failure both finalize, and a stop takes precedence over either.
A synthesized typed reviewer crash report is persisted before finalization, so
ownership, path or storage refusal cannot discard the original diagnostic.
Finalization refusal still propagates and never seals the mission. After successful
finalization, a recovered stop selects cooperative-stop attention while the crash
report remains durable.
Sequence-zero attempts retain the same existing-schema terminal snapshot and
stable carrier. Terminal records are hidden from active inspection, reject delayed
checkpoint or stale save resurrection, and reserve the attempt identity across
restart. Finalization never unlinks the snapshot, carrier or policy. A role's
pre-transaction admission read cannot authorize publication over this terminal
fence. The coordinator already owns project admission and skips reacquiring it;
standalone finalization shares one absolute bound across admission, transaction
and snapshot acquisition. No provider work occurs under these locks.

Controlled dispatcher overlap tests exercise finalization against independent
checkpoint writers. Ordinary ACP dispatch separately closes and reaps its adapter
before returning, and the coordinator joins its effect thread; the controlled
schedule does not establish an ordinary ACP teardown overlap.

The waiter establishes its original absolute cutoff once. Admission,
transaction and all nested snapshot contention share that cutoff, without
reset, including recovery rows for other attempts. Other supervision callers
have a five-second internal transaction contention limit, shared by every
inner snapshot acquisition; this does not create a public attempt deadline.
The transaction scopes the cutoff and its clock/sleep functions to saves in
its mission's snapshot directory. Standalone coordinator saves retain separate
snapshot ownership and do not acquire the mission transaction.
Nonblocking acquisition attempts
sleep at most ten milliseconds between retries. An immediately available lock
can publish the existing timeout outcome at the cutoff; after contention
reaches the cutoff, `project_busy` refuses without claiming success. Failure to
acquire the outer transaction cannot publish a timeout receipt. If an inner
snapshot lock is unavailable after a receipt became durable, that receipt
remains available for reconciliation and mission ownership is released.
Lock I/O faults use `project_lock_error`; invalid private
carrier state uses `supervision_storage_integrity_error`, distinct from corrupt
receipt history. These bounds do not promise preemption of filesystem syscalls.

Restart reconciles a pending inbox published before its receipt, and completes
a consumed receipt after durable inbox consumption. Nudge bodies return at
most once. A crash or lost response after durable consumption may lose delivery;
it never authorizes replay. Cleanup releases ownership even on exceptions and
preserves the original operation error if descriptor cleanup also fails.
Snapshot cleanup attempts both unlock and close, even if unlock fails; any
acquisition/body `BaseException`, including cancellation, takes precedence over
cleanup failures. Without an operation failure, the first cleanup failure is
exposed. A cleanup exception alone is not evidence of a descriptor leak.

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
