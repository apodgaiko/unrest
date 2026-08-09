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
defaults to 3600. `--strict` is an additive `--all` mode: it emits the same
complete text or schema-v1 JSON payload, then exits 1 when any project failed;
default degraded collections retain exit 0, and successful collections exit 0
in either mode. Invalid ambient configuration closes as the value-free
`invalid_configuration` Click diagnostic.

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
and makes at most three snapshot attempts. Each selected regular file is capped
at 4 MiB, the captured content total is capped at 16 MiB, at most 4,096 files or
directory entries are selected, and traversal is capped at depth 6 relative to
the project root. Selection and enumeration are bytewise sorted. A cursor that
exceeds a file, total-byte, selected-file, or depth limit closes with the
value-free `unsafe_cursor` code; an overfull or non-directory projects root
closes with value-free `unsafe_project_path`. A generation that changes through
all three attempts closes with `snapshot_changed`. The observer therefore
returns a stable coherent snapshot or a closed failure code; it does not
present a mixed cross-file read as authoritative. The operation creates no
files and performs no reconciliation, recovery, dispatch, gate evaluation, or
attention decision.

The snapshot reports structural progress, task/status/type counts,
attention-kind counts, ready gates, per-task dependency and attempt facts,
anomalies, and one advisory shadow scheduler action. Active progress excludes
superseded tasks. Count category names and order come from the corresponding
closed model literals, and every emitted count group reconciles to its source
item total. It deliberately does not emit an effort percentage, ETA,
completion projection, or inferred supervision state.

Text display identifiers are at most 80 characters. Values requiring
shortening or control-character normalization use a 16-hex SHA-256 suffix
inside that bound. Every text line is at most 240 characters; large anomaly ID
sets emit an exact total and `omitted=0`, followed by one bounded line per ID.

Ready gates use authored task-list order, matching the coordinator's graph
tie-break. When any task is marked running, the advisory action names the full
authored-order reconciliation pass; per-task timing and anomaly facts retain
the distinctions between completed, malformed, missing, stale, and
cursor-mismatched attempts. A failed-task anomaly is suppressed per task only
when an open attention cursor has that same mission and node identifier.

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
`non_current_mission`, `snapshot_changed`, `unsafe_cursor`, and
`unsafe_project_path`. A supplied mission selector is current-only in schema
version 1: the current mission is supported, a syntactically invalid selector
is `malformed_cursor`, and any valid non-current or missing mission is
`non_current_mission`; historical task, attention, and scheduler attribution is
not attempted. Runtime anomaly
codes are `mission_cursor_mismatch`, `failed_task_without_attention`,
`running_without_attempt_id`, `attempt_cursor_mismatch`,
`malformed_attempt_handoff`, `completed_attempt_unreconciled`, and
`stale_running_candidate`. Persisted state, derived state, shadow action, and
shadow reason are closed categorical fields rather than arbitrary display
strings.

Attempt timing accepts the existing UTC filename timestamp form
`YYYY-MM-DDTHH-MM-SSZ` with an optional four-digit parallel suffix. The
timestamp portion is ASCII and calendar-valid. Numeric UTC construction now
preserves that operator-visible grammar without loading `_strptime` or
`calendar` during a cold first observation; no attempt-file rename or cursor
migration is required.

## Validated capture performance

`OPT-OBS-001` compares fixed base `2d393cf1` with the sealed implementation
tree `42d84aed5c0f96e3ca0e61f1fde1cd750a7fc8db` under CPython 3.13.12. The 19
public cases and the prospectively committed v3 case produced exact normalized
output, deterministic fields, and unchanged observed trees. Across the six
public 10/40-history cases the candidate read no contract prose or irrelevant
history bodies, reduced read bytes by at least 96.486%, and had a maximum
median traced peak of 86,889 bytes. The v3 case selected 6 rather than 128
files, read 1,529 rather than 63,167,217 bytes, and reduced median traced peak
from 64,846,835 to 85,044 bytes. These are observer capture/cold-start results,
not mission elapsed-time savings.

The evidence chronology remains part of the result. V1 is incomplete negative
evidence: it failed the public memory guardrail and lacked a frozen held-out
derivation, input hash, and oracle. V2 was prospectively reproducible but also
failed: its candidate held-out peak was 1,221,623 bytes, above the 307,200-byte
ceiling, because cold `datetime.strptime` loaded `_strptime` and `calendar`
inside the measured region. Only the later, prospectively frozen v3 result is
acceptance evidence for the parser repair. Warm-cache latency was recorded as
a secondary metric and is not generalized beyond the measured cases.

Schema version 1 and persisted cursor formats are unchanged. The hardening
requires no data migration; rolling back means reverting this release's
product and documentation changes and reinstalling the preceding wheel.
Existing projects must then be checked with focused observer/CLI coverage and
a before/after tree inventory, because observation must not mutate runtime
cursors in either direction.

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

The approved base's overlapping-writer
[`BASE-SCHEDULER-DEFECT-001`](../../evals/baseline/fixtures/concurrent-writers.json)
fixture remains historical characterization only; current dispatch behavior is
governed by `ARCH-DISPATCH-001`.

Provider adapters at the approved base also select unrestricted modes
implicitly. That is the non-normative
[`BASE-CAPABILITY-DEFECT-001`](../../evals/baseline/fixtures/implicit-unrestricted-defaults.json)
observation.
