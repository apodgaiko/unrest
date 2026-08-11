---
id: SPEC-TASK-001
status: active
applies_to:
  - src/unrest_harness/coordinator.py
  - src/unrest_harness/envelope.py
  - src/unrest_harness/models.py
  - src/unrest_harness/task_list_patch.py
  - src/unrest_harness/task_validation.py
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_runnable_selection.py
  - tests/test_task_list_patch.py
  - tests/test_task_validation.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Task-list product contract

## Purpose

Define the current typed mission task list, its contract-coverage rules,
patching semantics, and deterministic dispatch behavior. This document
describes the accepted task/gate/handoff boundary at the Batch 0 base; it does
not make the baseline's concurrent shared-checkout writers normative.

## Public contract

`TaskList` contains an authored-order list of `Task` objects. Unknown fields are
rejected. A task has:

| Field | Contract |
| --- | --- |
| `id` | Mission-unique; matches `^[A-Za-z][A-Za-z0-9_-]*$`. |
| `type` | `work`, `validate`, or `gate`. |
| `body` | Required non-empty Markdown for work/validate; empty for a gate. |
| `targets` | Contract assertion IDs. A validator and gate need at least one; targetless work is allowed only for coherent setup/integration work. |
| `skill` | Required for work/validate; `null` for a gate. |
| `auto_merge` | Legacy no-op retained in serialized shape; defaults to `true`. Work runs in the project workspace. |
| `depends_on` | Direct upstream task IDs; defaults to `[]`. |

Task statuses are `pending`, `running`, `cleared`, `failed`, or `superseded`.
Assertion statuses are `pending`, `passed`, or `failed`.

## Invariants

- `ARCH-TASK-001`: every contract assertion has exactly one active,
  non-superseded work owner. Validators and gates may cover multiple targets.
- `ARCH-DISPATCH-001`: authored list order is the topological tie-break; a
  capacity slice containing work selects exactly its first task before state
  persistence, while validator-only slices may batch.
- `ARCH-GATE-001`: a gate clears only when every covering upstream validator
  passes each gate target; dissent, omitted items, and uncovered targets fail.
- `COMPAT-PATCH-001`: supersede/cancel rewrites direct dependency edges in
  `tasks.json`; the decision record, not a hidden chain reader, preserves why.
- `COMPAT-ENVELOPE-001`: the envelope field remains named `dag`, although its
  value is a textual task-list view.

## Flow

### Authoring

Before `submit_plan`, the orchestrator writes one `contract/<ID>.md` file per
assertion. Submission then validates, in order:

1. the contract directory exists, is non-empty, and contains valid assertion
   filenames;
2. the task list is non-empty and task IDs are valid and unique;
3. type-specific body, skill, and target shape;
4. resolving, non-self dependencies;
5. acyclicity;
6. exact one-work-owner coverage of every assertion.

Validation stops at the first failing check group and returns stable
`ValidationError.code` values. A successful submission writes `tasks.json`,
initializes task and contract cursors, and enters `mission_running`.

### Goal G4 — authored order is the deterministic tie-break

The runtime preserves authored list order when more than one non-gate task is
runnable. Rendered task views also use authored order to break topological
ties. Gate evaluation itself is ordered by gate ID for deterministic
checkpoints.

## Patching

`TaskListPatch` is valid only when at least one operation is non-empty:

- `add_items`: declares new assertion IDs whose matching contract files are
  already present. Undeclared newly discovered files are rejected.
- `add`: appends globally new tasks.
- `supersede`: maps an existing pending/failed task to a replacement task and
  rewrites every downstream `depends_on` reference to the replacement.
- `cancel`: marks an existing pending/failed task superseded and removes it
  from every downstream dependency list.

Superseded and cancelled tasks remain in the task list for ID/audit continuity.
Rewritten dependency lists preserve order and deduplicate replacements. A
patch is transactional: on any validation error the original list, state, and
contract ID set are returned unchanged. After rewriting, shape, references,
acyclicity, and assertion coverage are rechecked.

Cleared tasks, running tasks, and any task in the transitive upstream closure of
a cleared gate cannot be superseded or cancelled.

## Dispatch

A non-gate task is runnable when it is `pending` and every direct dependency is
`cleared`. Retired dependencies have already been rewritten, so dispatch does
not interpret supersession chains.

When a pending gate's complete validator lane is ready, those validators are
preferred before unrelated work, up to `max_parallel_nodes`; any remaining
validators refill the next dispatch step in authored order. Validators report
one typed verdict per assigned target. Work completion clears the work task;
incomplete work fails and raises attention. Validation failure is surfaced
immediately only when no pending downstream gate will surface it.

Outside ready-gate priority, dispatch considers the authored runnable prefix up
to `max_parallel_nodes`. If that prefix contains work, only its first authored
task is selected. Therefore work/work and work/validator intervals never
overlap, and newly scheduled state never marks multiple work tasks `running`.
If the prefix contains only validators, it may dispatch as one batch. Ready
gate validator lanes retain their priority and may batch only up to the same
capacity ceiling. At capacity one, a ready gate dispatches one validator per
step.

Batch-capable dispatchers and the coordinator's per-request fallback receive
only validator-only batches. Historical state with multiple `running` tasks is
reconciled completely before any fresh selection: landed attempts are consumed,
missing attempts fail, and the reconciliation step returns without dispatching
new work.

Concurrent validators use independent MCP child lifecycles. The production
runner serializes the advisory free-port probe through confirmed MCP readiness,
then runs the agent sessions concurrently. A request that crashes before its
handoff retains a bounded, known-credential-redacted cause in its own failed
attempt; a successful sibling remains independently applicable.

Gate coverage is transitive over upstream validate tasks. Missing attempt
files, wrong handoff type, missing expected target items, explicit dissent, or
no covering validator all count as failure. A cleared gate still emits a
`gate_checkpoint` attention item.

## Failure modes

- Invalid submission: no task/runtime state is initialized.
- Dispatcher exception: a typed failed handoff is synthesized and persisted.
- Worker `done=false`: task becomes failed and `node_failed` attention opens.
- Validator omission or dissent: a downstream gate fails, or node attention
  opens when no gate owns the failure.
- Gate failure: gate becomes failed and requires a decision.
- Running cursor without its exact generation attempt after resume, or with a
  malformed/mismatched attempt: the runtime persists a synthetic failed
  handoff rather than guessing success.

## Edge Cases

- Contract `README.md` is ignored; other invalid Markdown stems are errors.
- Work may be targetless for setup/integration, but an empty contract is never
  valid and targetless work cannot satisfy coverage.
- `cancel` and `supersede` may not name the same task in one patch.
- A replacement cannot be itself, unknown, or cancelled in the same patch.
- Duplicate dependency edges introduced by replacement are collapsed in first
  occurrence order.
- A validator's aggregate `passed` flag does not excuse missing per-target
  items at a gate.
- `end_mission` never dispatches runnable work or evaluates a ready gate; the
  caller must advance first.

## Change protocol

Changes to task shape, coverage, patch rewriting, gate aggregation, status
transitions, or authored ordering require:

1. an accepted ADR when compatibility changes;
2. updates to this document and the component/ID registries;
3. focused positive, negative, patch, gate, resume, and serialization tests;
4. baseline fixture reclassification rather than silent golden replacement.

## Required verification

```bash
uv run pytest -q tests/test_models.py tests/test_task_validation.py \
  tests/test_task_list_patch.py tests/test_runnable_selection.py \
  tests/test_coordinator.py tests/test_coordinator_parallel.py \
  tests/test_terminal_review.py
```

At a completed implementation slice, also run the milestone checks in the root
`AGENTS.md`; this focused task-list check does not consume the single
frozen-candidate full-suite checkpoint.

## Related decisions

ADR-0002 removes historical baseline generation while retaining this task-list
contract.

## Historical characterization

The approved Batch 0 base allowed overlapping shared-checkout workers. That
historical characterization is not an invariant or compatibility promise.
`ARCH-DISPATCH-001` defines repaired runtime behavior.
