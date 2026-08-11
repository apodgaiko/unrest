---
id: PLAN-V5-001
status: active
applies_to:
  - src/unrest_harness/controller.py
  - src/unrest_harness/coordinator.py
  - src/unrest_harness/server.py
  - src/unrest_harness/storage.py
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_terminal_review.py
related_decisions: []
schema_version: 1
---

# V5 implementation plan and completion map

## Purpose

Map the implemented runtime phases to their canonical source, persisted
artifacts, and verification. This is a completion map for current behavior,
not a promise that known Batch 0 defects are acceptable.

## Public contract

The runtime provides a disk-resumable sequence:

1. project creation and mission planning;
2. contract-backed task-list submission;
3. worker/validator dispatch and typed handoff persistence;
4. gate aggregation and attention decisions;
5. patch/retry/recovery;
6. explicit closure request;
7. fresh terminal review and seal.

## 1. Phases 1–6 — plan, execute, validate, and request closure

| Phase | Implementation | Durable/runtime evidence | Primary tests |
| --- | --- | --- | --- |
| Project | `ProjectController.start_project`, `ProjectStore.create_project` | `brief.md`, `project.json`, `state.json` | `test_storage.py`, `test_server.py` |
| Plan | `submit_plan`, task validation | contract Markdown, `tasks.json`, task/contract state | `test_task_validation.py`, `test_coordinator.py` |
| Execute | coordinator runnable selection and dispatcher | JSON/Markdown attempts | `test_coordinator.py`, `test_acp_runner.py` |
| Validate | typed validation handoff and gate aggregation | contract cursor, attempts, gate attention | `test_coordinator.py`, `tests/contracts/test_lean_lifecycle.py` |
| Adapt | `decide_attention`, `TaskListPatch` | numbered decision Markdown, rewritten tasks | `test_task_list_patch.py`, `test_supersede_chain.py` |
| Close request | `end_mission`, root preflight | terminal-review config | `test_terminal_review.py`, `test_storage.py` |

Every phase resumes from disk. The controller is reconstructed for each tool
invocation, and the coordinator reads current task/contract/attention state
before transitioning.

## 2. Phase 7 — terminal review and closure

Phase 7 begins only after the caller explicitly invokes `end_mission` and the
mission has no runnable task work or ready gate.

1. Canonical deliverable roots are persisted or reused.
2. Roots are revalidated immediately before reviewer dispatch.
3. A fresh terminal reviewer receives the mission and writes a typed result.
4. The store preserves JSON and Markdown review artifacts.
5. `done=true` writes `closeout.md` and moves the project to `done`.
6. `done=false`, timeout, or reviewer crash opens terminal-review attention and
   leaves the mission unsealed for repair/retry.

`next_mission` is restricted to terminal-review gaps that cannot be patched in
the current mission. It seals the old mission as
`done_with_acknowledged_gaps` and returns to planning with the next sequential
mission ID.

## Invariants

- `ARCH-STATE-001`: each coordinator step advances no more than one state
  transition.
- `ARCH-GATE-001`: validation evidence, not worker completion prose, controls
  gate verdicts.
- `ARCH-CLOSURE-001`: only a successful terminal review or explicit
  acknowledged-gap decision seals closure.
- `ARCH-STORAGE-001`: every runtime JSON handoff with durable value has a
  Markdown mirror under the mission record.

## Failure modes

Each phase persists enough evidence to resume or diagnose:

- malformed plans/patches fail before partial application;
- dispatcher failures become typed attempts;
- missing running attempts become typed recovery failures;
- gate dissent and omission are visible in attention;
- terminal-review failures preserve review artifacts and avoid premature seal.

## Change protocol

When a phase changes, update its canonical task/storage/runtime/MCP document,
component edges, stable IDs, and tests in the same change. New future phases
belong in a separate accepted plan or ADR; do not retrofit them into current
completion semantics.

## Required verification

```bash
uv run pytest -q tests/test_coordinator.py tests/test_storage.py \
  tests/test_server.py tests/test_terminal_review.py \
  tests/contracts/test_lean_lifecycle.py
```

At a completed implementation slice, also run the milestone checks in the root
`AGENTS.md`. When CLI entry points, bundled assets, package data, or MCP surfaces
change, run the focused archive check and unrelated-cwd installed-wheel lifecycle
required by the package tier; do not rerun the full source suite after build.
The source distribution must also carry
`tests/test_persistence_schema_v1.py` and both JSON files under
`tests/fixtures/persistence_schema_v1/`. The adjacent manifest identifies the
orchestrator-frozen mission oracle and its SHA-256; it must not claim provenance
from a source revision that did not contain the corpus.

## Related decisions

No accepted repository ADR currently changes this plan.

## Known limitations

The withdrawn historical baseline's overlapping mutable-worker batching and
implicit unrestricted provider modes are explicitly non-normative. Git history
retains that characterization; it is not a current installed validation surface
or completion criterion for this plan.
