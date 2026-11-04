# ADR-0504: Classify bound work-unit state without execution authority

## Record metadata

id: ADR-0504
status: accepted
date: 2026-11-04
task_ids:
  - M1a-core
contract_targets:
  - VAL-M1A-01-32
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone

## Scope

- In scope: a new pure continuation_state module, immutable validated values, assess_unit and advance_progress, finite decision table, focused tests and architecture documentation under COMP-CONTINUATION.
- Out of scope: record adapters, coherent reads, scheduler, supervisor, wake/probes, codec, durable frontier, recovery/impossibility evaluation, project aggregation, MCP/CLI, RuntimeObservation v2, STOP mapping and release activation.

## Context

The proposed continuation layer must distinguish activity from accepted progress,
missing facts from stagnation, and an observation from permission to act. The
older prototype's default cleanup proof and fallthrough classification cannot
serve as a safe implementation oracle. Existing typed clocks and durations are
reusable; trust and provenance are not established by their types.

Bounded public research on 2026-11-04 covered Kubernetes, Temporal and Airflow
with three searches and four fetches. These systems distinguish progress,
liveness and timeout in different ways; Airflow can make timeout terminal. The
choice here not to derive completion or execution authority from a timer is our
policy, not an industry-wide invariant. Unopened sources and unpinned living
documents retain their recorded limitations.

## Decision

1. Implement a new inert pure core, not a port of the prototype. The unit is
   exactly bound by mission, continuation, origin, generation, candidate, scope
   and unit identity. No production importer or runtime integration is added.
2. Return Assessed, Indeterminate or Deferred. Assessed has seven states:
   working, ready, verifying, waiting_external, needs_user, stalled and
   paused_policy. Missing facts are not stalled; completion, recovery and
   impossibility evaluation outside this slice are Deferred. Claims cannot
   change the decision projection. Ready is conditional advice, not authority
   to dispatch, retry or complete work.
3. Use the finite table in the accepted contract as normative. Validate first;
   then apply known conservative P holds, early G*, I1-I9, user decision,
   observed waiting/working/verifying, excluded evaluations and readiness.
   G* applies only when the complete K context is known: no pending user
   decision, no wait, no attempt, satisfied or undeclared obligations and
   admissible eligibility. Known dependency, denied authority or another owner
   then yields paused_policy. Unknown eligibility does not establish K.
   Retain P/G* under stale snapshots with stale_observation, explicitly as a
   conditional negative assessment rather than current-world proof.
4. Keep admission observation separate from proposed-effect clearance. Dirty
   predecessor cells do not suppress an admitted working observation or grant
   a second dispatch. Settlement does not imply outcome resolution or replay
   clearance. Explicit complete coverage is required for positive readiness;
   empty lists and distinct resource IDs are not proofs of independence.
5. Use S2a clocks, epoch consistency and mandatory positive deadline profiles.
   Lifetime hard expiry precedes wait/progress expiry; phase can suppress only
   working-progress expiry. Ready remains inside the lifetime/progress window.
   In the named C1u/C2u unknown cells, evaluate hard only if admitted attempt or
   pending obligations establishes the specified domain. Preserve I6 ahead of
   this extension. No invented candidate, wait/progress/phase evaluation or
   automatic recovery follows. Pause never subtracts elapsed time or resets
   anchors.
6. Maintain a separate immutable acceptance frontier. Only a new accepted
   assertion/gate/blocker key advances the acceptance anchor. Diagnostics,
   activity and semantic repeats do not. Retain repeat identities in seen to
   detect identity conflicts. Exact duplicates precede capacity refusal.
7. Bound local fact tuples at 64, aggregate BasisRef occurrences at 64 and seen
   history at 1024. Token length is 1-128; there is no separate 128-key cap.
   Accepted/diagnostic keys reconstruct exactly from seen. Refuse exhaustion
   without eviction or reset. Singular basis roles have explicit optional
   cardinality; only controls.basis and obligations.refs are tuple basis roles.
8. Revalidate exact types and fields on public entry, including frozen-object
   bypasses. Use closed error codes without reflecting input values. Fact
   labels, basis references, completeness and exact bindings constrain form;
   none authenticates origin or truthful custody. Adapter responsibility is
   deferred, not implicitly satisfied by this core.

## Alternatives considered

- Prototype port or always-seven-state classification: rejected because missing facts and excluded completion are not measured stagnation or verification.
- Fable's later G with unknown eligibility: not selected; early G* requires a fully known applicable context and preserves observed work above later excluded evaluations.
- Astra's narrower hard-only domain: valid conservative alternative, not selected. The broader pending closure is adopted with I6 priority and discriminating test/mutation requirements.
- Per-collection caps only, discarding semantic repeats and Indeterminate on frontier exhaustion: Fable preferred these. Main retains aggregate limits, identity history and explicit update refusal; dissent remains.
- Universal runtime relevance solver: rejected in favor of an explicit finite table, including named known-negative exceptions and hard-only cells.

## Consequences

- Positive: deterministic, independently testable classification without launching work; explicit unknowns, conditional negatives and acceptance progress.
- Negative/cost: extensive validation and finite coverage; retained repeats consume capacity and can cause real new progress to be refused. The old frontier may then report stagnation despite unrecorded real progress.
- Compatibility/hard cut: additive inert API only; existing RuntimeObservation, continuation types/reservations, STOP, admission and durable readers remain unchanged.
- Schema/migration impact: no wire codec, durable record or migration. No frontier persistence guarantee.
- Security/privacy impact: no I/O or authority added. Caller-supplied evidence can be false. Complete coverage, coherent reads, source authentication, clock custody, resource independence and mission-wide anti-reset remain unproved. A new binding can create a new lifetime anchor.

## Review

- Reviewer: main integrator after independent Astra/Fable advice and two independent contract reviews.
- Approval date/evidence: 2026-11-04; profile execution 050-M1A-CONTRACT-V3.md, sha256 1580d77b7df9cc0fd3afe15fec90aebe44ded2979068f111fd05fa37c5f3226a. Review-1 E1-E14 and review-2 R1-R5/O-a-c incorporated; main verified the corrections and accepted V3C-01-05. No third review required for these narrow edits.
- Evaluation evidence: design accepted for bounded implementation only. Finite table, 32 VAL targets, GEN-G (495 inputs) and 106 working mutation identifiers are specified, not executed. No focused, mutation, runtime or release PASS follows from this ADR. Earlier CI success applies to 079f4d39, not to future implementation.

## Rollback

- Trigger: violated contract, independent validation failure or regression of inertness.
- Procedure: revert the implementation and its documentation/component registration together while quiescent; preserve this decision history or explicitly supersede it.
- Data recovery: none for this slice; no durable data is created or migrated.
- Verification: focused continuation-state/types/reservations and repository contracts, recursive static checks, independent scrutiny and evidence audit.

## Implementation and verification

- Components/paths: COMP-CONTINUATION; src/unrest_harness/continuation_state.py; tests/test_continuation_state.py; component-map.json.
- Canonical documents: docs/architecture/continuation-state.md; docs/architecture/index.md; this ADR and the decision index.
- Tests/evidence: VAL-M1A-01-32 in the accepted profile contract. Literal test table expectations must not derive from production. Each mutation requires unchanged-code control and a predetermined failing assertion; proxy, timeout and NOTRUN do not satisfy the gate.
- Focused gate: uv run --frozen pytest -q -p no:cacheprovider tests/test_continuation_state.py tests/test_continuation_types.py tests/test_continuation_reservations.py tests/test_repository_contract.py (with PYTHONDONTWRITEBYTECODE=1 and CODEX_PATH unset).
- Milestone gate: uv run --frozen ruff check .; uv run --frozen mypy src; uv run --frozen unrest check-repository; git diff --check.
- Hermetic no-subprocess guarantee applies to the new module/new test; existing repository-contract subprocess checks retain the unchanged standard guard. No guard waiver.
- Not authorized here: Tier P, full suite, new CI run, live workers/providers, build/install, push, merge, tag, publication or activation.

## References

- Kubernetes deployment: https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
- Temporal failure detection: https://docs.temporal.io/encyclopedia/detecting-activity-failures
- Airflow sensors: https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/sensors.html
- Profile execution: 050-m1a-research/PACK.md (bounded research and source provenance).
- Profile execution: 050-M1A-ADVICE-ASTRA.md; 050-M1A-ADVICE-FABLE.md (independent advisory positions and retained dissent).
- Profile execution: 050-M1A-CONTRACT-REVIEW-1.md; 050-M1A-CONTRACT-REVIEW-2.md; 050-M1A-REVIEW-2-MAIN-DISPOSITIONS.md (errata supersedes conflicting earlier instructions).
- Profile execution: 050-M1A-MAIN-V3-VERIFICATION.json.
