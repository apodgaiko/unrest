# ADR-0505: Observe one explicit task without continuation classification

## Record metadata

id: ADR-0505
status: accepted
date: 2026-11-04
task_ids:
  - E2E-0-preflight
contract_targets:
  - VAL-PF-01-25
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone
  - installed-cli

## Scope

- In scope: one experimental read-only CLI command, internal captured-byte projection, explicit project/mission/task selectors, closed observations with presence and provenance, versioned JSON, focused tests and documentation under COMP-OBSERVABILITY.
- Out of scope: continuation classification or activation, synthetic frontier/history/clock lineage, durable records, planner, readiness, supervisor, loop, worker/provider execution, MCP, public Python API, coherent cross-root reads and changes to RuntimeObservation v2.

## Context

The pure continuation core requires reliable binding, progress history and clock
inputs that current runtime cursors cannot establish. Missing inputs must not be
replaced with a new lifetime anchor or an assertion that no acceptance occurred.
A read-only fact preflight can expose that gap without pretending to classify
work. A durable continuation record is not established as a prerequisite for
this narrower operation. It remains a separate design problem.

Bounded public research on 2026-11-04 examined DBOS checkpoints, Temporal event
history, Apple fsync and Linux process identity. Checkpoint/replay systems resume
from recorded history; their write/recovery mechanisms do not establish a need
for new persistence in a one-shot reader. Research coverage is PARTIAL: fencing,
lock death and modern filesystem guarantees are not proved. No such guarantees
are required or claimed by this decision.

## Decision

1. Add `unrest continuation-preflight --project PROJECT_ID --mission MISSION_ID
   --task TASK_ID`, with all three selectors required. This is a new public CLI
   surface, but not MCP or a new public Python API. Its explicit invocation is
   the opt-in: experimental features remain off by default because no background
   execution, default activation or worker effect is enabled. Static command help
   does not import its implementation.
2. Always return adapter-level `assessment.status=unavailable` in schema v1.
   Never import or call the continuation core. Do not fabricate frontier,
   acceptance absence, candidate, profile, binding or epoch. Observations and
   persisted status strings are not core decisions, readiness or execution
   authority. This is preflight plumbing, not M1a integration, and does not
   implement the record adapters or coherent reads excluded by ADR-0504.
3. Use exactly the existing runtime cursor capture. Permit only the bounded
   intra-package private imports specified in the accepted contract. Keep
   runtime_observability.py byte-identical. Source hashes are verification
   baselines, not runtime self-hashing or a guarantee of a supported private API.
   No new parser, lock, controller, coordinator, RunControl construction or
   ProjectStore load route is introduced. RunControl with recovery disabled is
   not read-only and is forbidden here.
4. Validate selector grammar with fullmatch and bind to the mission selected by
   the captured cursors. Reject project/state mission mismatch before selector
   mismatch. Operate on one explicit task, never a runnable-task selection or
   mission aggregate. Recheck content-derived errors against a second capture;
   allow three bounded attempts. Stat equality is not a coherent instant,
   authenticity, complete coverage or a same-stat rewrite detector.
5. Expose only the eight closed observation families, with recorded-field
   presence from model_fields_set, never model defaults as observed facts.
   Association and status provenance remain separate for dependencies and
   targets. Attempt references are grammar-checked opaque references and exact
   captured-key lookups, not process identity, age or liveness. Attention counts
   use the documented mission/task join, not an assertion of no attention.
6. Parse task-state and contract-state whenever captured, including for a task
   with no targets. Broken contract-state therefore refuses with malformed_cursor
   even for empty targets. This deliberately differs from observe-project,
   which does not parse that file; observe-project remains unchanged. Explicitly
   preserve this difference in the canonical spec.
7. Keep supervision contents excluded. Coverage lists fourteen families and a
   closed definition of captured cursor paths. Patch transactions are not
   captured; coverage itself is nonexhaustive. No project durable records,
   run-control records or cross-root read is added. Limits remain 4 MiB per file,
   16 MiB total, 4096 files/entries, depth 6 and three attempts for the entire
   capture-selected mission. Exceeding limits refuses; no truncation.
8. Use closed schema version 1, deterministic key/collection order and compact
   JSON with one trailing newline. Adding keys or changing semantics requires a
   version increase and documented migration. Exact G1/G2 byte goldens are the
   serialization oracle. The ensure_ascii/allow_nan toggles are equivalent on
   reachable ASCII/integer outputs, not mutation kills; structural checks pin
   those parameters separately. read_at is one aware wall-clock read, converted
   to UTC; it asserts only read time, not source freshness or comparability.
9. Separate lazy-import failure from execution failure. Pass through only the
   fourteen closed error codes, otherwise internal_error, without exception
   text, paths, source bodies, private reports or new logs. Build all output
   before writing stdout. Click argument-parsing errors remain outside this
   closed envelope. Exit zero means only that a report was constructed.
10. Treat project_bucket/path provenance as lexical only. Intermediate mission
    directory symlinks are not contained by the existing reader; duplicate-key
    selector ambiguity and same-stat rewrites remain inherited limitations.
    Neither physical containment, a read-only sandbox nor runtime safety proof
    follows. These limitations do not waive a failed validation assertion.

## Alternatives considered

- M2a-first durable record: not selected for this no-history preflight; introduces a new writer and recovery/identity problem without making existing cursor facts more trustworthy.
- Real M1a assessment using now or attempt start as a fabricated acceptance anchor: rejected; unknown history is not a recorded absence of progress. A core amendment for unknown history is separate and not adopted.
- Extract a planner or enable advance_project(max_steps=1): excluded; one coordinator step can batch work and mutate before dispatch. Readiness advice cannot authorize effects.
- Extract shared reader/config helpers or widen capture to supervision: not selected. Bounded private imports and a local configuration block minimize changes to the pinned v2 command, at the cost of coupling and duplication.

## Consequences

- Positive: inspectable missing information and explicit per-fact provenance without executing work or changing durable state.
- Negative/cost: assessment is always unavailable; command naming does not imply a real continuation assessment. Private-reader coupling, mission-wide capture limits and inherited reader limitations remain.
- Compatibility/hard cut: additive experimental CLI; observe-project source segments, existing runtime reader, models, core and public catalogs remain pinned. Unconditional contract-state refusal is a documented divergence of the new command only.
- Schema/migration impact: new closed output schema v1; no durable data or migration is introduced.
- Security/privacy impact: narrow output and closed errors, but no authenticity, physical isolation, source completeness or sandbox promise. Parsed-command errors can echo user-provided unknown options. Read auditing is fixture-root bounded.

## Review

- Reviewer: main integrator after independent Astra/Fable consultation and two sequential independent contract reviews.
- Approval date/evidence: 2026-11-04; profile execution 050-ATTACHED-ONCE-CONTRACT-V3.md, sha256 ddc72fd88b6758e838d2b29cb808b85b5c71a4f973da95b95707874299f6c2ac, plus CONTRACT-AMENDMENT-1 (presence-matrix cascades follow the normative fact rules). REVIEW-1 E1-E15 and REVIEW-2 R1-R7 incorporated; main read the full V3 and verified the crosswalk. No third review required for the bounded text corrections.
- Evaluation evidence: design accepted for bounded implementation only. Main independently checked both literal JSON golden byte lengths/hashes, five pinned CLI source-segment hashes and 25 full file hashes using stdlib text operations. This is not product execution, Pydantic/Click behavior proof, a mutation PASS, local slice acceptance or runtime/release PASS.

## Rollback

- Trigger: contract violation, privacy/read-only regression or independent validation failure.
- Procedure: revert the new CLI callback, internal projection, tests and associated documentation/component registration as one coherent change; preserve or explicitly supersede this ADR.
- Data recovery: none; no new persistence or migration.
- Verification: focused preflight, existing runtime observability/CLI/core guards, repository contracts and static checks; compare pinned source baselines and absence of the new command.

## Implementation and verification

- Components/paths: COMP-OBSERVABILITY; src/unrest_harness/continuation_preflight.py; one callback in cli.py; tests/test_continuation_preflight.py; component-map.json.
- Canonical documents: docs/architecture/continuation-preflight.md; architecture and decision indexes; README.md; docs/v5/07-runtime-architecture.md.
- Tests/evidence: VAL-PF-01-25 in the accepted contract, with G1/G2 full bytes, presence and selector matrices, closed error/clock seams, capture-read/write audits, import isolation and compatibility pins. Test expectations must not derive from production. Matrix output cascades follow the independent fact rules, not only abbreviated row assertions.
- Focused: uv run --frozen pytest -q tests/test_continuation_preflight.py tests/test_runtime_observability.py tests/test_cli.py tests/test_continuation_state.py tests/test_continuation_reservations.py tests/test_continuation_types.py; changed-path ruff and mypy. Keep the unchanged standard guard; denied pristine-interpreter launch is NOTRUN, not PASS.
- Milestone: uv run --frozen ruff check .; uv run --frozen mypy src; uv run --frozen unrest check-repository; documentation/repository contracts.
- CLI distribution floor: uv build, distribution byte/member checks, safely extracted sdist persistence cases and installed-wheel command use from unrelated cwd, with provenance. Source tests alone cannot certify this surface. Build/install and child execution require their bounded execution authorization; no guard waiver follows from this ADR.
- Mutations: separate bounded lane with unchanged-code controls, fixed witnesses and independent causal/evidence review. Proxy, timeout, NOTRUN and equivalent mutations do not count as kills.
- Not authorized here: full suite before frozen candidate, new CI/push, merge/tag/publication, real workers/providers, E2E-1, M5, broader OS probes, guard changes or blanket subprocess permission. Runtime/release acceptance remains false.

## References

- [ADR-0504](ADR-0504-continuation-state.md): pure core remains inert and unchanged.
- DBOS architecture: https://docs.dbos.dev/architecture
- Temporal Workflow Execution: https://docs.temporal.io/workflow-execution
- Profile execution: 050-M2A-RESEARCH-PACK.md, retrieved 2026-11-04; dated source excerpts and limitations retained there.
- Profile execution: 050-ATTACHED-ONCE-ASTRA-ADVICE.md; 050-ATTACHED-ONCE-FABLE-ADVICE.md and its ADDENDUM-1; both draft addenda; 050-ATTACHED-ONCE-MAIN-SYNTHESIS.md.
- Profile execution: 050-ATTACHED-ONCE-REVIEW-1.md; 050-ATTACHED-ONCE-REVIEW-2.md; corresponding MAIN-DISPOSITIONS; 050-ATTACHED-ONCE-MAIN-V3-VERIFICATION.md; 050-ATTACHED-ONCE-CONTRACT-AMENDMENT-1.md.
