# ADR-0501: Bound inert recovery reservation accounting and snapshot custody

## Record metadata

id: ADR-0501
status: accepted
date: 2026-11-03
task_ids:
  - S2b-LR
contract_targets:
  - S2BR01-S2BR18
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone
  - guarded-ci

## Scope

- In scope: an inert recovery reservation ledger, its closed canonical snapshot, cooperative single-writer custody, bounded reader and focused evidence.
- Out of scope: execution permission, acquisition of cost or clocks, runtime wiring, delivery/outbox, reset, migration, automatic cleanup, anti-copy authority and publication.

## Context

S2a supplies inert value types but no continuation custody. Recovery accounting
must preserve outstanding reservations and supplied actual observations without
pretending that a local reservation grants execution or replay authority.
Independent Astra and Fable advice considered replace-snapshot, immutable facts,
existing journal reuse and SQLite against dated public filesystem documentation.
Two bounded contract reviews resolved accounting, publication and error precedence.

## Decision

1. Implement one inert `continuation_reservations.py` leaf. No runtime importer or
   effects are introduced. Its canonical specification carries the exact closed
   API, schema, error ordering and S2BR01-S2BR18 requirements.
2. Use a bounded canonical replace-snapshot ledger under
   `.unrest/continuation/recovery-reservations-v1/<mission_id>/`, with at most
   256 operations and a 2 MiB reader bound. Encode full nonnegative int64 resource
   dimensions as decimal strings over unchanged canonical JSON foundations.
3. Reserve attempts, recoveries, wall_ms and cost_units atomically across mission,
   lineage and supplied causal scopes. Used includes actual exactly once;
   reserved includes outstanding reservations; overrun is diagnostic only.
   Unknown observations retain reservation. Exact retries do not debit twice.
4. Actual accumulation overflow durably enters mission-wide `accounting_blocked`.
   Block new reservations while retaining late observations of admitted work;
   never clamp, silently drop evidence or reset the ledger.
5. Use stable `writer.lock`, nonblocking flock, PID/session locking and inode,
   epoch and snapshot revalidation. Child close never issues LOCK_UN. Closed and
   poisoned checks occur under the session lock after the PID guard.
6. Publish by exclusive staging creation, write and file fsync, rename, then
   directory fsync. Init additionally syncs created ancestors. K3/K4 uncertainty
   is `publication_unknown`; refuse rather than infer rollback or retry effects.
7. Detect partial init and orphan staging with bounded refusal, not automatic
   cleanup or a claim of recovered writer liveness. Missing required names
   outrank extra names. No retained history or chain-verification claim exists.
8. Guarantees apply only to one supplied physical namespace and truthful caller
   inputs. Copy/restore, semantic identity, remote filesystems and hostile same-uid
   activity are outside this slice. STATE-003 remains PARTIAL/OPEN and STATE-004
   remains OPEN. Linux, real fork and process-crash evidence remain OPEN;
   injection and same-process probes must be labelled as such. No power-loss claim.

## Alternatives considered

- SQLite: transaction machinery is useful but adds a second persistence stack
  before runtime integration justifies it.
- Immutable facts/history: stronger historical audit at the cost of compaction,
  growth and additional publication boundaries.
- Existing mutation journal: risks conflating continuation reservations with
  execution authority and unrelated lifecycle semantics.
- Count-only budget or overflow refusal alone: insufficient resource accounting
  or loss of durable late receipt evidence.
- Per-key quarantine: less conservative than mission-wide accounting_blocked;
  Fable's advisory alternative is not selected.

## Consequences

- Positive: bounded, inspectable accounting with explicit publication uncertainty.
- Negative/cost: no automatic cleanup; a crash-left namespace can lose writer
  liveness until a separately authorized operator procedure.
- Compatibility/hard cut: no existing runtime behavior or foundation is changed.
- Schema/migration impact: new isolated v1 namespace; no legacy import or reset.
- Security/privacy impact: no approval authority; closed error codes and bounded
  data exposure, not suppression of caller-owned exception context.

## Review

- Reviewer: main integrator after independent Astra/Fable architecture advice and
  two independent bounded contract reviews.
- Approval date/evidence: 2026-11-03; profile execution artifacts
  `050-S2B-CONTRACT-V3.md` (sha256
  `f610becc87783a3d6d704ec8e1c84194632fda244ae9bc39c7ba9f801eabe6c9`),
  `050-S2B-CONTRACT-REVIEW-1.md`, `050-S2B-CONTRACT-REVIEW-2.md`, and
  `050-S2B-MAIN-VERIFICATION.json`. R1-R6 and O1/O2 verified by main.
- Evaluation evidence: design accepted for implementation only. Runtime,
  distribution, Linux, real-fork and real-process-crash acceptance is unverified.

## Rollback

- Trigger: contract violation or failed independent implementation validation.
- Procedure: revert the inert implementation and its documentation together;
  do not automatically remove or alter ledger data.
- Data recovery: preserve snapshots and uncertainty; no repair/reset procedure is
  authorized by this ADR.
- Verification: focused documentation and reservation-contract tests, then the
  independently reviewed milestone gate. No inferred production acceptance.

## Implementation and verification

- Components/paths: COMP-CONTINUATION; planned
  `src/unrest_harness/continuation_reservations.py` and
  `tests/test_continuation_reservations.py`.
- Canonical documents: planned `docs/architecture/continuation-reservations.md`.
- Tests/evidence: S2BR01-S2BR18, M01-M51 crosswalk, independent scrutiny and
  evidence audit; real Linux/fork/crash evidence separately OPEN.

## References

- ADR-0500 and the existing continuation-types specification remain unchanged.
- Profile execution `050-S2B-SYNTHESIS.md`, `050-s2b-research/PACK.md`,
  `050-S2B-CAPACITY-PROBE.md` and `050-S2B-CAPACITY-MAIN-DECISIONS.md`.
