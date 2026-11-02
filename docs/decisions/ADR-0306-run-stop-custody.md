# ADR-0306: Bound manual run cancellation and pending terminal receipt recovery

## Record metadata

id: ADR-0306
status: accepted
date: 2026-11-03
task_ids:
  - STOP-A1
contract_targets:
  - VAL-050-STOP-A01-A22
  - VAL-050-STOP-R1-R7
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone
  - guarded-ci

## Scope

- In scope: RunControl manual cancellation, stop accounting, pending terminal receipt reconciliation, focused regression tests and runtime architecture documentation.
- Out of scope: autonomous signalling, supervisor, host delivery, stronger process identity, admission-recovery corruption (G12), legacy duplicate receipt migration, services and release publication.

## Context

The v0.4.7 base b307cc6 records a cancel request before signalling but can repeat
SIGTERM under a new idempotency key. A controller crash can leave a terminal
receipt without its referencing event; constructing a different receipt on the
same prefix can violate receipt ID uniqueness. Recovery also has ambiguous
cancel/draining branches. No cleanup or external effect proof follows from a
controller terminal state.

## Decision

1. Extend the existing RunControl cancellation authority; do not add a second
   stop engine, killpg or controller escalation to SIGKILL.
2. Under the existing per-run lock, publish a create-only attempt before the
   SIGTERM syscall. Every existing attempt, across all idempotency keys,
   suppresses further signals for that immutable running binding. A missing
   delivery record means ambiguous, never permission to resend. Publication or
   validation errors do not fall through to a signal. No delivery guarantee is made.
3. The supported fault model is process crash only. Machine crash, power loss,
   tree rollback and live mixed-version deployment are excluded. Cold activation
   requires quiescence and an intact shared lock namespace.
4. Preserve the PID/session/cursor predicate only for manual compatibility.
   It is not positive process identity and remains vulnerable to PID reuse and
   check-to-signal races. No autonomous successor may rely on this exception.
5. A recorded EPERM requires independent death proof before controller/recovery
   settlement, including draining branches. Cursor mismatch and getsid errors
   are not death proof. A delivered EPERM publication failure remains ambiguous;
   that loss of precision is an explicit compatibility limitation.
6. Reconcile pending terminal receipts only at W1 (finalize), W2 (settle), W3
   (cancel convergence), W4 (recovery after failed reattach). Consider exactly
   four receipt candidates on the current prefix. One valid candidate is adopted
   by digest, custody repaired, then terminal event appended; conflicts are
   typed errors. Bound-owner validation precedes adoption on owner stop paths.
7. Progress writers remain unfenced. Evidence written before reconciliation is
   preserved; superseded receipts may remain unreferenced. A terminal run event
   is the sole authoritative receipt reference. No consumer may infer outcome
   by enumerating receipt files or custody. Receipt constructor/catalog stay
   unchanged; literal-input golden digests bind compatibility to b307cc6.
8. Validate transitions before publishing a receipt. Invalid transitions retain
   invalid_transition; a missing required settlement class is internal_error.
   New typed recovery conflicts isolate that run in recovery_blocked, without
   inventing a terminal outcome or masking unrelated legacy errors.
9. StopStatus is read-only. Only never_dispatched gives replay_clearance=clear;
   all other settlements are unresolved, including owner-reported completion.
   Controller settlement is not proof of drain, cleanup or product effect.
10. Terminal cancel returns the existing summary before custody validation;
    inspect_stop reports invalid marked terminal custody as integrity_error.
    This D6 choice deliberately rejects validation-before-terminal-return.
    Legacy-only terminal prefixes without a class are legacy_unclassified.
11. Preserve admission -> run -> local-worker lock ordering. No nested run-lock
    acquisition, wait, project inspection or resource lock in stop convergence.
    Settle/finalize use event snapshots refreshed after their own writes.

## Alternatives considered

- Resend after an ambiguous attempt: rejected because a second TERM can interrupt cleanup.
- Fence every lifecycle writer behind a pending receipt: rejected because progress evidence written before reconciliation must survive.
- Move the W5 stop runtime or strengthen identity in the same slice: deferred to keep one mutation authority and bounded compatibility scope.
- Power-loss durability: deferred; it requires additional directory-publication barriers and a different validation floor.

## Consequences

- Positive: bounded signalling and explicit uncertainty, with deterministic receipt recovery.
- Negative/cost: an ambiguous live run may remain non-terminal indefinitely; an attempt may be consumed without sending a signal.
- Compatibility/hard cut: cold activation only; manual settlement with a missing cursor remains owner_unproven, not proof that work has stopped.
- Schema/migration impact: additive stop records and event details; no legacy rewrite, no receipt constructor/catalog change.
- Security/privacy impact: no added authority, host calls, credentials or external data transfer. Stop path validation is fail-closed but not isolation from active filesystem replacement.

## Review

- Approval: accepted implementation direction under the delegated 0.5.0 continuation, 2026-11-03; not a claim of runtime acceptance.
- Contract review: V3 required E1-E13; V4 was checked against each correction, with removal of the already-decided Q2 provisional label accepted as editorial only.
- Evaluation evidence: design review only at acceptance; implementation tests, independent scrutiny and caller-surface validation remain outstanding.

## Rollback

- Trigger: failed slice validation or unsafe activation prerequisites.
- Procedure: do not activate the new runtime; revert source changes only in an isolated, quiescent checkout.
- Data recovery: no online downgrade with in-flight stop records is certified; preserve durable evidence. No automatic deletion or migration.
- Verification: old controllers/workers absent before activation, focused lifecycle and receipt checks passing, release gates independently satisfied.

## Implementation and verification

- Components/paths: src/unrest_harness/run_control.py, tests/test_run_stop_custody.py, tests/test_run_receipt_golden.py.
- Canonical documents: docs/v5/07-runtime-architecture.md; this decision.
- Tests/evidence: stop VAL A01-A22 and R1-R7 (the contract intentionally has no A16/A21); negative controls against b307cc6; unchanged pinned tests; focused suite, ruff, mypy and check-repository.
- CI REGISTERED case, Linux CI, full unexcluded frozen-candidate suite and cold activation remain release gates, not implementation prerequisites.

## References

- Base: b307cc619cc0 (v0.4.7); prerequisite commits 626369c and f6a4ab2.
- Local engineering evidence: execution/050-STOP-SLICE-CONTRACT-V4.md and execution/050-STOP-CONTRACT-REVIEW-3.md in the release execution dossier. V4 SHA256 is recorded in execution/050-STOP-V4-MAIN-VERIFICATION.json.
- Public-practice evidence: Python 3.13 asyncio task cancellation documentation; systemd.kill documentation; Temporal retry policies; OpenAI Codex app-server documentation. Retrieved source pack: execution/050-research/PACK.md. These describe practice, not runtime proof.
