# ADR-0502: Isolate incomplete admission and preserve durable key binding

## Record metadata

id: ADR-0502
status: accepted
date: 2026-11-03
task_ids:
  - ADM-R
contract_targets:
  - VAL-ADM-01-21
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone

## Scope

- In scope: RunControl admission preflight, durable idempotency claims, scoped recovery, stage-specific I/O errors and the existing frozen error envelope.
- Out of scope: continuation runtime wiring, supervisor, automatic repair of incomplete admission, cleanup, new launch authority, operator disposition, provider execution and release publication.

## Context

On base 825c944, a request published before its first queued event blocks later
controller operations, including after an injected live ENOSPC. Failure to write
the idempotency index after queued permits another admitted run to reuse the key.
Independent in-process Darwin probes reproduced both defects. These are not real
crash, Linux, power-loss or concurrent-controller results. Public-practice research
retrieved primary documentation but breadth search was PARTIAL (4/20 queries);
architectural conclusions remain provisional with that limitation.

## Decision

1. The first valid queued event is the admission commit fact. A request without
   events is a held, uncommitted claim, not permission to append queued on retry.
   Recognizable incomplete admissions are isolated; contradictory or corrupt
   records remain fail-closed. Keep cancel_run on empty streams as not_found.
2. Under the existing admission lock, classify all retained claims before repair
   or dispatch, including terminal and live-cursor runs. Read raw stored fields
   for strict legacy-compatible identity validation; confirm suspicious event
   streams under the run lock. Do not call the project inspector in preflight.
3. Multiple claims for a key quarantine the whole key; an index chooses no winner.
   Hold every member resource, including terminal members, while quarantined.
   Exact committed retry returns the original admission receipt without writes
   or launch. No expiry, key rebind, roll-forward or automatic tombstone exists.
4. Treat the idempotency index as a projection. Only recover may create a missing
   index for a uniquely committed claim, with baseline bytes and create-only
   publication. Never overwrite a conflicting record. Submit dedupe is read-only.
5. Preserve admission-to-run lock order. Recover uses one preflight snapshot,
   then sorted index repair and per-run actions. Quarantine prevents dispatch,
   not permitted STOP-A1 non-dispatch reconciliation in a non-halted pass.
6. This ADR adds a narrow exception to ADR-0500 reconciliation ordering: an
   attributable Phase B repair write OSError or repair conflict, or a Phase C
   action OSError caught inside its run lock, halts all remaining repair and run
   actions in that invocation, including STOP receipt adoption, settle and
   finalize. Preserve completed progress and report halted work; a later pass
   may reconcile it. No atomic recovery or unconditional STOP progress is claimed.
   Lock-acquisition errors and other baseline escaping exceptions remain so.
7. Submit I/O errors are stage-specific: before invoking queued publication,
   admission_io_not_committed; any OSError after entering queued publication,
   admission_io_unknown; index OSError after queued helper returns normally,
   admission_committed_io_error. No read-back downgrade, rollback or automatic
   retry follows. Preserve baseline spawn/error behavior outside these stages.
8. Keep the frozen public error enum. Explicitly map all six new admission
   exception codes; recovery-only report codes are not wire codes. Own error
   messages and chains must not expose paths, arguments, keys or errno. Coarse
   wire mapping is not operator visibility.
9. Permit new admission into an absent run directory, an empty real directory,
   or one containing only regular non-symlink .run-* staging files. Preserve
   their bytes; perform no cleanup. Reject foreign entries and symlinks before
   writes. This preserves retry after a pre-link request publication failure.
10. No activation acceptance follows from implementation: operator visibility,
    an owner and manual-disposition runbook, legacy byte corpus, cold activation,
    concurrency, Linux and real process-crash evidence remain separate gates.
    No user data migration, power-loss guarantee or live mixed-version claim.

## Alternatives considered

- Exact-retry roll-forward of incomplete admission: rejected; it completes an
  unresolved durable claim and potentially launches work rather than isolating it.
- Index-selected winner for duplicate claims: rejected; a projection cannot erase
  contradictory durable claims.
- Release terminal-member resources during quarantine: Fable's availability
  alternative; rejected in favor of conservative all-member retention. Manual
  disposition and visibility remain activation blockers.
- Tombstones, cleanup, SQLite or a new transaction namespace: deferred; larger
  migration and authority changes than this compatibility slice requires.
- Read-back classification after queued write failure: rejected; absence observed
  through a glob does not prove that publication did not commit.

## Consequences

- Positive: torn admission no longer poisons unrelated healthy recovery; key reuse cannot silently bypass retained claims.
- Negative/cost: full preflight costs retained request/event/index scanning; indefinite holds and deferred STOP progress can reduce availability.
- Compatibility/hard cut: exact retry is no longer index-fast and does not inspect project/result data; corrupt preflight blocks before recovery actions. Cold activation requires quiescence.
- Schema/migration impact: preserve healthy v0.4.7 request/event/index bytes; no rewriting, cleanup or new persistence schema.
- Security/privacy impact: no new execution or signal authority; operator visibility is explicitly not provided by the existing coarse envelope.

## Review

- Reviewer: main integrator after independent Astra/Fable advice and two bounded independent contract reviews.
- Approval date/evidence: 2026-11-03; profile execution 050-ADM-CONTRACT-V3.md, sha256 5ba5ab975fc49ef2e9cc664edce906b4f8de7cfb050703516089b5a2d742148c. Main checked the V2-to-V3 diff against R1-R8/O1 of 050-ADM-CONTRACT-REVIEW-2.md; no third review required.
- Evaluation evidence: accepted for implementation only, with research PARTIAL. No architecture-completeness, runtime, Linux, real-crash, concurrency or release PASS.

## Rollback

- Trigger: contract violation or failed independent validation.
- Procedure: revert the implementation and affected documentation together while quiescent; do not automatically alter retained run trees.
- Data recovery: preserve incomplete claims, quarantine and uncertain writes for a separately authorized manual procedure; reverting code does not repair them.
- Verification: focused admission and STOP regressions plus independent scrutiny; no inferred live acceptance.

## Implementation and verification

- Components/paths: src/unrest_harness/run_control.py, src/unrest_harness/foundation_tools.py, tests/test_run_admission_recovery.py.
- Canonical documents: docs/v5/07-runtime-architecture.md; ADR-0500 remains in force except for Decision 6 above.
- Tests/evidence: VAL-ADM-01-21 and mutation crosswalk; hermetic focused tier and separately audited read-only git tier. Process-launching tier, full suite, CI and distribution are not authorized by this decision. Legacy v0.4.7 corpus must have isolated baseline provenance before its acceptance claim.

## References

- ADR-0500; ADR-0501 remains inert and unchanged.
- Profile execution: 050-ADM-SYNTHESIS.md; 050-ADM-CONTRACT-REVIEW-1.md; 050-ADM-CONTRACT-REVIEW-2.md; 050-ADM-V2-MAIN-DISPOSITIONS.md.
- Profile execution: 050-ADM-REPRO.md; 050-ADM-REPRO-RECHECK.md; 050-adm-research/PACK.md (research PARTIAL).
