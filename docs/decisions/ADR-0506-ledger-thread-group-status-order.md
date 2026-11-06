# ADR-0506: Admit bounded reordered thread group status in the release-guard ledger

## Record metadata

id: ADR-0506
status: accepted
date: 2026-11-06
task_ids:
  - LEDGER-ORDER-V1N
contract_targets:
  - VAL-LO-01-15
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone

## Scope

- In scope: the release-guard process ledger admission of a non-leader thread terminal observed before its group leader's exit stop, for canonical normal statuses with an observed own exit stop and for the existing exact SIGKILL status; membership exec epoch; eager status agreement; refusal of late own exit and of leader exec while an observed obligation is unresolved; admission of a thread child only under a leader normalized parent; ledger-owned settlement predicates used by retirement, case completion and final source completion; the measured enforcement ceiling.
- Out of scope: tracer harvest or ptrace changes, PTRACE_GETEVENTMSG former-TID capture, other signal or core statuses, all-Birth terminal completeness, support or refusal of non-leader exec (de_thread), new root admission rules, atomicity of pre-existing ledger refusals, launch authority, schemas, persistence and CI.

## Context

Release-source CI run 41988665971 refused one reordered observation: a thread
with own exit 0 was reaped with status 256 before its leader's exit stop was
observed. The same facts in the opposite order were accepted. The reducer
already accepted this order only for exact SIGKILL. Kernel and man-page sources
show no ordering guarantee between a thread's reap and its leader's exit stop.
The root cause of that run is not established; this decision makes the outcome
independent of the observation order for the selected family only.

## Decision

1. Admit a group-dependent thread terminal before the exact leader exit only for
   canonical normal statuses with an actually observed earlier own exit stop, or
   exact status 9 with or without an own exit stop.
2. Require the thread's membership epoch to equal the leader's current exec
   generation for every such admission, including status 9. This is a normative
   change for status 9: an obligation is never reconciled against another exec
   generation.
3. Refuse a second received group-dependent terminal with a different status.
4. Reconcile received obligations at the actual leader exit; refuse a mismatch
   before recording the exit. Missing member terminals are not required there.
5. Refuse an own exit reported after the same task's terminal, and refuse a
   leader exec while an observed obligation is unresolved.
6. Keep the existing post-exit join without an epoch check. This is a bounded
   scope choice that differs from the architecture advice; it is not certified
   cross-generation attribution.
7. Admit a thread child only when the creator's normalized thread-group parent
   is a group leader. This is an admission tightening; it is not a non-leader
   exec policy and its runtime compatibility with de_thread is unknown.
8. Retirement requires no unresolved obligation in the retiring leader's group.
   Case completion first requires that no case actor has an unresolved own
   obligation, then that no member of a group led by a case actor has one; when
   both fail, the actor refusal is reported. Obligations of the root's and other
   groups are checked only at final source completion, which fails the whole run
   after the case has been recorded.
9. Synthesize no exit, terminal or parent wait; failure cleanup never settles.
   Every refusal introduced by this decision, and every refusal exercised by the
   contract's oracle and negative-control prefixes, leaves the ledger state and
   kernel sequence unchanged. No claim is made for other pre-existing refusals.

## Alternatives considered

- Keep the current refusal: rejects a kernel-permitted order on facts that are accepted in the other order.
- Admit every validated status (any signal): broader than the evidence.
- Defer reaping in the tracer: changes the trusted tracer and cannot force a stop that may never occur.
- Require a terminal for every thread Birth: introduces a de_thread compatibility policy that is not established.
- Document the actor's own obligation as a limitation caught only at final completion instead of checking it at case completion: advisory dissent, not selected.
- Refuse registration of non-leader actors: a non-leader exec policy outside this scope.

## Consequences

- Positive: one additional reordered family is accepted with an explicit obligation that only the same leader Birth's actual exit can settle.
- Negative/cost: status-9 handling across an exec generation is refused earlier, and refused instead of accepted when the new image also ends with status 9. A thread child under a non-leader normalized parent is now refused. A leader that exits with one status before another thread starts a group exit with a different status is refused in both observation orders. Enforcement grows by 39 measured lines.
- Compatibility/hard cut: settlement checks are defence in depth; their redundancy on current-tracer traces holds only for named domains and premises in the contract, not unconditionally. Completed cases in a failed source result are not evidence of case closure.
- Schema/migration impact: none; no persisted schema changes.
- Security/privacy impact: tighter refusals only; no new authority, launch or data exposure.

## Review

- Reviewer: maintainer authorization of the bounded protected repair and measured ceiling, after independent Astra/Fable consultation and two independent contract reviews.
- Approval date/evidence: 2026-11-05/06; profile execution 050-LEDGER-ORDER-CONTRACT-V3.md, sha256 cc80319ba04c8f21da97d9c00240629e61b257a57e61af96977176e10eb37f3f, plus 050-LEDGER-ORDER-CONTRACT-AMENDMENT-1.md and 050-LEDGER-ORDER-IMPLEMENTATION-AUTHORIZATION.md.
- Evaluation evidence: focused in-process tests only; mutation, Linux-native and CI evidence are not part of this record. Implementation acceptance, runtime and release acceptance remain false until independent verification.

## Rollback

- Trigger: contract violation, a refusal on a kernel-permitted order inside the accepted family, or independent validation failure.
- Procedure: revert the ledger, observer, host, test, ceiling and documentation changes together; preserve or explicitly supersede this ADR.
- Data recovery: none; historical evidence and the failed run remain unchanged.
- Verification: focused ledger and source-integration tests, size budget at the previous ceiling, repository and documentation contracts.

## Implementation and verification

- Components/paths: .github/release-guard/process_ledger.py, source_observer.py, source_host.py, size_budget.py, test_process_ledger.py, test_source_integration.py.
- Canonical documents: docs/architecture/release-guard-integration.md; this index entry.
- Tests/evidence: VAL-LO-01-15, including a 984-variant ledger-API linear-extension oracle with per-variant kernel plausibility labels and atomicity checks. Ledger-API and synthetic tests are not kernel trace evidence. Mutation classification is fixed before any mutation run; Linux-native and CI runs need separate authorization.

## References

- docs/architecture/release-guard-integration.md
- ptrace(2), wait(2) (man-pages 6.19, retrieved 2026-11-05)
- Linux kernel/exit.c and fs/exec.c (v6.8 and master, retrieved 2026-11-05)
- Profile execution: 050-LEDGER-ORDER-CONTRACT-REVIEW-1.md; 050-LEDGER-ORDER-CONTRACT-REVIEW-2.md; 050-MAIN-LEDGER-V3-VERIFICATION.md; Astra and Fable advice and addenda.
