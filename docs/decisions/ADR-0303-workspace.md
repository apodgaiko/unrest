# ADR-0303: Govern isolated child work and parent-only integration

## Record metadata

id: ADR-0303
status: accepted
date: 2026-08-18
accepted_date: 2026-08-24
accepted_by: maintainer-v0.3.1-instruction
task_ids:
  - W-WORKSPACE-EFFECTS
contract_targets:
  - VAL-WS-001
  - VAL-WS-002
  - VAL-WS-003
  - VAL-WS-004
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - lifecycle-simulation

## Authority status

Accepted for v0.3.1 by the maintainer's explicit 2026-08-24 full-implementation
instruction. The implemented tier is T1 Git separation with parent-only
integration; it is not an OS confinement claim. Proposal-era wording below is
dated design rationale, not the current runtime-status oracle.

## Scope

- In scope: workspace isolation tiers and their non-guarantees, leases, child
  patch return, conflict and freshness checks, parent-only integration,
  external-effect authority, cancellation, drain, orphan recovery, cleanup,
  evidence retention, and terminal workspace disposition.
- Out of scope: OS/process/network/credential confinement, canonical identity
  ownership, Mission-truth authority, evaluator scoring, promotion decisions,
  and heuristic migration.

## Context

Current direct checkout mutation has no lease, patch-return, parent integration,
or complete effect-recovery boundary. A future isolation design must state what
each tier proves and must not acquire Mission, effect, or promotion authority
from its mechanism.

## Current v0.2 truth

Current v0.2 workers run in and mutate the canonical project checkout. The
runtime passes the project workspace as the child process working directory;
`auto_merge: false` is a legacy no-op and does not allocate a child workspace.
Current single mutable-work selection reduces concurrent write races, but it is
not a child-patch or parent-integration protocol.

Current callback-root, working-directory, and application capability checks do
not prove OS confinement. Current v0.2 has no `WorkspaceLease.v1`, isolated
workspace provider, patch-return receipt, orphan claimant, total live-worker
cancellation, or external-effect ledger. These are compatibility-sensitive
facts, not compliance with the proposal below.

A Git worktree alone isolates only the repository working tree and index. It
does **not** prove process, network, credential, service, database, port, home,
cache, host-filesystem, or external-effect isolation. Deleting a worktree does
not terminate processes, revoke credentials, undo a database write, or retract
a publication.

## Accepted decisions and dispositions

| Decision ID | Disposition | Rule |
| --- | --- | --- |
| WS-D01 | accepted | Admit work only at an explicit isolation tier whose guarantees, non-guarantees, resource namespaces, setup, allowed work/effects, and cleanup are lease-bound. |
| WS-D02 | accepted | Give every mutable child one writer, one immutable base, one unique `WorkspaceLease.v1`, finite authority, and a declared return contract. |
| WS-D03 | accepted | A child returns an identity-bound patch/candidate and evidence; it cannot merge, push, promote, update Mission truth, or change the accepted working point. |
| WS-D04 | accepted | Only `parent_integration_authority` may stage and integrate an exact returned candidate after identity, base, freshness, conflict, effect, and integrated-verification checks. |
| WS-D05 | accepted | External effects require separate, narrowly scoped authority and receipts; workspace admission or capability possession never supplies effect authority. |
| WS-D06 | accepted | Cancellation revokes future authority, drains for a declared bound, records partial/unknown effects, and terminates in release or durable attention; it never infers cleanup. |
| WS-D07 | accepted | Orphan claim and cleanup are identity-bound, single-owner, idempotent, evidence-retaining operations with explicit terminal dispositions. |
| WS-A01 | rejected | Treat a shared checkout, directory convention, container label, or Git worktree as full isolation. |
| WS-A02 | rejected | Let a child self-integrate because its patch is disjoint, its tests pass, its lease is recent, or its return happened later. |
| WS-A03 | rejected | Treat process exit, cancellation request, worktree removal, cleanup timeout, or missing telemetry as proof that work and effects settled. |
| WS-A04 | deferred | Select concrete sandbox/container/VM providers and enforcement technology; a later implementation decision must prove each claimed tier. |
| WS-A05 | deferred | Set universal lease, drain, orphan, and evidence-retention durations; policy must bind explicit finite values per admitted workload. |
| WS-A06 | deferred | Automate integration of nominally disjoint patches; parent authority, exact identity, and integrated verification remain mandatory first. |

## Admitted isolation tiers

The normative matrix is in the
[workspace contract](../v03/contracts/workspace.md#admitted-isolation-tier-matrix)
and the executable
[tier fixture](../../tests/fixtures/v03_decisions/workspace/isolation-tiers.v1.json).
Admission records the selected tier; it cannot claim a stronger tier from an
implementation name.

- `WS-T0-SHARED`: the canonical checkout and host resources are shared. It is
  admitted only for current-v0.2 compatibility, serial trusted maintenance, or
  read-only inspection. Mutable child work is compatibility-sensitive and no
  isolation or external-effect claim follows.
- `WS-T1-WORKTREE`: a detached verified Git worktree provides a separate
  repository working tree and index. All process/network/credential/service/
  database and host resources remain shared unless separately constrained.
- `WS-T2-SANDBOXED`: T1 plus a proven process sandbox, bounded writable roots,
  explicit network mode, scoped credential-set ID, and isolated home/cache/temp
  and process namespace. Services and databases remain shared unless separately
  namespaced; irreversible effects still need authority.
- `WS-T3-NAMESPACED`: T2 plus exclusive service/database/port namespaces and
  provisioned resource cleanup. This is the only tier admitted for mutable work
  requiring those resources, but it still grants no publication, promotion,
  integration, production, or other external-effect authority.

An admission request that needs a guarantee absent at every implemented tier is
rejected or serialized under external authority. It is never silently lowered.

## Lease, setup, and return

`WorkspaceLease.v1` binds its public lease ID and digest to the task/work owner,
parent run and candidate lineage, immutable base revision and accepted-working-
point digest, tier and provider identity, root, predicted and protected paths,
resource namespaces, allowed operations, separately referenced effect grants,
public credential-set ID, network mode, budget, expiry/use bound, drain bound,
orphan threshold, cleanup policy, return contract, and evidence-retention
policy. Exact canonical encoding belongs to
[ADR-0301](ADR-0301-identity.md); no implementation may improvise it.

Allocation verifies the base object, clean initial state, unique root and
resource ownership, provider enforcement evidence, and absence of conflicting
live leases before activating authority. Setup failure leaves no active lease;
partially allocated resources enter cleanup under the lease authority.

The child return is `PatchReturn.v1`: a closed reference to the lease, base,
accepted-working point at admission, candidate and patch identities, exact
patch/artifact manifest, predicted and observed path/resource writes, focused
test evidence, effect ledger, process/service inventory, deviations, partial
artifacts, and cleanup state. The return is evidence, not acceptance. Missing,
extra, protected, or unverifiable writes fail closed.

## Parent-only accepted-working-point integration

The child has no integration authority. `promotion_authority` first records a
closed, single-use `PromotionDecisionGrant.v1`; then
`parent_integration_authority`, resolved through [ADR-0300's closed
catalog](../v03/contracts/authority.md#closed-authority-role-catalog), records
`ParentApplicationPlan.v1` and alone runs this ordered application protocol:

1. verify the closed return, issuer/lease authority, canonical digests, exact
   lease/candidate/patch identity, single-use nonce, and absence of replay;
2. require the lease base and admitted accepted-working-point digest to equal
   their recorded objects, and require the current accepted point to equal the
   declared integration predecessor (or issue a new rebase/rework identity);
3. recompute the patch and artifact digests; reject prohibited or undeclared
   writes, unresolved processes/effects, missing receipts, and policy drift;
4. compare observed writes/resources with all changes since the immutable base,
   run deterministic three-way applicability/conflict checks, and require all
   identity and upstream receipts to be fresh under
   [Receipt.v1](../v03/contracts/receipt-v1.md#freshness-algorithm);
5. verify the grant and plan bind the exact predecessor, candidate, patch,
   lease, evaluation/review evidence, required validations, use/expiry bounds,
   staging point, atomic compare-and-swap result, and recovery owner;
6. apply only to the plan's parent-owned integration staging point, never by
   asking the child to merge or mutate the canonical checkout;
7. run the required integrated tests and policy/repository checks against the
   exact staged candidate; and
8. only after every check passes, atomically compare-and-swap the accepted
   working point and persist the exact mutation result;
9. after that durable mutation, append one `integration_receipt.v1`; only then
   may `promotion_authority` append `promotion_receipt.v1`.

The receipts in step 9 are post-application evidence. They are forbidden as
prerequisites for steps 1-8. A crash after step 8 but before receipt emission is
reconciled by `parent_integration_authority` from the exact durable transaction;
it emits the delayed integration receipt or invokes exact rollback. It does not
reapply the candidate.

Conflict, stale base, replay, unauthorized effect, missing evidence, or
integrated-test failure changes no accepted working point and produces a
retained `rejected`, `stale`, or `rework` disposition. If staging touched a
canonical surface before failure, the parent recovery owner restores the exact
predecessor and verifies it before disposition; no acceptance receipt is fresh
or retained as successful. Disjointness permits an integration attempt, not
automatic acceptance.

## Effects and partial outcomes

Workspace authority covers only the admitted local operations. Every process,
network, credential, service, database, filesystem-outside-root, publication,
promotion, or integration effect is forbidden or references a separate grant
defined by the [authority contract](../v03/contracts/authority.md#external-effect-contract).
The executor validates exact subject/scope/expiry/use count and records an
`EffectAttempt.v1` before execution plus a terminal or partial receipt after it.

A partially executed or response-unknown effect is `partial` or `unsettled`,
never absent. Its ledger retains the public grant reference, intended operation,
start/stop evidence, bounded result, affected public resource IDs, receipt or
missing-receipt status, and the one recovery owner; it excludes secrets,
prompts, source bodies, reports, and unrelated command output. Workspace
cleanup cannot close that effect. Compensation, quarantine, rollback, or typed
attention belongs to `external_effect_recovery_authority`.

## Cancellation, drain, orphan claim, and cleanup

Cancellation and timeout follow one fail-closed sequence:

1. the lease authority durably records reason/time metadata and revokes new
   child jobs, tools, credentials, and effect attempts;
2. it requests cooperative stop, then waits no longer than the lease-bound
   drain duration;
3. it inventories child/descendant processes, handles, namespaces, writes,
   artifacts, receipts, and effects, marking each settled, partial, or unknown;
4. it snapshots permitted partial artifacts and the effect ledger under the
   retention policy, then terminates/quarantines within provider authority;
5. it cleans idempotently only resources whose ownership is proven; and
6. it emits a cleanup receipt and `released`, or persists `cleanup_failed`/
   `unsettled_effect` attention with the workspace quarantined.

A crash or coordinator restart does not itself create an orphan. After the
lease heartbeat/expiry threshold, one supervisor with orphan-claim authority
atomically claims the exact lease generation after proving the prior owner is
absent and comparing durable lease state, process identity/start data,
worktree inventory/lock reason, namespaces, return receipts, and effects. A
claim conflict or uncertain live owner quarantines and raises attention. A
successful claimant resumes the same bounded inventory/cleanup protocol;
cleanup retries get new attempt IDs and never overwrite earlier evidence.

Terminal workspace dispositions are `released`, `rejected`, `rework`,
`stale`, `cancelled_released`, `crashed_released`, `orphan_released`,
`quarantined`, `cleanup_failed_attention`, or
`unsettled_effect_attention`. `cancelling`, `timed_out`, `crashed`, `orphaned`,
and `returned` are non-terminal. Evidence named by retention policy survives
root removal and terminal disposition; deletion or expiry needs its own
receipt and never rewrites history.

## Preconditions, errors, compatibility, and rollback

- Authority: lease admission/claim/cleanup, parent integration, and each
  external effect have separately named owners; capability possession is not
  authority.
- Identity/freshness: [ADR-0301](ADR-0301-identity.md),
  [Identity.v1](../v03/contracts/identity-v1.md), and
  [Receipt.v1](../v03/contracts/receipt-v1.md) own encoding and freshness.
- Error owner: lease/provider failures belong to `workspace_lease_authority`;
  integration failures to `parent_integration_authority`; partial effects to
  `external_effect_recovery_authority`. Ambiguity becomes typed
  attention.
- Compatibility: none today. v0.2 continues to mutate the canonical checkout;
  adopting this proposal is a compatibility-sensitive future change requiring
  versioned interfaces and implementation gates.
- Rollback before acceptance: delete or reject only this new draft and its
  supporting contract/fixtures. After future acceptance, disable new lease
  admission, drain/settle existing leases, preserve receipts, revert to the
  last accepted current-v0.2 path under explicit maintainer authority, and
  validate it. External effects retain separate recovery obligations.

## Alternatives considered

- WS-A01 is rejected because filesystem separation is not authority or complete
  confinement; a worktree is useful plumbing, not a force field.
- WS-A02 is rejected because branch-local success cannot establish freshness,
  conflict freedom, integrated correctness, or acceptance authority.
- WS-A03 is rejected because absence of an observation is not evidence of
  termination or reversal.
- WS-A04 through WS-A06 remain deferred because the proposal fixes semantic
  guarantees without pretending a provider, duration, or automation policy has
  already been selected and proven.

## Consequences

- Positive: child mutation is bounded and parent integration is attributable,
  exact, conflict-aware, and replay-resistant.
- Positive: cancellation and orphan paths retain partial effects instead of
  laundering uncertainty through cleanup.
- Negative/cost: stronger tiers require provider evidence, resource
  provisioning, reconciliation, receipts, and retained quarantine capacity.
- Compatibility/hard cut: replacing direct canonical-checkout mutation changes
  worker execution and handoff semantics and needs a future migration gate.
- Schema/migration impact: new `WorkspaceLease.v1`, `PatchReturn.v1`, effect,
  integration, and cleanup records; no current schema-v1 record changes here.
- Security/privacy impact: public IDs and bounded evidence only; no secret
  values/hashes, prompts, source bodies, reports, or unrelated output.

## Open questions

- `WS-Q01` / `WS-A04`: which sandbox, container, or VM providers can prove the
  admitted isolation tiers.
- `WS-Q02` / `WS-A05`: which lease, drain, orphan, cleanup, and retention bounds
  apply per workload policy.
- `WS-Q03` / `WS-A06`: whether any disjoint-patch integration can be automated
  without weakening parent authority or integrated verification.

All three remain deferred. Their relationship to authority, identity, and
compatibility is recorded in the
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory).

## Review

- Reviewer: none; downstream maintainer review required.
- Approval date/evidence: 2026-08-24 maintainer full-implementation instruction,
  accepted decision index, T1 workspace runtime, and validation contract.
- Evaluation evidence: focused deterministic fixture/link checks only; these do
  not prove a runtime provider or accept the decision.

## Rollback

- Trigger: rejection, unresolved provider proof, incompatible authority or
  identity decision, or failed downstream integration.
- Procedure: disable the additive workspace runtime while retaining this
  accepted decision, its evidence, and any already-issued receipts.
- Data recovery: retain workspace and integration records according to policy.
- Verification: confirm current v0.2 sources and accepted indexes are unchanged.

## Implementation and verification

- Components/paths: workspace provider and parent integration
  boundary; this task changes documentation and fixtures only.
- Canonical documents: this ADR, the
  [workspace contract](../v03/contracts/workspace.md), and its three fixtures.
- Tests/evidence: strict JSON parsing, deterministic ordering, semantic fixture
  assertions, relative-link/anchor resolution, and focused repository checks.

## References

- [ADR-0300 authority proposal](ADR-0300-authority.md)
- [ADR-0301 identity proposal](ADR-0301-identity.md)
- [Current accepted ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Proposed workspace contract](../v03/contracts/workspace.md)
- [Current runtime architecture](../v5/07-runtime-architecture.md)
- [Current task-list product contract](../../specs/task_list/PRODUCT.md)
