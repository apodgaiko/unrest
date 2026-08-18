# Proposed v0.3 workspace and integration contract

This contract supports unaccepted [ADR-0303](../../decisions/ADR-0303-workspace.md).
It is proposal evidence only. It does not authorize a workspace, effect,
integration, or Mission mutation and emits no receipt.

## Current v0.2 baseline

Current v0.2 mutable workers receive the canonical project checkout as their
working directory and mutate it directly. `auto_merge` does not create an
isolated candidate or parent integration step. Current single mutable selection
limits concurrency but supplies no lease, patch-return, complete cancellation,
or orphan-cleanup contract.

Current application checks and a Git worktree do not prove process, network,
credential, service, database, port, home/cache, host-filesystem, or external-
effect isolation. Every proposed rule below therefore requires future
acceptance and implementation.

## Admitted isolation tier matrix

| Tier | Guaranteed boundary | Explicit non-guarantees | Admitted work/effects | Setup and cleanup proof |
| --- | --- | --- | --- | --- |
| `WS-T0-SHARED` | No isolation; at most policy-controlled serial ownership | All filesystem, process, network, credential, service, database, port, home/cache, and effects are shared | Current-v0.2 compatibility, trusted serial maintenance, or read-only inspection; no isolation/effect claim | Record canonical root and current owner; inventory writes/processes; do not call shared state isolated |
| `WS-T1-WORKTREE` | Separate verified Git working tree and index at immutable base | Processes, network, credentials, services, databases, ports, home/cache, other host paths, and effects remain shared | Filesystem-only candidate work inside admitted paths; effects forbidden absent separate grants | Detached add, base/porcelain/root proof and lock; reconcile/retain patch, then remove/prune only after ownership settles |
| `WS-T2-SANDBOXED` | T1 plus proven process namespace, writable roots, network mode, credential-set scope, and isolated home/cache/temp | Shared services/databases/ports unless separately namespaced; no publication/promotion/integration or production authority | Mutable build/test needing bounded processes or explicitly configured network/credentials; every irreversible effect separately granted | Verify provider policy before activation; drain descendants, revoke scoped credentials, retain inventory, remove sandbox/worktree idempotently |
| `WS-T3-NAMESPACED` | T2 plus exclusive service, database, and port namespaces with lease ownership | No semantic tenant isolation beyond proven provider controls; no publication/promotion/integration/production authority; external effects are not reversible by cleanup | Integration-like tests and mutable work requiring provisioned services/data; only grant-scoped effects | Provision unique namespaces from recorded manifests; inventory/stop/drain, compensate or quarantine effects, destroy owned resources, retain receipts |

The deterministic
[tier fixture](../../../tests/fixtures/v03_decisions/workspace/isolation-tiers.v1.json)
lists every boundary independently. Admission fails when a needed guarantee is
absent, provider proof is missing, or resources cannot be partitioned. Naming a
tier, worktree, sandbox, container, or namespace is not proof.

## `WorkspaceLease.v1`

The lease is a closed identity-bound record with these required fields:

| Group | Required fields |
| --- | --- |
| Identity/authority | schema version, lease ID/digest/generation, admission decision, `workspace_lease_authority`, child writer, `parent_integration_authority`, parent run/candidate IDs |
| Lineage | immutable base revision/digest, admitted accepted-working-point digest, candidate lineage ID, provider/tier identity |
| Filesystem | canonical root, predicted writes, protected paths, allowed operations, initial-state/porcelain digest |
| Resources | process/network mode, public credential-set ID, home/cache/temp policy, service/database/port namespaces, separately authorized effect-grant refs |
| Bounds | activation/expiry metadata, use count, budget, drain duration, heartbeat/orphan threshold, cleanup and retention policy IDs |
| Return | `PatchReturn.v1` schema, required evidence, expected terminal dispositions, single-use return nonce |

All collections are closed, typed, uniquely keyed, and deterministically sorted.
Secret values/hashes, prompts, source bodies, reports, and unrelated command
output are forbidden. [Identity.v1](identity-v1.md) owns canonical bytes;
[Receipt.v1](receipt-v1.md) owns receipt integrity and freshness.

State transitions are:

```text
requested -> admitted -> allocated -> active -> returned -> integrating
                                                    |          |
                                                    |          +-> accepted|rejected|rework|stale
                                                    +-> cancelling|timed_out|crashed|orphaned

all recovery paths -> released|quarantined|cleanup_failed_attention|unsettled_effect_attention
```

`returned`, `integrating`, `cancelling`, `timed_out`, `crashed`, and `orphaned`
are not terminal. Each transition binds the current lease generation, exact
owner, reason, and retained evidence. Retry/claim creates a new attempt ID and
does not overwrite history.

## `PatchReturn.v1` and exact integration checks

The closed child return must include lease/base/admitted-working-point,
candidate, patch, artifact-manifest and return-nonce identities; exact patch
bytes reference; predicted and observed writes/resources; focused test and
policy evidence; deviations; process/service inventory; effect ledger; partial
artifact manifest; and cleanup state.

Only `parent_integration_authority`, resolved through the
[closed role catalog](authority.md#closed-authority-role-catalog), may consume
it. Before staging, it MUST possess a valid single-use
`PromotionDecisionGrant.v1` issued by `promotion_authority` and MUST record a
closed `ParentApplicationPlan.v1`. Their exact fields, canonical digest
preimages, and concrete vectors are in the
[cross-family protocol fixture](../../../tests/fixtures/v03_decisions/integration/cross-family-authority.v1.json).
The checks are conjunctive and ordered:

1. **Identity:** schema, issuer, lease ID/digest/generation, child writer,
   candidate/patch/artifact digests and nonce match exactly; canonical bytes
   recompute; the nonce and candidate were not consumed before.
2. **Base and lineage:** immutable base bytes match the lease; admitted accepted
   point matches the lease; current predecessor is exactly the integration
   decision's predecessor; a rebase/edit creates a new lease/candidate/return.
3. **Freshness:** lease, policy, provider/environment, base, predecessor,
   candidate, patch, artifacts, effect/cleanup and required test receipts all
   resolve and are fresh under [Receipt.v1](receipt-v1.md#freshness-algorithm).
4. **Writes/effects:** actual writes/resources are a subset of admitted ones;
   protected or undeclared writes fail; every attempted effect is authorized
   and receipt-bound; partial/unknown effects block integration.
5. **Conflict:** compare the exact patch read/write set with every predecessor
   change since base, then perform deterministic three-way apply/rebase
   simulation. Textual cleanliness does not override semantic protected-resource
   overlap.
6. **Pre-application authorization and plan:** verify the promotion grant's
   exact predecessor/candidate/evaluation/review/patch/lease scope, one-use and
   expiry bounds, then verify the plan binds that grant, staging point,
   compare-and-swap result, validations, ordered steps, and sole recovery owner.
7. **Staging application:** apply only to the plan's parent-owned staging point.
8. **Integrated verification:** run every plan validation against the exact
   staged candidate and persist `IntegratedValidationResult.v1`.
9. **Atomic acceptance:** compare-and-swap the expected predecessor to the
   planned result only after steps 1-8 pass; persist `AcceptedPointMutation.v1`.
10. **Post-application receipts:** after the durable mutation, append one
    `integration_receipt.v1`. `promotion_authority` may then append
    `promotion_receipt.v1`; neither receipt is consumed by steps 1-9.

No child command, merge, push, test result, evaluator recommendation,
integration/promotion receipt, disjointness claim, timestamp, or replay can
authorize the accepted-point application.
Failures retain evidence and leave it unchanged. The
[integration fixture](../../../tests/fixtures/v03_decisions/workspace/integration-scenarios.v1.json)
independently covers disjoint success, conflict, stale base, unauthorized
effect, integrated-test failure, and replay.

## External effects and partial recording

Workspace admission never grants an external effect. The exact external
authority, grant checks, and effect classes come from the
[external-effect contract](authority.md#external-effect-contract). Each attempt
is recorded before execution and settled afterward as `not_started`,
`denied`, `completed`, `partial`, `unknown`, `compensated`, `quarantined`,
`rolled_back`, or `unsettled`.

For `partial`/`unknown`/`unsettled`, retain grant reference, public subject and
resource IDs, intended operation, start/stop evidence, receipt or missing-
receipt status, bounded result, and exactly one recovery owner. Do not record
secret values/hashes or arbitrary output. Cleanup cannot promote these states
to completed or absent.

## Cancellation, orphan, cleanup, and retention

The common cancellation algorithm is persist/revoke, cooperative stop, bounded
drain, inventory, snapshot, terminate/quarantine, idempotent cleanup, and
terminal receipt/attention. The lease must contain a finite positive drain
duration; policy selects the value. At bound expiry, unknown descendants or
effects remain explicit and force quarantine/attention.

Orphan claim requires: threshold reached; durable lease not terminal; atomic
claim of exact generation; previous owner absence proven against process
identity/start data and heartbeat; root/porcelain/lock, namespace, return, and
effect state reconciled; and no competing claimant. Uncertain owner or claim
conflict fails closed. Cleanup removes only proven-owned resources, is
idempotent, and emits a receipt even for no-op/retry/failure.

Retain the lease and transitions, patch/partial artifact manifests, bounded
write/resource/process inventory, effect attempts/receipts, cancellation and
claim decisions, cleanup attempts/receipt, integration disposition, and all
error/attention references according to the lease policy. Root deletion occurs
only after evidence is durably retained. Evidence expiry/deletion is separately
receipt-bearing and never changes a terminal disposition.

The
[recovery fixture](../../../tests/fixtures/v03_decisions/workspace/recovery-scenarios.v1.json)
covers cancel before work, cancel during process/effect, worker crash,
coordinator restart, orphan lease, cleanup failure, and unresolved external
effect. Every case has one decision owner and one terminal disposition.

## Error ownership and terminal rules

| Failure | Sole decision/recovery owner | Required terminal behavior |
| --- | --- | --- |
| Admission/allocation/provider proof | `workspace_lease_authority` | rejected or cleanup attention; never active by inference |
| Child/lease cancellation or crash | `workspace_lease_authority` | released, quarantined, or explicit cleanup/effect attention |
| Orphan claim | `orphan_recovery_supervisor` | claim and reconcile, or quarantine/attention |
| Integration identity/freshness/conflict/test | `parent_integration_authority` | rejected, stale, rework, or predecessor restored-and-verified |
| Partial/unknown external effect | `external_effect_recovery_authority` | compensated, rolled back, quarantined, escalated, or unsettled attention |

No terminal rule accepts `unknown`, `partial`, `stale`, `returned`,
`cancelling`, `timed_out`, `crashed`, `orphaned`, or `cleanup_failed` as success.

## Compatibility and rollback

This proposal changes no current behavior. Future adoption replaces direct
canonical-checkout mutation with lease/return/integration semantics and is
therefore compatibility-sensitive. It must use new versioned records and must
not silently alter current Task, Envelope, MCP, or persisted schema-v1 fields.

Before acceptance, rollback is deletion/rejection of this draft slice. After
future acceptance, stop admission, cancel/drain/settle active leases, preserve
evidence, restore the last accepted current-v0.2 execution path under explicit
maintainer authority, and verify that accepted working point. External-effect
recovery remains separately owned.

## Verification obligations

1. Strictly parse all fixtures with duplicate-key rejection and verify stable
   key/record ordering.
2. Require every tier to enumerate all ten boundaries with explicit guarantee
   or non-guarantee, setup, cleanup, and admitted-work/effect policy.
3. Independently mutate each integration identity/freshness/conflict/effect/
   test/replay check and require fail-closed, unchanged accepted point.
4. Require every cancellation/recovery case to have one owner, finite drain
   when applicable, retained evidence, and one terminal disposition.
5. Resolve every relative Markdown path and anchor in this owned slice.

Passing verifies only artifact consistency. It does not prove provider
enforcement, implement behavior, accept ADR-0303, or issue a receipt.
