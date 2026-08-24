# ADR-0300: Bound v0.3 authority to the preserved Mission kernel

## Record metadata

id: ADR-0300
status: accepted
date: 2026-08-18
accepted_date: 2026-08-24
accepted_by: maintainer-v0.3.1-instruction
task_ids:
  - W-AUTH-INQUIRY
contract_targets:
  - VAL-AUTH-001
  - VAL-AUTH-002
  - VAL-FND-001
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - adversarial-authority-review

## Authority status

Accepted for v0.3.1 by the maintainer's explicit 2026-08-24 instruction to
implement FM-000 fully rather than ship proposal-only policy. The accepted
[decision index](index.md), runtime implementation, v0.3.1 contract, and
validation evidence are the integration record. Proposal-era wording below is
retained as dated design rationale; it is not the current runtime-status oracle.

## Scope

- In scope: Mission-truth mutation, adjacent-plane reverse edges, the retained
  Mission kernel, external effects, cancellation and recovery ownership, and
  the authority requirements that future v0.3 decisions must satisfy.
- Out of scope: family-owned identity encoding, OS-level workspace confinement,
  automated promotion/canary authority, heuristic migration, or a second
  Mission coordinator.

## Context

Six proposal families need one explicit authority spine without turning their
specialized lifecycle, identity, integration, evaluation, or compatibility
rules into competing Mission mutation paths. The current kernel and its known
cancellation/effect limits are therefore the baseline for this proposal.

## Current v0.2 truth

At product object `96d5c0f0b240bd3373809546d7aecc1e407f837b`,
[ADR-0002](ADR-0002-lean-core-v0.2.md) and the canonical
[architecture index](../architecture/index.md) govern. Every controller call
reconstructs Mission truth from disk. `ProjectController` is the public
mutation boundary; one `MissionCoordinator.step()` exposes at most one state
transition; and `ProjectStore` owns normal persistence. Work is selected singly
in the shared checkout, validator-only lanes may batch, and gates consume
persisted independent validator handoffs fail-closed.

Current `abort_project` seals available durable Mission evidence and marks the
project aborted. It is not a cooperative live-worker cancellation protocol:
task-list `cancel` only rewrites pending or failed graph nodes, terminal-review
teardown is not worker cancellation, and the current runtime has no total
process/effect drain or orphan-claim lifecycle. Current callback-root and
working-directory checks are application authority checks, not an OS sandbox;
there is no network-denial guarantee.

Current v0.2 has no Inquiry, isolated workspace lease, evaluator/promotion
service, or evolution campaign. Nothing below describes current behavior.

## Accepted v0.3 decisions and dispositions

Each row is independently reviewable. `accepted` rows are operative in v0.3.1;
rejected and deferred rows retain their original disposition.

| Decision ID | Disposition | Rule |
| --- | --- | --- |
| AUTH-D01 | accepted | Preserve one Mission mutation path: an explicit external actor decision enters through `ProjectController`, is applied by the single `MissionCoordinator`, and is persisted by `ProjectStore`. |
| AUTH-D02 | accepted | Adjacent Inquiry, execution, evidence, telemetry, adapter, evaluator, and evolution planes return typed requests, artifacts, patches, evidence, or recommendations only; none writes Mission truth or the accepted working point. |
| AUTH-D03 | accepted | Capability possession never authorizes an irreversible effect. Each such effect is forbidden or requires a narrowly scoped external authority grant and a retained receipt. |
| AUTH-D04 | accepted | Every cancellation and recovery route has exactly one decision owner, a bounded action, retained evidence, and a terminal disposition; unsettled effects produce attention rather than inferred cleanup. |
| AUTH-D05 | accepted | Any future kernel change requires a separately accepted ADR plus canonical specification, compatibility, recovery, fixture, real-surface, and rollback updates. |
| AUTH-A01 | rejected | Treat worker prose, skill instructions, successful tests, evidence, evaluator scores, telemetry, timestamps, or chronology as Mission mutation or acceptance authority. |
| AUTH-A02 | rejected | Add a second Mission coordinator, let an adjacent store shadow canonical Mission truth, or let an evaluator self-promote. |
| AUTH-A03 | rejected | Treat task-list graph cancellation, terminal-review teardown, worktree deletion, or process exit as proof of total cancellation or effect reversal. |
| AUTH-A04 | deferred | Automate low-risk promotion or canary authority. A later decision must define identity, freshness, quorum, stop, rollback, and effect boundaries first. |
| AUTH-A05 | deferred | General durable workflow ownership. A bounded adapter may later be evaluated, but its history cannot become Mission truth. |

## Proposed authority graph

The graph has one-way subordinate edges. An arrow means “may submit to,” not
“may mutate the target.”

```text
external actor / maintainer
  | explicit lifecycle, integration, effect, promotion, rollback decision
  v
ProjectController -> single MissionCoordinator -> ProjectStore -> Mission truth
       ^                      ^
       | typed request        | typed evidence or recommendation
Inquiry controller        workspace / adapter / evaluator / evolution
       |                                      |
       +---------- immutable artifacts -------+
                              |
                              v
                  evidence / telemetry projection
```

The Inquiry controller is a controller for its separate `Inquiry.v1` store; it
is not a Mission coordinator. A future `parent_integration_authority` may apply
an exact, verified child return only after `promotion_authority` records the
pre-application decision/grant and the parent records a closed application
plan. The parent stages, applies, validates, and atomically changes the accepted
point; only afterward does it emit `integration_receipt.v1`, followed by the
promotion authority's `promotion_receipt.v1`. Neither receipt is an application
prerequisite. The parent must invoke the existing Mission authority path for
any Mission mutation. Evidence and telemetry have no reverse write edge.
Adapters cannot call privileged kernel mutations on their return path. No
timestamp or “later succeeded” relation supplies authority.

All authority and recovery labels resolve through the closed role catalog in
the [authority contract](../v03/contracts/authority.md#closed-authority-role-catalog).
One transition has one scalar catalog role. `promotion_integration_authority`,
an owner array, or wording that assigns both promotion and parent integration
authority to one step fails closed. Promotion decides; the parent applies.

The executable adversarial inventory is
[authority graph fixture](../../tests/fixtures/v03_decisions/authority/authority-graph.v1.json).
The fixture enumerates every named plane, its allowed output, and forbidden
reverse edges rather than relying on this diagram alone.

## Preserved Mission kernel

The complete source-to-proposal map is in the
[authority contract](../v03/contracts/authority.md#preserved-mission-kernel).
The proposed boundary preserves all of these together:

1. disk-reconstructed centralized Mission truth;
2. at most one externally visible transition per coordinator step;
3. exactly one active work owner per contract assertion;
4. independent validation with missing, stale, mismatched, omitted, or
   dissenting evidence failing gates closed;
5. structural role/tool authority rather than prompt-only roles;
6. finite effective capability policy resolved before child creation;
7. atomic durable persistence with durable `.unrest/` records separate from
   `.unrest-runtime/` cursors;
8. typed attention and bounded, validated replanning;
9. restart reconciliation bound to the exact task and dispatch generation;
10. single mutable-work selection until a separately accepted isolation and
    integration design changes it; and
11. fresh advisory terminal review whose recommendation is sealed only by the
    coordinator.

Inquiry status, branch success, a child patch, adapter output, evidence receipt,
evaluator result, evolution outcome, telemetry, skill text, and chronology
cannot bypass or weaken any item. A proposal to change one must be gated under
AUTH-D05; silence is preservation, not permission to replace it.

## Irreversible effects

An irreversible effect is an operation whose consequences are not fully
withdrawn by deleting local state. The effect classes are process, network,
credential, service, database, filesystem, publication, promotion, and
integration. Before execution, the effect request must bind:

- a named external authority identity and decision reference;
- exact subject, scope, allowed operation, and expiry or use count;
- the current run/candidate/workspace identity inputs required by the owning
  decision family;
- preconditions and prohibited resources;
- the receipt schema and expected terminal outcome;
- exactly one failure/recovery owner; and
- compensation, rollback, escalation, or explicit non-reversibility.

The executor verifies the grant but does not issue it. Missing, expired, stale,
mismatched, replayed, or broader-than-requested grants fail before the effect.
Partial execution retains a receipt and enters the recovery path; it never
becomes “clean” because a process stopped or a workspace disappeared. The
[effect fixture](../../tests/fixtures/v03_decisions/authority/external-effects.v1.json)
contains all effect classes and independently failing authority mutations.

## Cancellation and recovery

Cancellation revokes future authority; it cannot promise that a non-cooperative
child stopped or an external effect reversed. Every route in the
[cancellation matrix](../../tests/fixtures/v03_decisions/authority/cancellation-recovery.v1.json)
names exactly one decision owner and terminal disposition. The common bounded
sequence is:

1. persist the cancellation reason and stop admitting new work or effects;
2. request cooperative stop from the currently owned activity;
3. drain for a declared bound and inventory processes, leases, artifacts,
   evidence, and effects;
4. persist settled, unknown, stale, or partial status without upgrading it;
5. let the route's sole recovery owner retry, compensate, quarantine, reassign,
   roll back, or raise typed attention; and
6. record the terminal disposition while retaining evidence.

Pending work may be graph-cancelled by `mission_controller_authority`. Running work is
owned by that role's future live-cancellation integration and
cannot be declared stopped from the current graph operation. Inquiry,
workspace, external-effect, evaluation, promotion, and rollback paths retain
their own state but cannot resolve Mission truth. Crash/restart reconciliation
rejects stale attempts and never guesses success. An orphan is a durable state
requiring an explicit ownership claim; timeout is a cancellation reason, not a
terminal disposition by itself.

## Preconditions, errors, terminal outcomes, compatibility, and rollback

- Authority: the downstream maintainer decides whether to accept this record;
  runtime actors receive only the specific authority stated above.
- Identity: proposed grants and receipts must bind versioned public identities;
  their canonical encoding is owned by the separate identity decision family.
- Preconditions: ADR acceptance and canonical integration precede any runtime
  implementation; each effect or mutation also satisfies its local state and
  identity preconditions.
- Error/cancellation/recovery owner: the sole owner in the authority and
  cancellation matrices. Ambiguous or unavailable ownership fails closed into
  typed attention.
- Terminal disposition: one of the route-specific retained outcomes in the
  matrices; unknown and partial are explicit outcomes, never success aliases.
- Compatibility effect: none today. Current v0.2 remains authoritative and its
  single coordinator, storage, task, MCP, and capability contracts are
  unchanged. Future implementation is schema- and compatibility-gated.
- Rollback: before acceptance, delete or reject only these new draft artifacts.
  After a future acceptance, restore the last accepted kernel/working-point
  digest through `rollback_authority`, validate it, retain receipts,
  and invalidate dependent evidence. External effects follow their separate
  compensation or escalation plans.

## Alternatives considered

- AUTH-A01 through AUTH-A03 are rejected because they convert evidence or local
  mechanism into authority and defeat fail-closed Mission governance.
- AUTH-A04 and AUTH-A05 are deferred because the required identity, operational
  burden, and rollback evidence do not yet exist.
- Keeping all proposed planes observational forever was considered but not
  selected: explicit typed request boundaries permit useful future behavior
  without granting a reverse write edge.

## Consequences

- Positive: new planes can evolve independently without duplicating Mission
  authority.
- Positive: effect and cancellation failures remain attributable and
  inspectable.
- Negative/cost: every integration or irreversible effect needs explicit
  authority and receipt handling; automation is deliberately constrained.
- Compatibility/hard cut: none in this draft; any future change is gated.
- Schema/migration impact: none in current v0.2; proposed records require
  versioned schemas before implementation.
- Security/privacy impact: authority records must exclude secrets, prompts,
  source bodies, reports, and unrelated output; capability possession is not
  authorization.

## Open questions

- `AUTH-Q01` / `AUTH-A04`: whether any low-risk promotion or canary authority
  can be automated after identity, quorum, stop, effect, and rollback evidence
  exists.
- `AUTH-Q02` / `AUTH-A05`: whether a bounded durable workflow adapter should
  exist and, if so, which non-Mission history it may own.

These questions are deferred and grant no authority. Their cross-family owners
and dependencies are inventoried in the
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory).

## Review

- Reviewer: none
- Approval date/evidence: 2026-08-24 maintainer full-implementation instruction,
  accepted decision index, v0.3.1 runtime, and validation contract.
- Evaluation evidence: focused fixture and link checks only; no runtime
  acceptance or integration evidence exists

## Rollback

- Trigger: downstream rejection, a reverse Mission write edge, duplicated
  coordinator authority, incomplete cancellation ownership, or a kernel bypass.
- Procedure: reject this proposal and remove its newly owned draft, contract,
  and fixtures; do not modify current canonical sources.
- Data recovery: none; this record creates no runtime data.
- Verification: confirm current v0.2 index and source tree remain unchanged and
  all added draft references are gone.

## Implementation and verification

- Components/paths: future integration owners only; this task adds documentation
  and fixtures under FM-000-owned paths.
- Canonical documents: current
  [runtime](../v5/07-runtime-architecture.md),
  [task](../../specs/task_list/PRODUCT.md),
  [storage](../../specs/memory_v2/PRODUCT.md),
  [MCP](../v5/08-mcp-surface.md), and
  [capability](../architecture/capability-policy.md) contracts remain canonical.
- Tests/evidence: strict fixture parsing, matrix assertions, and relative-link
  resolution over the newly owned files.

## References

- [Authority contract](../v03/contracts/authority.md)
- [ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Architecture index](../architecture/index.md)
- [Inquiry proposal](ADR-0302-inquiry.md)
