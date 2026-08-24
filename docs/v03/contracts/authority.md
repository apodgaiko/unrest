# Accepted v0.3 authority contract

Status: accepted for v0.3.1 and owned by
[ADR-0300](../../decisions/ADR-0300-authority.md). Proposal-era baseline and
alternative language below is retained as dated rationale; current authority is
the accepted ADR, implemented runtime, and v0.3.1 validation contract.

## Current authority baseline

| Current invariant | Canonical source | Current owner/seam | Proposed preservation |
| --- | --- | --- | --- |
| Disk reconstruction | [runtime architecture](../../v5/07-runtime-architecture.md#public-contract) | `ProjectController`, `MissionCoordinator`, `ProjectStore` | Adjacent stores remain subordinate and cannot reconstruct or replace Mission truth. |
| One visible transition | [runtime invariant `ARCH-STATE-001`](../../v5/07-runtime-architecture.md#invariants) | `MissionCoordinator.step()` | No adapter or adjacent callback hides multiple Mission transitions. |
| Exact one work owner | [task invariant `ARCH-TASK-001`](../../../specs/task_list/PRODUCT.md#invariants) | submission/patch validation | Inquiry branches, workspaces, and candidates are not additional contract owners. |
| Independent validation | [task dispatch and gates](../../../specs/task_list/PRODUCT.md#dispatch) | validator handoff plus coordinator gate | Candidate tests and evaluator output are evidence only; every gate target remains fail-closed. |
| Fail-closed gates | [runtime gates](../../v5/07-runtime-architecture.md#gates-and-attention) | `MissionCoordinator._evaluate_gate` | Missing, stale, mismatched, omitted, uncovered, or dissenting evidence cannot clear a gate. |
| Structural role authority | [MCP surface](../../v5/08-mcp-surface.md#public-contract) | four separately constructed MCP servers | New roles require separate effective tool authority, not prompt or skill text. |
| Finite pre-launch policy | [capability policy](../../architecture/capability-policy.md#runtime-authority) | role/provider policy resolution | Dynamic requests compile into an inspectable finite policy before child creation. |
| Atomic durable persistence | [storage invariants](../../../specs/memory_v2/PRODUCT.md#invariants) | `ProjectStore` and atomic writers | Mission writes stay centralized; durable/runtime roots and generation checks remain distinct. |
| Typed attention | [runtime gates and attention](../../v5/07-runtime-architecture.md#gates-and-attention) | controller/coordinator decision path | Ambiguous authority, cleanup, or evidence fails into typed attention. |
| Restart reconciliation | [runtime dispatch and recovery](../../v5/07-runtime-architecture.md#dispatch-and-recovery) | coordinator plus exact attempt generation | Adjacent history or latest timestamps cannot stand in for exact generation evidence. |
| Single mutable selection | [task dispatch](../../../specs/task_list/PRODUCT.md#dispatch) | coordinator selection before persistence | Preserved until separately accepted workspace/integration behavior exists. |
| Fresh terminal review | [runtime terminal review](../../v5/07-runtime-architecture.md#terminal-review) | reviewer recommends; coordinator seals | Inquiry answers, evaluator results, and campaign completion cannot seal a Mission. |

Current v0.2 `abort_project` records abort but does not provide total cooperative
live-worker cancellation, process drain, external-effect settlement, or orphan
claim. Task-list `cancel` applies only to pending/failed graph nodes. These gaps
are current limitations, not permissions to claim future success.

## Closed authority-role catalog

Every `owner`, `authority`, `issuer_authority`, and recovery owner in the six
families MUST resolve to exactly one `role_id` in the closed `role_catalog` of
the [cross-family protocol fixture](../../../tests/fixtures/v03_decisions/integration/cross-family-authority.v1.json).
Aliases, free text, arrays of owners, slash-joined owners, and compound names
such as `promotion_integration_authority` are invalid. The catalog is closed:
an unlisted role requires a later accepted version of this contract and fixture.
Applying a decision is not a second decision owner.

The protocol-critical separation is exact: `promotion_authority` owns the
pre-application promotion decision/grant and the post-application promotion
receipt; `parent_integration_authority` alone owns the parent plan, staging,
application, integrated validation, atomic accepted-point mutation,
`integration_receipt.v1`, and transaction reconciliation. When an external
effect needs recovery, that separate atomic route is owned by
`external_effect_recovery_authority`; it does not become a co-owner of the
parent transition.

## Proposed mutation authority table

| Subject | Sole decision authority | Applying component | Allowed subordinate input | Forbidden substitute |
| --- | --- | --- | --- | --- |
| Mission lifecycle/state | `mission_controller_authority` | `ProjectController` and the single `MissionCoordinator` | typed task, handoff, validation, or attention inputs | Inquiry state, adapter callbacks, telemetry, evaluator score, chronology |
| Contract ownership/gate | `mission_controller_authority` | current controller/coordinator path | persisted validator verdicts | worker claim, candidate test, missing/omitted result |
| Promotion decision/grant | `promotion_authority` | decision recorder only; no application | exact predecessor/candidate plus fresh evaluation, review, patch, policy, and quorum evidence | integration receipt, candidate, evaluator, score, or chronology |
| Accepted working point | `parent_integration_authority` | parent-owned staging/application transaction entering the Mission authority path | `PromotionDecisionGrant.v1`, `ParentApplicationPlan.v1`, exact patch return, and fresh validation inputs | child merge/push, workspace return, promotion receipt, evaluator recommendation |
| External effect | `external_effect_authority` | admitted effect executor | verified one-use/bounded grant | capability possession, ambient credential, prior grant |
| Promotion completion receipt | `promotion_authority` | append-only receipt issuer after integration | fresh `integration_receipt.v1` for the exact grant/candidate/result | receipt used as retroactive application permission |
| Rollback decision | `rollback_authority` | exact-predecessor recovery path; parent application remains a separately ordered transition | exact accepted predecessor and rollback plan | child cleanup, arbitrary commit, unverified inverse |

No other component may write these subjects. “Sole decision authority” is not
duplicated by the applying component: the component validates and applies the
external decision within its bounded state machine.

## Preserved Mission kernel

For VAL-AUTH-005, every adjacent plane must satisfy all twelve baseline rows
above. The machine-readable
[authority fixture](../../../tests/fixtures/v03_decisions/authority/authority-graph.v1.json)
maps each plane to allowed outputs and negative reverse edges. A validator must
fail the draft if any plane can:

- write canonical Mission or accepted-working-point state;
- create another active work owner;
- convert its own result into a gate or terminal seal;
- expand child tools through prose, skills, or dynamic configuration after
  launch;
- persist Mission truth outside `ProjectStore` or bypass generation checks;
- infer recovery from time, telemetry, latest filenames, or resident state; or
- schedule overlapping mutable work before a separately accepted isolation and
  integration contract is active.

## External effect contract

The complete class inventory is in
[external-effects.v1.json](../../../tests/fixtures/v03_decisions/authority/external-effects.v1.json).
Every row must supply one of two forms:

1. `forbidden`: the effective policy denies the operation; or
2. `externally_authorized`: authority ID, exact scope, subject identity,
   preconditions, expiry/use bound, expected receipt, one failure owner, and
   recovery/compensation/rollback disposition are present and fresh.

Process, network, credential, service, database, filesystem, publication,
promotion, and integration are the minimum exhaustive classes for this
decision. A mechanism may belong to more than one class and must satisfy each
applicable grant. The executor is never the issuer by default. The following
mutations independently fail: missing grant, stale grant, subject mismatch,
scope mismatch, replay, over-broad operation, missing receipt plan, missing
failure owner, or missing non-reversibility/escalation declaration.

## Cancellation and recovery contract

The
[cancellation fixture](../../../tests/fixtures/v03_decisions/authority/cancellation-recovery.v1.json)
is the deterministic inventory. Every row has one and only one `owner`, a
bounded action, evidence retained, and a terminal disposition. Required
subjects and routes are:

| Subject | Required routes | Owner boundary | Terminal requirement |
| --- | --- | --- | --- |
| Inquiry | pre-start, in-flight, timeout, crash/restart | `inquiry_lifecycle_authority` | cancelled, failed, paused, budget-exhausted, or answered with branch/effect inventory retained |
| Pending work | pre-start/cancel patch | `mission_controller_authority` | superseded with dependency rewrite and decision record |
| Running work | in-flight, timeout, crash/restart, stale attempt | `mission_controller_authority` | settled failure/cancel result or typed attention with unknown process/effect state |
| Workspace lease | pre-allocation, active, returned, cleanup retry | `workspace_lease_authority` | released or durable cleanup exception/attention |
| Workspace orphan claim | orphan | `orphan_recovery_supervisor` | claimed generation or quarantine/attention |
| Partial external effect | post-effect, timeout, retry, crash/restart | `external_effect_recovery_authority` | compensated, rolled back, quarantined, escalated, or explicitly unsettled |
| Evaluation | queued, in-flight, timeout, evaluator error, stale input | `independent_evaluation_authority` | cancelled, failed, invalid, stale, or completed evidence; no promotion |
| Promotion decision | pre-apply, stale evidence, mismatch | `promotion_authority` | rejected, rework, or inconclusive with accepted point unchanged |
| Parent application | plan, staging, apply, integrated validation, atomic mutation, receipt-recovery | `parent_integration_authority` | accepted point unchanged, integrated-and-validated, rolled back, or attention |
| Promotion receipt | missing after successful integration, stale integration result | `promotion_authority` | promoted, rejected, rework, or inconclusive without another application |
| Rollback decision/recovery | pre-start, in-flight, failed validation | `rollback_authority` | restored-and-validated or explicit failed/unsettled attention |
| Rollback external effect | partial or unknown effect | `external_effect_recovery_authority` | compensated, rolled back, quarantined, escalated, or explicit unsettled attention |

Task graph cancellation is not live-worker cancellation. Terminal-review
teardown is not live-worker cancellation. Worktree deletion is not process or
effect cleanup. Retry creates a new attempt/generation and does not rewrite the
old outcome. Crash/restart reconstructs from durable records; stale attempts
remain evidence but cannot settle a newer generation.

## Error and rollback rules

Unknown authority, ambiguous owner, unavailable evidence, non-unique terminal
disposition, or an unsettled irreversible effect fails closed into typed
attention. No actor may turn `unknown`, `partial`, `stale`, `cancel_requested`,
or `cleanup_failed` into success merely to complete a lifecycle.

Before acceptance, rollback is deletion/rejection of the new draft set. After
a future acceptance, Mission rollback is an external integration decision bound
to the exact previous accepted working point, followed by fresh validation and
receipt invalidation. Effect compensation is separately owned and may end in
explicit escalation when no inverse exists.

## Verification obligations

1. Strictly parse every referenced fixture with duplicate-key rejection.
2. Confirm plane, invariant, effect-class, subject, and route IDs are unique and
   deterministically sorted.
3. Confirm every forbidden edge has no permission and every permitted mutation
   names its external decision authority.
4. Confirm each cancellation row has exactly one non-empty owner and terminal
   disposition.
5. Exercise every negative mutation independently; no combined failure may hide
   an untested bypass.
6. Resolve every relative Markdown link and anchor in this owned slice.

Passing these checks verifies the proposal artifact only. It does not accept
the ADR, implement behavior, or issue an integration receipt.
