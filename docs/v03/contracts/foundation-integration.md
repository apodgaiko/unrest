# Proposed v0.3 foundation integration contract

Status: proposed, non-authoritative, and unindexed. This contract integrates
the six FM-000 proposal families for review; it does not accept them, modify
current v0.2 behavior, issue a receipt, or authorize runtime implementation.

## Exact family inventory

Exactly these six family ADR filenames are in the FM-000 decision set:

| Family | Proposal ADR | Primary concern | Supporting contracts |
| --- | --- | --- | --- |
| authority | [ADR-0300](../../decisions/ADR-0300-authority.md) | Mission mutation, external decision authority, common cancellation/effect rules | [authority](authority.md) |
| identity | [ADR-0301](../../decisions/ADR-0301-identity.md) | canonical public identity, receipt encoding, dependency freshness, secret-safe metadata | [Identity.v1](identity-v1.md), [Receipt.v1](receipt-v1.md) |
| inquiry | [ADR-0302](../../decisions/ADR-0302-inquiry.md) | separate Inquiry lifecycle and explicit evidence handoff | [Inquiry.v1](inquiry-v1.md) |
| workspace | [ADR-0303](../../decisions/ADR-0303-workspace.md) | isolation tiers, leases, patch return, parent integration mechanism, cleanup | [workspace](workspace.md) |
| evolution | [ADR-0304](../../decisions/ADR-0304-evolution.md) | campaign governance, independent evaluation, promotion policy, exact rollback | [evolution](evolution.md) |
| compatibility | [ADR-0305](../../decisions/ADR-0305-compatibility.md) | pinned v0.2 surface classification and no-extra rollback perimeter | [compatibility](compatibility.md) |

There is one filename per family and one family per filename. Every ADR has
canonical template metadata with `status: proposed`, is absent from the
[accepted decision index](../../decisions/index.md), names no reviewer or
acceptance evidence, and separates current v0.2 truth from proposed v0.3 rules.
No extra `ADR-03xx` family is admitted by this contract.

The deterministic file and metadata oracle is
[tree manifest](../../../tests/fixtures/v03_decisions/integration/tree-manifest.v1.json).

## Primary concern ownership

Each concern has one semantic owner. A dependent family may bind or consume
that concern but must link to its owner rather than restating the rule as its
own authority.

| Concern | Primary family | Permitted dependent use | Forbidden duplication or bypass |
| --- | --- | --- | --- |
| Mission truth mutation | authority | all families may submit typed inputs | adjacent store, worker, evaluator, adapter, evidence, telemetry, or chronology writes/seals |
| Accepted working-point decision | authority | workspace applies the exact parent decision; evolution supplies promotion evidence/policy | child self-integration, evaluator self-promotion, compatibility shim mutation |
| External effect grant | authority | workspace/evolution execute only an exact scoped grant | capability, credential, lease, score, or successful test treated as authority |
| Common cancellation semantics | authority | each lifecycle specializes owner/action/evidence/outcome | process exit, timeout, graph cancellation, deletion, or silence treated as total settlement |
| Canonical identity bytes/digests | identity | every family binds typed references | family-local canonicalizer, coercion, untyped hash substitution |
| Receipt integrity and freshness | identity | consumers declare family-specific dependencies/outcomes | timestamps, latest file, success, or issuer self-assertion establishes freshness |
| Inquiry state and branch budget | inquiry | authority governs only a later Mission launch decision | Inquiry branch becomes Mission work owner or mutates product state |
| Inquiry-to-Mission evidence handoff | inquiry | identity owns bytes; authority owns separate launch | handoff generation, answered state, tool alias, or chronology launches Mission |
| Isolation tier and lease lifecycle | workspace | authority supplies mutation/effect decisions; identity supplies references | tier name or worktree overclaims confinement/authority |
| Patch return and integration mechanism | workspace | authority supplies parent decision; evolution consumes for promotion | child merge/push or disjointness bypasses checks |
| Campaign freeze and genealogy | evolution | identity supplies exact candidate/run references | author/worker changes freeze inputs or rewrites lineage |
| Evaluation/review/holdout policy | evolution | authority treats outputs as evidence only | evaluator/reviewer/score gains promotion or Mission authority |
| Promotion and exact-predecessor rollback policy | evolution | authority supplies external decisions; workspace applies exact point | latest-known-good, score, canary, or chronology selects target |
| v0.2 compatibility classification | compatibility | every future family consults its exact row | specialized family silently promises migration or revives a hard cut |
| Persistence narrow-reader boundary | compatibility | identity adds only new explicit versions | generic migration, null coercion, replay, or heuristic reader |
| No-extra rollback perimeter | compatibility | future adapters/extras declare removable core fallback | extra becomes required for Mission semantics or authority |

The machine-readable
[cross-family authority graph](../../../tests/fixtures/v03_decisions/integration/cross-family-authority.v1.json)
contains the same primary-owner relation and independently failing bypasses.
`decides`, `applies`, `encodes`, `produces_evidence`, and `classifies` are
distinct edge types; applying or producing never implies deciding.

## Cross-record authority graph

```text
external actor / maintainer
  | Mission/effect/integration/promotion/rollback decision (authority)
  v
ProjectController -> single MissionCoordinator -> ProjectStore -> Mission truth
       ^                         ^
       | typed launch/input      | typed evidence/recommendation only
Inquiry lifecycle        workspace + evolution + compatibility adapters
       |                         |
       +--- identity-bound artifacts/receipts ---+
                             |
                             v
                   evidence / telemetry only
```

Identity encodes references and derives freshness but decides no lifecycle.
Inquiry owns only Inquiry state. Workspace owns lease/cleanup state and the
parent application protocol but not the pre-application promotion decision/
grant. Evolution owns campaign/evaluation/promotion record policy and evidence;
the external `promotion_authority` issues the exact grant but cannot apply it.
Compatibility classifies and tests;
it never supplies a migration coordinator. These distinctions remove the only
plausible overlaps rather than disguising them with different nouns.

## Ordered cross-family application protocol

The normative proposal order is exact. Every owner is one scalar ID from the
[closed role catalog](authority.md#closed-authority-role-catalog); inputs are
limited to independently existing evidence or outputs of earlier rows.

| Order | Transition ID | Phase | Owner role | Required inputs | New output |
| --- | --- | --- | --- | --- | --- |
| 1 | `XAPP-01-PROMOTION-DECISION-GRANT` | pre-application | `promotion_authority` | predecessor/candidate plus fresh evaluation, review, patch, policy, and quorum evidence | `PromotionDecisionGrant.v1` |
| 2 | `XAPP-02-PARENT-APPLICATION-PLAN` | pre-application | `parent_integration_authority` | grant, `WorkspaceLease.v1`, `PatchReturn.v1` | `ParentApplicationPlan.v1` |
| 3 | `XAPP-03-STAGE` | parent application | `parent_integration_authority` | grant and plan | `StagedApplication.v1` |
| 4 | `XAPP-04-APPLY-STAGING` | parent application | `parent_integration_authority` | staged application | `AppliedStagingPoint.v1` |
| 5 | `XAPP-05-VALIDATE-STAGING` | parent application | `parent_integration_authority` | applied staging point and plan validations | `IntegratedValidationResult.v1` |
| 6 | `XAPP-06-ATOMIC-ACCEPT` | parent application | `parent_integration_authority` | passing validation, grant, plan, exact predecessor compare-and-swap | `AcceptedPointMutation.v1` |
| 7 | `XAPP-07-INTEGRATION-RECEIPT` | post-application | `parent_integration_authority` | durable accepted-point mutation and validation | `integration_receipt.v1` |
| 8 | `XAPP-08-PROMOTION-RECEIPT` | post-application | `promotion_authority` | grant, evaluation, review, integration receipt, resulting point | `promotion_receipt.v1` |

The closed grant, plan, and receipt field sets; canonical digest preimages;
concrete recomputable vectors; transition inputs/outputs; and per-row
`future_outputs_consumed: []` proof are in the
[cross-family authority fixture](../../../tests/fixtures/v03_decisions/integration/cross-family-authority.v1.json).
The grant adds exact patch/lease, validation, operation, use, expiry, and
chronology fields. The plan adds grant, staging, compare-and-swap result,
effect-grant refs, ordered steps, and one recovery plan. Integration and
promotion receipts bind rows 6 and 7 only after those rows complete.

Failures before row 6 leave the accepted point unchanged. A crash after row 6
but before row 7 is reconciled by `parent_integration_authority` from the exact
durable transaction: emit the delayed receipt or invoke exact rollback, never
reapply. A missing row-8 receipt is recovered by `promotion_authority` without
another application. Partial external effects are a separate transition owned
only by `external_effect_recovery_authority`.

## Cancellation and recovery owner matrix

Every route has one decision/recovery owner, one bounded recovery action, an
evidence-retention obligation, and explicit terminal outcomes. The common
persist/revoke, cooperative-stop, bounded-drain, inventory, recover/escalate,
and retain sequence belongs to authority; state-specific transitions remain
with the owning family.

| Route | Sole owner | Owning family | Required terminal outcomes |
| --- | --- | --- | --- |
| Inquiry pre-start/in-flight/timeout/restart | `inquiry_lifecycle_authority` | inquiry | answered, cancelled, failed, paused, or budget-exhausted with branch inventory |
| Pending/running Mission work cancellation/reconciliation | `mission_controller_authority` | authority | superseded, settled failure/cancel, or typed attention retaining unknowns |
| Workspace allocation/active/returned/cleanup retry | `workspace_lease_authority` | workspace | released, quarantined, cleanup-failed attention, or unsettled-effect attention |
| Workspace orphan claim | `orphan_recovery_supervisor` | workspace | claimed generation or quarantine/attention |
| External effect post-attempt/timeout/retry/restart | `external_effect_recovery_authority` | authority | compensated, rolled back, quarantined, escalated, or explicitly unsettled |
| Evaluation queued/in-flight/timeout/error/stale | `independent_evaluation_authority` | evolution | cancelled, failed, invalid, stale, or completed evidence; never promotion |
| Promotion decision pre-apply/stale/mismatch | `promotion_authority` | evolution | rejected, rework, or inconclusive; accepted point unchanged |
| Parent application/reconciliation | `parent_integration_authority` | workspace | unchanged, integrated-and-validated, rolled back, or attention |
| Promotion receipt recovery | `promotion_authority` | evolution | promoted, rejected, rework, or inconclusive; never reapply |
| Exact rollback decision/recovery | `rollback_authority` | evolution | restored-and-validated or failed/unsettled attention |
| Compatibility probe cancellation | `compatibility_probe_validator` | compatibility | bounded failed/blocked transcript and probe-owned temporary cleanup only |

The normalized executable form is the
[owner matrix](../../../tests/fixtures/v03_decisions/integration/cancellation-recovery-owners.v1.json).
No row permits multiple owners for the same decision step; compound routes are
split into ordered steps when authority changes.

## Disposition and open-question inventory

Every family contains proposed decisions, rejected alternatives, and deferred
alternatives. Across the six ADRs the closed inventory contains 64 decision
rows: 31 proposed, 19 rejected, and 14 deferred. The IDs and expected counts
are frozen in
[decision inventory](../../../tests/fixtures/v03_decisions/integration/decision-inventory.v1.json).

Deferred rows are questions, not implicit defaults:

| Question IDs | Primary family | Downstream decision owner | Blocking dependencies |
| --- | --- | --- | --- |
| `AUTH-Q01`, `AUTH-Q02` | authority | maintainer authority decision | identity, effect, stop, rollback, and adapter boundary evidence as applicable |
| `ID-Q01`, `ID-Q02` | identity | security/key-custody and data-governance/storage decisions | public suite/custody model and retention/store evidence |
| `INQ-Q01`, `INQ-Q02` | inquiry | public-surface authorization and data-governance decisions | accepted Inquiry identity/lifecycle and compatibility classification |
| `WS-Q01`, `WS-Q02`, `WS-Q03` | workspace | provider, workload-policy, and integration decisions | enforcement proof, finite bounds, identity/freshness, parent verification |
| `EVO-Q01`, `EVO-Q02` | evolution | canary/custody/campaign-policy decisions | blast radius, stop, effect, identity, quorum, rollback, technology evidence |
| `COMP-Q01`, `COMP-Q02`, `COMP-Q03` | compatibility | public-API, dependency/release, and persistence decisions | actual candidate surfaces and fresh inventory/oracle evidence |

An unresolved question fails closed at the affected boundary. It cannot be
resolved by file order, implementation choice, default library behavior, or a
successful fixture.

## Scenario coverage map

The cross-family
[scenario coverage fixture](../../../tests/fixtures/v03_decisions/integration/scenario-coverage.v1.json)
maps each required class to existing independently parseable fixtures:

| Required class | Positive evidence | Failure/bypass evidence |
| --- | --- | --- |
| positive | canonical vectors, Inquiry answer/handoff, disjoint integration, exact promotion/rollback, frozen persistence | n/a |
| negative | bounded lifecycle and reader outcomes | encoding, authority, lifecycle, integration, promotion, rollback, and persistence mutations |
| rejected | each ADR alternative table | authority/Inquiry/workspace/evolution bypasses and compatibility rejection fixture |
| deferred | every ADR deferred row and open-question section | deferred automation/provider/custody/retention/extras/API/migration records fail closed |
| unresolved | 14 explicit question IDs | missing required decision blocks affected consumption |
| cancellation/recovery | Inquiry, workspace, evaluation, effect, promotion, rollback, and probe owners | unknown/partial/timeout/deletion/retry shortcuts rejected |
| compatibility | 85 source surfaces classified exactly once and 14 frozen schema cases | null/mismatch/replay probes and hard-cut revival rejection |
| rollback | proposal deletion, no-extra restore, workspace predecessor restore, promotion/removal rollback | guessed target, stale trigger, failed/unsettled restoration |

Each coverage entry names a family, scenario class, artifact path, JSON pointer
or Markdown anchor, and expected disposition. Missing classes or dangling
references fail validation.

The compatibility count is derived, not declared independently: parse the
pinned `v02-source-inventory.v1` artifact, require 85 unique `surface_id`
values, and require the matrix row IDs to be the exact same set with no
duplicates. The five rows added by fresh source enumeration are the bounded
subprocess stream limit and the four documented MCP worker/reviewer handoff
environment fields. Their producer/consumer file-and-line locators resolve at
base commit `96d5c0f0b240bd3373809546d7aecc1e407f837b`, and the newly referenced
`acp_runner.py` bytes are pinned in `source_hashes`; no proposal prose or old
matrix count is used as the enumeration oracle.

## Whole-tree deterministic validation

Validation operates on all new `docs/decisions/ADR-03*.md`,
`docs/v03/contracts/**`, and `tests/fixtures/v03_decisions/**` files together:

1. require exactly the six ADR paths in the tree manifest and reject any extra
   `ADR-03*.md` family filename;
2. parse every JSON fixture as UTF-8 with duplicate-key rejection, reject
   non-finite numbers, require two-space sorted-key serialization plus one
   trailing newline, and byte-compare the reserialization;
3. require fixture paths and recursively keyed collections to appear in stable
   deterministic order as declared by their local contracts;
4. parse every local Markdown destination, resolve it relative to its source,
   and require the destination to be an existing file in the repository;
5. for every fragment, derive GitHub-style heading slugs with duplicate-heading
   suffixes and require the exact anchor to exist;
6. reject links into runtime-managed mission state and reject any new ADR link
   that implies acceptance through the current decision index;
7. compare all decision IDs, question IDs, primary ownership rows, owner routes,
   and scenario classes with their closed fixtures; and
8. scan the owned files for acceptance claims, integration receipts, secret
   material categories, prompts/source bodies/reports, and unrelated output.

The tree manifest declares the roots and rules, not computed success. A
validator must execute them against the current checkout; source inspection or
schema-shaped JSON alone is insufficient.

## Compatibility, recovery, and rollback

This integration contract changes no v0.2 runtime, accepted index, registry,
dependency, persistence, or release surface. Before acceptance, recovery is to
repair or reject the affected new proposal family and recompute the entire
cross-family validation. Rollback is deletion/rejection of the unaccepted
proposal tree. After any future acceptance, each primary family retains its
own separately accepted compatibility and rollback process; this cross-record
map never becomes a generic migration or recovery authority.

## Verification obligations

1. Strictly validate every JSON fixture and deterministic byte form.
2. Resolve every relative path and heading anchor over the entire new tree.
3. Assert the exact six ADR filenames, canonical non-accepted metadata, and
   absence from the accepted index.
4. Assert each concern has exactly one primary family and every cross-family
   edge has a non-mutating type or explicit external decision owner.
5. Assert every cancellation/recovery step has exactly one owner and at least
   one non-success terminal outcome for unknown or partial state.
6. Assert the complete proposed/rejected/deferred ID inventory and all 14 open
   questions.
7. Assert all eight required scenario classes are covered across all six
   families and every named path/pointer/anchor resolves.

Passing verifies proposal consistency only. It does not accept any ADR, change
the accepted working point, implement v0.3, or issue an integration receipt.
