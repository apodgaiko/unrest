# Proposed v0.3 offline evolution and promotion contract

Status: proposed, non-authoritative, and unindexed. This contract supports
[ADR-0304](../../decisions/ADR-0304-evolution.md). It inherits authority from
[ADR-0300](../../decisions/ADR-0300-authority.md), canonical identity and
receipt freshness from [ADR-0301](../../decisions/ADR-0301-identity.md), and
parent-only integration from [ADR-0303](../../decisions/ADR-0303-workspace.md).
Those links assign ownership; this contract does not duplicate or accept them.

## Current v0.2 baseline

Current v0.2 has no evolution campaign, protected holdout custodian,
evaluator/promotion service, candidate portfolio, or automated canary. Existing
Mission validators produce gate evidence under the single Mission coordinator;
they do not establish this proposed offline lifecycle.

## Closed `EvolutionCampaign.v1` freeze

`campaign_authority` must freeze every field below before launch.
The machine-readable [freeze fixture](../../../tests/fixtures/v03_decisions/evolution/campaign-freeze.v1.json)
is exhaustive and independently mutates every field.

| Freeze group | Required identity-bound fields |
| --- | --- |
| Lineage | campaign ID/generation, exact parent candidate, base revision, accepted-working-point digest |
| Goal | objective vector with direction/weight/floors, correctness oracle and safety/burden rules |
| Independent evaluation | evaluator identity/authority, reviewer identity set/independence policy/quorum, workload identity, protected holdout manifest and custodian |
| Replay | environment identity, route/profile and provider-configuration identities, context identity, seed/randomization policy |
| Bounds | budget identity/ledger policy and `campaign_budget_authority`; stop/cancel rules and drain under `campaign_stop_authority` |
| Adjudication | retry/exclusion policy and separately named decision authority, promotion policy and external authority |
| Mutation/effects | closed mutation scope, prohibited surfaces, workspace tier/lease requirements, effect permissions/grants |
| Recovery | exact predecessor rollback target, triggers, `rollback_authority`, ordered procedure, compatibility prerequisites, retention policy |

All collections are closed, typed, unique, and deterministically sorted.
Candidate authors/workers cannot be any freeze-field authority and cannot amend
the campaign. A material mutation creates a newly admitted generation and
stales dependent evidence. Time, file order, “latest,” and successful score do
not freeze or refresh a field.

## Roles, custody, and evidence boundary

Authority roles resolve only through the
[closed role catalog](authority.md#closed-authority-role-catalog):
`campaign_authority`, `campaign_budget_authority`,
`campaign_stop_authority`, `independent_evaluation_authority`,
`independent_review_authority`,
`holdout_custodian`, `retry_exclusion_decision_authority`,
`promotion_authority`, `parent_integration_authority`, and
`rollback_authority`. `candidate_author` and `mutation_worker` are participants,
not authority roles. The accepted independence policy declares prohibited
identity and control collisions. At minimum:

- authors/workers do not select or operate evaluator, reviewer, holdout,
  retry/exclusion, promotion, integration, or rollback authority;
- evaluator and reviewers are independent of authors/workers; reviewer quorum
  cannot be satisfied by the evaluator alone;
- holdout custody is outside candidate workspaces and exposes only authorized
  blinded tasks and bounded result artifacts; and
- `promotion_authority` is external to author, worker, evaluator, reviewer, and
  adapter. Campaign/evaluation/review completion is not Mission authority.

The [independence fixture](../../../tests/fixtures/v03_decisions/evolution/evaluation-independence.v1.json)
covers author-evaluator collision, author-reviewer collision, evaluator-only
quorum, leaked holdout, stale environment, dissent, missing workload identity,
and reward-hacking signal. Each fails independently. Evaluator and reviewer
outputs are typed evidence/recommendations consumed only by named authorities.

## Immutable genealogy and attempt retention

`CandidateGenealogy.v1` is append-only and requires candidate digest; ordered
parent digests; campaign ID/generation; base and accepted-point digests;
producer run/workspace lease; mutation mechanism/scope; hypothesis; predicted
effect; regressions; falsification test; and artifact refs. Candidate bytes are
never embedded. A mutation, rebase, changed retry input, or changed frozen
dimension creates a new candidate/run/genealogy node. Duplicate content may
share content identity but no attempt, cost, decision, or outcome is dropped.

## Evaluation and reward-hack rules

Before evaluation, verify exact candidate, campaign generation, evaluator,
workload/holdout, environment, route/provider, context/seed, policy, budget,
base, accepted point, custody, and authority. Cheap checks may precede matched
replay but cannot replace required holdout/reviewer evidence.

Every admitted case remains in accounting. Retry or exclusion requires a
decision by the named authority under the frozen policy and retains original
attempt, reason, cost, and replacement link. Missing, skipped, timed-out,
errored, cancelled, excluded, or contaminated observations use their declared
non-improving treatment. They cannot be silently omitted or imputed as pass.

Candidate access to protected holdouts; evaluator/oracle/test mutation;
completion-criteria change; failure suppression; selective retry/exclusion;
public-reference leakage; missing-data benefit; or suspicious proxy/holdout
divergence produces `suspected_reward_hack` or `contamination`, blocks
promotion, and is retained for independent disposition. Passing candidate-
authored tests does not clear that block.

## Complete outcomes and retention

The exact required outcome classes are:

1. `pass`
2. `fail`
3. `timeout`
4. `skip`
5. `infrastructure_error`
6. `evaluator_error`
7. `policy_rejection`
8. `cancellation`
9. `stale_evidence_rejection`
10. `contamination`
11. `suspected_reward_hack`
12. `dissent`
13. `learning_projection_invalidation`

The [retention fixture](../../../tests/fixtures/v03_decisions/evolution/outcome-retention.v1.json)
contains exactly one canonical row per class and declares its owner, evidence,
cost/completeness, and terminal disposition. Implementations may append more
attempts but cannot remove a class or retain only success. All raw evidence,
genealogy, decisions, dissent/minority reports, costs, and invalidation edges
are immutable and identity-bound.

Learning summaries are derived, versioned records with source digests, domain,
confidence, counterexamples, expiry/policy, and state. Contradiction, rollback,
or stale evidence appends an invalidation and marks/rebuilds disposable
projections. It never rewrites source evidence or genealogy.

## Promotion decision, parent application, and completion

`PromotionDecisionGrant.v1` is the pre-application external decision with:

- exact campaign generation, predecessor/accepted-point, candidate,
  evaluation, review, patch, lease, policy, and authority-grant digests;
- required independent reviewer identities, quorum rule/result, dissent refs,
  and freshness results for every dependency;
- correctness/safety/burden/reward-hack/custody checks and complete denominator;
- decision `promote`, `reject`, `rework`, or `inconclusive`, issuer, one-use/
  expiry bounds, required integrated validation IDs, rationale artifact ref,
  and chronology-is-authority literal `false`; and
- exact rollback metadata defined below.

The [promotion fixture](../../../tests/fixtures/v03_decisions/evolution/promotion-scenarios.v1.json)
covers accept, reject, stale predecessor/environment, dissent/quorum failure,
reward hack, candidate mismatch, chronology/score bypass, and deferred
automated canary. Promotion is conjunctive: exact candidate and predecessor;
valid external authority; fresh authorized evaluation/review/patch evidence;
independent quorum; complete accounting; all floors; no unresolved
contamination/reward-hack; and a parent application plan. Failure of any one
check blocks the pre-application grant.

The grant authorizes only the exact parent protocol; it does not assert that
application occurred. `parent_integration_authority` owns plan, staging,
application, integrated validation, atomic accepted-point mutation, and
`integration_receipt.v1`. After that receipt exists, `promotion_authority`
appends `promotion_receipt.v1` binding the exact grant, candidate, evaluation,
review, integration receipt, and resulting accepted point. The integration and
promotion receipts are outputs, never prerequisites for parent application.
The exact record schemas, transition order, and digest vectors are in the
[cross-family protocol fixture](../../../tests/fixtures/v03_decisions/integration/cross-family-authority.v1.json).

A recommendation, score, terminal review, later passing task, or canary signal
is evidence only. Automated canary promotion/removal/rollback remains
`deferred_gated`; no tier exists until a later accepted decision names its
authority, identity, blast radius, observation, stop, quorum, effects, rollback,
compatibility, and operator burden.

## Exact predecessor rollback

Every promotion or removal decision must carry this closed rollback metadata:

- `predecessor_digest`, `candidate_digest`, and `resulting_point_digest`;
- exact `rollback_target_digest`, equal to the predecessor;
- trigger policy and observed trigger evidence refs;
- rollback issuer identity and external authority-grant ref;
- ordered procedure and sole recovery owner;
- compatibility prerequisites and their required evidence;
- immutable evidence-retention policy; and
- required `rollback_receipt.v1` outcome and terminal disposition.

The [rollback fixture](../../../tests/fixtures/v03_decisions/evolution/rollback-scenarios.v1.json)
covers accept, reject, stale trigger/current point, exact predecessor restore,
candidate/predecessor mismatch, guessed-recency target, and failed/unsettled
rollback. Handoff rollback metadata must expose the same exact fields; a vague
“revert latest” string is invalid.

Rollback verifies the current accepted point, trigger, target, authority, and
compatibility evidence; stops new effects; applies the exact predecessor via
parent integration; validates the restored digest; retains all evidence; and
emits `restored_and_validated`/`restored` or
`failed_unsettled`/`attention`. It never searches chronology for another point.

## Error, cancellation, and terminal ownership

| Route | Sole decision/recovery owner | Required terminal behavior |
| --- | --- | --- |
| Campaign admission/freeze failure | `campaign_authority` | rejected or rework before launch; record zero/actual cost |
| Evaluation timeout/error/cancel/stale | `independent_evaluation_authority` | retained explicit outcome; no promotion |
| Retry or exclusion request | `retry_exclusion_decision_authority` | approve/reject with immutable prior attempt and accounting |
| Review dissent/missing quorum | `independent_review_authority` | dissent/inconclusive/reject/rework retained; no promotion |
| Promotion pre-apply/stale/mismatch | `promotion_authority` | reject/rework/inconclusive; accepted point unchanged |
| Parent plan/staging/application/validation/transaction reconciliation | `parent_integration_authority` | accepted point unchanged, integrated-and-validated, exact rollback, or durable unsettled attention |
| Promotion receipt missing/stale after integration | `promotion_authority` | append from exact durable inputs or retain reject/rework/inconclusive; never reapply |
| Rollback decision/failure | `rollback_authority` | restored-and-validated or failed/unsettled attention |
| Rollback partial external effect | `external_effect_recovery_authority` | compensated, rolled back, quarantined, escalated, or unsettled attention |

Cancellation stops new launches/effects, records the request, performs the
campaign-bound cooperative drain, inventories attempts/effects, and retains
partial evidence/cost. `cancel_requested`, timeout, missing telemetry, or
process exit is not a terminal success state. Retry creates a new attempt.

## Compatibility and proposal rollback

This contract creates no current runtime behavior or migration. Future records
are new v1 domains and cannot be inferred from schema-v1 Mission data. The
ordinary Mission-only core remains usable without evaluator/evolution extras.

Before acceptance, rollback is deletion/rejection of only this ADR/contract/
fixture family. After implementation, stop new campaigns, keep immutable
history, disable consumers, restore exact applied predecessors when required,
and leave automated canaries disabled. Evidence invalidation cannot be reversed
into freshness by disabling the subsystem.

## Verification obligations

1. Strictly parse every fixture with duplicate-key rejection and deterministic
   key/list ordering checks.
2. Assert the exhaustive freeze-field set and one independent mutation per
   field; no candidate-owned authority is admitted.
3. Assert all independence failures and distinguish evidence producers from
   promotion/Mission decision authorities.
4. Assert every promotion check is conjunctive and independently failing,
   exact candidate/predecessor equality, freshness, quorum, reward-hack block,
   and deferred canary policy.
5. Assert exact rollback metadata and target equality for promotion/removal,
   including failed rollback and handoff projection.
6. Assert exactly all 13 outcome classes, each with owner, evidence, cost, and
   terminal disposition; dissent/negative/invalidation records remain retained.
7. Resolve every relative Markdown link and anchor in the owned slice.

Passing proves only internal artifact consistency. It does not accept this
contract, authenticate an actor, promote a candidate, seal a Mission, run a
canary, or issue an integration receipt.
