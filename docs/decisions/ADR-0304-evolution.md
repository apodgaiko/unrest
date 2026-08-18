# ADR-0304: Govern offline evolution, exact promotion, and rollback

## Record metadata

id: ADR-0304
status: proposed
date: 2026-08-18
task_ids:
  - W-EVOLUTION
contract_targets:
  - VAL-EVO-001
  - VAL-EVO-002
  - VAL-EVO-003
  - VAL-EVO-004
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - adversarial-authority-review

## Authority status

This record is an unindexed, non-authoritative proposal. Authorship, filename,
date, campaign score, fixture success, bundle inclusion, or later chronology
does not accept or integrate it. Only a downstream maintainer may accept and
canonically integrate an exact version through the boundary proposed by
[ADR-0300](ADR-0300-authority.md). This record issues no integration receipt.

## Scope

- In scope: externally governed offline campaigns, evaluator/reviewer and
  holdout independence, immutable candidate genealogy, complete outcome and
  learning retention, exact-candidate promotion, freshness/quorum, reward-hack
  resistance, exact-predecessor rollback, and automated-canary disposition.
- Out of scope: acceptance, runtime implementation, evaluator adapter choice,
  storage engine, public surfaces, Mission coordination, live continuation,
  dependency changes, and changing current v0.2 behavior.

## Context

Offline candidate search becomes unsafe when authors can select evaluation,
discard failures, or translate a score directly into promotion. This proposal
separates campaign, custody, evidence, promotion, integration, and rollback
roles while retaining the single Mission authority path.

## Current v0.2 truth

At product object `96d5c0f0b240bd3373809546d7aecc1e407f837b`,
[ADR-0002](ADR-0002-lean-core-v0.2.md) and the accepted
[architecture index](../architecture/index.md) govern. Current Unrest has one
Mission coordinator and independent Mission validator handoffs, but no
evaluator/promotion service, protected holdout custodian, evolution campaign,
candidate portfolio, automated canary, or promotion/rollback receipt flow.

The proposed identity and receipt records in
[ADR-0301](ADR-0301-identity.md) and the isolated patch-return lifecycle in
[ADR-0303](ADR-0303-workspace.md) are also unaccepted proposals. They are
cross-linked dependencies, not present behavior. Nothing below changes v0.2.

## Proposed decisions and dispositions

| Decision ID | Disposition | Proposed rule |
| --- | --- | --- |
| EVO-D01 | proposed | Admit only offline campaigns whose complete governance record is externally frozen before launch; candidate authors and mutation workers cannot change its inputs or authorities. |
| EVO-D02 | proposed | Keep candidate authors/workers, evaluator, reviewer quorum, `holdout_custodian`, `retry_exclusion_decision_authority`, and `promotion_authority` independent as declared by the campaign policy. Evaluation and review produce evidence or recommendations only. |
| EVO-D03 | proposed | Give every candidate immutable content identity and complete genealogy. Any edit, rebase, retry input change, or mutation creates a new candidate/run rather than rewriting lineage. |
| EVO-D04 | proposed | Retain every evaluation, review, decision, dissent, cost, and learning/projection invalidation outcome. Missing, excluded, skipped, failed, or contaminated data never improves a score or disappears from denominators. |
| EVO-D05 | proposed | Promotion requires a named external authority, an exact candidate and predecessor, fresh identity-bound evidence, satisfied independent quorum, a recorded decision, parent-only integration, and terminal receipts. |
| EVO-D06 | proposed | Promotion or removal predeclares an exact predecessor rollback target, trigger, issuer, procedure, compatibility checks, retention, and terminal receipt. Rollback never chooses “latest known good.” |
| EVO-A01 | rejected | Let a candidate author, mutation worker, evaluator, reviewer, adapter, score, chronology, terminal-review recommendation, or successful test directly promote or mutate Mission truth. |
| EVO-A02 | rejected | Let candidate code read protected holdouts, alter evaluator/oracle/completion criteria, suppress failures, choose its own retries/exclusions, or benefit from missing observations. |
| EVO-A03 | rejected | Retain only winners, aggregate away dissent/error classes, rewrite genealogy after retry/rebase, or delete evidence when a learning summary changes. |
| EVO-A04 | deferred | Automated canary promotion, removal, or rollback. A future accepted decision must define an explicitly gated tier, identity, blast radius, stop authority, quorum, effect permissions, observation window, exact rollback, and operator burden. Until then automation may emit evidence only. |
| EVO-A05 | deferred | Concrete evaluator adapter, holdout storage technology, signature/key custody, retention duration, and campaign-wide quorum numbers. Each campaign must bind accepted policy identities before launch; this draft does not choose implementations or universal values. |

## Frozen campaign and candidate genealogy

The proposed [evolution contract](../v03/contracts/evolution.md) defines the
closed `EvolutionCampaign.v1` record. Before launch, the external campaign
authority freezes the parent/accepted point; objective and correctness oracle;
evaluator and reviewer identities; workload and separately custodied holdout;
environment; route/provider; context and seed; budget plus its authority,
stop/cancel authority; retry/exclusion policy and its named decision authority; promotion
authority; mutation scope; effect permissions; and exact rollback plan.

Every field is identity-bound under [Identity.v1](../v03/contracts/identity-v1.md).
The [campaign fixture](../../tests/fixtures/v03_decisions/evolution/campaign-freeze.v1.json)
is the exhaustive freeze-field oracle. Candidate authors and workers receive
only admitted candidate/workspace inputs. They do not receive protected
holdout contents or authority grants. A frozen-field mutation invalidates the
campaign generation and requires a newly admitted campaign; it is not a
runtime tweak.

Each `CandidateGenealogy.v1` node binds its candidate digest, ordered parent
digests, campaign generation, immutable base and accepted point, mutation
mechanism/scope, producer run and workspace lease, hypothesis, predicted
effect, regression risks, and falsification test. Duplicate content shares a
content identity but every attempt/outcome remains append-only. An edit or
rebase creates a new node with an explicit edge; retries never overwrite the
prior node, run, cost, or outcome.

## Independent evaluation, review, and reward-hack resistance

The [independence fixture](../../tests/fixtures/v03_decisions/evolution/evaluation-independence.v1.json)
separates six roles: candidate author/mutation worker, evaluator, reviewer,
`holdout_custodian`, `retry_exclusion_decision_authority`, and
`promotion_authority`.
The campaign's accepted independence policy defines prohibited identity,
organizational, configuration, and data-custody collisions. A collision,
missing workload identity, leaked holdout, stale environment, absent review,
or unresolved dissent fails closed; an author-produced test may support but
never substitute for independent evidence.

Evaluation runs against exact candidate, evaluator, workload/holdout,
environment, route/provider, context/seed, policy, budget, base, and accepted-
point identities. It emits `evaluation_receipt.v1`; review binds the exact
candidate and complete evidence set in `review_receipt.v1`. Both are evidence.
Neither receipt, evaluator adapter, reviewer recommendation, majority score,
nor terminal review owns promotion or Mission authority.

Protected holdouts are accessible only to the named custodian/evaluation path.
Candidates cannot select observations, retries, exclusions, stopping, scoring,
or completion criteria. The retry/exclusion decision owner records each choice
and reason against the frozen policy. Denominators include all admitted cases;
timeout, skip, error, cancellation, exclusion, contamination, and missing data
have declared non-improving treatment. Suspected manipulation, leaked holdout,
failure suppression, evaluator mutation, oracle gaming, or suspicious metric
divergence produces a retained reward-hack signal and blocks promotion pending
external disposition.

## Exact-candidate promotion

The [promotion fixture](../../tests/fixtures/v03_decisions/evolution/promotion-scenarios.v1.json)
applies conjunctive checks:

1. `promotion_authority` records a current, single-use
   `PromotionDecisionGrant.v1` for the exact candidate/predecessor;
2. the recorded predecessor equals the current accepted point and campaign
   parent; the candidate equals evaluation, review, patch return, and decision;
3. required evaluation/review/patch receipts are intact, authorized,
   fresh under [Receipt.v1](../v03/contracts/receipt-v1.md#freshness-algorithm),
   and bind the complete frozen campaign generation;
4. evaluator/reviewer independence and the campaign's exact quorum are met;
   missing evidence or unresolved dissent fails closed;
5. correctness, safety, cost, effect, contamination, and reward-hack floors
   pass without success-only filtering; and
6. the grant records `promote`, `reject`, `rework`, or `inconclusive` before
   parent application and binds required validation, use, and expiry bounds;
7. `parent_integration_authority` records `ParentApplicationPlan.v1`, stages,
   applies, validates, and atomically changes the exact accepted point; and
8. only after that mutation does the parent emit `integration_receipt.v1`,
   after which `promotion_authority` emits `promotion_receipt.v1`.

Any edit, rebase, candidate mismatch, predecessor drift, stale environment,
changed workload/evaluator/reviewer/policy, quorum failure, or suspected reward
hack blocks promotion. Score, recency, chronology, evaluator recommendation,
and automated canary never repair a failed check. Parent integration follows
ADR-0303. Integration and promotion receipts are post-application outputs and
cannot authorize the action that creates them. Promotion decision and parent
application are separate, single-owner transitions from the closed authority
role catalog; `promotion_integration_authority` is not a valid role.

## Exact-predecessor rollback and removal

Every promote or removal decision records `predecessor_digest`,
`candidate_digest`, resulting accepted-point digest, rollback target (exactly
the predecessor), predeclared trigger/policy, issuer/grant, ordered procedure,
compatibility prerequisites, evidence-retention policy, recovery owner, and
required `rollback_receipt.v1`. The
[rollback fixture](../../tests/fixtures/v03_decisions/evolution/rollback-scenarios.v1.json)
covers accepted, rejected, stale, exact restoration, and failed/unsettled
rollback, including the mandatory handoff metadata projection.

`rollback_authority` first verifies current point, triggering evidence,
target identity, and compatibility prerequisites; stops new effects; applies
the named predecessor through `parent_integration_authority`; validates the exact
restored point; retains campaign/promotion/removal/effect evidence; and emits
`restored_and_validated` or `failed_unsettled`. Failure raises durable attention
and never guesses another target by timestamp, branch name, tag, or recency.

## Complete retention and learning invalidation

The [retention fixture](../../tests/fixtures/v03_decisions/evolution/outcome-retention.v1.json)
enumerates every required outcome: pass, fail, timeout, skip, infrastructure
error, evaluator error, policy rejection, cancellation, stale-evidence
rejection, contamination, suspected reward hack, dissent, and learning/
projection invalidation. Every row retains exact owner, identity-bound evidence
references, declared cost/completeness, and terminal disposition.

Raw evidence, genealogy, minority reports, and negative outcomes are immutable.
Editable learning summaries and disposable projections retain source digests,
confidence, counterexamples, policy/expiry state, and invalidation edges.
Contradiction, rollback, or stale evidence appends an invalidation and rebuilds
or discards projections; it never deletes or rewrites source outcomes.

## Authority, preconditions, errors, compatibility, and rollback

- Authority: external campaign, evaluation, review, holdout-custody,
  retry/exclusion, promotion, integration, rollback, and effect authorities are
  named separately; evidence is never authority.
- Identity: exact public identities and receipt semantics are owned by
  ADR-0301; this record binds them and does not redefine canonical encoding.
- Preconditions: future acceptance and schema/policy integration, then a fully
  frozen admitted campaign generation, precede any candidate launch.
- Error/cancellation/recovery owner: the single owner named for each campaign
  route; unknown ownership, partial effects, or unverifiable evidence produces
  retained failure/attention, not inferred success.
- Terminal disposition: every attempt ends in one retained outcome from the
  contract; campaign closure and recommendation do not seal a Mission.
- Compatibility effect: none today. Current v0.2 remains authoritative. Future
  implementation is new, optional, offline, schema-gated, and must preserve the
  Mission-only core path.
- Rollback: before acceptance, reject/remove only this new draft family. After
  future implementation, disable new campaigns, retain history, restore the
  exact accepted predecessor for any applied candidate, and keep canaries off.

## Alternatives considered

EVO-A01 through EVO-A03 are rejected because they turn mechanism, incomplete
measurement, or selective memory into authority. EVO-A04 and EVO-A05 remain
deferred because safe automation and concrete custody/retention technologies
need separate accepted operational evidence. A success-only leaderboard was
considered and rejected: it makes infrastructure failure look like progress.

## Consequences

- Positive: candidates cannot move their own goalposts or promote themselves.
- Positive: exact lineage and negative evidence make comparisons auditable.
- Negative/cost: independent custody, exhaustive retention, and reruns after
  any material mutation consume time and storage.
- Compatibility/hard cut: none in current v0.2; future live/autonomous
  promotion remains gated off.
- Schema/migration impact: new proposal-only v1 records; no heuristic reader.
- Security/privacy impact: only public identities and bounded artifact refs are
  retained; protected holdout bodies, secrets, prompts, reports, and raw output
  remain excluded from metadata and candidate access.

## Open questions

- `EVO-Q01` / `EVO-A04`: whether an automated canary tier can ever satisfy the
  required identity, blast-radius, stop, quorum, effect, observation, rollback,
  and operator-burden gates.
- `EVO-Q02` / `EVO-A05`: which evaluator adapter, holdout storage, signature
  custody, retention duration, and campaign quorum policies should be used.

These remain deferred and cannot authorize live automation. See the
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory).

## Review

- Reviewer: none
- Approval date/evidence: none; proposed and unindexed
- Evaluation evidence: focused fixture, completeness, and link checks only; no
  runtime acceptance, promotion, canary, or rollback evidence exists

## Rollback

- Trigger: downstream rejection; authority collision; mutable freeze input;
  missing outcome/dissent; candidate mismatch; stale/quorum bypass; reward-hack
  benefit; guessed rollback target; or automated promotion without a later gate.
- Procedure: reject and remove this ADR, its contract, and evolution fixtures;
  do not modify current canonical sources or sibling proposal families.
- Data recovery: none; this proposal creates no runtime data.
- Verification: confirm current accepted index and v0.2 sources are unchanged.

## Implementation and verification

- Components/paths: future evaluator/evolution/integration owners only; this
  task adds FM-000-owned documentation and decision fixtures.
- Canonical documents: current [runtime](../v5/07-runtime-architecture.md),
  [task](../../specs/task_list/PRODUCT.md), and
  [storage](../../specs/memory_v2/PRODUCT.md) contracts remain authoritative.
- Tests/evidence: strict JSON parsing; exact freeze/outcome class assertions;
  role-collision, promotion, rollback, reward-hack, and non-accepted disposition
  checks; relative-link and anchor resolution.

## References

- [Evolution contract](../v03/contracts/evolution.md)
- [Authority proposal](ADR-0300-authority.md)
- [Identity proposal](ADR-0301-identity.md)
- [Workspace proposal](ADR-0303-workspace.md)
- [ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Architecture index](../architecture/index.md)
