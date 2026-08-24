# ADR-0302: Specify a separate inspectable Inquiry lifecycle

## Record metadata

id: ADR-0302
status: accepted
date: 2026-08-18
accepted_date: 2026-08-24
accepted_by: maintainer-v0.3.1-instruction
task_ids:
  - W-AUTH-INQUIRY
contract_targets:
  - VAL-INQ-001
  - VAL-INQ-002
  - VAL-INQ-003
  - VAL-INQ-004
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - lifecycle-simulation

## Authority status

Accepted for v0.3.1 by the maintainer's explicit 2026-08-24 full-implementation
instruction. Inquiry remains a separate evidence lifecycle and creates no
Mission implicitly. Proposal-era wording below is dated design rationale, not
the current runtime-status oracle.

## Scope

- In scope: the `Inquiry.v1` identity and lifecycle, actor observability,
  budgets, ambiguity, branch failure, cancellation, resumption, dissent,
  retention, terminal outcomes, and a digest-bound evidence handoff to a
  separately launched Mission.
- Out of scope: mutable implementation work, Mission transitions, automatic
  Mission launch, family-owned canonicalization, workspace integration,
  evolution promotion, and provider credential policy.

## Context

Open-ended investigation needs an inspectable lifecycle, but reusing Mission
tasks would create extra work ownership and a route from research evidence to
mutation. This proposal separates Inquiry state and makes Mission launch a
fresh external decision.

## Current v0.2 truth

Current v0.2 has no Inquiry object or Inquiry store. `inspect_project` and
`observe-project` are read-only views over an existing Mission; neither starts
an exploration lifecycle, owns branch budgets or artifacts, nor authorizes a
Mission transition. Project creation is an explicit `start_project` operation,
and Mission truth remains under the current controller/coordinator/store path.

This proposal does not reinterpret current observation as Inquiry and does not
add behavior to v0.2.

## Accepted decisions and dispositions

| Decision ID | Disposition | Rule |
| --- | --- | --- |
| INQ-D01 | accepted | Add a versioned actor-visible `Inquiry.v1` lifecycle with its own persisted identity, activation history, states, budget, branches, artifacts, dissent, errors, and retention metadata. |
| INQ-D02 | accepted | Initial Inquiry branches are read-only and cannot write product state, Mission truth, an accepted working point, promotion state, or external effects. |
| INQ-D03 | accepted | Ambiguity, partial failure, budget exhaustion, cancellation, resumption, and dissent remain distinct inspectable outcomes rather than being collapsed into success or generic failure. |
| INQ-D04 | accepted | Inquiry may emit a digest-bound evidence handoff, but only an explicit external actor decision may launch a fresh, separately identified and separately planned Mission that consumes it. |
| INQ-D05 | accepted | Immutable history and evidence are retained according to explicit actor/data-governance policy; deletion is receipt-bearing and cannot rewrite a terminal Inquiry into another outcome. |
| INQ-A01 | rejected | Treat `answered`, successful synthesis, a handoff file, a tool alias, a timestamp, or proximity to a Mission as implicit Mission creation or mutation. |
| INQ-A02 | rejected | Reuse current Mission observation or task states as the Inquiry lifecycle, or model Inquiry branches as extra Mission work owners. |
| INQ-A03 | rejected | Let a branch mutate the repository, invoke an irreversible effect, suppress negative evidence, or discard dissent to complete synthesis. |
| INQ-A04 | deferred | Exact CLI, MCP, and public API surface and actor authorization mechanism, pending a separately owned public-surface decision. |
| INQ-A05 | deferred | Default retention durations and organization-specific deletion policy; `Inquiry.v1` must record the selected policy and disposition without inventing a universal duration. |

## Proposed object model

An `Inquiry.v1` record contains:

- `inquiry_id`, schema version, actor authority reference, objective, desired
  output, constraints, accepted assumptions, and source-scope declaration;
- immutable creation identity plus provider/route/context/policy version
  references that contain no secret values or hashes;
- current lifecycle state, monotonically ordered activation records, and the
  exact transition authority and reason;
- total budget envelope, spent and remaining budget, per-branch allocations,
  amendment history, and stop conditions;
- branch IDs, genealogy, roles/hypotheses, immutable input digests, progress,
  artifacts, negative evidence, errors, and terminal outcomes;
- synthesis revisions, claim-to-evidence references, limitations, unresolved
  questions, dissent/minority reports, and answer or no-answer disposition;
- retention policy ID, retain-until or indefinite marker, legal/actor holds,
  deletion/tombstone receipt reference, and artifact availability; and
- an optional evidence-handoff reference. The reference is not a Mission ID.

Each activation has a fresh `activation_id`/run receipt while preserving the
same `inquiry_id`. Canonical fingerprint encoding and exact receipt dependency
rules belong to the separate identity decision family; implementation must not
guess them from this draft.

A branch has exactly one Inquiry-owned search role and budget slice. It is not
a contract-assertion work owner. Its progress summary is advisory, never a
percentage-complete or liveness promise.

## Lifecycle and observables

```text
draft -> clarifying -> exploring -> synthesizing -> answered
             |            |              |
             +----------> paused <-------+
             +----------> cancelled
             +----------> budget_exhausted
             +----------> failed

paused or budget_exhausted --explicit resume/amendment--> clarifying|exploring|synthesizing
```

`answered`, `cancelled`, and `failed` are immutable terminal outcomes.
`paused` and `budget_exhausted` are quiescent, resumable outcomes; resumption
creates a new activation and rechecks input freshness. A follow-up to a
terminal Inquiry creates a linked revision with a new `inquiry_id`.

Every transition exposes state, transition reason, actor or policy authority,
activation, budget spent/remaining, branch outcome counts, latest artifact
references, retained errors, dissent status, and whether launch/drain remains
active. Telemetry may project these facts but never owns the state.

The actor flow and transition preconditions are normative for this proposal:

1. `draft -> clarifying`: an authorized actor records the objective,
   constraints, desired output, source scope, and budget.
2. `clarifying -> exploring`: material ambiguity is resolved by supplied
   sources, visible accepted assumptions, or narrowed scope; unresolved
   ambiguity stays in `clarifying`, pauses, or cancels.
3. `exploring`: a bounded portfolio runs materially distinct read-only
   branches. New launches require remaining budget. Branch failures retain
   partial and negative evidence.
4. `exploring -> synthesizing`: declared evidence/coverage preconditions are
   met or a coverage gap is explicitly carried into synthesis.
5. `synthesizing -> answered`: the answer binds its evidence, limitations,
   dissent, budget, and unresolved questions. Unsupported certainty is an
   error, not an unlock.
6. Pause stops new launches and drains in-flight branches to a recorded bounded
   state. Cancellation also revokes future Inquiry authority and proceeds
   through the total recovery contract in
   [ADR-0300](ADR-0300-authority.md#cancellation-and-recovery).
7. Budget exhaustion stops new launches and produces a partial answer or
   explicit no-answer. Only the actor or named external budget authority may
   amend the budget.
8. Resume requires actor authorization, a new activation, freshness checks,
   budget sufficiency, and preserved prior artifacts/errors/dissent.

The complete scenario data is in the
[Inquiry lifecycle fixture](../../tests/fixtures/v03_decisions/inquiry/inquiry-lifecycle.v1.json)
and the prose contract is
[Inquiry.v1 contract](../v03/contracts/inquiry-v1.md).

## Failure, cancellation, recovery, and retention

The Inquiry lifecycle owner may mutate only the Inquiry store. For branch
failure it retains partial output and selects, under frozen policy and remaining
budget, continue, replacement, synthesize-with-gap, pause, or fail. For
cancellation it prevents new launches, requests cooperative child stop, drains
for a bounded interval, and persists settled or unknown child state. Unknown
does not mean stopped. Crash/restart reconstructs the Inquiry from persisted
state and activation receipts; a stale or mismatched branch attempt is retained
and rejected, not applied.

Terminal and quiescent records retain objective, assumptions, transitions,
budget ledger, branch genealogy and all outcome classes, artifact/evidence
references, errors, dissent, synthesis revisions, answer/no-answer, and any
handoff. Retention policy is explicit per Inquiry. Expiry permits the named
data-governance authority to delete eligible artifact bytes and append a
tombstone/receipt while preserving the minimum identity, disposition, and audit
record required by policy. A runner, branch, synthesizer, or Mission consumer
cannot shorten retention or erase contrary evidence. INQ-A05 remains deferred
because the universal duration is a product/policy choice, not an architectural
fact.

## Explicit Inquiry-to-Mission evidence handoff

An authorized actor may request an `InquiryMissionHandoff.v1` only from a
persisted Inquiry activation. The handoff is an immutable evidence artifact
that binds:

- handoff schema/version and handoff identity;
- source `inquiry_id`, activation identity, state, objective, constraints,
  accepted assumptions, and spent budget;
- exact answer/no-answer revision, evidence manifest digest, artifact
  references, negative evidence, dissent, limitations, and open questions;
- proposed Mission brief, validation needs, prohibited actions, and consumer
  compatibility range;
- producer authority and an explicit statement that chronology is not
  authority; and
- a content digest whose canonical preimage/version is defined by the separate
  identity decision before implementation.

Generating or verifying this handoff does not call `start_project`, allocate a
Mission ID, submit a task list, write a Mission cursor, alter the working point,
or imply acceptance. To consume it, an external actor separately decides to
launch, supplies the exact handoff/evidence digest, and invokes the ordinary
project/Mission creation and planning surface. The new Mission has a fresh
Mission identity; it records the consumer decision and handoff digest as input
provenance. Mission planning may reject, narrow, or supersede proposed work,
and normal contract ownership and gates apply.

Missing, stale, mismatched, unavailable, unauthorized, or digest-invalid
handoffs fail before Mission launch. A changed handoff or consumer brief
requires a new consumer decision. No transition table, tool alias, shared ID,
successful synthesis, or “next” timestamp may bridge the boundary. Positive
and bypass cases are in the
[handoff fixture](../../tests/fixtures/v03_decisions/inquiry/inquiry-mission-handoff.v1.json).

## Authority, identity, preconditions, outcomes, compatibility, and rollback

- Authority: the actor owns open/pause/cancel/resume/handoff requests and the
  separate Mission-launch decision; the Inquiry lifecycle owner applies only
  Inquiry transitions. Mission authority remains exclusively under ADR-0300.
- Identity: one immutable Inquiry identity with new activation identities on
  resume; handoff and evidence are digest-bound; encoding is gated on the
  separate identity decision.
- Preconditions: this ADR and required schema/public decisions must first be
  accepted and integrated. Individual transitions obey the lifecycle rules.
- Error/cancellation/recovery owner: the Inquiry lifecycle owner for Inquiry
  state and branch drain; external actor for budget amendment and launch;
  Mission controller only after a separate Mission exists.
- Terminal disposition: `answered`, `cancelled`, or `failed`; quiescent
  resumable dispositions are `paused` and `budget_exhausted`; every branch has
  its own explicit outcome and retained evidence.
- Compatibility effect: none now. v0.2 observation and Mission surfaces remain
  unchanged. Future implementation adds new versioned records rather than
  silently extending Mission tasks or persistence.
- Rollback: disable new Inquiry creation, retain/tombstone records per policy,
  retain this accepted decision and its evidence, and leave
  the current v0.2 Mission path operable; an Inquiry rollback never rewrites a
  Mission.

## Alternatives considered

- INQ-A01 through INQ-A03 are rejected because they collapse search, evidence,
  or chronology into mutation authority.
- INQ-A04 and INQ-A05 are deferred so this decision does not usurp public
  surface or data-governance ownership.
- Making every Inquiry automatically produce implementation work was rejected:
  an answer, including a no-answer, is a complete Inquiry outcome.

## Consequences

- Positive: actors can inspect bounded research, failures, budget, and dissent
  without opening a mutable Mission.
- Positive: useful evidence can cross into implementation with exact
  provenance and an explicit human/maintainer decision.
- Negative/cost: lifecycle and retention records add concepts and storage that
  must be versioned and operated.
- Compatibility/hard cut: none in this draft.
- Schema/migration impact: future `Inquiry.v1` and handoff schemas are new;
  current schema-v1 Mission persistence is untouched.
- Security/privacy impact: public identities exclude secret values/hashes;
  retention and deletion authority must be explicit, and evidence handoff must
  not copy prompts, source bodies, reports, or unrelated output by default.

## Open questions

- `INQ-Q01` / `INQ-A04`: which CLI, MCP, or public API surface and actor
  authorization mechanism should expose Inquiry.
- `INQ-Q02` / `INQ-A05`: which default retention and deletion policies apply
  to Inquiry records and artifacts.

These are deferred and cannot be filled in by an implementation convention.
See the
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory).

## Review

- Reviewer: none
- Approval date/evidence: 2026-08-24 maintainer full-implementation instruction,
  accepted decision index, Inquiry runtime, and validation contract.
- Evaluation evidence: lifecycle and handoff fixture checks only; no runtime
  behavior or acceptance exists

## Rollback

- Trigger: implicit Mission launch, Inquiry mutation authority, missing
  lifecycle outcome, unowned cancellation, or unverifiable retention.
- Procedure: reject and remove the new Inquiry draft, contract, and fixtures.
- Data recovery: none; no runtime data is created.
- Verification: current observation and Mission creation remain unchanged.

## Implementation and verification

- Components/paths: future Inquiry packages and public integrators; this task
  changes only FM-000-owned decision, contract, and fixture paths.
- Canonical documents: current
  [runtime](../v5/07-runtime-architecture.md) and
  [MCP](../v5/08-mcp-surface.md) contracts remain authoritative.
- Tests/evidence: strict fixture parsing, lifecycle/handoff semantic checks,
  and relative-link resolution.

## References

- [Authority proposal](ADR-0300-authority.md)
- [Inquiry.v1 contract](../v03/contracts/inquiry-v1.md)
- [ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Architecture index](../architecture/index.md)
