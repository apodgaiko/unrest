# Proposed Inquiry.v1 contract

Status: proposed, non-authoritative, and unindexed. This contract supports
[ADR-0302](../../decisions/ADR-0302-inquiry.md) and inherits the one-way
authority boundary from [ADR-0300](../../decisions/ADR-0300-authority.md).

## Separation from current surfaces

Current `inspect_project` and `observe-project` inspect an existing Mission.
They do not become Inquiry aliases. `Inquiry.v1` is a new versioned object with
its own store and lifecycle. It never uses Mission task status, contract
ownership, attention, or terminal review as an implicit Inquiry state, and an
Inquiry state never mutates those Mission records.

## Required record fields

An implementation schema must be strict and versioned and must represent:

| Concern | Required content |
| --- | --- |
| Identity | `inquiry_id`, schema version, actor authority reference, creation identity, activation identities, route/context/policy version references without secret values or hashes |
| Objective | question, desired output, constraints, source scope, known unknowns, accepted assumptions with actor decision references |
| Lifecycle | exact state, transition sequence, reason, authority, activation, timestamps as metadata only |
| Budget | envelope, currency/units, total, branch allocations, spent, remaining, amendments, stop conditions, budget authority |
| Branches | stable IDs, role/hypothesis, genealogy, immutable inputs, budget slice, progress, artifacts, negative evidence, status, error, terminal outcome |
| Synthesis | revision, claims and evidence refs, consensus, limitations, unsupported claims, open questions, majority/minority reports, answer/no-answer |
| Retention | policy ID, retain-until or indefinite, hold, artifact availability, deletion/tombstone authority and receipt |
| Handoff | optional immutable handoff reference and digest; never a Mission ID or launch result |

Unknown fields fail at authority boundaries. Exact canonicalization, digest
preimage, and receipt invalidation are gated on the separately owned identity
decision; Inquiry code cannot invent an encoding.

## State machine

Allowed states are `draft`, `clarifying`, `exploring`, `synthesizing`,
`answered`, `paused`, `cancelled`, `budget_exhausted`, and `failed`.

| From | To | Preconditions and owner | Required observable |
| --- | --- | --- | --- |
| draft | clarifying | authorized actor opens with objective/constraints/source scope/budget | creation and activation identities, unknowns, full budget |
| clarifying | exploring | actor resolves ambiguity through sources, visible assumptions, or narrowing; portfolio and stop rules fit budget | accepted assumptions, branch plan, allocations, coverage target |
| clarifying | paused/cancelled/failed | actor/policy owns pause/cancel; lifecycle owns typed failure | reason, retained inputs, no branch launch claim |
| exploring | exploring | lifecycle applies branch progress/outcome under frozen policy | spent/remaining, artifacts, negative evidence, errors, active count |
| exploring | synthesizing | coverage precondition met or explicit gap carried forward | complete branch outcome inventory and evidence refs |
| exploring | paused/cancelled/budget_exhausted/failed | actor/policy/lifecycle owner according to reason | launch stop, bounded drain, settled/unknown branches, retained evidence |
| synthesizing | answered | evidence-bound synthesis includes limitations, dissent, budget, unresolved questions | immutable answer/no-answer revision |
| synthesizing | paused/cancelled/budget_exhausted/failed | same owner rules; no fabricated answer | partial synthesis and all evidence retained |
| paused | clarifying/exploring/synthesizing | explicit actor resume, new activation, freshness recheck, sufficient budget | prior state reference and new activation receipt |
| budget_exhausted | clarifying/exploring/synthesizing | explicit actor/budget-authority amendment plus resume and freshness checks | amendment, new total, prior spend, new activation |

`answered`, `cancelled`, and `failed` are immutable terminal states. `paused`
and `budget_exhausted` are immutable activation outcomes but resumable Inquiry
states. A terminal follow-up uses a new linked `inquiry_id`.

The
[lifecycle fixture](../../../tests/fixtures/v03_decisions/inquiry/inquiry-lifecycle.v1.json)
must cover happy, ambiguous, failure, cancel, resume, budget, dissent, and
retention cases. Each has distinct observables and an explicit outcome.

## Branch and synthesis rules

- Initial branches are read-only. Capability possession cannot extend this.
- A branch is an Inquiry search role, not a Mission contract work owner.
- Duplicate mechanisms are collapsed before launch and all branches consume a
  bounded allocation from the shared envelope.
- Failure and cancellation retain partial artifacts and negative evidence.
- Replacement branches require frozen policy permission and remaining budget;
  the replaced outcome remains in the denominator.
- Synthesis names evidence gaps, unsupported claims, and the strongest dissent.
  A minority report retains mechanism, evidence, rejection reason, and
  resurrection condition.
- Missing evidence cannot improve confidence or silently disappear from an
  aggregate.

## Cancellation, recovery, and retention

Cancellation first persists the request and revokes new launch authority, then
requests cooperative stop, drains for a bounded interval, inventories branch
and artifact/effect state, and persists settled or unknown outcomes. The
Inquiry lifecycle owner owns these store transitions; it cannot settle a
Mission, process, workspace, or external effect owned elsewhere. Unknown
children or effects raise the corresponding recovery/attention route.

Restart reconstructs from the Inquiry store and exact activation/branch
receipts. Mismatched or stale output is retained as rejected evidence and never
applied to the current activation. Resume never overwrites prior activation
history.

Every quiescent or terminal record retains the objective, assumptions,
transition history, budget ledger, complete branch genealogy/outcomes,
artifacts and negative evidence, errors, synthesis revisions, dissent, and
handoffs. A named data-governance authority may later delete eligible bytes
under the record's explicit policy and append a tombstone/receipt. A branch,
runner, synthesizer, or Mission consumer cannot delete inconvenient evidence or
rewrite the outcome. Exact default durations remain deferred.

## InquiryMissionHandoff.v1

The handoff is an immutable evidence artifact, not an action envelope. It must
bind source Inquiry/activation identity, objective, constraints, assumptions,
answer/no-answer revision, complete evidence manifest digest, artifact refs,
negative evidence, dissent, limitations, budget, open questions, proposed
Mission brief, proposed validation needs, prohibited actions, producer
authority, consumer compatibility, and a versioned content digest.

The explicit consumer flow is:

```text
persisted Inquiry activation
  -> actor requests immutable evidence handoff
  -> actor inspects exact handoff/evidence digest
  -> actor separately decides whether to launch
  -> ordinary start_project creates a fresh project/Mission identity
  -> Mission planning records consumer decision + exact digest as provenance
```

No earlier arrow creates or mutates a Mission. The handoff generator cannot
call `start_project`; `answered` cannot trigger it; tool aliases cannot combine
the actions; shared IDs and timestamps cannot supply the decision. A missing,
invalid, stale, mismatched, unavailable, or unauthorized handoff fails before
launch. Modified bytes or a modified consumer brief require a new decision.

The
[handoff fixture](../../../tests/fixtures/v03_decisions/inquiry/inquiry-mission-handoff.v1.json)
contains the positive case and independent implicit-launch bypass cases. The
positive case requires different Inquiry and Mission identities, the exact
evidence digest, and a non-null external consumer decision.

## Compatibility and rollback

No current record, task type, envelope, observer schema, or MCP tool changes in
this draft. Future implementation uses new schemas and public operations and
must retain the current Mission-only path as rollback. Disabling Inquiry must
stop new Inquiry creation while preserving or policy-tombstoning existing
records; it never rolls back, deletes, or mutates a Mission.

## Verification obligations

1. Strictly parse both fixtures with duplicate-key rejection.
2. Confirm lifecycle cases cover all eight required scenarios and every case
   has authority, observables, and outcome.
3. Confirm terminal states have no outgoing transition and resume creates a new
   activation without changing `inquiry_id`.
4. Confirm every handoff bypass case is invalid for its own stated reason.
5. Confirm the positive handoff binds Inquiry, evidence, actor decision, and a
   fresh distinct Mission identity.
6. Resolve all relative links and anchors in the owned slice.

Passing verifies only internal consistency of this proposal. It is not ADR
acceptance, runtime implementation, Mission launch, or integration.
