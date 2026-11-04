# Continuation unit state (M1a-core)

`continuation_state` is an inert pure module that classifies one exact-bound
work unit from caller-supplied facts and maintains an immutable acceptance
frontier. Accepted by
[ADR-0504](../decisions/ADR-0504-continuation-state.md). Nothing in the
product imports it. It reads no clock, file, environment or process, calls no
provider or host, and imports only `ClockReadingMs`, `DurationMs`,
`elapsed_between` and `DURATION_MS_MAX` from
[continuation value types](continuation-types.md).

No result is an execution permission. `ready` is conditional advice that an
already proposed transition is admissible on the supplied snapshot; it never
authorizes dispatch, retry, recovery, cancellation or completion. Basis
references and source kinds constrain form only; they do not authenticate
origin, prove coverage, prove resource independence or establish custody.

## Operations

- `assess_unit(facts, frontier, profile, now)` returns exactly one of
  `Assessed(state, primary_reason, hint, reasons, liveness, claims, basis)`,
  `Indeterminate(code, hint="facts_required", ...)` or
  `Deferred(feature, reason, hint="evaluation_deferred", ...)`.
  Assessed states are `working`, `ready`, `verifying`, `waiting_external`,
  `needs_user`, `stalled` and `paused_policy`. Missing facts are never
  `stalled`; completion, recovery and impossibility evaluation are `Deferred`.
- `advance_progress(frontier, claim)` returns
  `ProgressUpdate(disposition, frontier)` with disposition
  `acceptance_advanced`, `diagnostic_advanced`, `semantic_repeat`,
  `exact_duplicate` or `activity_ignored`.

## Values

All values are frozen, slotted dataclasses with no defaults on inputs.
Constructors validate every field and the exact class of every field value.
Every public operation revalidates the exact class and every field of all
its inputs, so instances changed with `object.__setattr__`, built with
`object.__new__` or of a subclass are refused there; constructing a subclass
instance is not itself refused. `Binding` has seven exact
components (mission, continuation, origin, positive int64 generation,
candidate, scope, unit). Tokens fully match
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` (length 1–128); integers are native int64.

`UnitFacts` holds one holder per dimension (controls, integrity, coherence,
policy hold, attempt, clearance cells and coverage, user decision, wait,
obligations, readiness, related holds and coverage, failure, constraint
conflict, phase observation, agent claims). Every known status carries
exactly one singular `BasisRef` of the allowed source kinds; every `unknown`
status carries `None`; `None` where a basis is required is `detail_mismatch`.
Five roles are typed `BasisRef` without `None` (`WaitSpec.source`,
`PhaseObservation.basis`, `PhaseEnvelope.source`, `ClaimFact.basis`,
`ProgressClaim.basis`): `None` there is `invalid_type` in constructors and on
revalidation alike. Only `controls.basis` and `obligations.refs` are tuple
basis roles. Admitted-attempt liveness time and its basis are present
together or not at all. Explicit `Coverage(complete|unknown)` is required for
clearance cells and related holds; an empty list is not a proof of absence.
Clearance cells describe the next proposed effect: settlement is diagnostic
only, and an unresolved cell beside an admitted attempt is a diagnostic, not a
second-dispatch permission or a certification of that admission.

## Bounds

Each fact tuple holds at most 64 entries, checked by length before any element
is read. The whole `UnitFacts` may hold at most 64 `BasisRef` occurrences
(each slot counted separately, including nested cell, relation and claim
references), counted structurally before reference payloads are validated.
The frontier holds at most 1024 seen observations; accepted and diagnostic
keys reconstruct exactly from that history and have no separate cap.

## Decision table

The finite table of the accepted contract is normative; there is no general
runtime relevance rule. After structural validation (classes, local and
aggregate caps, field semantics, exact binding, one epoch, no future clock
except the next external check, attempt not before the frontier start, liveness
not before the attempt) the rows are, in order:

1. **P** — known direct holds: cancel, pause, drain, integrity refused,
   coherence inconsistent, unresolved applicable outcome or replay clearance
   with no attempt, policy hold → `paused_policy`.
2. **G\*** — only on a fully known proposal context K (no pending user
   decision, no wait, no attempt, satisfied or undeclared obligations,
   admissible eligibility): known dependent relation, denied authority or
   another owner → `paused_policy` with hint `none`.
3. **I1–I9** — stale snapshot, unknown control, integrity, coherence, policy,
   attempt against a dirty cell, cell applicability, cell state, user decision.
4. **N1** — pending user decision → `needs_user`.
5. Observed work: waiting (C1), unknown wait (C1u), admitted attempt (C2),
   unknown attempt (C2u), pending obligations (C3), unknown obligations (C3u).
6. Excluded evaluations: asserted conflict → impossibility, unknown conflict,
   recoverable failure → recovery, unknown failure.
7. Readiness: unknown eligibility; not admissible → completion (all
   satisfied) or `no_classifiable_condition`; unknown authority, owner,
   coverage or relation; otherwise `ready`.

P and G\* also apply to a stale snapshot, with the `stale_observation`
diagnostic; this is a conditional negative assessment of the supplied
snapshot, not proof about the current world.

## Time

Thresholds compare `elapsed >= timeout` on S2a clocks of one epoch. The hard
deadline runs from the frontier start S (the fixed lifetime start of this
bound unit); the progress deadline runs from the last first-time accepted key
(or S); the wait deadline runs from the wait establishment. Waiting uses hard
and wait; working, verifying and ready use hard and progress. A matching
fresh phase observation can suppress only the progress deadline of an admitted
attempt. The unknown-wait row with an admitted attempt or pending
obligations, and the unknown-attempt row with pending obligations, evaluate
the hard deadline only; no candidate, wait, progress or phase evaluation is
invented. Holds, user decisions, excluded evaluations and other
indeterminate rows are never turned into `stalled` by timers. Pause never
subtracts elapsed time or moves anchors. A new binding yields a new S; no
mission-wide budget or anti-reset guarantee follows. `elapsed_between` is
called only after its preconditions hold: after the epoch and future checks
for decisions, and inside `WaitSpec` validation after that value's own
same-epoch and non-decreasing checks.

## Progress frontier

Only a new key of `assertion_satisfied`, `gate_satisfied` or `blocker_cleared`
moves the acceptance anchor. Diagnostics, activity and semantic repeats never
do. Activity is ignored without entering history. A repeated evidence
identity is an exact duplicate only when every field is equal, and otherwise
an identity conflict; semantic repeats with new identities are retained in
history so that later changed content is detected. When history is full, new
identities are refused with `frontier_capacity_exhausted`; there is no
eviction, wrap or reset. Retained repeats consume capacity, and an old frontier
may later report elapsed progress despite unrecorded real progress; callers
must handle refusal.

## Errors

Every failure is `ContinuationStateError` with one closed `code` from
`STATE_CODES`; `str(error) == code`. Errors carry no input value and do not
chain internal exceptions; S2a value errors never escape.

Validation stops at the first failure. The steps run in a fixed order: the
classes of the four arguments and of the fixed-depth frontier and profile
slots; then the facts (slot classes, tuple lengths, element classes, aggregate
count, field semantics); then the frontier (fields, capacity, keys, each seen
observation, reconstruction), so a facts failure is reported before a
malformed seen element; then the profile and `now`; then binding, epoch,
future and attempt-order checks. Within a step, fields follow declaration order and collection
elements follow caller order. Malformed elements are never sorted or
normalized first, so permutations of an input with several faults may report
different codes; one input always reports the same code.

## Limits of the claim

The classifier is advice over the supplied snapshot. Truthful facts, complete
coverage, coherent reads, source authentication, clock custody, resource
independence and durable frontier custody are caller or adapter
responsibilities that this slice does not provide. There is no codec, adapter,
scheduler, supervisor or durable state. Module-level lookup tables such as
`PRIMARY_REASONS`, `DEFERRED_PAIRS` and the progress source-kind table are
plain mutable mappings; they are not protected against in-process mutation
and are not an origin or security boundary.
