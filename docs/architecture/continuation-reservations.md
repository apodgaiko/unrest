# Continuation recovery reservations (S2b-LR)

`continuation_reservations` is an inert leaf module that keeps durable
*custody* of recovery reservations and supplied actual observations for one
mission. Accepted by [ADR-0501](../decisions/ADR-0501-recovery-reservation-custody.md).
Nothing in the product imports it. It reads no clock, acquires no cost, calls
no provider or host, and generates no event identifiers.

No result of this module is an execution permission, replay clearance,
cleanup clearance or approval. `newly_reserved` records a reservation;
`already_reserved_reconcile_only` means "inspect, do not dispatch again".
STATE-003 remains PARTIAL/OPEN and STATE-004 remains OPEN.

## Values

All values are frozen, slotted, keyword-only dataclasses without defaults.
Constructors and every public boundary revalidate the exact class and every
field, so instances changed with `object.__setattr__` are refused with
`invalid_value`.

- `ResourceVector(attempts, recoveries, wall_ms, cost_units)` — four native
  `int` values in `0..2**63-1` (`INT64_MAX`). `bool`, `int` subclasses,
  floats, decimals and strings are refused.
- `CausalKey(mission_id, root_lineage_id, goal_branch_id, cause_code,
  effect_family)` — caller-supplied identity. Equal bytes give equal
  accounting; this is not proof of semantic stability against a caller that
  maps identities inconsistently.
- `ReservationPolicy(cost_unit, authority_ref, mission_ceiling,
  root_lineage_ceiling, causal_key_ceiling)` — immutable injected policy.
  `cost_unit` is a denomination token compared by equality only (no FX, no
  price authority). The store does not certify `authority_ref`. A zero
  ceiling denies.
- `ReservationRequest(operation_id, causal_key, reservation, cost_unit,
  request_fingerprint)` — one future recovery attempt: attempts and
  recoveries exactly 1, `wall_ms` and `cost_units` positive.
- `Observation(outcome, evidence_digest, actual, cost_unit)` — `unknown`
  (no actual, no unit) or `accepted`/`rejected` with an explicit actual
  vector. Unknown is never zero.

Tokens fully match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`; digests fully match
`[0-9a-f]{64}`.

## Storage

```
<project_root>/.unrest/continuation/recovery-reservations-v1/<mission_id>/
  writer.lock     created once at initialization; never unlinked or replaced
  snapshot.json   closed canonical snapshot, schema_version 1
```

`project_root` is an exact absolute, normalized `str` supplied by a trusted
caller; nothing is discovered from the working directory. The snapshot is
Canonical JSON v1 with integers as canonical decimal strings, sorted
operations, at most 256 operations and a 2 MiB reader bound. It stores no
totals, timestamps, clock readings, paths or free text; totals are recomputed
by the reader. Readers refuse anything else, including legacy W5 formats, with
`invalid_record` and never migrate.

Each component is opened relative to its parent without following symlinks.
Controlled directories and files must be owned by the effective user and not
group- or world-writable (`.unrest` may be group-writable); files must be
regular with one link.

## Accounting

For the mission, each root lineage and each causal key, `used` is the sum of
actual vectors of accounted operations (each counted once) and `reserved` is
the sum of reservations of operations without accounted settlement. A new
reservation is refused with `budget_exhausted` unless, for every scope and
dimension, `used <= ceiling`, `reserved <= ceiling - used` and
`request <= ceiling - used - reserved`. A determinate observation replaces the
reservation with its actual once; overrun is a diagnostic only. Actual above a
ceiling is retained as a fact.

A pending operation for the same causal key refuses a new operation
(`causal_pending`). Exact retries are idempotent; changed immutable fields
are `intent_conflict`.

If a determinate actual would make any aggregate exceed `INT64_MAX`, the
observation is stored, the operation becomes `unaccounted` and the ledger
durably enters mission-wide `accounting_blocked`. Blocked ledgers refuse every
new reservation, freeze settlement, keep accepting late observations for all
outstanding operations, and expose only `BlockedAccounting`
(`accounting_complete` is always false). There is no reset or unblock.

Capacity for the blocked marker and both observations of every operation is
reserved before a new operation is admitted (worst-case size 355 552 bytes for
256 maximal operations).

## Custody and publication

`initialize_ledger` explicitly creates the namespace; `read_ledger` never
writes or locks. `acquire_writer` takes a nonblocking `flock` on the stable
lock, refuses unexpected entries, and publishes the next writer epoch. A
session refuses with `custody_lost` after close, after poisoning, or from a
process other than the acquiring one; a forked child's `close()` only closes
descriptors and never issues `LOCK_UN`. A session without `close()` holds the
lock until process exit. Re-entrant `close()` from inside a session method in
the same thread is unsupported.

Publication writes an exclusive staging file, fsyncs it, renames it over the
snapshot and fsyncs the directory; initialization also syncs created
ancestors. A failure at or after the rename is `publication_unknown`; the
session is poisoned, nothing is rolled back and callers must reconcile by
reading before any external effect.

## Known loss of writer liveness

Crash-left state is detected and refused, not recovered:

- an orphan staging file, `.DS_Store` or any other extra entry in the mission
  directory makes `acquire_writer` refuse with `namespace_conflict` while a
  snapshot exists;
- a partial initialization (directory, lock or staging without a snapshot) is
  `not_initialized` for initialization, reading and writing.

No cleanup, repair or reset API exists in v1; recovery is a separately
authorized operator procedure.

## Limits of the claim

Guarantees cover one physical mission namespace reachable from the supplied
trusted root, cooperative writers using this module, a local filesystem and a
process crash. Copies, restores or moves of the tree create independent,
undetected ledgers. Power loss, remote filesystems and hostile same-user
activity are not covered. In-tree tests use same-process locking and injected
faults only; Linux, real fork and real process-crash evidence remains open.

## Errors

Every failure is `ReservationLedgerError` with one closed `code` from
`CODES`; `str(error) == code`. Errors are raised outside internal handlers,
carry no path, token, OS text or snapshot content, and do not chain module
exceptions.

Returned views are not write sources: every mutator re-reads and revalidates
the snapshot and builds its candidate from those bytes. Private attributes of
views and sessions are not isolated against deliberate in-process mutation
(for example `object.__setattr__` on `_state`); that is outside the trust model.
