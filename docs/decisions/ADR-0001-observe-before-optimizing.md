# ADR-0001: Observe before optimizing iteration

## Record metadata

id: ADR-0001
status: proposed
date: 2026-08-07
task_ids:
  - TELEMETRY-MAIN
contract_targets:
  - VAL-OBS-ALL
  - VAL-OBS-CLI
  - VAL-OBS-CONTAINMENT
  - VAL-OBS-NONPREDICTIVE
  - VAL-OBS-PACKAGE
  - VAL-OBS-PRIVACY
  - VAL-OBS-PROJECTION
  - VAL-OBS-READONLY
  - VAL-OBS-SHADOW
  - VAL-OBS-SNAPSHOT
supersedes: []
superseded_by: null
protected_surfaces: []
evaluation_tier:
  - full-repository
  - installed-wheel
  - real-cli

## Scope

- In scope: a read-only operator snapshot and a durable inventory of postponed
  iteration-speed changes.
- Out of scope: dispatch, recovery, gate, attention, evidence-policy,
  capability-policy, promotion, concurrency, and persistence changes.

## Context

Recent missions spent days between useful state transitions, but the runtime
did not expose a coherent state, freshness, progress, or timing view. Without a
measurement surface, a scheduler change could make a run appear faster while
silently weakening validation or duplicating mutable work.

The first increment therefore adds observation without new authority. It does
not claim that elapsed time is a heartbeat, that a process is dead, or that a
completion estimate can be inferred from cursor timestamps.

## Decision

Ship `unrest observe-project` as a read-only schema-version-1 projection. Its
shadow scheduler output remains diagnostic and cannot trigger runtime work.
Keep the following optimization candidates postponed until each candidate has
its own accepted contract, benchmark, rollback, and protected review.

| Candidate | Material upside | Main downside | Self-improving quality risk | Earliest activation evidence |
| --- | --- | --- | ---: | --- |
| Event-driven wake and dispatch | Removes idle gaps between completed attempts and the next runnable task | Competing wakeups can double-dispatch or reorder authored work | 4/5 | Single-writer ownership, idempotent wake tests, crash/restart tests, and measured idle-gap reduction |
| Bounded automated recovery | Reconciles landed attempts without waiting for an operator | File age is not liveness; false recovery can race a live provider | 4/5 | Explicit lease/heartbeat contract, process-ownership proof, and recovery race tests |
| Exact-identity evidence reuse | Avoids repeating expensive checks when source, command, environment, and artifacts are identical | Stale or incomplete identity can convert old proof into a false pass | 5/5 | Immutable revision binding, clean-tree proof, complete artifact inventory, fail-closed mismatch tests, and protected evaluation |
| Readiness and gate-result reuse | Avoids rerunning unchanged final checks | A cache-key omission can bypass fresh validation or terminal review | 5/5 | Normative freshness policy, dependency closure in the key, invalidation tests, and rollback drill |
| Finite capability-analysis closure | Prevents open-ended semantic review from repeatedly inventing adjacent obligations | A boundary that is too narrow can hide a real egress or authority gap | 3/5 | Accepted finite source/transform/sink inventory with explicit allow, deny, and unsupported outcomes |
| More mutable work concurrency | Can shorten independent implementation slices | Shared checkout, cursors, fixtures, or generated files can corrupt attribution | 5/5 | Isolated worktrees and evidence roots, deterministic integration, conflict tests, and no shared mutable workers |
| ETA prediction | Improves operator planning but does not itself speed execution | Sparse and heterogeneous attempts produce confident-looking fiction | 3/5 | Enough labelled timing samples, calibrated error reporting, and an explicit unknown state |

The validated telemetry-hardening release does not activate any row in this
table. Its disposition of the earlier inventory is:

- already landed before this release: hermetic temporary Git repositories,
  passive timing telemetry, scheduler/recovery characterization, truthful
  report-only states, and passive shadow scheduling;
- landed in this release: bounded capture, corrected schema-v1 rendering and
  projection, additive strict collection exits, ambient-configuration
  diagnostics, and removal of the observer's cold timestamp-parser import
  cost;
- superseded: the draft capability corpus, which Batch 0 replaced with the
  formal finite capability policy; and
- still postponed: event-driven/background wake and dispatch, automated
  recovery, evidence or gate-result reuse, ETA, coordinator-owned memory
  semantics, and concurrent mutable work.

Uncapped `advance_project` already proceeds synchronously from one completed
worker into the next coordinator step. The remaining multi-day iteration issue
is outside that loop: external host wake cadence plus attention,
gate-checkpoint, and closure boundaries. Changing that cadence requires a
persistent cross-process single-writer lease and restart/idempotency evidence;
observer output does not supply or authorize either.

Priority after telemetry is based on measured wall-time loss, not theoretical
throughput. Idle-gap removal should be investigated first. Evidence or gate
reuse must not be activated merely because it offers the largest apparent
saving; it has the most direct route to degrading self-improving quality.

This ADR remains proposed and is absent from the accepted-decision index. It
records the scope boundary and does not authorize any postponed behavior.

## Validation contract

### VAL-OBS-CLI: Operator command

Surface: CLI.
Needs: a configured empty or populated Unrest projects root.
Behavior: exactly one project or `--all` produces schema-version-1 text or JSON
with deterministic ordering; rendering is byte-deterministic for a fixed
observation time and unchanged cursor generation. Invalid selectors, format,
threshold, or project return closed value-free errors.
Evidence: focused `CliRunner` cases and fresh installed-wheel commands with
stdout, stderr, and exit codes.

### VAL-OBS-PROJECTION: Structural runtime facts

Surface: CLI.
Needs: representative typed cursor fixtures.
Behavior: the documented state, progress, tasks, gates, attention, attempts,
timings, and anomaly fields project existing cursor facts without bodies.
Evidence: an exact draft schema-v1 golden and representative state tests.

### VAL-OBS-READONLY: No authority or mutation

Surface: CLI.
Needs: a real project tree and persistence-method spies.
Behavior: observation performs no filesystem writes and leaves tree membership,
types, symlink targets, contents, modes, and modification times unchanged. File
access times are outside this promise because ordinary reads may update them.
It invokes no persistence, coordinator, dispatcher, recovery, gate, attention,
or scheduler authority.
Evidence: complete before/after tree inventory of the promised fields,
mutator-call traps, source-edge check, and repeated installed-wheel observation.

### VAL-OBS-SNAPSHOT: Coherent bounded capture

Surface: data.
Needs: atomic cursor replacement fixtures.
Behavior: observation returns one coherent generation or `snapshot_changed`
after three attempts, never mixed old and new cursor facts.
Evidence: one-change recovery and three-change exhaustion tests.

### VAL-OBS-CONTAINMENT: Filesystem boundary

Surface: data.
Needs: filesystem fixtures with symbolic links and external sentinels.
Behavior: observation stays within one immediate configured project and fails
closed on traversal, links, or non-regular cursor components.
Evidence: project selector, projects-root, durable-root, cursor, and malformed
attempt tests with sentinel-absence assertions.

### VAL-OBS-PRIVACY: Bounded output

Surface: CLI.
Needs: malformed and valid-but-adversarial cursor fixtures.
Behavior: output excludes task bodies, reports, workspace paths, credentials,
environment values, control characters, and overlong identifiers; failures
contain only closed codes and bounded references.
Evidence: body sentinels, malformed JSON, control-character, overlong-ID, and
value-free option-error tests.

### VAL-OBS-ALL: Complete aggregation

Surface: CLI.
Needs: empty and mixed valid/corrupt multi-project roots.
Behavior: `--all` sorts projects, uses one observation time, retains every
bounded failure, and handles a missing or empty root.
Evidence: empty-root, order, shared-time, and per-project corruption-isolation
tests.

### VAL-OBS-SHADOW: Passive scheduler parity

Surface: library.
Needs: the current coordinator selection as the oracle.
Behavior: advisory task selection matches current capacity/order/dependency
cases, always reports `dispatch_performed=false`, and has no authority import.
Evidence: a differential coordinator matrix, zero dispatcher calls, and a
source-edge assertion.

### VAL-OBS-NONPREDICTIVE: Timing boundary

Surface: CLI.
Needs: controlled file timestamps.
Behavior: elapsed values are labelled `file_mtime`; stale means inspection
candidate, and no heartbeat, effort percentage, ETA, or completion prediction
is emitted.
Evidence: controlled stale/recovery tests plus schema and output absence checks.

### VAL-OBS-PACKAGE: Installed distribution

Surface: artifact.
Needs: a frozen candidate wheel and an unrelated working directory.
Behavior: the installed package exposes `observe-project` without importing
the source checkout.
Evidence: build and distribution checks, import provenance, help, empty-root,
and representative real-project commands.

## Alternatives considered

- Activate shadow scheduling immediately: quicker apparent progress, but the
  observer has no single-writer or idempotency authority.
- Persist new telemetry events: richer history, but it introduces another
  writer and migration surface before file-derived observation is evaluated.
- Publish an ETA from attempt timestamps: attractive dashboard output, but the
  current timestamps cannot separate provider, tool, test, queue, and idle
  time.

## Consequences

- Positive: operators can identify active, stale, runnable, gate-ready,
  recovery-ready, attention, and terminal states without changing them.
- Negative/cost: telemetry alone does not materially shorten a mission.
- Compatibility/hard cut: observation JSON starts at schema version 1 and uses
  closed, value-free error codes.
- Compatibility after hardening: schema version 1 is retained. `--strict` is
  additive and limited to `--all`; without it, degraded collections keep their
  prior zero exit after emitting the complete payload.
- Schema/migration impact: none; the observer persists nothing.
- Security/privacy impact: output is limited to identifiers, counts,
  timestamps, hashes, and closed reason codes; it excludes task bodies,
  prompts, reports, workspace paths, credentials, and environment values.

## Protected-surface review

- Protected categories: none under the current protected-surface selectors;
  future activation is expected to touch coordinator, governance, promotion,
  or capability surfaces and must be classified then.
- Required reviewers: none for this proposed record; maintainer approval is
  still required for merge under repository policy.
- Review evidence: focused observer and CLI tests plus real-project CLI output.
- Evaluation evidence: repository, installed-wheel, and real-CLI checks.

## Rollback

- Trigger: observation writes state, exposes excluded content, diverges from
  authoritative selection, or breaks an existing CLI surface.
- Procedure: revert the isolated telemetry commit and reinstall the preceding
  wheel.
- Data recovery: none because the feature writes no project data.
- Verification: compare the project tree before and after observation and run
  the focused CLI and observer tests.

## Implementation and verification

- Components/paths: `COMP-OBSERVABILITY`,
  `src/unrest_harness/runtime_observability.py`, and
  `src/unrest_harness/cli.py`.
- Normative documents: `ARCH-RUNTIME-001` and `ARCH-OBSERVE-001`.
- Tests/evidence: `tests/test_runtime_observability.py`, `tests/test_cli.py`,
  repository validation, wheel inspection, and a real `observe-project` call.

## References

- `docs/v5/07-runtime-architecture.md`
- `docs/architecture/change-governance.md`
- `policy/protected-surfaces.yaml`
