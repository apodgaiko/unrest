# Telemetry and cold-start hardening

This release finalizes the read-only schema-v1 runtime observer hardening on
sealed implementation tree `1f963ef1004b308a82dfc402ebcdec436afeef03`,
compared for performance with fixed base
`2d393cf1e077e081598719292456c20f6bd1a616`. It changes observation and operator
diagnostics only. It does not grant the observer dispatch, recovery, gate,
attention, evidence-reuse, ETA, or concurrency authority.

## Operator changes

- `unrest observe-project --all --strict` emits the same complete text or JSON
  payload as default `--all`, then exits 1 if any project failed. Default
  degraded collections continue to exit 0; successful collections exit 0 in
  either mode. `--strict` is not valid with a single project.
- A malformed project no longer suppresses successful projects in an aggregate
  result. Text lines are capped at 240 characters, display identifiers at 80
  characters including their deterministic digest, and large anomaly sets
  retain the exact total with no omitted identifiers.
- Invalid supported ambient configuration produces the closed
  `invalid_configuration` diagnostic and a nonzero exit without a traceback or
  offending value. Observation failures remain closed codes:
  `invalid_format`, `invalid_project_id`, `invalid_stale_threshold`,
  `malformed_cursor`, `project_not_found`, `non_current_mission`,
  `snapshot_changed`, `unsafe_cursor`, and `unsafe_project_path`.
- Mission selection remains current-only. The current mission is supported; a
  malformed selector is `malformed_cursor`, while a valid missing or
  non-current mission is `non_current_mission`.
- Capture is limited to 4 MiB per selected regular file, 16 MiB total, 4,096
  selected files or directory entries, depth 6 from the project root, and
  three coherent snapshot attempts. Enumeration is bytewise sorted. Limit,
  containment, replacement, non-regular-file, and filesystem failures close
  with bounded codes; capture does not follow links, block on swapped FIFOs, or
  leak descriptors.
- Ready-gate projection follows authored order. Running-task diagnostics retain
  every reconciliation classification, and failed-task attention correlation
  is scoped to the same mission and task. These projections remain advisory
  and report `dispatch_performed=false`.
- Attempt timestamps keep the existing operator-visible
  `YYYY-MM-DDTHH-MM-SSZ` form and optional four-digit parallel suffix, with
  ASCII UTC and calendar validation. The parser now avoids cold imports of
  `_strptime` and `calendar`; existing attempt files require no rename.

## Compatibility, upgrade, and rollback

The public JSON schema remains version 1, cursor formats are unchanged, and the
observer still writes nothing. Upgrade by installing the candidate wheel; no
project-data migration or cursor rewrite is required. Scripts that need a
degraded aggregate to fail should add `--strict`; scripts relying on the
existing default zero exit can remain unchanged.

Rollback by reverting this release's product and documentation changes and
reinstalling the preceding wheel. No data recovery is required. Verify rollback
with focused observer and CLI tests, read an existing project using the
preceding wheel, and compare project-tree membership, types, link targets,
contents, modes, and modification times before and after observation.

## Performance evidence and negative results

Only the public ruler and the prospectively frozen v3 run support release
performance claims. The public run on predecessor implementation tree
`42d84aed5c0f96e3ca0e61f1fde1cd750a7fc8db` is retained as historical
evidence: on all 19 cases, normalized output was exact, deterministic fields
were stable, and observed trees were unchanged. Across the six public
10/40-history cases, contract-prose and irrelevant-history body reads were
zero, minimum read reduction was 96.486%, and maximum candidate median traced
peak was 86,889 bytes. The final v3 held-out record binds to implementation
tree `1f963ef1004b308a82dfc402ebcdec436afeef03`: it selected 6 instead of 128
files, read 1,529 instead of 63,167,217 bytes (99.997579% less), and reduced
median traced peak from 64,846,835 to 85,044 bytes (99.868854%). Its paired
loopback record also binds to `1f963ef1004b308a82dfc402ebcdec436afeef03`.

The failures are retained rather than averaged away. V1 failed the public
memory guardrail and was incomplete as held-out evidence because it had no
frozen derivation, input hash, or oracle. V2 supplied a valid prospective case
but failed the cold first-observation limit: its candidate peak was 1,221,623
bytes, above the 307,200-byte ceiling; public 40/0 also peaked at 1,221,363
bytes with only 31.1167% reduction. Attribution found the cold
`datetime.strptime` import inside the measured region. The numeric parser
repair was accepted only by the later v3 commitment and ledger.

Latency was measured with one warmup and seven alternating fresh processes,
but it is a secondary, environment-sensitive signal. The figures above prove
bounded observer I/O and allocation for the validated workloads; they do not
claim universal latency or mission elapsed-time savings.

## Landed, superseded, and deferred work

- Already landed before this release: hermetic temporary Git repositories,
  passive timing telemetry, scheduler/recovery characterization, truthful
  report-only states, and passive shadow scheduling.
- Landed here: bounded current-generation capture, coherent replacement and
  filesystem handling, corrected bounded rendering/aggregation, schema-v1
  count and selector behavior, passive projection parity, additive strict
  exits, ambient-configuration diagnostics, and cold timestamp parsing.
- Superseded: the draft capability corpus; Batch 0's formal finite capability
  policy is authoritative. The unused exact-identity helper remains excluded.
- Deferred: autonomous/background dispatch, automated recovery, evidence or
  gate-result reuse, ETA, coordinator-owned memory semantics, and concurrent
  mutable work.

Uncapped `advance_project` already continues synchronously through coordinator
steps. The remaining multi-day iteration issue is external wake/checkpoint
cadence around host automation, attention, gate-checkpoint, and closure
boundaries. Addressing it needs a separate protected design for cross-process
single-writer ownership, restart, and idempotency; this release neither solves
nor measures that saving.

## Claim-to-contract evidence map

| Release claim | Contract | Validated evidence |
| --- | --- | --- |
| Complete aggregate payload and additive exit 1 under `--strict` | `VAL-CLI-001`, `VAL-RENDER-002`, `VAL-SCHEMA-002` | Installed source/wheel default/strict text/JSON matrices for success, mixed, and all-failed roots |
| Bounded identifiers, lines, exact anomaly totals, and canonical counts | `VAL-CLI-002`, `VAL-RENDER-001`, `VAL-SCHEMA-001` | Boundary and 100-ID render cases plus the executable 43-scenario schema-v1 corpus |
| Value-free configuration and selector diagnostics | `VAL-CLI-003`, `VAL-MISSION-001`, `VAL-SCHEMA-002` | Installed 12-mode CLI matrix and malformed/current/non-current selector matrix |
| Current-only, bounded, coherent, nonblocking, descriptor-safe capture | `VAL-CAPTURE-001` through `VAL-CAPTURE-006` | Adversarial limit, replacement, FIFO/non-regular, filesystem-fault, resource, tree-identity, and 121-case observer tests |
| Authored gate order, complete running reconciliation, and task-specific attention | `VAL-SHADOW-001`, `VAL-SHADOW-002`, `VAL-ANOMALY-001` | Differential real-coordinator traces with mutation traps and exact per-task classifications |
| Timestamp grammar preserved without cold heavy imports | `VAL-COLDSTART-001` | Exhaustive calendar/suffix equivalence, cold subprocess module-absence proof, and legacy/current deep traces |
| Zero prohibited body reads and bounded public/v3 allocation | `VAL-PERF-001`, `VAL-PERF-REPAIR-001` | Historical 19-case public ledger on predecessor `42d84aed...`; final v3 held-out and loopback records on `1f963ef...`; v1/v2 failures retained |
| No migration and bounded rollback | `VAL-ROLLBACK-001` | Schema-v1/cursor compatibility, isolated wheel lifecycle, focused observer/CLI checks, and read-only tree inventory |

The normative operator details are in
[`ARCH-RUNTIME-001`](../v5/07-runtime-architecture.md); the authority boundary
and postponed inventory remain in
[`ADR-0001`](../decisions/ADR-0001-observe-before-optimizing.md), which is still
proposed and does not activate deferred work.
