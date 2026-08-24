# ADR-0305: Preserve the v0.2 compatibility and rollback perimeter

## Record metadata

id: ADR-0305
status: accepted
date: 2026-08-18
accepted_date: 2026-08-24
accepted_by: maintainer-v0.3.1-instruction
task_ids:
  - W-COMPATIBILITY
contract_targets:
  - VAL-COMP-001
  - VAL-COMP-002
  - VAL-COMP-003
  - VAL-BUR-001
  - VAL-BUR-002
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - real-reader-probe
  - installed-wheel

## Status and boundary

Accepted for v0.3.1 by the maintainer's explicit 2026-08-24 full-implementation
instruction. It extends rather than replaces the accepted authority in
[ADR-0002](ADR-0002-lean-core-v0.2.md) and the current
[architecture index](../architecture/index.md). Proposal-era wording below is
dated design rationale, not the current runtime-status oracle. Authorship,
chronology, successful verification, or mere presence still cannot independently
grant authority; the recorded maintainer decision and integrated evidence do.

Pinned v0.2 truth and the accepted additive v0.3.1 rules are deliberately
separate below.
The machine-readable [source inventory](../../tests/fixtures/v03_decisions/compatibility/v02-source-inventory.v1.json)
and [classification matrix](../../tests/fixtures/v03_decisions/compatibility/compatibility-matrix.v1.json)
are [contracted](../v03/contracts/compatibility.md).

## Scope

- In scope: exact classification of the pinned v0.2 install, Python, CLI, MCP,
  configuration, public API, persistence, directory, discovery, package-data,
  optional-extra, verification, coordinator, observer, and hard-cut surfaces;
  narrow readers; and the no-extra rollback path.
- Out of scope: heuristic migration, resurrection of deliberate hard cuts,
  required optional adapters/services, provider choice, or a second coordinator.

## Context

The v0.3.1 families introduce additive versioned concepts around a pinned base
whose current compatibility perimeter must remain explicit. The decision is
identified by base commit `96d5c0f0b240bd3373809546d7aecc1e407f837b`,
base tree `a6746372e3367ee11d974cbe4778f968a38f940f`, inventory
version `v02-source-inventory.v1`, and matrix version
`compatibility-matrix.v1`; a mutation requires a new classification.

## Current v0.2 truth

- The distribution is `unrest-harness==0.2.0`, supports Python 3.11–3.13,
  publishes `unrest` and `unrest-server`, supports `python -m unrest_harness`,
  and has no optional-dependencies table.
- Claude and Codex are the complete supported provider set. Four structurally
  separate MCP server identities expose seven orchestrator tools, a strict
  `end_node` tool to worker and validator identities, and a strict terminal
  review tool.
- `ProjectController` reloads from disk for public calls, one
  `MissionCoordinator.step()` owns one transition, and `ProjectStore` owns
  storage paths and atomic writes. There is no second coordinator.
- Durable records are under `.unrest/`; orchestrator cursors and handoff
  transport are under `.unrest-runtime/`. Workspace host discovery uses only
  the three skill surfaces and conditional `AGENTS.md` shim documented in the
  storage product contract.
- Persisted project/mission state remains schema v1. The frozen compatibility
  suite contains exactly 14 cases. Only a raw *absent* `attempt_id` receives
  narrow base-era treatment: filename generation and requested task identity
  bind it in memory without rewriting bytes. Explicit null, generation
  mismatch, and replay are invalid. The observed `items`/`passed` attempt-kind
  reader is retained but is not a schema-evolution mechanism.
- The compact read-only observer is schema v2. Observer v1, its aliases,
  detailed timing/count projections, and shadow scheduling are absent.
- ADR-0002 deliberately removed `check-governance`, `check-commit`, the third
  child-provider surface, terminal child credential inheritance, transformed
  secret redaction, duplicate root schemas, historical baseline generation,
  and broad static/recursive assurance. Those cuts have no compatibility shim.

## Accepted v0.3 decision

### Decisions and dispositions

| Decision ID | Disposition | Rule |
| --- | --- | --- |
| COMP-D01 | accepted | Classify every pinned v0.2 surface exactly once as preserved, changed, migration-sensitive, or gated, with authority, verification, compatibility effect, and rollback. |
| COMP-D02 | accepted | Preserve one Mission coordinator and only the two observed narrow readers; unsupported or ambiguous records fail closed without rewrite. |
| COMP-D03 | accepted | Preserve the ordinary no-extra wheel as the complete current Mission rollback path and require explicit removable boundaries for any future extra. |
| COMP-A01 | rejected | Add a shadow coordinator, observer scheduler, or adapter-owned Mission transition path. |
| COMP-A02 | rejected | Add a generic migration registry, heuristic reader, null coercion, replay fallback, or best-effort future-schema loading. |
| COMP-A03 | rejected | Revive an ADR-0002 hard cut through an alias, optional package, or renamed command. |
| COMP-A04 | rejected | Let an optional extra become required for Mission semantics or acquire Mission authority. |
| COMP-A05 | deferred | Select concrete future extras and their dependency/configuration removal drills after such extras exist. |
| COMP-A06 | deferred | Promise third-party stability for importable internal Python objects before a public-API decision. |
| COMP-A07 | deferred | Introduce migration for a future persistence record; until separately accepted, new records use explicit side-by-side versions. |

### Exact surface classification

Adopt the source inventory as the exhaustive baseline namespace and require
the compatibility matrix to reference every `surface_id` exactly once. Each
row has exactly one disposition from `preserved`, `changed`,
`migration-sensitive`, or `gated`, plus a rationale, current authority,
downstream owner, verification, compatibility effect, and rollback.

The inventory is source-derived rather than inferred from proposal prose. It
covers install, Python, distribution/version, CLI/module entries, providers,
MCP identities/tools/envelopes/handoffs, config, declared and uncertain public
APIs, persistence, runtime/durable directories, discovery shims, package data,
capability policy, optional extras, verification, aliases/no-op fields,
observer schema, coordinator ownership, and deliberate v0.2 hard cuts.
Missing, duplicate, unknown, or vaguely classified IDs fail the artifact.

### Compatibility authority and identity

The accepted v0.2 documents and exact base bytes remain current authority.
This decision is identified by the tuple
`(base_commit, base_tree, inventory_version, matrix_version)`. A later source
change, accepted ADR, package candidate, or inventory mutation requires a new
identity and fresh classification; chronology cannot carry a verdict forward.

FM-050 owns any future persisted-schema/storage integration, FM-200 owns the
coordinator/attention/ACP/capability path, FM-210 owns public CLI/MCP/config and
observer integration, and FM-390 owns dependency/package/registry/release
integration. None receives authority merely because this file names it.

### One coordinator and narrow readers

Compatibility preserves the single `MissionCoordinator` authority path. A
second coordinator, observer scheduler, adapter-owned transition path, or
compatibility controller is rejected. Compatibility preserves only the two
current narrow readers:

1. an absent `attempt_id` is bound in memory to the requested filename
   generation and task, without byte rewrite; and
2. an attempt containing `items` or `passed` is parsed as validation handoff,
   explicitly classified `observed_legacy`.

A generic legacy framework, heuristic schema guessing, coercion of explicit
null, “nearest version” selection, replay acceptance, or implicit rewrite is
rejected. New records use explicit versions and fail closed when unsupported.

### Persistence preconditions and recovery

The 14-case suite and its frozen files are not edited. Their recorded fixture
hashes and base-era provenance must match before any compatibility verdict.
The suite must collect and pass exactly 14 cases. The absent-member work and
validation bytes must survive two restarts unchanged.

Fresh real-reader probes separately materialize current runtime state and call
`ProjectStore.read_attempt` for:

- explicit JSON null `attempt_id`;
- a non-null `attempt_id` different from the filename generation; and
- a valid old attempt replayed under a different generation filename.

Each probe must raise `AttemptValidationError`, preserve the exact attempt
bytes, and make no success/cleared-state claim. The fixture definitions name
preconditions, operation, oracle, forbidden outcome, and cleanup owner. The
probe runner owns temporary-directory cleanup; FM-050 owns any future reader
change. Malformed or future state remains a bounded read failure with no
rewrite.

### Core-without-extras rollback

The ordinary wheel installed with no extras from an unrelated directory is
the rollback path. It must preserve:

- distribution import and version, bundled policy/config discovery, and
  fail-closed unsupported capability startup;
- `unrest --help`, `unrest-server --help`, and
  `python -m unrest_harness --help`;
- provider-independent create, plan, work, validate, gate, attention decision,
  restart, terminal review, closure, and schema-v1 reading; and
- separation of `.unrest/` from `.unrest-runtime/`.

No future v0.3 extras exist in the pinned `pyproject.toml`, so this mission can
prove only the no-extra wheel and specify future removal behavior. It must not
claim that a future extra was empirically removed or that T2 removal testing
occurred. Any future exporter, evaluator, durability, search, or workspace
extra must remain adapter/subsystem authority, be removable without changing
Mission state semantics, and have a named core fallback. Removing it means
uninstalling its dependency/configuration and rerunning the no-extra wheel
lifecycle; it never selects, coordinates, validates, promotes, or closes a
Mission.

Rollback owner is the maintainer/release integrator. On failure, disable the
additive v0.3.1 slice and reinstall the last accepted no-extra wheel; preserve
`.unrest/` and `.unrest-runtime/` separately. There is no schema-v1 Mission
data migration to reverse.

## Error, cancellation, and terminal disposition

Compatibility inspection is read-only. Any missing inventory member,
duplicate disposition, source-hash mismatch, frozen-oracle mutation, dangling
reference, reader acceptance of null/mismatch/replay, shadow authority path,
or no-extra lifecycle failure terminates validation as failed/blocked. It must
not synthesize a migration or compatibility shim.

Cancellation stops new probes, waits for any started subprocess, retains the
completed bounded transcript, and removes only the probe-owned temporary
directory. Candidate archives, canonical product bytes, frozen fixtures, and
project records are never deleted as cleanup. The validator owns probe
termination; the maintainer owns disposition of an incomplete decision.

## Alternatives considered

- **Rejected:** a compatibility `MissionCoordinator`, observer-driven
  scheduling, or adapter that writes Mission truth.
- **Rejected:** a generic migration registry, heuristic handoff classifier
  beyond the observed narrow reader, null-as-absent coercion, replay fallback,
  and best-effort future-schema loading.
- **Rejected:** reviving any ADR-0002 hard cut or hiding it behind an alias,
  optional package, or renamed command.
- **Rejected:** letting an optional extra become required for create/plan/work/
  validate/gate/restart/review/closure or obtain Mission authority.
- **Deferred:** concrete names, dependencies, and removal tests for future
  extras, because none exist on this base.
- **Deferred/gated:** third-party stability commitments for importable internal
  Python objects. `unrest_harness.__version__` and documented command/MCP
  surfaces are classified; all other import reachability needs a downstream
  public-API decision before a promise.

## Open questions

1. `COMP-Q01` / `COMP-A06`: Which internal Python objects, if any, will be intentionally exported as a
   versioned v0.3 library surface?
2. `COMP-Q02` / `COMP-A05`: Which future extras will be accepted, and what exact dependency/config
   removal drill will each require?
3. `COMP-Q03` / `COMP-A07`: Will any future persistence record require migration rather than a new
   versioned side record? Until accepted, the answer is no.

The cross-family dependencies and downstream owners are in the
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory).

## Consequences

The decision adds no migration framework. Its cost is an explicit matrix that
downstream changes must update
when they intentionally alter a surface. Rollback disables the additive
v0.3.1 surfaces while retaining this decision and its evidence; current
schema-v1 Mission behavior remains untouched.

- Positive: every compatibility promise has a pinned source and verification
  owner rather than inheriting authority from chronology.
- Negative/cost: every later intentional surface change must refresh the
  inventory, classification, and evidence.
- Compatibility/hard cut: all deliberate ADR-0002 cuts remain absent; no shim
  is introduced.
- Schema/migration impact: current schema-v1 reading remains exact; new future
  records require explicit versions and no generic migration facility.
- Security/privacy impact: compatibility evidence remains bounded and cannot
  expose secrets, prompts, source bodies, reports, or unrelated output.

## Review

- Reviewer: none
- Approval date/evidence: 2026-08-24 maintainer full-implementation instruction,
  accepted decision index, compatibility lanes, and validation contract.
- Evaluation evidence: focused fixture, link, frozen-oracle, real-reader, and
  installed-package checks.

## Rollback

- Trigger: downstream rejection, an incomplete classification, frozen-oracle
  drift, shadow authority, reader bypass, or failed no-extra lifecycle.
- Procedure: disable/remove the v0.3.1 additive surfaces; reinstall the last
  accepted no-extra wheel for any later failed implementation.
- Data recovery: preserve `.unrest/` and `.unrest-runtime/` separately; additive
  v0.3.1 stores remain side-by-side and do not rewrite schema-v1 Mission data.
- Verification: rerun the frozen schema-v1 and ordinary-wheel lifecycle checks
  against the accepted product object.

## Verification

The focused procedure is defined in the compatibility contract. It validates
inventory/matrix exactness, immutable fixture provenance, real-reader negative
probes, single coordinator ownership, rejected alternatives, and the existing
14-case suite. Installed-wheel proof belongs to frozen-candidate validation;
this draft specifies its required transcript and does not counterfeit one.

## Implementation and verification

- Components/paths: compatibility, storage, public-surface, and release owners.
- Canonical documents: ADR-0002, this accepted additive decision, its contract,
  and the architecture index are authoritative for their respective surfaces.
- Tests/evidence: strict fixture parsing, exact inventory/matrix partition,
  relative link/anchor resolution, three real-reader probes, the 14-case frozen
  suite, and the later installed-wheel lifecycle.

## References

- [Compatibility contract](../v03/contracts/compatibility.md)
- [Foundation integration contract](../v03/contracts/foundation-integration.md)
- [ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Architecture index](../architecture/index.md)
