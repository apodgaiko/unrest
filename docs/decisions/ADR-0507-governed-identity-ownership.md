# ADR-0507: Own project and mission identity for governed criterion admission

## Record metadata

id: ADR-0507
status: accepted
date: 2026-11-10
task_ids:
  - GOVERNED-S1
contract_targets:
  - VAL-GS1-01-62
  - VAL-GS1-IC-01-10
  - VAL-GS1-ID-01-14
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-inprocess
  - milestone

## Scope

- In scope: exclusive bucket claim in `start_project`; the `.unrest/identity` footprint (initialization, readiness, per-mission reservations and legacy-consumption markers); four-way identity classification; the single next-mission reservation point in `decide_attention`; the reservation capacity; identity preconditions of governed admission; the governed S1 admission, dispatch gate, execution scope, transport witness and inspector described in `docs/architecture/governed-s1.md`.
- Out of scope: identity for projects created by other routes (they stay legacy), repair or migration of existing projects, cleanup of incomplete buckets, RunControl worker delivery, assessment, terminal review, `cli.py`, public catalogs, persistence schemas of existing records.

## Context

Governed admission must only bind criteria to a mission that has never run.
The baseline creates project buckets with `exist_ok` directories and allocates
the next mission as the count of runtime mission directories plus one, so a
reused project id or a removed runtime directory can give an old mission name
to new work. A freshness check over mutable runtime state alone cannot exclude
that history. A durable identity record outside `.unrest-runtime/` is needed
before admission can reject reuse.

## Decision

1. `start_project` claims the bucket with `os.mkdir` without `exist_ok` before
   any other effect; `FileExistsError` refuses `project_id_collision`.
2. On a governed-capable host it then writes `identity/init.json`, reserves
   `mission-001`, creates the project record and state, and finally publishes
   `identity/ready.json`. A crash at any point leaves the bucket incomplete;
   nothing repairs, cleans up or retries it.
3. `classify_identity` returns exactly one of `LEGACY` (only `lstat` ENOENT of
   `identity`), `INITIALIZING` (valid footprint without `ready.json`),
   `ELIGIBLE` and `IDENTITY_UNAVAILABLE` (any other shape, including more than
   4096 reservations). Partial or corrupt identity never falls back to the count
   allocator.
4. One mission id is allocated per decision batch, after validation and before
   the patch/seal fork: legacy keeps the count allocator; initializing and
   eligible reserve `1 + max(reserved index)` with exclusive creation (gaps
   allowed, reuse never); unavailable identity refuses
   `mission_identity_unavailable`; an existing reservation refuses
   `mission_id_reserved`. Every reservation producer calls one capacity check
   first; at 4096 existing reservations it refuses
   `mission_identity_capacity_exhausted` before any reservation or decision
   effect. Existing records stay readable.
5. Legacy `submit_plan` keeps the baseline sequence for `LEGACY`. Any
   `IDENTITY_UNAVAILABLE`, and `INITIALIZING`/`ELIGIBLE` without a reservation
   of the mission, refuse `mission_identity_unavailable` before submit effects.
   For `INITIALIZING`/`ELIGIBLE` the contract and task list are validated
   read-only first (no directory creation; a missing contract validates as
   empty), then `mission-NNN.consumed` is created or verified, and only then do
   the baseline contract-directory creation and writes run. A validation refusal
   leaves no marker; a marker failure or unknown outcome refuses; a marker on
   disk is never rolled back, so later failures keep the mission consumed.
   Exception parity with the baseline is limited and listed in
   `docs/architecture/governed-s1.md`. The existing no-follow governed
   classification refuses a non-regular `missions` or `missions/<mid>` for
   every cohort before these steps, for legacy submit and legacy dispatch.
6. Governed admission requires `ELIGIBLE`, a reservation for the mission and no
   consumption marker (`governed_identity_unavailable`), plus a freshness shape
   screen (`governed_mission_not_fresh`).
7. The identity codes are private `ToolError` codes of the lifecycle tools, like
   the other governed codes: the orchestrator MCP tools return them in the
   existing legacy error shape and RunControl projects them to the public
   `invalid_argument`. No public catalog changes.

## Alternatives considered

- Freshness from runtime directories only: cannot detect a removed runtime directory or a reused bucket.
- Re-using the count allocator for initializing projects: reintroduces reuse after a gap.
- Evicting or overwriting old reservations at the cap: destroys the reuse evidence the record exists to keep.
- Repairing incomplete buckets at start-up: adds a writer that can race the creator; deliberately not selected.

## Consequences

- Positive: governed missions cannot be admitted twice under one name inside one identity footprint, and reuse after runtime loss is refused instead of silently allowed.
- Negative/cost: a crash during project creation leaves an unusable bucket; capable new projects allocate mission ids from reservations, so a removed runtime directory leaves a gap; at most 4096 missions per identity footprint.
- Compatibility/hard cut: projects without `identity/` keep legacy allocation; deleting the whole footprint returns a project to legacy behavior (declared limit). Every cohort refuses legacy submit and idles legacy dispatch for a non-regular `missions` or `missions/<mid>` (link, dangling link, file, unsearchable directory), where the pre-governed baseline followed the link or raised; legacy compatibility holds only for absent or real, accessible `missions` and `<mid>` directories; identity-cohort submits differ from the baseline in the listed exception cases; rejected decision batches consume reservations (4096 including orphans).
- Schema/migration impact: new write-once records under `.unrest/identity` and `.unrest/missions/<mid>/governed`; existing records unchanged; no migration.
- Security/privacy impact: identity records hold only project and mission ids and pass the redaction guard; no new authority.

## Review

- Reviewer: maintainer authorization of governed S1 implementation after two independent design consultations, two contract reviews, an implementation scrutiny and a maintainer amendment of legacy submit ordering.
- Approval date/evidence: 2026-11-09/10; maintainer contract, amendment and authorization records kept outside the repository.
- Evaluation evidence: focused in-process tests under the no-launch guard only. Implementation, runtime and release acceptance remain false until independent verification.

## Rollback

- Trigger: contract violation, identity reuse, a refusal that leaves partial decision effects, or failed independent validation.
- Procedure: revert the governed modules, controller, coordinator, dispatcher, runner, server, test and documentation changes together with their pin rotations; preserve or explicitly supersede this ADR.
- Data recovery: existing identity and governed records are inert for the reverted code and may be left in place.
- Verification: focused governed and regression tests, pin closure, repository and documentation contracts.

## Implementation and verification

- Components/paths: COMP-GOVERNED (`src/unrest_harness/governed_records.py`, `src/unrest_harness/governed_admission.py`); controller, coordinator, dispatcher, ACP runner and server wiring.
- Canonical documents: docs/architecture/governed-s1.md; this index entry.
- Tests/evidence: `tests/test_governed_s1_*.py` run with `-p tests.governed_no_launch`; in-process only. CHILD-PY, Git, native ACP, distribution and CI evidence are separate.

## References

- docs/architecture/governed-s1.md
- docs/v5/08-mcp-surface.md
