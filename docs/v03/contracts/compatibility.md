# Compatibility and rollback contract

Status: **accepted for v0.3.1**. This contract supports
[ADR-0305](../../decisions/ADR-0305-compatibility.md). Proposal-era wording and
the pinned v0.2 inventory below remain dated compatibility provenance; current
runtime authority comes from the accepted ADR and v0.3.1 contract.

## Artifact set

All paths are relative to the repository root:

- `tests/fixtures/v03_decisions/compatibility/v02-source-inventory.v1.json`
- `tests/fixtures/v03_decisions/compatibility/compatibility-matrix.v1.json`
- `tests/fixtures/v03_decisions/compatibility/persistence-probes.v1.json`
- `tests/fixtures/v03_decisions/compatibility/rollback-and-rejections.v1.json`

Collections use the declared inventory order with two-space indentation and one
trailing newline. Matrix rows are positional according to their explicit
`columns` array. These are decision fixtures, not runtime schemas or migration
inputs.

## Exact-once matrix rules

The inventory declares `surface_id`, `category`, `surface`, and one or more
current source locators. The matrix must:

1. use the same exact base commit/tree and inventory version;
2. contain exactly the inventory `surface_id` set—no missing, duplicate, or
   unknown IDs;
3. use exactly one of `preserved`, `changed`, `migration-sensitive`, or
   `gated` per row;
4. provide non-empty current truth, proposed rule, rationale, current
   authority, downstream owner, compatibility effect, verification, and
   rollback fields; and
5. retain each accepted v0.2 hard cut as an absence, never as a revival.

The only `migration-sensitive` row is the absent-`attempt_id` base-era reader.
The attempt-kind reader is preserved narrow observed legacy, not a migration
facility. Uncertain internal public API and future optional extras are gated.

## Frozen persistence oracle

`tests/test_persistence_schema_v1.py` and everything below
`tests/fixtures/persistence_schema_v1/` remain unchanged. The inventory pins
their current hashes. The exact test command is:

```bash
uv run pytest -q tests/test_persistence_schema_v1.py
```

Collection must be exactly 14 and the result must be exactly 14 passed. The
fixture hash/baseline test, eight state scenarios, two absent-member handoff
cases, and three malformed/future-state cases are the frozen partition.

## Fresh negative probe contract

`persistence-probes.v1.json` defines three independently materialized
temporary cases. A runner must use the real `ProjectStore.read_attempt` method,
not model validation alone or a mock. It must write the declared canonical
bytes beneath a fresh `.unrest-runtime/.../attempts/` path and record SHA-256
before and after.

Explicit null, mismatch, and replay must each raise `AttemptValidationError`;
the bytes and digest must be unchanged. A probe must not dispatch, clear a
task, write a durable Markdown mirror, or mutate the frozen suite. Temporary
root cleanup belongs to the runner after results are captured.

## Single-authority and rejection rules

Source inspection must find one product definition of `MissionCoordinator` and
the documented `ProjectController -> MissionCoordinator.step -> ProjectStore`
transition path. The decision fixtures must reject a second coordinator,
observer scheduler, generic migration framework, heuristic schema reader,
null-as-absent coercion, replay fallback, and all hard-cut revivals.

## Core-without-extras rollback rules

The base has no `[project.optional-dependencies]`. A later frozen candidate is
valid only if its ordinary wheel, installed without extras into an isolated
environment and exercised from an unrelated directory, proves the commands
and provider-independent lifecycle listed in ADR-0305. The transcript must
record exact archive identity, installed metadata, commands, exit codes,
created state, restart result, terminal review, closure, schema-v1 read, and a
fail-closed unsupported-capability probe.

Future extras are only a gated contract. This artifact makes no T2 removal
claim because there is presently nothing to remove.

## Failure and cancellation

Any invariant failure is terminal for this artifact review. Do not repair it
by editing frozen fixtures, adding a compatibility runtime, or weakening the
inventory. On cancellation, stop subprocesses and remove only runner-owned
temporary state; retain source and transcripts already produced.
