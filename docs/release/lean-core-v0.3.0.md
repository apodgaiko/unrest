# Unrest v0.3.0 — Foundation & Safety

Unrest v0.3.0 is a backward-compatible foundation and runtime-safety release.
It promotes the substantial FM-000 research foundation and the mutation-safety
work developed during the intermediate v0.2.1 cycle. It does **not** yet ship
the proposed general-thinker runtime.

## Main updates

### Governed v0.3 foundation

- Six proposed ADRs cover authority, identity, Inquiry, workspace isolation,
  evolution, and compatibility.
- Eight contract documents and their decision fixtures make the future v0.3
  boundaries concrete and testable.
- These artifacts remain explicitly proposed: they guide later missions but do
  not silently change current Mission authority.

### Cross-process mutation safety

- All five mutating orchestrator MCP operations share one per-project OS lock.
- A second server fails fast with `project_busy` instead of overlapping a live
  mutation or fabricating missing-attempt failures.
- Lock setup and acquisition errors fail closed as `project_lock_error`.
- Different projects remain independently runnable.

### Cancellation-safe ownership

- Caller cancellation no longer releases mutation ownership while the
  controller thread is still running.
- Acquire, controller execution, and release remain in one worker-thread
  lifetime.
- Detached mutations are retained and observed until completion, preventing a
  timed-out caller from admitting duplicate work.

### Stronger release evidence

- Release identity is bound across package metadata, runtime, lockfile,
  citation, tests, CI, source inventory, and archive names.
- The release flow verifies complete wheel and sdist membership and bytes,
  safe sdist extraction, the extracted persistence suite, and an installed
  wheel from an unrelated directory.
- FM-000, FM-010, and recovery-run forensics are preserved so unfinished or
  aborted research cannot masquerade as shipped capability.

## Compatibility and installation burden

- Python `>=3.11` remains supported.
- No dependency family, data migration, always-on service, or configuration
  step is added.
- Existing persisted project formats and ordinary CLI/MCP entry points remain
  compatible.
- Operators may newly observe `project_busy` or `project_lock_error` when a
  competing mutation would previously have been unsafe.

## Deliberate non-goals

This release does not include asynchronous run admission/attach, the FM-010
measurement baseline, Inquiry fan-out, mutable parallel agents, automatic
self-improvement campaigns, or the general-thinker runtime. Those remain
separate, bounded follow-up missions.

The active release binding is
`effab6ecbde8d8336dd56a16211be8d9587ad3258234dbf0bd7bb82a5a37c2a4`
over `134` product/package/test files. See
[`lean-core-v0.3.0-manifest.json`](lean-core-v0.3.0-manifest.json) and the
[`v0.3.0 rollback record`](lean-core-v0.3.0-rollback.md).
