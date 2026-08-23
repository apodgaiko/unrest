# Unrest v0.2.1 local candidate

Status: locally verified candidate; not tagged or published. The candidate is
resolved through `refs/heads/codex/v0.2.1-foundation-safety`; the future
annotated release is resolved through `refs/tags/v0.2.1` only after the parent
creates it.

## What changed

This intermediate release preserves FM-000 commit
`2b17a613b99ef182c9bae18b8171efc17e8fe8d2`: its six ADRs, eight contracts,
and decision fixtures remain proposed, non-authoritative groundwork. The only
runtime delta is an OS-owned, fail-fast per-project lock shared by the five
mutating orchestrator operations. It prevents independent MCP server processes
from mutating one project concurrently and adds `project_busy` and fail-closed
`project_lock_error` outcomes. It adds no dependency or migration.

FM-010 is untrusted research, not release evidence. Its measurement baseline,
pre-dispatch custody chain, telemetry framework, capability-policy changes,
and general-thinker runtime are not implemented by v0.2.1.

## Identity and authority

- Version: `0.2.1` in package metadata, runtime, lockfile, citation, tests, CI,
  and expected archive names.
- Live product/package/test binding: `0f63515120030781dd4258de2747b6f61717100a966e22feccf3f6fc57d50600` over 133
  prospective committed regular files selected from `pyproject.toml`, `uv.lock`,
  and `src/**`, `tests/**`, and `tools/**`.
- Live manifest: [`lean-core-v0.2.1-manifest.json`](lean-core-v0.2.1-manifest.json).
- Historical authority: the five `lean-core-v0.2` carriers are byte-identical
  to tag `v0.2.0`; their `0.2.0` identities and chronology are intentionally
  unchanged.

The [forensic report](unrest-v0.2.1-forensics.md) records why this release is
narrow. The [rollback record](lean-core-v0.2.1-rollback.md) and
[parent handoff](unrest-v0.2.1-parent-handoff.md) are pre-publication operator
records. Exact candidate commit/tree and built wheel/sdist sizes and hashes live
in the out-of-tree `mission-002/evidence/candidate-release-receipt.json`.
The exact annotated-tag-object identity belongs to the finalized post-tag
handoff evidence. Keeping those values out of tracked carriers avoids making a
file claim an identity that its own edit changes.
