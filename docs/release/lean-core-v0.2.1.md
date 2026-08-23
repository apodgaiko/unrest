# Unrest v0.2.1 local release record

Status: the candidate is resolved symbolically through
`refs/heads/codex/v0.2.1-foundation-safety`, and the annotated release through
`refs/tags/v0.2.1`. Exact commit, tree, artifact, and current tag-state facts
belong to mission-003 out-of-tree evidence and live Git inspection.

## What changed

This intermediate release preserves FM-000 commit
`2b17a613b99ef182c9bae18b8171efc17e8fe8d2`: its six ADRs, eight contracts,
and decision fixtures remain proposed, non-authoritative groundwork. The only
runtime delta is an OS-owned, fail-fast per-project lock shared by the five
mutating orchestrator operations. It prevents independent MCP server processes
from mutating one project concurrently, and it remains held for the controller
mutation's true worker-thread lifetime when a public await is cancelled. It
adds `project_busy` and fail-closed `project_lock_error` outcomes, with no new
dependency or migration.

FM-010 is untrusted research, not release evidence. Its measurement baseline,
pre-dispatch custody chain, telemetry framework, capability-policy changes,
and general-thinker runtime are not implemented by v0.2.1.

## Identity and authority

- Version: `0.2.1` in package metadata, runtime, lockfile, citation, tests, CI,
  and expected archive names.
- Live product/package/test binding: `469d6f831b32c4237e88c9d35f610c838b1abf8f505b1c3dee892c2cafadb656` over 133
  prospective committed regular files selected from `pyproject.toml`, `uv.lock`,
  and `src/**`, `tests/**`, and `tools/**`.
- Live manifest: [`lean-core-v0.2.1-manifest.json`](lean-core-v0.2.1-manifest.json).
- Historical authority: the five `lean-core-v0.2` carriers are byte-identical
  to tag `v0.2.0`; their `0.2.0` identities and chronology are intentionally
  unchanged.

The [forensic report](unrest-v0.2.1-forensics.md) records why this release is
narrow. The [rollback record](lean-core-v0.2.1-rollback.md) and
[parent handoff](unrest-v0.2.1-parent-handoff.md) are operator records. Exact
candidate commit/tree, built wheel/sdist sizes and hashes, and literal tag state
live in mission-003 out-of-tree receipts and the finalized handoff. Keeping
those values out of tracked carriers avoids making a file claim an identity
that its own edit changes.
