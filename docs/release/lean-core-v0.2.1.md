# Unrest v0.2.1 local candidate

Status: candidate; not tagged or published. Candidate commit and archive checks
remain owned by the freeze/verification step.

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
- Live product/package/test binding: `efc1aeae63456cfa92d9d10c141e3da27cbe1747b8e5a703afe372d6c728bfd4` over 133
  prospective committed regular files selected from `pyproject.toml`, `uv.lock`,
  and `src/**`, `tests/**`, and `tools/**`.
- Live manifest: [`lean-core-v0.2.1-manifest.json`](lean-core-v0.2.1-manifest.json).
- Historical authority: the five `lean-core-v0.2` carriers are byte-identical
  to tag `v0.2.0`; their `0.2.0` identities and chronology are intentionally
  unchanged.

The [forensic report](unrest-v0.2.1-forensics.md) records why this release is
narrow. The [rollback record](lean-core-v0.2.1-rollback.md) and
[parent handoff](unrest-v0.2.1-parent-handoff.md) remain pre-publication
operator records.
