# Lean Core v0.2 release seal

Status: accepted current-candidate release record, 2026-08-11.

Lean Core v0.2 preserves the contract-backed mission lifecycle, schema-version-1
project persistence, single mutable-work scheduling, Claude/Codex provider
support, finite runtime authority, exact-known-value protection at the named
Unrest boundaries, compact read-only status schema version 2, the finite
repository checker, and the installed-wheel lifecycle.

The accepted hard cuts remove the historical baseline generator, governance
and commit-policy engine and commands, duplicate root schemas, static
capability source/sink proof, transformed-secret inference, detailed observer
schema version 1, the unsupported legacy child-provider surface, and raw root
release-history bulk. Git history and the concise historical release carriers
remain; raw current-mission evidence remains in the external Unrest mission
record rather than the product tree.

## Candidate and artifacts

- Scoring reference: commit `93c59e4378407f3d7cfb918cf86c8bdc81daa141`,
  tree `35152a4a8c56198664f519691ec952ec9ca519f4`.
- Frozen source checkpoint: combined binding
  `54e344233dbe7080bfcf8a4474b2e6ce5ac23cdc1beb7cbed9ab8c5d7f5aff3d`.
- Accepted post-remediation package source binding:
  `c420736a1ccba7a3d8891d6ddc6a976302df369d5822709468dc66c8ade385e0`.
- Accepted wheel SHA-256:
  `b0b02bc0820d03b9d7bdd42cb65cb9a624ba65504e553178eddfe4046d8a25b3`.
- Accepted sdist SHA-256:
  `504aa2eeb3c18173c5bc6bd2c1f908b6f6fb59f6e1613fcc10e259368e45a042`.

The package remediation added only the validated startup boundary and its
tests/docs after the frozen source checkpoint. The final archives are bound to
that remediated source. They contain neither this release record nor its
[manifest](lean-core-v0.2-manifest.json) or
[rollback record](lean-core-v0.2-rollback.md).

## Conclusion and measurements

The candidate is accepted against the Lean Core contract. Final package-source
physical LOC is 12,270 under `src/unrest_harness` and 25,958 across `src`,
`tests`, and `tools`, reductions of 52.31% and 50.42% from 25,730 and 52,351.
The conservative capability classification is 1,529 lines, including the
15-line post-freeze server startup boundary, below the 2,500-line ceiling.

All seven focused manifests passed their three frozen measured runs; medians
were repository 5.61s, lifecycle 2.50s, persistence 2.48s, scheduling 1.87s,
provider/security 10.39s, status 2.48s, and package 4.98s. The single accepted
source checkpoint for the refrozen binding ran
`env -u CODEX_PATH uv run pytest -q` and passed 681 tests with 7 explicit live
provider skips in 179.025s. The CLI cold-import median was 0.1755s (win); server
was 0.6257s (neutral, below its hard ceiling). Ruff, mypy, repository,
distribution, exact-wheel install, startup, lifecycle/restart, schema-v2
status, redaction, and package evidence-closure checks passed. Exact commands,
bindings, target maps, and results are in the manifest's seven slice ledgers.

## Final-candidate recovery

Release recommendation: accept the corrected Lean Core v0.2 delivery for the
separately governed branch-ready handoff. The fresh authoritative recovery
record is external at `mission-001/evidence/final-release-recovery-v7`; its
immutable command matrix
has SHA-256
`56bac287a2f7cff7d4fae5e62221df36b4f4ae72bf87f8fc88438f1563705c70`.
All 12 current product/repository rows and all 9 accepted-evidence rows passed
as separate processes on one pre-carrier delivery binding,
`b9b6f9b0fde712819a86e81b9ee8c422627648be29e7cf40f290cb2a289c6075`.

The first handoff commit and its v6 recovery ledger remain immutable failed
history: their plain diff gate omitted a then-untracked scheduling contract,
whose committed two-LF ending produced the base-aware `new blank line at EOF`
failure. Recovery v7 removes exactly that one terminal LF and changes no other
product, source, or test byte relative to the failed commit.

The recovery replayed the accepted frozen and quarantine-portable package
verifiers through their supported CLIs, rehashed the exact accepted wheel and
sdist, and compared current packaged source and restart-oracle bytes against
both archives with the current distribution checker. The fixed comparison
directory was confirmed to be a real directory containing exactly the two
expected archive symlinks, then those links alone were unlinked and the empty
directory removed. The four carrier-closure rows and the separately timed
provider/security guard passed after this carrier update; their raw streams,
timings, bindings, safe-cleanup records, and final recommendation are retained
only in the external v7 ledger. No full-suite rerun, standalone build, accepted
archive regeneration, or replacement installation was performed. The focused
provider/security rows did perform their intrinsic fixture-controlled temporary
build/install work in isolated test storage; that work created no accepted
release artifact.

## Evidence-retention conclusion

The root `evidence/` tree is absent. Equivalent raw current-mission history was
found under the repository-root `.validation/` tree, so the earlier claim that
new raw root logs/transcripts/manifests were simply absent was false. That tree
was moved intact, without link traversal or deletion, by a same-filesystem
rename to the external mission's
`evidence/repository-root-validation-quarantine-v3/payload`; its sibling
[control manifest](/Users/aleksandrpodgaiko/.unrest/projects/20260809T170516Z-read-only-assessment-of-the-attached-batch-0-5-lean-core-compact/.unrest/missions/mission-001/evidence/repository-root-validation-quarantine-v3/control/payload-manifest-summary.json)
binds 147,146 regular files, 2,284,382,540 bytes, 95 symlinks, and the identical
pre/post payload inventory SHA-256
`4c842e57f2357fa34b63d8727af36d9c8438c3b77bc85df0b233adc6ef8d99ba`.

The seven named concise historical carriers under `docs/release/` remain, and
their resolving references were corrected without embedding raw logs. The
three Lean Core carriers are the only new repository release records. Per-
mission evidence remains under the external mission's `.unrest/missions/
mission-001/` carriers, and the accepted archives remain checksum-bound there;
neither class is copied into package membership. This is the approved hard-cut
retention outcome, not a claim that Git history was rewritten or that the raw
validation history was discarded.

## Known limitations

- Status output is schema version 2 only; out-of-tree schema-v1 observer
  consumers must migrate or remain on v0.1. Persisted project/mission schema
  version 1 remains readable and unchanged.
- Exact-known credential values are protected under the documented short-token
  rule. Unknown or transformed secrets and intentional exfiltration by a
  credential-bearing child are outside the guarantee.
- Callback-root and terminal-cwd checks are not an operating-system sandbox,
  and Lean Core makes no network-denial claim.
- Server cold import is neutral rather than an optimization win.
- The seven source-suite skips are explicit live-provider smokes. The accepted
  source checkpoint required an approved local loopback-capable lane because
  the normal sandbox rejects loopback bind with `EPERM`.
- `VAL-SLICE-001` and `VAL-SLICE-002` remain failed historical provenance
  assertions outside the final release gate. The accepted observer-v2 evidence
  does not contain separately measured elapsed times for its Ruff, mypy, and
  then-current repository-check commands; grouped timings cannot be apportioned
  or replaced by present-day reruns. Current-candidate readiness is governed
  separately by the passing `VAL-RELEASE-RECOVERY-002` v7 record. It does not
  retroactively repair either historical assertion or convert the failed v6
  recovery/handoff into passing history.

The machine-readable provenance is in
[lean-core-v0.2-manifest.json](lean-core-v0.2-manifest.json). Rollback triggers,
the exact accepted artifact, reinstall command, data statement, and focused
checks are in [lean-core-v0.2-rollback.md](lean-core-v0.2-rollback.md).
