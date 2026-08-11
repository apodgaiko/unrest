# Lean Core v0.2 rollback

Use rollback when a retained lifecycle/restart behavior fails, schema-version-1
project data no longer loads, a retained provider or security boundary weakens,
the installed package differs from its accepted membership/provenance, status
writes state or violates schema version 2, or a withdrawn subsystem is
recreated under another maintained path. Roll back the failing slice; do not
preserve an unvalidated dual implementation.

## Last accepted source and artifact

- Scoring-reference commit: `93c59e4378407f3d7cfb918cf86c8bdc81daa141`
- Scoring-reference tree: `35152a4a8c56198664f519691ec952ec9ca519f4`
- Accepted package-source binding:
  `c420736a1ccba7a3d8891d6ddc6a976302df369d5822709468dc66c8ade385e0`
- Accepted wheel SHA-256:
  `b0b02bc0820d03b9d7bdd42cb65cb9a624ba65504e553178eddfe4046d8a25b3`
- Accepted wheel carrier:
  `/Users/aleksandrpodgaiko/.unrest/projects/20260809T170516Z-read-only-assessment-of-the-attached-batch-0-5-lean-core-compact/.unrest/missions/mission-001/evidence/final-package-evidence-ledger-v2/records/23-remediation-scrutiny-dist-unrest_harness-0-1-0-py3-none-any-whl.whl`

Verify the checksum, then reinstall that exact local artifact without resolving
or replacing dependencies:

```bash
shasum -a 256 /Users/aleksandrpodgaiko/.unrest/projects/20260809T170516Z-read-only-assessment-of-the-attached-batch-0-5-lean-core-compact/.unrest/missions/mission-001/evidence/final-package-evidence-ledger-v2/records/23-remediation-scrutiny-dist-unrest_harness-0-1-0-py3-none-any-whl.whl
uv pip install --force-reinstall --no-deps /Users/aleksandrpodgaiko/.unrest/projects/20260809T170516Z-read-only-assessment-of-the-attached-batch-0-5-lean-core-compact/.unrest/missions/mission-001/evidence/final-package-evidence-ledger-v2/records/23-remediation-scrutiny-dist-unrest_harness-0-1-0-py3-none-any-whl.whl
```

The checksum command must report the accepted wheel hash above before
installation.

## Data statement

Persisted project and mission records remain schema version 1 and require no
data migration or recovery. Observer schema version 2 is a read-only
projection, so rolling back changes only the observer/API shape; it does not
rewrite durable project data. Preserve `.unrest/` and `.unrest-runtime/` as
separate trees.

## Focused verification

From the source checkout, run:

```bash
uv run pytest -q tests/contracts/test_lean_package.py tests/test_server.py tests/test_persistence_schema_v1.py
uv run ruff check src/unrest_harness/server.py tests/test_server.py
uv run mypy src/unrest_harness/server.py
uv run unrest check-repository
```

From an unrelated working directory in the target environment, run the
installed surfaces:

```bash
unrest --help
unrest-server --help
python -m unrest_harness.installed_wheel_check
```

Re-exercise one provider-independent work/validation/gate lifecycle through
restart and one schema-v2 strict-status plus exact-known-value redaction case.
Do not rerun the frozen source-suite checkpoint or rebuild an archive merely to
perform rollback verification.

The raw repository-root validation history was preserved rather than deleted.
Keep the external quarantine payload and sibling control records together. If
the root tree must be restored for forensic use, follow the exact reverse-move
preconditions and command in the external
[restore procedure](/Users/aleksandrpodgaiko/.unrest/projects/20260809T170516Z-read-only-assessment-of-the-attached-batch-0-5-lean-core-compact/.unrest/missions/mission-001/evidence/repository-root-validation-quarantine-v3/control/RESTORE.md);
never merge it into an existing `.validation` path.

The accepted corrected-delivery readiness record is the external
`mission-001/evidence/final-release-recovery-v7` ledger, produced from command
matrix SHA-256
`56bac287a2f7cff7d4fae5e62221df36b4f4ae72bf87f8fc88438f1563705c70`.
It replays the accepted frozen/package verifiers and archive hashes, checks
wheel/sdist source parity, and records the separately timed current repository
closure. It is evidence for this final candidate only; rollback verification
must not rewrite it, regenerate the accepted archives, or treat it as missing
historical slice provenance. The failed v6 recovery and first handoff commit
remain immutable non-authority history: v6's plain diff gate omitted the then-
untracked scheduling contract and therefore missed its final blank line.

`VAL-SLICE-001` and `VAL-SLICE-002` remain failed historical provenance
assertions outside the final release gate. Rollback does not reconstruct or
waive their missing observer-v2 per-command timings; current-candidate release
readiness is established separately by the passing
`VAL-RELEASE-RECOVERY-002` v7 record and does not retroactively repair those
timings or the failed v6 gate.

See the [release record](lean-core-v0.2.md) and
[manifest](lean-core-v0.2-manifest.json) for the complete provenance.
