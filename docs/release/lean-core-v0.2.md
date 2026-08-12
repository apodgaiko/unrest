# Lean Core v0.2 release candidate

This carrier records the local frozen-candidate result for Unrest Harness
`0.2.0`. It does not certify the final pull-request head: GitHub CI supplies
that separately through the run and artifact metadata named below.

## Frozen identities

- Fixed comparison base: commit
  `93c59e4378407f3d7cfb918cf86c8bdc81daa141`, tree
  `35152a4a8c56198664f519691ec952ec9ca519f4`.
- Repository HEAD when the checkpoint ran:
  `6cf713cb855ff77f372c008bc249064a03a2ca35`.
- Pre-carrier delivery binding: 150 files,
  `2c971c79f3afbfe8ddf11422ca0e666a00ab9ffde044349057a2f705d6149f47`.
- Frozen product/package/test binding: 105 files,
  `cc9ec091838a4c8ac2845a2bdcba44ed151b50e92e833e6d4531b665e1e2ef3a`.

Both bindings are SHA-256 over each sorted UTF-8 repository-relative path,
NUL, raw file bytes, NUL. The narrower binding covers `pyproject.toml`,
`uv.lock`, and regular files under `src/`, `tests/`, and `tools/`, excluding
cache directories. No file in that surface changed after the checkpoint.

## Local checkpoint and archives

The sole Python 3.13 checkpoint ran on 2026-08-12:

```text
env -u CODEX_PATH uv run pytest -q
892 passed, 7 skipped, 0 failed in 179.78s; exit 0
```

The reviewed local candidate archives built from the frozen source are:

- `unrest_harness-0.2.0-py3-none-any.whl` — 217,773 bytes — SHA-256
  `44808498624b50bf7e44eff8c80ecc5fe0021b445f6e4a8204ff8387addbab97`.
- `unrest_harness-0.2.0.tar.gz` — 293,800 bytes — SHA-256
  `ed9da36e1591f627486a728fc0db8dec696961460b90df6c53e57a76ee1793c9`.

The exact wheel passed the installed entry-point, bundled policy/assets,
create/restart/abort, genuine legacy handoff, configuration rejection,
provider-role projection, and terminal-credential-exclusion probes from an
unrelated directory. These hashes identify the reviewed local archives only.
Archive timestamps can change bytes between independent builds, so they are
not expected CI hashes and this release makes no reproducibility claim.

## Scope and CI handoff

Lean Core retains the contract-backed lifecycle, schema-v1 persistence,
single mutable-work scheduling, Claude and Codex providers, finite authority
and credential boundaries, schema-v2 read-only status, repository validation,
and the installed-wheel lifecycle. It cuts the historical baseline generator,
governance/commit-policy engine, duplicate root schemas, static capability
source/sink proof, transformed-secret inference, detailed observer-v1 schema,
the unsupported legacy child-provider surface, and raw root release-history
bulk.

Python 3.11 and 3.12 remain focused source-compatibility lanes: locked install,
package/policy import, assets plus configuration/model contracts, supported CLI
help, and repository validation. They do not repeat either the Python 3.13 full
source suite or its installed lifecycle.

The final Python 3.13 job preserves the archive filename, version, member,
distribution, and installed-wheel gates. It then generates `SHA256SUMS` from
the two archives produced by that run, verifies the checksum file against those
same bytes, and uploads all three files as the single GitHub Actions artifact
`lean-core-v0.2.0-python313` with 90-day retention.

Consumers must select a successful `ci.yml` run by the exact final-head SHA,
confirm that the selected run's `headSha` equals that SHA and its conclusion is
`success`, download the named artifact, and run
`shasum -a 256 -c SHA256SUMS` inside the downloaded directory before using an
archive. Selection by branch or recency is insufficient. The run URL, head
SHA, artifact ID, creation time, expiry, and CI-run hashes from `SHA256SUMS` are
external final-head evidence.
See the [manifest](lean-core-v0.2-manifest.json) for structured facts and the
[rollback carrier](lean-core-v0.2-rollback.md) for portable retrieval.

The only permitted post-checkpoint repository edits are these three concise
release carriers and `.github/workflows/ci.yml`. No GitHub Release is created.

## Known limits

- For the removed duplicate root schemas, external publication unverified;
  repository-only absence does not establish external absence.
- For observer-v1, external publication and consumers unverified; any external
  consumer must migrate to the read-only schema-v2 projection or remain on
  v0.1.
- Protection covers exact-known credential values at documented boundaries,
  not transformed secrets, intentional exfiltration, network denial, or an OS
  sandbox.
- Server cold import is neutral rather than an optimization win.
