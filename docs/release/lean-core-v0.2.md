# Lean Core v0.2 final release checkpoint

This carrier binds the final local Unrest Harness `0.2.0` candidate after the
validator MCP identity correction. It preserves the earlier checkpoint as
chronology, but that checkpoint and all archives produced from it are
historical and superseded.

## Provenance chronology

The first Python 3.13 checkpoint ran on 2026-08-12 while `6cf713c` was the
checked-out commit. That commit was not the content identity of the candidate:
the tested worktree already contained later compaction changes and was bound
separately as 105 product/package/test files at
`cc9ec091838a4c8ac2845a2bdcba44ed151b50e92e833e6d4531b665e1e2ef3a`.
Its 892-pass transcript and local wheel/sdist hashes remain in the manifest for
audit, not release selection.

Commit `d5fff4dbdfecb9124f86958c4cd188dfff218d6e` subsequently published that
earlier bound tree. Exact-head run `31641194261` and artifact `9158990376`
qualified it at the time. The validator-specific MCP server identity then
changed `src/`, tests, and canonical documentation. That product change retires
the earlier local checkpoint, local archives, publication run, and artifact as
final evidence. A commit-range diff beginning at `6cf713c` describes publication
chronology; it is not a measure of mutation after the first checkpoint.

The new final checkpoint ran with `d5fff4d` as the checked-out predecessor while
the validator identity correction and this carrier work were present in the
worktree. Again, the checked-out commit is not the content identity. The final
product/package/test identity is the explicit binding below. Publication must
commit exactly this candidate and qualify that publication commit with a new
successful exact-head GitHub run and artifact.

## Final local candidate binding

- Fixed comparison base: commit
  `93c59e4378407f3d7cfb918cf86c8bdc81daa141`, tree
  `35152a4a8c56198664f519691ec952ec9ca519f4`.
- Product/package/test surface: `pyproject.toml`, `uv.lock`, and regular files
  under `src/`, `tests/`, and `tools/`, excluding cache files.
- Binding algorithm: SHA-256 over each sorted UTF-8 repository-relative path,
  NUL, raw file bytes, NUL.
- Final binding: 105 files,
  `24b85e4a3798cd498a08b685940e981f19db47e1d684d6bf0e9990fc166da60e`.

The binding was measured before and after the one final Python 3.13 source-suite
run and after package verification. Carrier-only edits do not enter this
surface.

## Final local checkpoint and archives

The sole full-suite run for this new candidate ran once on CPython 3.13.12 with
uv 0.11.0 on macOS arm64, from 2026-08-12T21:59:42Z through
2026-08-12T22:02:59Z:

```text
env -u CODEX_PATH uv run pytest -q
893 passed, 7 skipped, 0 failed in 172.15s; exit 0; no rerun
```

The final isolated local archives built after that checkpoint are:

- `unrest_harness-0.2.0-py3-none-any.whl` — 217,860 bytes — SHA-256
  `60bef82f6ecc939a91273280be58da1dcf97d688847b05a3aac6ae694292b269`.
- `unrest_harness-0.2.0.tar.gz` — 295,185 bytes — SHA-256
  `dc5f17071f08f3f4f49386fdec05a7d9b02c081d18ad94a36a0942fee5c548d2`.

The exact wheel passed distribution, entry-point, bundled asset, lifecycle,
strict configuration, provider-role, terminal-credential, and validator MCP
identity checks after installation from an unrelated directory. Local archive
hashes identify only this reviewed build; archive timestamps mean independent
CI builds are not expected to reproduce those bytes.

## Publication and CI binding

The local candidate becomes releasable only after its exact publication commit
and successful exact-head CI are established. Publication must satisfy all of
the following without filling speculative identifiers into this carrier:

1. the publication commit contains the final product/package/test binding;
2. local HEAD, the tracking ref, and the live PR head resolve to that exact SHA;
3. the selected successful `ci.yml` run reports the same `headSha`;
4. the run's `lean-core-v0.2.0-python313` artifact contains the wheel, sdist,
   and its run-local `SHA256SUMS`; and
5. both downloaded checksum rows and the installed-wheel lifecycle pass.

The [manifest](lean-core-v0.2-manifest.json) keeps final-publication identifiers
null until that external state exists. The publication worker and exact-head
validator record the commit, run, artifact, checksum, and ref-equality evidence;
branch name or recency alone is never release evidence. The
[rollback carrier](lean-core-v0.2-rollback.md) gives the portable retrieval
flow.

## Scope and known limits

Lean Core retains the contract-backed lifecycle, schema-v1 persistence,
single mutable-work scheduling, Claude and Codex providers, finite authority
and credential boundaries, role-specific MCP identities, schema-v2 read-only
status, repository validation, and the installed-wheel lifecycle. Python 3.11
and 3.12 remain focused compatibility lanes and do not duplicate the Python
3.13 full suite or installed lifecycle.

- For removed duplicate root schemas, external publication is unverified;
  repository-only absence does not establish external absence.
- For observer-v1, external publication and consumers are unverified.
- Protection covers exact-known credential values at documented boundaries,
  not transformed secrets, intentional exfiltration, network denial, or an OS
  sandbox.
- Server cold import is neutral rather than an optimization win.
