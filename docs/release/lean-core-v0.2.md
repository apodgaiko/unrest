# Lean Core v0.2 immutable release carrier

This carrier binds the current local Unrest Harness `0.2.0` rollback authority after the
validator MCP identity correction and external-publication contract test. It
is an immutable procedure and local checkpoint record. The mutable PR #6 body,
not this committed file, owns the current publication commit, run, artifact,
and run-local hashes.

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

The next checkpoint ran with `d5fff4d` as the checked-out predecessor while the
validator identity correction and carrier work were present in the worktree.
Its 105-file `24b85e4a3798cd498a08b685940e981f19db47e1d684d6bf0e9990fc166da60e`
binding, 893-pass checkpoint, local archives, and later `f00ac2c` publication
evidence are also historical and superseded after the focused publication
contract test changed.

That focused test update produced the 105-file
`e4c8f24658f7a3299fb3f84b63d7c61e4de2b8fa3dca85db2a69d765f1e398d4`
binding, 894-pass checkpoint, and local archives. They are historical and
superseded after the carrier binding regression test changed the bound test
surface. Both `24b85e4a…` and `e4c8f246…` remain chronology, not current
candidate identities.

The superseded `35e21ed3…` candidate had three distinct checkpoint invocations.
Invocation 1 was the environment-limited 880-pass/14-failure attempt in the
restricted sandbox (171.68 seconds, exit 1). Invocation 2 passed 894 tests with
7 skips in 174.83 seconds, exit 0, on the identical binding, but it is
historical, superseded, and unretained. Invocation 3 is also historical and
superseded, though its evidence remains retained below. Each invocation had zero within-invocation reruns;
three candidate checkpoint invocations is therefore not a rerun count of zero.

## Current rollback-authority binding

- Fixed comparison base: commit
  `93c59e4378407f3d7cfb918cf86c8bdc81daa141`, tree
  `35152a4a8c56198664f519691ec952ec9ca519f4`.
- Product/package/test surface: `pyproject.toml`, `uv.lock`, and regular files
  under `src/`, `tests/`, and `tools/`, excluding cache files.
- Binding algorithm: SHA-256 over each sorted UTF-8 repository-relative path,
  NUL, raw file bytes, NUL.
- Final tracked-file binding: 103 files,
  `8e6734f4d046cae6a81f9cd1abf7d99bc5ca5e7dd2f7269f9ceb26786974c7a7`.

The former 105-file filesystem-only digest
`35e21ed3a3a70f6687d35ad7fa8d03d7601d77935a72fabfdbf86a05f5e166e1`
is historical and superseded: it included ignored/generated egg-info and could
not be reproduced from a publication commit archive.

The binding was measured before and after the authoritative Python 3.13
source-suite invocation and after package verification. Carrier-only edits do
not enter this surface.

Decision 001 defines checkpoint authority. The sole local invocation of
`env -u CODEX_PATH uv run pytest -q` is a failed ordering probe: 919 passed, 7
documented live-provider skips, and exactly 2 carrier-currentness failures in
220.56 seconds, exit 1, with zero reruns. The two failing nodeids were
`tests/test_documentation_contract.py::test_review_audit_and_executable_crosswalk_are_release_carriers`
and `tests/test_release_binding.py::test_all_five_carriers_agree_with_tracked_binding_and_keep_chronology`.
It is not a clean checkpoint verdict. The clean frozen-candidate verdict is
pending and belongs to exact-head Python 3.13 `VAL-CI-EXACT`.

The older 899-pass/7-skip/170.80-second result and transcript SHA-256
`682852deb33039f01ddc84d5004d877dc3c53d56e24e0cbc923bb300d930fc2a`
are historical, superseded chronology only and are not current rollback or
checkpoint authority.
The final local-seal build, performed once after the tracked product, package,
test, and tool inputs settled, produced
`unrest_harness-0.2.0-py3-none-any.whl` (217,917 bytes) at
`c8c6ec9f13808703ba99ec1d6fde536df834358c8736fde3d5d105620f154411`
and `unrest_harness-0.2.0.tar.gz` (303,526 bytes) at
`5f8af7fc1470afb04896e5256b8f49f78edb3913db10f563280ec7727ae45633`.
The complete accepted before/after report is
[`lean-core-v0.2-measurements.md`](lean-core-v0.2-measurements.md).

## Superseded checkpoint and archive chronology

The evidence-retained but superseded loopback-authorized checkpoint (candidate invocation 3 of 3)
ran on CPython 3.13.12 with uv 0.11.0 on macOS arm64 from
`2026-08-12T23:43:25.569367Z` through `2026-08-12T23:46:20.475041Z`:

```text
env -u CODEX_PATH uv run pytest -q
894 passed, 7 skipped, 0 failed in 174.05s; exit 0; 0 per-invocation reruns
```

Its durable packet is
`mission evidence/W-CHECKPOINT-EVIDENCE-RETENTION-20260813T0342Z`.
`stdout.raw` has SHA-256
`ef8e3ec1544e3418aa6e76b5bc05529ddd0ae5bae19a1adc7da9218eabeaeefc`;
the packet's `SHA256SUMS` ledger has SHA-256
`14788e338d12d1cf4898b2eac8ce1d453bb8cc39e1698cf44f7b48b152f39bb5`.

The superseded single isolated local build is durably retained as chronology in
`mission evidence/W-ARCHIVE-EVIDENCE-RETENTION-20260813T002050Z`:

- `unrest_harness-0.2.0-py3-none-any.whl` — 217,860 bytes — SHA-256
  `778681c9ea77800bfab3934102d5e7b61ff7965e9262fe7c2501ccaa15b9688a`.
- `unrest_harness-0.2.0.tar.gz` — 295,954 bytes — SHA-256
  `0f73d258264f446969b864b0df4828e6fd2f00bd17fdc08accc64648a1c4ce51`.

The earlier disposable, unretained wheel
`68b44673932c0ac4702bc3c3c0368b52e59ce4eede9db2ee5eeace5949e25e63`
and sdist
`b7b19d0ce761d48b30b1112bcb65b9531d9b4224eb66ec7e41db8495f7c56e2f`
are historical and superseded by these retained bytes.

The exact wheel passed distribution, entry-point, bundled asset, lifecycle,
strict configuration, provider-role, terminal-credential, and validator MCP
identity checks after installation from an unrelated directory. Local archive
hashes identify only this reviewed build; archive timestamps mean independent
CI builds are not expected to reproduce those bytes.

## External publication evidence

Publication status is `external-evidence-required`. This immutable carrier
deliberately contains no current publication commit, head SHA, GitHub run ID,
or GitHub artifact ID. PR #6's mutable body owns that snapshot because adding
the carrier's own final commit or its post-commit CI identifiers here would
self-reference and immediately make the committed record stale.

Resolve the live PR #6 head SHA; require local HEAD, tracking ref, live PR head,
and successful `ci.yml` run `headSha` to equal it; download the named artifact
from that run and verify its `SHA256SUMS` before installation. This deterministic
procedure establishes the exact publication commit and successful exact-head CI:

1. the publication commit contains the final product/package/test binding;
2. local HEAD, the tracking ref, and the live PR head resolve to that exact SHA;
3. the selected successful `ci.yml` run reports the same `headSha`;
4. the run's `lean-core-v0.2.0-python313` artifact contains the wheel, sdist,
   and its run-local `SHA256SUMS`; and
5. both downloaded checksum rows and the installed-wheel lifecycle pass.

The [manifest](lean-core-v0.2-manifest.json) records the same immutable procedure
without embedding current self identifiers. The publication worker and
exact-head validator update PR #6 with the commit, run, artifact, checksum, and
ref-equality evidence; branch name or recency alone is never release evidence. The
[rollback carrier](lean-core-v0.2-rollback.md) gives the portable retrieval
flow.

## Attached review reconciliation

All three review rounds are identified by source SHA-256 and reconciled
claim-by-claim in the
[`attached-review-claims` ledger](lean-core-v0.2-attached-review-claims.json),
linked from the [review audit](lean-core-v0.2-review-audit.json). Findings that
were true at a review head are separated from final-head facts; accepted cuts,
merge conditions and superseded quantitative context are explicit rather than
collapsed into an aggregate “fixed” label. The 2026-08-16 follow-up records N1
and N2 separately as substantiated fixes with exact code and test citations;
its exact-head CI condition remains deferred to the final PR #6 snapshot. Its
SHA-256 is user-authorized from the mission brief, not a claim that the source
bytes were independently recomputed or retained in this repository.

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
