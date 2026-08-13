# Lean Core v0.2 rollback

Roll back when a retained lifecycle/restart behavior fails, schema-v1 data no
longer loads, a provider or credential boundary weakens, an MCP role has the
wrong identity or authority, installed membership differs from the accepted
archive, status writes state or violates schema v2, or a hard-cut subsystem
returns. Preserve `.unrest/` and `.unrest-runtime/` as separate trees; this
release has no data migration to reverse.

## Provenance guard

At the earlier checkpoint, `6cf713c` was the checked-out commit but was not the
content identity of the dirty-worktree candidate. The 105-file
`cc9ec091838a4c8ac2845a2bdcba44ed151b50e92e833e6d4531b665e1e2ef3a`
binding, its 892-pass checkpoint, its reviewed local archives, and its later
`d5fff4d` publication evidence are historical and superseded after the
validator MCP identity change. Do not retrieve or reinstall those bytes as the
final v0.2 candidate, and do not interpret a commit-range diff from `6cf713c`
as post-checkpoint mutation.

The final candidate is 103 tracked product/package/test files at
`a9e12eb7f210f1e6a005a2d2a3b8b335e9914e43dd53ce7cc737dcf79fe266be`.
The former 105-file filesystem-only digest
`35e21ed3a3a70f6687d35ad7fa8d03d7601d77935a72fabfdbf86a05f5e166e1`
is historical and superseded because it included ignored/generated egg-info
and was not commit-reproducible.

The commit-reproducible finalization is the rollback authority: 103 tracked
files at `a9e12eb7f210f1e6a005a2d2a3b8b335e9914e43dd53ce7cc737dcf79fe266be`,
with retained `unrest_harness-0.2.0-py3-none-any.whl` (217,889 bytes) and
`unrest_harness-0.2.0.tar.gz` (301,664 bytes) hashes
`054ebc22de5aa7387827fe62db12f67c6abbba46469e4f166b2f8c5cf1cfbe40`
and `05a82e272ad996330c8f7dfbbe2da29a9d06fd35f3ed0707565aff755d8a8b1a`.
Decision 001 defines checkpoint authority: the sole local full-suite invocation
is a failed ordering probe with 919 passed, 7 documented live-provider skips,
and exactly 2 carrier-currentness failures in 220.56 seconds, exit 1, with zero
reruns. It is not a clean checkpoint verdict. The clean frozen-candidate verdict
is pending and belongs to exact-head Python 3.13 `VAL-CI-EXACT`. The older
899-pass/7-skip/170.80-second result is historical, superseded chronology only;
it is not current rollback or checkpoint authority.
The former 105-file checkpoint/archive sequence below is superseded chronology.
The preceding `24b85e4a3798cd498a08b685940e981f19db47e1d684d6bf0e9990fc166da60e`
binding and its publication evidence, followed by the
`e4c8f24658f7a3299fb3f84b63d7c61e4de2b8fa3dca85db2a69d765f1e398d4`
binding, 894-pass checkpoint, and local archives, are historical and
superseded. The evidence-retained loopback-authorized checkpoint passed 894 tests with 7
skips in 174.05 seconds, exit 0, but is historical chronology only.

The `35e21ed3…` candidate had three distinct checkpoint invocations: (1) the
environment-limited 880-pass/14-failure restricted-sandbox attempt in 171.68
seconds, exit 1; (2) the successful 894-pass/7-skip invocation in 174.83
seconds, exit 0, which is historical, superseded, and unretained despite using
the identical binding; and (3) the retained 894-pass/7-skip invocation in
174.05 seconds, exit 0, retained as evidence but superseded as authority. Every invocation recorded zero within-invocation
reruns; do not mistake that field for the candidate-level invocation count of
three.

The retained invocation ran from `2026-08-12T23:43:25.569367Z` through
`2026-08-12T23:46:20.475041Z`. Its durable packet is
`mission evidence/W-CHECKPOINT-EVIDENCE-RETENTION-20260813T0342Z`;
`stdout.raw` has SHA-256
`ef8e3ec1544e3418aa6e76b5bc05529ddd0ae5bae19a1adc7da9218eabeaeefc`,
and the packet's `SHA256SUMS` ledger has SHA-256
`14788e338d12d1cf4898b2eac8ce1d453bb8cc39e1698cf44f7b48b152f39bb5`.

The superseded local archive bytes are retained as chronology in
`mission evidence/W-ARCHIVE-EVIDENCE-RETENTION-20260813T002050Z`: wheel
`778681c9ea77800bfab3934102d5e7b61ff7965e9262fe7c2501ccaa15b9688a`
(217,860 bytes) and sdist
`0f73d258264f446969b864b0df4828e6fd2f00bd17fdc08accc64648a1c4ce51`
(295,954 bytes). The disposable, unretained hashes
`68b44673932c0ac4702bc3c3c0368b52e59ce4eede9db2ee5eeace5949e25e63`
and `b7b19d0ce761d48b30b1112bcb65b9531d9b4224eb66ec7e41db8495f7c56e2f`
are historical and superseded; they are not rollback candidates.

## Locate and download the final candidate

This immutable procedure and local checkpoint carrier has status
`external-evidence-required`; PR #6's mutable body owns the current commit, run,
artifact, and run-local hashes. Resolve the repository slug and live PR #6 head
SHA. Do not pick a run by branch name or recency.

```bash
export FINAL_HEAD_SHA=FINAL_HEAD_SHA
gh run list --repo OWNER/REPO --workflow ci.yml --commit "$FINAL_HEAD_SHA" \
  --status success --json databaseId,headSha,conclusion,url
export RUN_ID=RUN_ID_SELECTED_FROM_THE_LIST
test "$(gh run view "$RUN_ID" --repo OWNER/REPO --json headSha \
  --jq .headSha)" = "$FINAL_HEAD_SHA"
test "$(gh run view "$RUN_ID" --repo OWNER/REPO --json conclusion \
  --jq .conclusion)" = success
gh run download "$RUN_ID" --repo OWNER/REPO \
  --name lean-core-v0.2.0-python313 --dir lean-core-v0.2.0
```

Record the publication SHA, run URL, artifact ID, creation time, expiry, and
run-local hashes alongside the rollback event. There is no GitHub Release for
this candidate.

## Verify and install without rebuilding

From the directory containing the downloaded artifact directory:

```bash
(cd lean-core-v0.2.0 && shasum -a 256 -c SHA256SUMS)
uv pip install --force-reinstall --no-deps \
  lean-core-v0.2.0/unrest_harness-0.2.0-py3-none-any.whl
```

Both rows must report `OK`. A rebuild is not retrieval. Neither the historical
superseded hashes nor any local build hashes substitute for the selected
exact-head CI run's `SHA256SUMS`.

## Focused verification

From an unrelated working directory in the target environment, run:

```bash
unrest --help
unrest-server --help
python -m unrest_harness --help
python -m unrest_harness.installed_wheel_check
```

Confirm validator mode identifies itself as `unrest-validator`, says
`Mode: validator`, and exposes only the strict `end_node` protocol. Then
exercise one provider-independent work/validation/gate lifecycle through
restart and one schema-v2 strict-status plus exact-known-value redaction case.
Do not rerun the frozen full source suite or rebuild archives merely to verify
rollback.

See the [release record](lean-core-v0.2.md) and
[manifest](lean-core-v0.2-manifest.json) for complete chronology and identities.
