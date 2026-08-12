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

The final candidate is 105 product/package/test files at
`24b85e4a3798cd498a08b685940e981f19db47e1d684d6bf0e9990fc166da60e`.
The checked-out predecessor at the new checkpoint was `d5fff4d`; it is not the
content identity or final publication SHA. Use only a later publication commit
whose exact-head CI run qualifies this binding.

## Locate and download the final candidate

Use the repository slug and exact final pull-request head SHA. Do not pick a run
by branch name or recency.

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
superseded hashes nor the final local build hashes substitute for the selected
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
