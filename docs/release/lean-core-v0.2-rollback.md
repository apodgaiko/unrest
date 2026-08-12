# Lean Core v0.2 rollback

Roll back when a retained lifecycle/restart behavior fails, schema-v1 data no
longer loads, a provider or credential boundary weakens, installed membership
differs from the accepted archive, status writes state or violates schema v2,
or a hard-cut subsystem returns under another maintained path. Preserve
`.unrest/` and `.unrest-runtime/` as separate trees; this release has no data
migration to reverse.

## Locate and download the candidate

Use the repository slug and the exact final pull-request head SHA. Do not pick a
run by branch name or recency alone.

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

The artifact is uploaded by the Python 3.13 `primary` job with 90-day
retention. Record the selected run URL, `headSha`, artifact ID, creation time,
and expiry alongside the rollback event. There is no GitHub Release for this
candidate.

## Verify and install without rebuilding

From the directory containing the downloaded `lean-core-v0.2.0/` directory,
verify the CI-run checksum file before installing:

```bash
(cd lean-core-v0.2.0 && shasum -a 256 -c SHA256SUMS)
uv pip install --force-reinstall --no-deps \
  lean-core-v0.2.0/unrest_harness-0.2.0-py3-none-any.whl
```

Both checksum rows must report `OK`. A rebuild is not retrieval and must not be
substituted for these bytes. The reviewed local hashes in the release record
identify a separate isolated build and are not a substitute for the selected
CI run's `SHA256SUMS`.

## Focused verification

From an unrelated working directory in the target environment, run:

```bash
unrest --help
unrest-server --help
python -m unrest_harness --help
python -m unrest_harness.installed_wheel_check
```

Then exercise one provider-independent work/validation/gate lifecycle through
restart and one schema-v2 strict-status plus exact-known-value redaction case.
Do not rerun the frozen full source suite or rebuild the archives merely to
verify rollback.

The fixed comparison base is commit
`93c59e4378407f3d7cfb918cf86c8bdc81daa141`, tree
`35152a4a8c56198664f519691ec952ec9ca519f4`. The candidate product/package/test
binding is
`cc9ec091838a4c8ac2845a2bdcba44ed151b50e92e833e6d4531b665e1e2ef3a`.
See the [release record](lean-core-v0.2.md) and
[manifest](lean-core-v0.2-manifest.json) for the remaining identities.
