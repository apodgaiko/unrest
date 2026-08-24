# Unrest v0.3.1 rollback

v0.3.1 adds no migration, dependency family, optional extra or always-on
service. Existing schema-v1 projects remain readable and byte-compatible.
The exact rollback perimeter is bound by
`docs/release/lean-core-v0.3.1-manifest.json`.

Before rollback, stop active Unrest hosts and copy the affected `.unrest/` and
`.unrest-runtime/` roots if v0.3.1 foundation runs must be retained. v0.3.0 does
not interpret new run-control, Inquiry, workspace or evolution records, but it
continues to read pre-existing Mission records.

Reinstall the immutable predecessor:

```bash
git switch --detach v0.3.0
uv sync --locked
uv run python -c 'import unrest_harness as u; assert u.__version__ == "0.3.0"'
```

For an installed archive, install the wheel attached to the v0.3.0 GitHub
Release and verify it against that release's `SHA256SUMS`. Do not move either
release tag. FM-010 result files are diagnostic artifacts and can be retained;
they are never runtime authority.
