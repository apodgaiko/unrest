# Unrest v0.4.0 rollback

v0.4.0 adds no migration, dependency family, optional extra, or always-on
service. Existing schema-v1 projects remain readable. The exact rollback
perimeter is bound by `docs/release/lean-core-v0.4.0-manifest.json`.

Before rollback, stop active Unrest hosts. The v0.4.0 adapters write only
through the existing Inquiry, Mission, workspace, and campaign authorities, so
their durable records remain foundation-runtime records rather than a new data
format.

Reinstall the immutable predecessor:

```bash
git switch --detach v0.3.1
UV_PYTHON=3.13 uv sync --locked
uv run python -c 'import unrest_harness as u; assert u.__version__ == "0.3.1"'
```

For an installed archive, install the wheel attached to the v0.3.1 GitHub
Release and verify it against that release's `SHA256SUMS`. Do not move either
release tag.
