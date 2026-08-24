# Unrest v0.3.0 rollback

v0.3.0 adds no data migration, dependency family, or always-on service. Its
runtime delta is confined to per-project mutation exclusion and
cancellation-safe ownership; FM-000 remains proposed documentation and fixture
groundwork.

The candidate binding is
`effab6ecbde8d8336dd56a16211be8d9587ad3258234dbf0bd7bb82a5a37c2a4`
over `134` product/package/test files.

For a remote/source rollback, select the last published stable release:

```sh
git switch --detach v0.2.0
uv tool install --editable --force "$PWD"
unrest --help
unrest-server --help
```

For a local-only comparison with the intermediate safety candidate, use
annotated tag `v0.2.1`. Preserve the failing project, exact release commit,
command output, and runtime directories before changing the installed tool.
Rollback does not require rewriting `.unrest/` or `.unrest-runtime/` records.
