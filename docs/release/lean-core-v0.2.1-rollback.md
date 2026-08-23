# Unrest v0.2.1 rollback

This candidate preserves FM-000 as proposed groundwork and implements only
cross-process project mutation exclusion. FM-010 and the custody, telemetry,
capability-policy, and general-thinker surfaces are untrusted research and are
not implemented, so rollback requires no data or schema migration.

The candidate binding is
`efc1aeae63456cfa92d9d10c141e3da27cbe1747b8e5a703afe372d6c728bfd4` over
133 files.
Before rollback, preserve the failing candidate commit, command output, and
project directory; do not rewrite historical v0.2 release records.

For an isolated source rollback without disturbing a dirty main checkout:

```sh
test "$(git -C /Users/aleksandrpodgaiko/Desktop/unrest rev-parse v0.2.0^{commit})" = \
  "96d5c0f0b240bd3373809546d7aecc1e407f837b"
git -C /Users/aleksandrpodgaiko/Desktop/unrest worktree add \
  /private/tmp/unrest-v020-rollback v0.2.0
uv tool install --editable --force /private/tmp/unrest-v020-rollback
/Users/aleksandrpodgaiko/.local/share/uv/tools/unrest-harness/bin/python -c \
  'import importlib.metadata as m; import unrest_harness as u; assert m.version("unrest-harness") == u.__version__ == "0.2.0"'
unrest --help
```

Keep the rollback worktree until the incident evidence and restored CLI are
reviewed. Removing it is a separate, explicit cleanup action.
