# Telemetry and cold-start release-candidate v2 rollback

This procedure is bounded to product tree
`d3da52281b6e10ac692ed88f39848bb65e5f03b5` and fixed base
`2d393cf1e077e081598719292456c20f6bd1a616`. It does not authorize changes to
unrelated paths, `.validation/`, or `validator-regressions/`.

No persisted schema migration is present. Existing `.unrest/` records remain
readable by the base wheel, passive observation does not mutate
`.unrest-runtime/`, and project-data recovery is neither needed nor authorized.

## Procedure

1. Stop candidate processes before replacing the installation.
2. Revert the governed release commit through ordinary protected review; do
   not rewrite shared history.
3. Confirm the revert touches only the 18 paths in
   `product-tree-manifest-v2.json` plus classified evidence/governance paths.
4. Confirm the restored product tree is
   `f53caa3aebacef998b670597b14254c62af0bfb7`.
5. Reinstall the wheel built from exact base
   `2d393cf1e077e081598719292456c20f6bd1a616`.
6. From an unrelated working directory, verify site-packages provenance,
   observe representative existing projects, and confirm project and runtime
   cursor inventories are unchanged.

The isolated tree and installed-wheel dry-run is recorded in
`evidence/telemetry-cold-start/rollback-transcript-v2.txt`.
