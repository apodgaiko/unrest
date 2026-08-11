# Historical telemetry and cold-start provenance-repaired rollback record

This is a non-operative record for a retired candidate. Its detailed root
evidence was intentionally removed by the Lean Core retention decision.

This procedure is bounded to product commit
`2e81494d98cc3e1d5c986e138f4dde06d9dedaf2`, product tree
`f52a245d043ca650042ab98e408d795ca3d54b57`, implementation commit
`d6c253a7d5f1ecb8e0df94efb271bfe8c34df2bd`, and fixed base
`2d393cf1e077e081598719292456c20f6bd1a616`. It does not authorize changes to
unrelated paths, `.validation/`, or `validator-regressions/`.

No persisted schema migration is present. Existing `.unrest/` records remain
readable by the base wheel, passive observation does not mutate
`.unrest-runtime/`, and project-data recovery is neither needed nor authorized.

## Procedure

1. Stop candidate processes before replacing the installation.
2. Revert the release-evidence, corrected-product, and implementation commits
   through ordinary protected review; do not rewrite shared history.
3. Confirm the product delta contains exactly the recorded 18 product paths
   plus the candidate's classified release artifacts.
4. Confirm the restored tree is
   `f53caa3aebacef998b670597b14254c62af0bfb7` at exact base commit
   `2d393cf1e077e081598719292456c20f6bd1a616`.
5. Reinstall the wheel built from that exact base.
6. From an unrelated working directory, verify site-packages provenance,
   observe representative existing projects, and confirm project and runtime
   cursor inventories are unchanged.

The removed detailed transcript recorded a successful isolated index
reconstruction; this document retains only that conclusion.
