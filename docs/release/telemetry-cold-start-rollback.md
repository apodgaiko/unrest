# Historical telemetry and cold-start rollback record

This is a non-operative record for a retired candidate. Its detailed root
evidence was intentionally removed by the Lean Core retention decision.

This procedure is bounded to the telemetry and cold-start candidate whose
product tree is `c6450e3a6691ab2c28fef12c330c93f39fee3afc` and whose base is
`2d393cf1e077e081598719292456c20f6bd1a616`. Do not use it for unrelated
changes or user artifacts.

No persisted schema migration is present. Existing `.unrest/` project records
remain readable by the base wheel, and passive observation does not mutate
`.unrest-runtime/` cursors. Project-data recovery is therefore neither needed
nor authorized.

## Procedure

1. Stop any running candidate process before changing the installation.
2. Identify the governed release commit from the reviewed release record. If
   no governed commit exists, as in the current blocked state, there is nothing
   to revert.
3. In an isolated checkout, run `git revert --no-commit <release-commit>` and
   confirm that only the candidate's recorded product paths plus its reviewed
   release artifacts are reverted.
4. Confirm the restored product tree is
   `f53caa3aebacef998b670597b14254c62af0bfb7`, then commit the revert through
   ordinary protected review. Do not rewrite shared history.
5. Reinstall the wheel built from exact base
   `2d393cf1e077e081598719292456c20f6bd1a616`.
6. From an unrelated working directory, confirm imports resolve from that
   environment's `site-packages`, run `unrest observe-project --all --format
   json` against representative existing projects, and verify their file
   inventory is unchanged.

The removed detailed transcript recorded a successful isolated dry-run and
base/candidate wheel observations; this document retains only that conclusion.
