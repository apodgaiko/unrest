# Batch 0 rollback procedure

Trigger rollback if protected CI fails after merge, a role-scoped credential is
observable at a persistence or protocol boundary, or the installed candidate
cannot complete and resume the provider-independent lifecycle.

Revert the Batch 0 commits in reverse order using ordinary non-destructive Git
reverts. Rebuild the wheel from the restored tree and run the repository's
common gate plus the installed-wheel lifecycle check before republishing or
reinstalling. Do not delete project records: this change introduces no storage
schema migration, and existing `.unrest/` and `.unrest-runtime/` records remain
readable by the restored version.

Verify recovery by confirming the restored commit passes `unrest
check-repository`, the full test suite, wheel build, and installed-candidate
smoke surfaces. If credential exposure triggered rollback, preserve the
value-free forensic record and rotate the affected external credential; never
copy the credential into the rollback evidence.
