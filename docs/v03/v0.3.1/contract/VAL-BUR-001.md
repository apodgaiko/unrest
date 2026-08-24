# VAL-BUR-001 — Installation and first-use burden

**Surface:** package and installed CLI.

**Needs:** v0.3.0 dependency/first-project baseline.

**Behavior:** No required service, database, migration, account, crypto suite,
provider baseline, or setup step is added. No-extra install and the old first-
project path work. Provider/Git/optional prerequisites are checked only when
their capability is invoked and fail with actionable stable errors.

**Evidence:** Dependency/lock diff, clean no-extra install, old flow, absent
Git/provider/config cases, ordinary help/import, and rollback.

