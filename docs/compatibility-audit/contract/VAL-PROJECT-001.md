# VAL-PROJECT-001: Project worker overrides preserve role semantics

Surface: MCP API, storage, and subprocess environment.
Needs: a configured Codex worker, a configured non-Codex worker, current role
configuration, and a legacy project-record fixture.
Behavior: Optional validated worker model/effort supplied to `start_project`
persists and applies only to work nodes; validators and terminal review retain
their configured role efforts. A non-Codex worker rejects either override before
creating or changing a project record. Records without the new fields load
unchanged.
Evidence: Fresh MCP call, persisted reload, legacy record load, and captured
work/validator/reviewer subprocess configs with and without overrides. Separate
non-Codex MCP calls exercise model-only, effort-only, and combined overrides;
each returns an error and preserves exact before/after project-record inventory,
creates no bucket, and does not mutate any existing record.
