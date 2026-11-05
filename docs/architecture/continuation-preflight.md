# Continuation preflight (experimental)

`unrest continuation-preflight --project PROJECT_ID --mission MISSION_ID
--task TASK_ID` prints a read-only report of recorded facts about one explicit
task. Accepted by
[ADR-0505](../decisions/ADR-0505-continuation-preflight.md) under
ARCH-OBSERVE-001. It is experimental preflight plumbing: explicit invocation is
the only opt-in, nothing runs in the background, and the command performs no
dispatch, recovery, persistence, lock, provider or MCP action.

The report never classifies continuation state. `assessment.status` is always
`unavailable` in schema version 1, with seven fixed reasons. Exit code 0 means
only that a report was constructed; it is not readiness or permission to act.
The implementation lives in `continuation_preflight` and is imported only when
the command executes; its help text is static and does not load it.

## Selection

All three selectors are required. The project ID, mission ID and task ID must
fully match the existing runtime-observation project and mission grammars and
the task grammar (at most 128 characters). Within one captured cursor set:

1. `project.json`, `state.json` and `attention.json` are parsed with the
   existing models; a malformed cursor refuses.
2. A mission-bearing state (`mission_planning`, `mission_running`) whose
   mission differs from the project cursor refuses with
   `subject_mission_cursor_mismatch`, before selector comparison.
3. The selected mission is the state mission for mission-bearing states and
   the project cursor otherwise (`selection_basis`). It must equal `--mission`.
4. The plan, `task-state.json` and `contract-state.json` are parsed; task and
   dependency IDs and task-state keys are checked as in `observe-project`.
5. Exactly one plan task must have the requested ID, and its targets must match
   the assertion grammar.

`task-state.json` and `contract-state.json` are parsed whenever captured, even
for a task without targets. A broken `contract-state.json` therefore refuses
with `malformed_cursor` here although `observe-project`, which does not parse
that file, still reports. This divergence is deliberate; `observe-project` is
unchanged.

## Capture and stability

The command reuses the existing runtime capture without widening it. Inherited
limits: 4 MiB per file, 16 MiB total, 4,096 selected files or entries, depth 6
and three snapshot attempts, for the whole capture-selected mission. Violations
refuse with `unsafe_cursor`; nothing is truncated. One aware wall-clock read is
taken before the first capture and rendered as `read_at` in UTC; it asserts only
the read time.

Each attempt captures, projects and recaptures; equal stat identities return
the report. Errors derived from captured content are confirmed by one more
capture before they are reported. Stat equality is not a coherent instant,
authenticity proof or same-stat rewrite detector.

### Closed definition of `project_runtime_cursors: captured`

`captured` means exactly the following, relative to the project bucket, where
`S` is the capture-selected mission:

- `.unrest-runtime/`: `lstat`, top-level `scandir` and the type of each direct
  entry, without content;
- `.unrest-runtime/project.json` (required), `state.json` and `attention.json`
  bytes when present;
- `.unrest-runtime/missions/S/tasks.json`, `task-state.json` and
  `contract-state.json` bytes when present;
- `.unrest-runtime/missions/S/attempts/*.json`: bytes only for the latest
  attempt of each running task, otherwise metadata;
- `.unrest-runtime/missions/S/terminal-reviews/*.json`: metadata only.

It does not include `mutation.lock` contents, `terminal-review-config.json`,
`patch-transactions/`, `provider-reviews/`, `supervision/`, other missions or
`<project>/.unrest/`. The coverage list is non-exhaustive, and `captured`
promises neither semantic completeness, authenticity nor safety.

## Output schema version 1

One compact JSON line with a trailing newline, keys in fixed order:
`schema`, `schema_version` (1), `surface` (`experimental_preflight`),
`read_at`, `read_at_meaning` (`read_time_only`), `subject`, `observations`,
`coverage`, `stability`, `assessment`. The schema is closed: adding a key or
changing a meaning requires a new version and a documented migration.

Observations are `mission_record_state`, `task_type`, `task_status`,
`task_last_attempt`, `attempt_record`, `dependencies`, `targets` and
`attention`. Presence comes from recorded fields only (`file_absent`,
`collection_absent`, `entry_absent`, `field_absent`, `explicit_null`,
`malformed_reference`, `present`); model defaults are never reported as facts.
Each fact carries `{"root":"project_bucket","path",...,"capture"}` provenance;
dependencies and targets carry separate association and status sources. The
attempt reference is a grammar-checked opaque string and is looked up only by
its exact captured key; it is never a time, age or liveness signal. Attention
counts join on mission and task and exclude terminal reviews and state-embedded
items; zero counts do not assert the absence of attention.

Coverage lists fourteen families with fixed statuses, including
`patch_transactions: not_captured` and `supervision_snapshots: not_captured`.
`stability.limitations` names `coverage_list_non_exhaustive`,
`same_stat_rewrite_undetected` and `uncaptured_families_unchecked`.

## Errors and privacy

Failures exit 1 with exactly `Error: <code>` on stderr and empty stdout. The
fourteen codes are `invalid_project_id`, `invalid_mission_id`,
`invalid_task_id`, `invalid_configuration`, `project_not_found`,
`unsafe_project_path`, `unsafe_cursor`, `malformed_cursor`,
`snapshot_changed`, `subject_mission_cursor_mismatch`,
`subject_mission_not_selected`, `subject_plan_absent`, `subject_task_absent`
and `internal_error`. Any other message, including an import failure of the
implementation, becomes `internal_error`; exception text, paths, file bodies,
task bodies, attention reports and invalid values are never printed. Click
usage errors exit 2 outside this envelope and may echo an unknown option.

## Limitations

- `root: project_bucket` and `path` are lexical statements. The existing reader
  protects only the final path component; an intermediate `missions/S`
  symbolic link is not detected. No physical containment, read-only sandbox or
  safety guarantee is made.
- Duplicate JSON keys can make the capture's mission choice differ from the
  validated selection when the wrongly chosen mission has no files; the
  command still fails closed, possibly as `subject_plan_absent`.
- A rewrite that preserves size, inode and mtime is not detected.
- The report is not coherent across roots and reads no durable project
  records, run-control records or supervision snapshots.
