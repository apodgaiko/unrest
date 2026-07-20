# Upstream compatibility mission

## Outcome

Integrate the preserved runtime-reliability and terminal-dashboard work onto the
licensed upstream `a21c071` baseline without undoing newer upstream behavior,
then prove compatibility through upstream CI-equivalent checks, feature tests,
and real CLI/TUI surfaces.

## Scope

- Preserve upstream Apache licensing, CI, non-empty contract validation,
  per-role Codex reasoning configuration, and terminal-review stderr draining.
- Port the documented codex-acp environment integration, executable pinning,
  project-scoped worker overrides, diagnostic handoffs, recorded workspace use,
  and recoverable terminal-review runtime failures.
- Port the read-only live snapshot, JSON/text CLI, dashboard view-model, and
  Textual terminal dashboard.
- Preserve provider isolation and avoid leaking Codex-only configuration to
  Claude or Hermes workers.

## Non-goals

- No claim of compatibility with upstream commits newer than `a21c071` without
  fetching and repeating this audit.
- No redesign of mission/task semantics beyond the preserved runtime changes.
- No restoration of deleted technical-report build products.

## Validation strategy

- Run upstream CI commands: Ruff, mypy, and the full pytest suite.
- Run on every upstream-supported Python version locally available through uv.
- Retain and update upstream tests rather than replacing them with fork-only
  tests.
- Exercise real `zenith --help`, `zenith live --once`, `zenith live --json`,
  invalid option combinations, project selection, and a bounded Textual app
  startup/exit flow against disposable project buckets.
- Review the final diff against both upstream and preservation branches for
  omitted behavior, reverted fixes, and accidental mutations.

## Risks

- The preserved runtime branch predates upstream per-role effort controls and
  would erase them if replayed wholesale.
- The dashboard branch modifies the same CLI and lockfile as upstream.
- Unit tests can fake compatibility if they mock ACP process configuration or
  never exercise the installed CLI.

