# Unrest repository guidance

These rules apply repository-wide. A nearer `AGENTS.md` adds rules for its
semantic subtree; read the complete root-to-leaf chain before editing.

## Authority and scope

- Resolve conflicts in this order: current maintainer/user instruction,
  accepted normative specification or ADR, the active task brief, effective
  `AGENTS.md`, then existing implementation.
- Keep one task to one coherent change. Do not begin an adjacent batch task,
  silently change task/gate/handoff semantics, or self-approve a protected
  change.
- Historical observations and `known_defect` fixtures are evidence, not a
  normative behavior oracle.

## Engineering rules

- Use Python 3.11+ and `uv`; `uv.lock` is authoritative. Prefer direct,
  typed, locally legible code and deterministic serialization.
- Never run concurrent mutable workers in one checkout. Sort enumerated inputs
  before persisted or generated output.
- Keep durable records in `.unrest/` and runtime cursors in
  `.unrest-runtime/`; do not collapse that boundary.
- Do not expose secrets, prompts, source bodies, reports, or unrelated command
  output in generated metadata or evidence.
- Update the canonical document and focused tests with any changed invariant,
  configuration contract, or operator workflow. Architecture and accepted
  decision entry points are listed in `docs/architecture/index.md`.

## Durable annotations

Use permanent comments only for non-obvious constraints and keep them locally
legible. Existing structured runtime invariant IDs remain documentation aids;
the repository command does not parse or recursively protect them. Keep
conversations, agent identity, hidden reasoning, and temporary handoff notes
out of source and documentation.

## Verification

Use three verification tiers. During a focused change, run the narrow tests and
static checks that exercise the edited behavior:

```bash
uv run pytest -q <focused-test-paths>
uv run ruff check <changed-product-paths>
uv run mypy <changed-typed-paths>
```

Use only the applicable changed paths, and record a stable reason when one of
the three check types does not apply. Escalate to the milestone tier when a
coherent implementation slice is complete; do not escalate a minor edit to the
release tier unless it is part of the frozen candidate.

At an implementation milestone, run the exact recursive repository checks plus
the focused tests for the completed slice:

```bash
uv run ruff check .
uv run mypy src
uv run unrest check-repository
uv run pytest -q <milestone-test-paths>
```

Reserve one full source-suite run for the frozen release candidate on Python
3.13. The release checkpoint is `env -u CODEX_PATH uv run pytest -q`; do not
repeat it after build or require it after minor edits. Python 3.11 and 3.12 are
compatibility lanes for package imports, focused contracts, repository
validation, and supported CLI surfaces, not duplicate full-suite lanes.

When CLI entry points, bundled assets, package data, or MCP surfaces change,
also run `uv build`, `uv run python tools/check_distribution.py dist`, and the
installed-wheel lifecycle from an unrelated temporary directory. The archive
check must verify complete member bytes and safely extract the sdist, then run
all 14 `tests/test_persistence_schema_v1.py` cases from that extracted tree
with package module, test module, cwd, and `sys.path` provenance excluding the
checkout. Post-build verification is focused on archive membership and content,
entry points, policy discovery, persistence/restart behavior, and fail-closed
startup; it does not rerun the full source suite.
