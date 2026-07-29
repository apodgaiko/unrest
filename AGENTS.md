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
- Treat `evals/baseline/` as evidence about the approved base. An
  `observed_legacy` or `known_defect` fixture is not a normative behavior
  oracle.

## Engineering rules

- Use Python 3.11+ and `uv`; `uv.lock` is authoritative. Prefer direct,
  typed, locally legible code and deterministic serialization.
- Never run concurrent mutable workers in one checkout. Sort enumerated inputs
  before persisted or generated output.
- Keep durable records in `.unrest/` and runtime cursors in
  `.unrest-runtime/`; do not collapse that boundary.
- Do not expose secrets, prompts, source bodies, reports, or unrelated command
  output in generated metadata or evidence.
- Update the canonical normative document and focused tests with any changed
  invariant, schema, configuration contract, or operator workflow. Normative
  metadata and stable IDs are governed from
  `docs/architecture/index.md`.

## Durable annotations

Use structured permanent annotations only for non-obvious constraints:
`INVARIANT[ID]`, `SECURITY[ID]`, `COMPAT[ID]`, `WHY[ADR-ID]`, or
`TODO[#issue; remove-after=condition]`. Every reference must resolve through
the architecture registries. Keep conversations, agent identity, hidden
reasoning, and temporary handoff notes out of source and documentation.

## Verification

Run focused tests first, then the common gate from the repository root:

```bash
uv sync --locked
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run unrest check-repository
uv build
```

The provider-independent suite assumes provider discovery controls
`CODEX_PATH`; if the host injects that variable, run the full test command as
`env -u CODEX_PATH uv run pytest -q`.

When CLI entry points, bundled assets, package data, or MCP surfaces change,
also exercise the installed wheel from an unrelated temporary directory.
