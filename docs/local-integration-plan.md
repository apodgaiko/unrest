# Local branch integration plan

This plan records how the two local development lines should be integrated into
`product-main`, which starts at licensed upstream commit `a21c071`.

## Guardrail

Do not merge `fork/runtime-reliability` wholesale. It is based on `17ef688`, five
upstream changes behind `product-main`; a plain merge would reintroduce removed
technical-report build artifacts and obscure newer upstream license, CI,
contract-validation, ACP, and configuration work.

Port behavior in focused changes, with current-upstream tests retained.

## Runtime reliability line

Source: dirty working tree on `fork/runtime-reliability`.

### Port with redesign against current upstream

1. **Documented codex-acp configuration path**
   - Replace command-line `-c` injection with the adapter's `CODEX_CONFIG`,
     `INITIAL_AGENT_MODE`, and `CODEX_PATH` surfaces.
   - Preserve upstream per-role reasoning configuration rather than replacing it
     with the old branch's worker-only model.
   - Decide separately whether model selection should be global, per role, or
     persisted per project; do not silently make `gpt-5.6-sol` a permanent
     product default.

2. **Installed executable pinning**
   - Preserve resolved `uv` and Codex executable paths in generated MCP config
     where this is required for GUI-hosted agents.
   - Retain upstream environment allowlisting and validation.

3. **Failure diagnostics**
   - Preserve the tail of agent-message output when an ACP session ends without
     `end_node` and include it in the synthesized handoff.
   - Keep truncation and secret-exposure risk explicit in tests.

4. **Recoverable terminal-review runtime failure**
   - Convert a reviewer infrastructure crash into an attention item with the
     review artifact preserved, rather than treating it as proof that the
     mission failed.
   - Keep the normal reviewer verdict path unchanged.

5. **Workspace resolution**
   - Use the recorded project workspace consistently for workers and terminal
     review, while preserving explicit per-node `cwd` support.

### Retain from upstream

- The terminal-reviewer stderr drain from `ae200a3`; the old local diff would
  accidentally remove this fix.
- Non-empty contract enforcement from `bced7c3`/`feb1d62`.
- Per-role reasoning validation and configuration from `a21c071` unless a new
  contract deliberately replaces it.
- License, CI, security, contribution, and cleanup changes from `73f0004`.

### Drop or reconsider

- Do not restore deleted LaTeX build products.
- Do not remove upstream contract-empty checks.
- Do not replace the three per-role effort controls with one unvalidated
  worker-only string.
- Do not hard-code a model merely because it was current during the experiment.

## Terminal dashboard line

Source: commit `8ce5c28` on `experiment/terminal-dashboard`.

The dashboard is comparatively self-contained: three new implementation modules
and two new test modules. Port it after the runtime configuration decision so
the CLI and lockfile are resolved once.

Suggested port sequence:

1. Port the read-only snapshot model and `tests/test_live.py`.
2. Port the dashboard view-model and `tests/test_dashboard.py`.
3. Port the Textual application.
4. Integrate `zenith live` into the current CLI without overwriting newer init
   options.
5. Add `textual` through `uv add` and regenerate `uv.lock` from current upstream.
6. Run unit tests plus real `--once`, `--json`, and terminal-dashboard smoke
   checks against disposable project buckets.

The dashboard must remain observational: it may read project buckets but must
not mutate task, contract, attention, or mission state.

## Completion criteria

- Each port is a focused commit based on `product-main`.
- Current upstream tests remain green.
- New behavior has its own tests and at least one real-surface smoke check.
- `docs/upstream-lineage.md` records any upstream commits imported later.
- The old preservation branches remain intact until the ports have been
  independently verified.

