# Harness package guidance

This file adds package rules to the root `AGENTS.md`.

- Preserve the typed public models, MCP envelopes, stable error codes, and the
  authored task-order tie-break unless an accepted specification explicitly
  changes them.
- `MissionCoordinator.step()` owns one state transition at a time;
  `ProjectController` resumes from disk for every tool call; `ProjectStore`
  owns storage paths and atomic writes.
- Keep durable `.unrest/` records separate from orchestrator-only
  `.unrest-runtime/` cursors. Migration or compatibility behavior must be
  explicit, versioned, and tested; do not add heuristic readers.
- Provider and ACP changes must fail closed. Never broaden filesystem,
  terminal, network, credential, or environment authority as a fallback.
- Run the nearest focused tests under `tests/`, then the repository gate in
  the root guidance. Update the applicable document reached from
  `docs/architecture/index.md` when behavior changes.
