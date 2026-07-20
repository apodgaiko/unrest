# Compatibility inventory

| Area | Required compatibility | Evidence |
|---|---|---|
| Upstream baseline | License/community files, contract validation, stderr drain, and per-role reasoning survive | Diff review plus upstream tests |
| Codex ACP launch | Uses adapter-supported environment configuration and installed Codex executable | Environment unit tests and subprocess-config inspection |
| Provider isolation | Claude/Hermes do not inherit Codex-only sandbox/config hints | Unit tests |
| Project overrides | Optional worker model/effort persists and affects work nodes without flattening validator/reviewer role settings | Storage, server, controller, and runner tests |
| Failure handoff | Missing `end_node` reports retain bounded agent diagnostics | Unit tests with diagnostic chunks |
| Workspace | Worker and terminal review run in recorded workspace unless an explicit node cwd is supplied | Runner tests |
| Terminal review | Runtime crash becomes recoverable attention; real negative verdict behavior remains intact | Coordinator tests |
| Live snapshot | Project/mission/task/contract/attention/evidence summaries are read-only and resilient to partial state | Feature tests and before/after checksums |
| CLI | Text, JSON, watch, selection errors, and option conflicts behave through installed CLI | CLI tests and real commands |
| TUI | Dashboard renders, refreshes, navigates, and exits without mutating harness state | View-model tests and terminal smoke |
| Packaging | Textual dependency and lockfile resolve on Python 3.11–3.13 | uv sync and CI checks |

