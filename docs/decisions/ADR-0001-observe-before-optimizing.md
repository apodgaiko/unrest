# ADR-0001: Observe before optimizing iteration

## Record metadata

id: ADR-0001
status: proposed
date: 2026-08-07
supersedes: []
superseded_by: null

## Scope

This non-accepted record preserves the rationale for a read-only operator
status surface. It never authorized dispatch, recovery, scheduling, liveness
inference, persistence, or completion prediction.

## Current disposition

Lean Core retains only the compact schema-v2 status contract documented in
[the runtime architecture](../v5/07-runtime-architecture.md). The earlier
observer shape was removed as an approved compatibility hard cut: nested
counts, per-task detail rows, attempt timing, anomaly bodies, shadow scheduling,
aliases, and alternate detail modes have no source, package, or CLI surface.

Consumers migrate atomically to schema v2. There is no negotiation flag or
legacy rendering mode, and no project-data migration is needed because status
observation writes nothing. The five schema-v2 diagnostics remain bounded and
carry neither cursor bodies nor filesystem paths.

## Retained rationale

File timestamps can identify an item worth inspecting, but cannot establish
that a provider is dead or estimate remaining work. Any future wake, recovery,
reuse, or mutable-concurrency change needs its own accepted contract and
single-writer/restart evidence; observer output supplies no such authority.

## Verification

```bash
uv run pytest -q tests/test_runtime_observability.py tests/test_cli.py::TestObserveProject
uv run pytest -q tests/contracts/test_lean_status.py
```

Real CLI verification covers JSON/text bytes, every derived state and code,
the strict/ambient aggregate exit matrix, privacy sentinels, unchanged project
trees, and fresh-process import traps.
