# Unrest v0.4.0 — Composition Adapters

Unrest v0.4.0 adds a compact general-purpose composition layer over the v0.3.1
foundation runtime. It reduces the number of public orchestration calls needed
for bounded task, project, and improvement flows without creating competing
runtime authority.

## Main changes

- `run-task` and `unrest_harness.api.run_task` execute one bounded Inquiry
  lifecycle and return a canonical terminal result.
- `run-project` and `unrest_harness.api.run_project` execute an exact,
  already-submitted declarative Mission DAG. Independent leaves may run in
  parallel while the existing coordinator retains dispatch, workspace,
  integration, failure, and cleanup authority.
- `run-improvement` and `unrest_harness.api.run_improvement` carry one local
  candidate through evaluation and review, then stop at `decision_needed`.
  They cannot promote, roll back, call a provider, or use the network.
- A deterministic provider-free paired runner verifies equivalent outcomes and
  fewer public invocations for the primitive and adapter paths.
- Python 3.13 is now the minimum supported runtime and the single CI and release
  lane.

The paired ACT-200 run passed all outcome, operation-sequence, isolation, call
reduction, and median-time gates. It observed zero provider, network, and
subprocess attempts. The release adds no dependency family, always-on service,
or data migration.

## Practical perimeter

This release is the first general-thinker-oriented composition increment, not a
general autonomous scheduler. Task bounds remain finite; project DAGs must be
submitted before execution; improvement stops before promotion; and accepted
state still crosses the existing Mission authority boundary. Live-provider
campaigns, automatic promotion, and unrelated-project scheduling remain
outside v0.4.0.

## Release evidence

The release surface is bound by
`docs/release/lean-core-v0.4.0-manifest.json`; rollback is documented in
`docs/release/lean-core-v0.4.0-rollback.md`. The annotated `v0.4.0` tag and the
GitHub Release own the final commit and archive identities. The published
`v0.3.1` tag remains immutable.
