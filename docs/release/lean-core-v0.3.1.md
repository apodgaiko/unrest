# Unrest v0.3.1 — Foundation Runtime

Unrest v0.3.1 turns the accepted FM-000 foundation from proposal material into
an additive runtime and ships the FM-010 measurement protocol used to steer the
next increments. It is backward compatible with v0.3.0 and adds no dependency,
optional extra, service, or data migration.

## Main changes

- Durable asynchronous Mission run admission, inspection, attachment and
  cooperative cancellation.
- Canonical typed identities, dependency-bound receipts and stable public error
  envelopes.
- Read-only Inquiry fan-out, synthesis, pause/resume/cancel and explicit Mission
  handoff.
- Scoped Git-worktree leases, disjoint parallel child work, patch return and
  parent-authorized integration.
- Offline evolution campaigns with candidate genealogy, independent evaluation
  and review, explicit-grant promotion and rollback.
- Twenty-three additive operations exposed through the same MCP and installed
  Python-library contract; the seven v0.3.0 MCP operations remain unchanged.
- A manual provider-backed FM-010 command with four cases, five cold repetitions
  per case, exact correctness oracles, median/MAD reporting, private raw data and
  sanitized valid/invalid/inconclusive observations.

The accepted-point path is singular: adjacent planes and parallel workers
return evidence or requests, while the Mission authority owns integration and
durable truth. Mutation requests are idempotent and crash-reconciled across the
accepted-point Git/evidence boundary.

## Practical perimeter

This is an enabling increment, not the final general-thinker architecture.
FM-010 stops and reports an invalid observation when cost or cache telemetry is
unavailable; it does not estimate missing values. Synchronous provider calls
cannot be interrupted between an individual nested call and its returned
telemetry. Interactive per-candidate human adjudication, a general scheduler
across unrelated projects, and automatic online self-modification remain later
work.

Ordinary import, installation, help and CI never execute the repeated provider
campaign. Run it explicitly with:

```bash
unrest measure-baseline \
  --protocol fm010-baseline-v1 \
  --destination docs/v03/measurement/results/v0.3.1 \
  --confirm-provider-work
```

## Release evidence

The candidate surface is bound by
`docs/release/lean-core-v0.3.1-manifest.json`; exact test-burden observations are
in `docs/release/lean-core-v0.3.1-burden.json`; rollback is documented in
`docs/release/lean-core-v0.3.1-rollback.md`. The annotated `v0.3.1` tag and the
GitHub Release own the final commit and archive identities. The published
`v0.3.0` tag remains immutable.
