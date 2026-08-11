# ADR-0002: Define the Lean Core v0.2 compaction perimeter

## Record metadata

id: ADR-0002
status: accepted
date: 2026-08-09
task_ids:
  - BATCH-0.5-SCOPE-LOCK
contract_targets:
  - VAL-LEAN-LIFECYCLE
  - VAL-LEAN-PERSISTENCE
  - VAL-LEAN-SCHEDULING
  - VAL-LEAN-PROVIDERS
  - VAL-LEAN-SECURITY
  - VAL-LEAN-PACKAGE
  - VAL-LEAN-STATUS
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-contract
  - full-repository
  - installed-wheel
  - real-cli

## Scope

- In scope: a hard-cut v0.2 perimeter for the central Unrest mission lifecycle,
  runtime authorization, persistence, provider support, packaging, operator
  status, repository-development checks, and the measurements used to judge
  compaction.
- Out of scope: implementation before maintainer approval; Batch 1; autonomous
  wake or recovery; evidence or gate-result reuse; concurrent mutable workers;
  scoped revalidation; promotion or canary infrastructure; self-evolution; and
  rewriting Git history.

## Context

Current `main` at `93c59e4378407f3d7cfb918cf86c8bdc81daa141`
contains 25,730 installed production Python lines and 26,466 test Python
lines. The five largest assurance-oriented product modules account for 16,940
production lines. Leaving the 7,532-line capability module untouched makes the
15,438-line floor mathematically impossible even if the other four target
modules disappear completely: 16,322 lines remain, 884 above the ceiling. The
40% result is therefore gated on the riskiest slice. The recorded
Python 3.13 source suite took 4,246.59 seconds,
while the closed capability-model and source-graph tests alone took 476.99
seconds.

The main complexity is not the core mission state machine. It is repository
self-governance, historical reproduction, static capability-effect proof,
transformed-secret classification, and detailed telemetry projection. Keeping
all current guarantees makes a 40% reduction unrealistic. Removing guarantees
without first naming the retained perimeter risks a smaller but ambiguous
product.

The maintainer accepted this record and the supporting proposal package on
2026-08-09. The accepted package authorizes controlled implementation of the
scope, hard cuts, security contract, measurement protocol, and rollback plan.

## Decision

Adopt the following Lean Core v0.2 perimeter:

1. Preserve project creation, contract-backed planning, work/validation/gate
   semantics, attention decisions, bounded replanning, terminal review,
   restart/reconciliation, single mutable-work selection, and atomic text/JSON
   persistence.
2. Preserve Claude and Codex orchestration. Remove the unsupported third
   child-provider compatibility surface; no deployed/configured in-tree
   consumer exists. This is an explicit maintainer-approved compatibility hard
   cut. Retain only the abstraction needed by the supported providers.
3. Preserve read compatibility for current schema-version-1 project and
   mission records. Do not add a general migration framework.
4. Remove the public `check-governance` and `check-commit` commands. Retain one
   lazily imported `check-repository` development command with a deliberately
   small contract: required guidance, resolving important references, basic
   component ownership, loadable packaged runtime policy, and confirmation
   that installed-wheel validation remains wired into CI. Implement those
   duties directly with small command-local helpers; do not rehome the generic
   governance parser under a new name, and count every replacement line.
5. Delete historical baseline generation, its bundled sink anchors, repository self-protection
   machinery, static capability source/sink proof, semantic digests,
   transformed-secret inference and the current runtime redaction of supported
   transformed values, analyzer mutation suites, duplicate schemas, and
   detailed release evidence from the current product tree.
6. Preserve fail-closed runtime provider configuration, explicit role
   authority, canonical ACP filesystem callback roots, structured terminal
   invocation, explicit environment/credential allowlists, exact-known-value
   redaction, bounded inherited-FD inventory transport, and centralized atomic
   persistence. Add the currently missing exact-value inventory path from the
   orchestrator through attempt/terminal-review persistence, runtime cursors,
   CLI/config/bootstrap writers, and diagnostics; storage's optional parameter
   is not sufficient while coordinator and CLI call sites omit it.
7. Supply the finite selected provider/role credential set to the adapter
   process. Terminal children receive none of that set by default; any
   exception must be a new, explicit, named authorization rather than ambient
   inheritance.
8. State that callback roots and terminal working-directory checks are not an
   operating-system sandbox for arbitrary subprocess side effects. Lean Core
   makes no network-denial claim.
9. Replace observer schema version 1 with a documented schema version 2. Keep
   project-scoped and `--all` observation, `--strict`, bounded coherent reads,
   persisted and derived state, attention, running/runnable/failed task IDs,
   last-change age, and a small finite set of operator-relevant failure or
   anomaly codes. Remove shadow scheduling, detailed attempt timing,
   compatibility aliases, and nested count projections.
10. In both profiles, define exact-value matching with the retained short-token
    boundary guard: token-like values shorter than eight characters match only
    at token boundaries, while longer or non-token-like values match wherever
    embedded. Wildcard unsafe forwarding is authority only, never credential
    identity: both profiles retain a finite provider/role credential-name set,
    while undeclared values broadly inherited by unsafe mode remain outside the
    guarantee.
11. Ensure worker/reviewer MCP subprocess stdout and stderr are drained,
    redirected, or otherwise bounded so pipe backpressure cannot deadlock a
    mission.
12. Judge compaction by installed-core size, total maintained first-party size,
    preserved-behavior evidence, test latency, import reachability, packaging,
    and security-boundary evidence. Moving code to another maintained location
    does not count as deletion.

The supporting review drafts are under `docs/proposals/batch-0.5/`.

## Alternatives considered

- Preserve every current guarantee and refactor internally: lower compatibility
  risk, but likely limited to a 10–15% reduction and retains the dominant
  synchronized-change burden.
- Move advanced assurance into an optional package: reduces installed-core
  size but preserves maintenance cost and encourages a permanent dual product.
- Remove all capability machinery: smaller, but would delete runtime authority,
  provider safety, path checks, and redaction rather than the static assurance
  layer.
- Remove multi-project observation: smaller, but loses the bounded view that
  identified stale historical runtime records.
- Add autonomous wake or recovery during compaction: potentially improves
  mission elapsed time, but changes single-writer, restart, and idempotency
  semantics outside this batch.

## Consequences

- Positive: the critical mission path becomes the primary product rather than a
  substrate for repository theorem-proving.
- Positive: security claims become finite and testable at named boundaries.
- Positive: focused changes and the provider-independent release suite receive
  explicit time budgets.
- Negative/cost: repository checks lose several public guarantees. No in-tree
  schema-v1 observer consumer exists; any out-of-tree consumer must adopt
  schema version 2 or remain on v0.1.
- Compatibility/runtime hard cuts: `check-governance`, `check-commit`, terminal
  credential inheritance, transformed-secret redaction, detailed observer
  schema version 1, and the unsupported third child-provider surface are
  deliberately withdrawn.
- Assurance hard cuts: static egress completeness, semantic source-graph
  digests, and recursive repository self-protection are deliberately withdrawn.
- Schema/migration impact: persisted mission schema version 1 remains readable;
  observer output alone changes to schema version 2 and is read-only.
- Security/privacy impact: in safe mode, exact known credentials remain
  protected at named Unrest-owned boundaries using the documented short-token
  rule, but unknown or transformed secrets and intentional exfiltration by a
  credential-bearing child are outside the claim. The explicit unrestricted
  profile still protects the finite known credential set, but undeclared values
  inherited only through its wildcard authority are outside the claim.

## Historical acceptance record (non-operative)

The now-withdrawn governance process classified this decision as touching
capability policy, governance self-protection, and rollback controls. A
maintainer approved the ADR and its review drafts on 2026-08-09 using the
review and commit-trailer conventions then in force. This records how the
decision was accepted; it imposes no current protected-surface field, reviewer
role, or commit-trailer syntax. Evaluation used the focused behavior/security
contracts, repository measurements, installed-wheel lifecycle, real CLI
status, and the frozen-candidate Python 3.13 source-suite checkpoint.

## Rollback

- Trigger: a compaction slice breaks a retained behavior, weakens a retained
  authority boundary, cannot read current persisted projects, recreates the
  deleted subsystem under another name, or misses its recorded size/time gate.
- Procedure: revert only the failing compaction slice and reinstall the last
  accepted wheel; do not preserve an unvalidated dual implementation.
- Data recovery: none for the proposed observer change because it remains
  read-only; persisted schema version 1 is unchanged.
- Verification: run the retained behavior/security contract, schema-version-1
  project fixtures, installed-wheel lifecycle, and relevant real CLI flow.

## Implementation and verification

- Components/paths: `COMP-BASELINE`, `COMP-CAPABILITY`, `COMP-GOVERNANCE`,
  `COMP-OBSERVABILITY`, `COMP-REPOSITORY-CONTRACT`, `COMP-CLI-CONFIG`,
  `COMP-ACP`, and their associated source, test, schema, policy, and evidence
  paths.
- Normative documents: update the accepted runtime, capability, repository,
  task, storage, README, and ADR registries only after this proposal is approved.
- Tests/evidence: follow `docs/proposals/batch-0.5/behavior-contract.md`,
  `security-contract.md`, and `measurement-protocol.md`.
- Slice dependency: historical baseline deletion and retirement of every
  baseline sink anchor/affected repository-contract section land atomically so
  `check-repository` passes at each intermediate commit.
- External acceptance checks: determine whether the `unrest.dev` root-schema
  identifiers are published and record any out-of-tree observer schema-v1
  migration requirement. These questions do not justify retaining an unknown
  compatibility layer.

## References

- `docs/proposals/batch-0.5/README.md`
- `docs/proposals/batch-0.5/behavior-contract.md`
- `docs/proposals/batch-0.5/security-contract.md`
- `docs/proposals/batch-0.5/deletion-ledger.md`
- `docs/proposals/batch-0.5/measurement-protocol.md`
- `docs/release/telemetry-cold-start-hardening.md`
- `docs/architecture/capability-policy.md`
