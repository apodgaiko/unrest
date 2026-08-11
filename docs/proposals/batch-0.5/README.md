# Batch 0.5 Lean Core accepted scope package

Status: accepted 2026-08-09 as the implementation scope for ADR-0002.

## Purpose

Preserve the finite package accepted by the maintainer for controlled Lean Core
implementation. ADR-0002 is the decision authority; these documents define its
retained behavior, hard cuts, security boundary, and measurement method.

## Review order

1. `docs/decisions/ADR-0002-lean-core-v0.2.md` — decision and hard-cut summary.
2. `behavior-contract.md` — the complete retained user/runtime perimeter.
3. `security-contract.md` — the narrowed authority and credential promise.
4. `deletion-ledger.md` — guarantees, modules, tests, and assets proposed for
   removal or replacement.
5. `measurement-protocol.md` — fixed baseline, metrics, thresholds, and stop
   rules.
6. `review-notes-2026-08-09.md` — immutable reviewer input; the other drafts
   incorporate its accepted findings and the reconciliations below.

The behavior, security, deletion-ledger, and measurement documents are accepted
scope inputs to ADR-0002. The two review-note files remain immutable historical
review input rather than normative specifications or test results.

## Review reconciliation

- Accepted B1: explicit inventory propagation is new implementation work and
  now has atomic behavior/evidence requirements.
- Accepted B2: transformed-secret removal is labeled a current runtime security
  cut, with inverted evidence rather than silent test deletion.
- Accepted B3: baseline code, all baseline static bindings, and affected checker
  sections land atomically and leave `check-repository` green.
- Accepted major revisions 1–6: narrow checker replacements are counted;
  missing tests/guidance are in the ledger; the sink inventory is seventeen;
  terminal credential removal is a behavior cut; the short-token guard remains;
  and dependency rationales are split by actual consumer.
- Pushback on the review: the 30% maintained-code floor does not follow from the
  production cut, the unsupported third child provider was still a
  documented/tested compatibility surface, and unsafe `*` should mean
  forwarding authority—not an empty inventory or an attempt to classify every
  ambient value as a credential.

## Proposed product perimeter

### Retain

- project creation and durable mission state;
- contract-backed task planning;
- work, validation, and gate semantics;
- independent validator handoffs;
- attention decisions and bounded task-list patching;
- terminal review before closure;
- restart and reconciliation of current persisted missions;
- one mutable work task at a time in a shared checkout;
- deterministic authored ordering and validator-only parallel batches;
- atomic text and JSON persistence;
- Claude and Codex orchestration;
- fail-closed safe provider configuration and explicit unsafe opt-in;
- canonical ACP filesystem callback roots and terminal cwd checks;
- explicit environment and credential allowlists;
- finite provider/role credential inventories in safe and explicit unsafe mode,
  explicitly threaded through coordinator, persistence, CLI/config/bootstrap,
  and diagnostics;
- exact-known-credential redaction at seventeen named Unrest-owned boundaries,
  with the short-token boundary rule;
- installed-wheel lifecycle verification; and
- one concise read-only status surface for a project or all projects.

### Deliberately withdraw

- public `check-governance` and `check-commit` commands;
- repository-wide self-protection, commit-trailer, PR/ADR mini-language, and CI
  topology proof;
- historical baseline regeneration as installed product behavior;
- static proof of every possible capability-derived output call;
- source-graph semantic digests and mutation completeness suites;
- inference of arbitrary credential names or unknown secrets;
- semantic parsing of structured-looking strings and recursive transform
  enumeration, including the current runtime redaction of transformed values;
- observer shadow-scheduler projection, detailed attempt reconstruction,
  compatibility aliases, and dashboard-oriented nested models;
- detailed release execution history in the current product tree; and
- the unsupported third child-provider surface; no deployed/configured in-tree
  consumer was found, but its documented and tested compatibility surface made
  removal a maintainer-approved hard cut.

### Explicit limitations

- Filesystem callback roots do not confine arbitrary subprocess side effects.
- Lean Core does not enforce network denial.
- A child that receives a credential is trusted with it; redaction mitigates
  accidental reflection through named Unrest-owned outputs, not intentional
  exfiltration.
- Exact-known-value redaction does not detect partial, hashed, encoded,
  encrypted, reordered, or otherwise transformed credentials.
- Short token-like credentials use token boundaries: for example, `KEY` is
  redacted as a token but does not corrupt `MONKEY`; longer/non-token-like
  credentials remain embedded-substring matches.
- Wildcard unsafe forwarding is not credential identity. Safe and explicit
  unsafe modes retain a finite provider/role credential set; undeclared values
  broadly inherited only by unsafe mode remain outside the guarantee.
- Compaction targets code comprehension, local validation, and release-suite
  latency. It does not claim to remove host wake, attention, gate, or closure
  idle time.

## Proposed compatibility matrix

| Surface | v0.2 proposal | Compatibility treatment |
| --- | --- | --- |
| Persisted project/mission schema version 1 | Retain | Existing project fixtures must load and resume; no general migration framework |
| Orchestrator MCP lifecycle | Retain | Tool names and envelope behavior remain current unless separately approved |
| Claude orchestration | Retain | Safe and explicit unsafe configuration remain covered |
| Codex orchestration | Retain | Safe and explicit unsafe configuration remain covered |
| Unsupported third child-provider roles | Remove | No deployed/configured in-tree consumer exists; the former documentation/tests establish the approved compatibility cut |
| `check-repository` | Narrow | Keep one development command; remove recursive self-protection guarantees |
| `check-governance` | Remove | Document as a v0.2 hard cut |
| `check-commit` | Remove | Document as a v0.2 hard cut |
| Terminal provider credentials | Remove from terminal children | Runtime/compatibility hard cut from current inheritance; adapter delivery remains |
| Transformed-value redaction | Remove | Runtime security hard cut; retain an inverted evidence case |
| `observe-project` text/JSON | Replace | Publish schema version 2 and migration notes |
| `observe-project --all --strict` | Retain narrowly | Preserve bounded per-project success/failure aggregation |
| Installed-wheel lifecycle | Retain | Continue verification from an unrelated working directory |

## Review decisions required

The maintainer should explicitly answer these before implementation:

- Accept or reject the proposed public-command cuts.
- Accept removal of the documented/tested unsupported third child-provider
  surface despite the absence of a deployed/configured in-tree consumer.
- Confirm persisted schema-version-1 read/resume compatibility.
- Accept terminal children receiving none of the finite selected credential set
  by default as a runtime behavior cut, with before/after evidence.
- Accept the exact security limitations and named sink inventory.
- Accept observer schema version 2 and its proposed minimum fields.
- Accept 40% installed-core and 30% total-maintained-Python reduction as hard
  floors, with 50% and 40% respectively as stretch goals.
- Accept that the initial contract-test change may increase test LOC.
- Accept risk-separated changes rather than an absolute PR-count quota.
- Resolve whether `unrest.dev` publishes the root schemas and whether any
  out-of-tree observer schema-v1 consumer requires a migration notice.

## Proposed execution topology after approval

0. Scope lock and executable retained-behavior tests; no production rewrite.
1. Governance, repository-contract, historical baseline, associated schemas,
   baseline-specific sink anchors/static repository-proof sections, and root
   release-evidence cleanup; add command-local CLI imports and explicit small
   replacements for the retained checker duties.
2. Capability runtime rewrite alone, with two green internal milestones: first
   wire finite inventories, all seventeen sinks, terminal exclusion, diagnostic
   handling, and child-pipe lifecycle; then compact the redactor/static
   assurance and invert the transformed-secret evidence. Temporarily compare
   retained behavior during development, then remove the old implementation
   before merge.
3. Observer schema-version-2 compaction, dependency cleanup, installed-wheel
   validation, and frozen-candidate measurement.

Each implementation slice removes its withdrawn tests and guarantees together.
Every intermediate slice must pass the then-current `check-repository`; no
slice may leave imports or sink anchors pointing at a deleted module.
No permanent classic/lean feature flag or optional assurance copy is proposed.

The 40% installed-production floor is gated by slice 2. Leaving the 7,532-line
capability module untouched makes the floor impossible even if the other four
target modules disappear completely: 16,322 lines remain, 884 above the
ceiling. The 30% total-maintained floor is independent and also needs explicit
test/tool reductions. Acceptance of either headline target is not proof that
the replacement code fits its budget.
