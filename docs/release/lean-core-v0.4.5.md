# Unrest v0.4.5 — activation candidate

This is source preparation pending external gates, before final candidate freeze.
Source acceptance
is not benchmark certification or release eligibility. Candidate-specific
integration, independent real-surface validation, the full Python 3.13 source
suite, release packaging and installed-wheel verification remain pending.
No quality, speed, useful live-dogfood result, or publication is claimed here.

## Changes in the candidate

- Inquiry adds strict branch and synthesis output handling, bounded provider
  sessions, evidence-bound answers and diagnostics, and retained restart and
  idempotency state. Inquiry handoff remains an evidence artifact; creating a
  Mission requires a separate authorized decision.
- Evidence-frontier handling tracks the current task graph, attempts,
  validation, supersession and gates rather than treating historical success
  as current evidence.
- Legibility and supervision expose bounded public identities, read-only
  inspection and explicit steering through the existing coordinator. Atomic
  decision batches retain recovery and lineage. Checkpoints do not grade
  reasoning or style; elapsed time alone grants no stop or restart authority.
- ACP launch preflight checks an immutable launch plan before provider work,
  keeps environment and PATH authority explicit, and returns bounded failure
  categories. Rejection does not expand permissions or retry automatically.
- Dogfood activation provides closed request parsing and packaged examples for
  Inquiry, `run-task`, `run-project` and `run-improvement`. Examples are
  synthetic. `run-task` currently refuses with `provider_approval_required`
  before Inquiry/provider/durable work because the closed request lacks an
  externally authenticated approval carrier. Project and improvement calls
  require the exact externally supplied requests and matching prerequisites.
- The worker/validator completion check at `end_node` verifies structural
  handoff fields before independent review. One refusal permits repair in the
  same active attempt; a second invalid completion follows failure/attention
  handling. Passing this check is neither substantive validation nor approval.

These descriptions concern the integrated implementation, not fresh final
candidate certification. Relevant source surfaces are
[Inquiry](../../src/unrest_harness/inquiry.py),
[evidence frontier](../../src/unrest_harness/envelope.py),
[supervision](../../src/unrest_harness/supervision.py),
[atomic decision batches](../../src/unrest_harness/patch_transaction.py),
[ACP launch](../../src/unrest_harness/acp_runner.py),
[completion handling](../../src/unrest_harness/server.py), and the
[dogfood guide](../../src/unrest_harness/bundled/skills/v045-dogfood/SKILL.md).

## Compatibility and authority

Python >=3.13 remains required, with Python 3.13 as the single CI and release
lane. This metadata change adds no dependency and upgrades no locked dependency.
The integrated runtime retains legacy missing/null identity and lineage reads
without rewriting those records. New additive durable records still require
preservation; this is not a promise that v0.4.0 can interpret every new record.
See the [rollback procedure](lean-core-v0.4.5-rollback.md).

Existing Mission, provider, budget, gate, promotion and release authorities
remain in force. Supervision adds no second dispatcher, default provider call,
or automatic restart. Inquiry and adapter results cannot approve or promote.
The maintainer approved release profile `v045-correctness-release-exception-1`.
The manifest binds the actual approval and preserved proposal by SHA256; approval
is not completed validation and does not itself confer release eligibility.
The [2026-09-28 integrated validation amendment](lean-core-v0.4.5-gate-amendment.md)
superseded that profile's correctness, runner, and ruler gates. The later
[focused release gate](lean-core-v0.4.5-gate-amendment-2.md) is effective for
v0.4.5 and replaces the 70-target independent matrix with explicit bounded
checks while preserving the earlier decisions as history. The subsequent
[historical speed-runner exclusion](lean-core-v0.4.5-gate-amendment-3.md)
removes one obsolete v0.4 benchmark test module from this release checkpoint;
no benchmark pass is claimed.

## Approved profile and pending obligations

All 70 target dispositions remain an intended-behavior inventory: 66
unchanged targets and four qualified targets, ACT006, CROSS005, EVAL001 and
EVAL002. The earlier CLI applicability decision deferred nine historical CLI
scenarios and 45 assertions. The original profile required 52 correctness
cases: 11 C-INQ, 6 C-EVD, 13 C-LEG, 9 C-ACP, 9 C-ACT and 4 C-CROSS. The
2026-09-28 amendment replaced that campaign with a 70-target independent
matrix. Neither campaign completed or passed. The effective focused gate
requires a candidate-bound safety checklist, one bounded live Inquiry, final
source and distribution checks, exact CI, and a separate maintainer decision.
It does not certify all 70 targets. ACT006's 27 applicable outcome scenarios lack complete execution
and positive ACT008/ACT009 dogfood proofs remain unrun and are explicitly
deferred. No synthetic result is counted as a positive external dogfood run.

Comparative quality, Mission-speed, resource and historical workflow campaigns
are deferred without a pass. `benchmark_certified` is false and
`improvement_claims` is empty. API judge credentials and benchmark spending
are not prerequisites for this release route. Original blocked/not_run records
are preserved.

The historical correctness-run retry policy permitted at most one whole run
retry, only for narrowly evidenced transport/resource infrastructure failure.
Deterministic, candidate and semantic failures cannot be reclassified as infrastructure. Both attempts
count against the original provider-free limits: 180 executions, 1200 seconds
per execution and 21600 seconds aggregate. That policy does not govern the
focused release gate, and no correctness-run retry is claimed.

The separate bounded live Inquiry lifecycle uses installed public-library
`run_task` through existing Codex subscription access, with authenticated
project_id and a concrete planning question. It requires gpt-6-astra at medium,
at most two branches plus one synthesis, three attempts, 600 seconds aggregate,
65536 response bytes per attempt and max_steps=8 per attempt. Steps are reported
and validated via structured steps_used; unknown or over-budget results remain
non-passes. This is not an eight-tool-call cap, nor a token or USD estimate.
No automatic live replay, API purchase, API fallback or additional spending is
authorized. Read-only capabilities, private provider artifacts separate from
the product repository, schema-valid branch/synthesis objects, a non-null safe
answer, named planner consumption and Mission before/after bytes remain required.
ACP provider sessions count raw assistant text bytes before credential redaction
against the response-byte ceiling and keep a bounded redacted stream in private
artifacts. When ACP supplies message IDs for every chunk, the final assistant
message alone must be a closed JSON object; earlier progress messages are not
part of that object. Missing IDs fall back
to whole-stream parsing. A preamble in the final message, trailing prose, malformed
JSON, or an over-limit full stream still fails closed.

The installed CLI's `provider_approval_required` refusal is a separate behavior;
this approval does not add a CLI approval carrier or bypass library authority.

The following effective gates remain pending:

- Fresh candidate-bound integration reconciliation, planning review, and the
  focused safety checklist covering public profile and ABI compatibility,
  legacy reads and recovery, authority refusals, current evidence, privacy,
  ACP/MCP process behavior, restart, cancellation, and cleanup.
- The separately bounded live Inquiry proof with named planner consumption.
  Synthetic controls cannot substitute for this live lifecycle.
- The single final Python 3.13 source-suite checkpoint excluding only
  `tests/test_v04_speed_runner.py`, recursive checks,
  exact wheel/sdist archive verification, unrelated-directory installed
  lifecycle, fail-closed startup, and all 15 extracted-sdist persistence cases.
- Successful CI on the exact final HEAD, blocker reconciliation, and a separate
  maintainer release decision before tagging, publication or installation.

Source preparation can be accepted separately. Final candidate freeze, release
eligibility and publication remain pending until these results are recorded.

## Source and future artifacts

The active binding owner is
[lean-core-v0.4.5-manifest.json](lean-core-v0.4.5-manifest.json). It hashes sorted
regular Git-tracked files under `src`, `tests` and `tools`, plus
`pyproject.toml` and `uv.lock`. Commit verification must read exact Git blobs;
the binding CLI's `--revision` selects paths but still reads filesystem bytes.
The manifest excludes its containing commit and diff identity to avoid circular
hashes. Historical v0.4.0 and older release records remain immutable.

The release predecessor is `v0.4.0`, commit
`8decbecf7cad32552dfd7d48e069d4050e04ffd3`; the accepted assembly parent is a
separate identity recorded in the external candidate handoff. The release-prep branch is `codex/v045-release-prep-20260928`.

Expected future artifacts are `unrest_harness-0.4.5-py3-none-any.whl` and
`unrest_harness-0.4.5.tar.gz`, with CI bundle `unrest-v0.4.5-python313`.
Their actual archive hashes belong in an external `SHA256SUMS` after the
final candidate build. The local editable development installation verifies
source-stage identity only; it does not verify those future archives.
