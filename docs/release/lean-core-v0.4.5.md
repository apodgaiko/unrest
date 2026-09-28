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
The later [integrated validation amendment](lean-core-v0.4.5-gate-amendment.md)
supersedes that profile's correctness, runner, and ruler gates while retaining
its other release boundaries.

## Approved profile and pending obligations

All 70 target dispositions remain explicit: 66 unchanged functional targets and
four qualified targets, ACT006, CROSS005, EVAL001 and EVAL002. The approved
CLI applicability decision defers exactly nine historical CLI scenarios and
45 assertions without counting them as passes or changing the 52-case
inventory. The original profile required all 52 correctness cases, including
their visible/held-out split:
11 C-INQ, 6 C-EVD, 13 C-LEG, 9 C-ACP, 9 C-ACT and 4 C-CROSS. Those cases
are historical obligations superseded by the later amendment, not completed
results. The effective gate now requires candidate-bound independent integrated
dispositions for every one of the 70 contracts. The 67 product targets require
real-surface verdicts; CROSS005, EVAL001, and EVAL002 follow the amendment's
qualified governance obligations. Comparative quality, Mission-speed, resource
and historical workflow campaigns
are deferred, without a pass. `benchmark_certified` is false and
`improvement_claims` is empty. Deferral never waives functional behavior.
API judge credentials and benchmark spending are not prerequisites for this
approved deferred-campaign route; original blocked/not_run records are preserved.

The historical correctness-run retry policy permitted at most one whole run
retry, only for narrowly evidenced transport/resource infrastructure failure.
Deterministic, candidate
and semantic failures cannot be reclassified as infrastructure. Both attempts
count against the original provider-free limits: 180 executions, 1200 seconds
per execution and 21600 seconds aggregate. That policy does not govern the
replacement integrated matrix, and no correctness-run retry is claimed.

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
The installed CLI's `provider_approval_required` refusal is a separate behavior;
this approval does not add a CLI approval carrier or bypass library authority.

The following effective gates remain pending:

- Fresh applicable planning acceptance and the amendment's independent
  integrated matrix for all 70 contract dispositions.
- Integration and independent functional validation for all accepted contracts,
  followed by bounded live Inquiry proof. Synthetic controls cannot substitute
  for the live lifecycle or the integrated real-surface matrix.
- The final Python 3.13 source suite, including real process, ACP/MCP,
  supervision, cancellation and cleanup checks. The full suite remains a single
  frozen-candidate checkpoint, not a source-preparation check.
- Exact wheel/sdist archive verification, installed lifecycle, fail-closed
  startup, persistence/restart/recovery and all 15 extracted-sdist persistence cases.
- A separate release decision packet binding actual accepted public semantics,
  approval, final candidate and all preserved gate evidence, required CI and
  publication authority. No containing commit or imagined public schema identity
  is supplied by this source manifest.

Source preparation can be accepted separately. Final candidate checkpoint
admission waits for the amended planning and independent integrated validation
requirements; final freeze, release eligibility and publication remain pending.

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
separate identity recorded in the external candidate handoff. The candidate
branch is `codex/v045-release-r2`.

Expected future artifacts are `unrest_harness-0.4.5-py3-none-any.whl` and
`unrest_harness-0.4.5.tar.gz`, with CI bundle `unrest-v0.4.5-python313`.
Their actual archive hashes belong in an external `SHA256SUMS` after the
final candidate build. The local editable development installation verifies
source-stage identity only; it does not verify those future archives.
