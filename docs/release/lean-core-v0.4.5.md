# Unrest v0.4.5 — activation candidate

This is a frozen source candidate pending external gates. Source acceptance
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
Retry policy, benchmark-exception approval and credentials remain unresolved;
source preparation supplies none of those decisions.

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
