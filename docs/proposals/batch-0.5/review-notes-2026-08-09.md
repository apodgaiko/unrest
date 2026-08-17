# Batch 0.5 review notes — independent verification pass

Status: reviewer notes; non-normative; recorded 2026-08-09 against
`93c59e4378407f3d7cfb918cf86c8bdc81daa141` (current `main`). Produced by an
adversarial read-only verification of the five proposal documents and
ADR-0002 against the actual tree. Nothing in this file changes proposal or
implementation authority.

## Verdict

Approve the direction; revise before acceptance. The scope cut is aimed at the
right mass (the five assurance modules are 16,940 of 25,730 production lines —
verified exactly), the deletion-ledger discipline and the measurement
protocol's stop rules are unusually honest, and the import topology confirms
the slice design: governance, repository-contract, and baseline are reachable
only through `cli.py`, while `capability_policy.py` is imported by five core
runtime modules and correctly quarantined in its own slice.

Three findings should block acceptance as written; the rest are revisions or
recorded answers to the proposal's own review questions.

## Verified measurements

All numeric claims in `measurement-protocol.md` and ADR-0002 reproduce
byte-for-byte at the reference commit: 25,730 installed production LOC; 26,466
test LOC; 52,351 maintained first-party LOC; 16,940 for the five assurance
modules (7,532 + 3,909 + 2,627 + 1,659 + 1,213); 3,441 collected tests;
309,041-byte wheel; 7,946 evidence lines. One cosmetic mismatch: collection
time measured 1.02 s vs the documented 0.82 s (noise band). One provenance
flag: the dist wheel's mtime is 2026-08-09 14:50 — the same day as the
protocol — so "artifact predates this review" is unverifiable; the protocol
already requires a rebuild before comparison, which resolves it.

Feasibility of the hard floors: outside the five assurance modules sit 8,790
production lines, so the 15,438-line floor leaves a 6,648-line budget for the
five combined (a 61% cut of that block). Under the ledger's dispositions they
land near 3,500, clearing the floor with ~3,100 lines of margin — but without
the capability rewrite the core lands near 17,322, missing the floor by
~1,900 lines even if every other deletion is perfect. Inside
`capability_policy.py`, the withdrawable machinery measures ~5,388 lines
(static graph/AST/sink 619–3833; entropy/name helpers 4385–4855;
template-grammar/semantic traversal 4856–6557) against ~5,032 required — the
2,500-line stop rule is consistent but thin, with no allowance for replacement
code. The −30% total-maintained floor is comfortable: whole-file test
deletions alone (`test_capability_source_graph.py` 1,867, `test_governance.py`
1,558, `test_baseline.py` 477) cover the test-side requirement.

**Conclusion: −40% is reachable but gated entirely on slice 2. −30% falls out
of the production cut. The proposal should say this dependence out loud.**

## Blocking findings

### B1. The security contract's central mechanism is not built, and the contract does not say so

Today `redact_sensitive_value(value, inventory=None)`
(`capability_policy.py:7373`) derives its inventory from the payload itself —
name-sensitivity, semantic parsing, transform enumeration — when no inventory
is passed. **No orchestrator-side call site passes one**: `coordinator.py`
contains zero `inventory`/`redact` references (attempt mirrors and terminal
reviews go through `storage` defaults), and `cli.py` `_write_text_atomic`
calls `redact_sensitive_value(text)` bare. Only the worker/reviewer MCP
processes thread the inherited-FD inventory (`server.py:427,472`). Under the
proposed "exact known values from the explicit allowlist only" rule,
SEC-SINK-DURABLE-MIRROR and SEC-SINK-RUNTIME-CURSOR become no-ops until
inventory threading is added through `coordinator.save_attempt`/
`save_terminal_review` and `cli._write_text_atomic`. The contract must name
this as new work and add an evidence case proving an orchestrator-written
attempt mirror is redacted.

Corollary: in `unsafe-development-unrestricted` the credential allowlist is
`["*"]`, and `credential_source_values` excludes `"*"` from declared names
(`capability_policy.py:4592-4596`). Under the new rule the unsafe profile's
exact-value inventory is empty — unsafe mode would emit raw ambient secrets at
every sink. Either define what "explicitly authorized" means under `*` or
state plainly that unsafe mode carries no redaction guarantee.

### B2. Transform stripping is a runtime behavior cut presented as an assurance cut

`security-contract.md` lists "Base64, hexadecimal, percent, mixed, or repeated
transform enumeration" under "Assurance deliberately removed," but that
machinery is live enforcement: `StreamingCredentialRedactor.feed` calls
`_redact_semantic_fragments` (`capability_policy.py:7082-7136,:7177`) on every
chunk, reaching the bounded semantic traversal at 6095–6501. Removing it
changes what today's product redacts, not what it proves. It also directly
contradicts an existing exhaustive test
(`tests/test_capability_policy.py:2759-2792`, triple-base64 across every
split), which must be explicitly inverted per LEAN-SECURITY-004 — silently
deleting it has exactly the shape of a weakened-guarantee regression. The cut
may still be the right call; it must be labeled as a runtime cut in the ADR's
Consequences and the contract.

### B3. Slice ordering breaks CI between slices 1 and 2

`repository_contract.py:27` imports `generate_baseline` (called at
:3381-3382), `check-repository` runs in both CI jobs
(`.github/workflows/ci.yml:34,54`), and
`bundled/policies/capability-sinks.v1.json:45-61` anchors four sinks to
`baseline.py` functions with expected egress primitives hardcoded at
`capability_policy.py:2591-2594`. Deleting `baseline.py` in slice 1 while
sink-anchor validation survives to slice 2 fails `check-repository` on the
intermediate commit. Slice 1 must also retire the baseline sink anchors (and
the affected `repository_contract` sections), or baseline deletion moves into
slice 2.

## Major revisions

1. **Unacknowledged retained→deleted import edge.**
   `repository_contract.py:39-51` imports eleven symbols from `governance.py`,
   including `load_component_paths` and the CommonMark parsers that the
   narrowed checker promised by ADR-0002 §4 still needs; `cli.py:27-33`
   imports four more. The ledger must either name these as rehomed — which
   makes it a move, not a deletion, under its own Rule — or commit to explicit
   lightweight replacements.
2. **Missing ledger rows.** `tests/test_documentation_contract.py` (1,029 LOC)
   imports from both deleted modules and enumerates 24 index targets; it
   breaks on nearly every proposed deletion and is absent from the accounting.
   `tests/test_repository_contract.py` (3,160 LOC) has no disposition despite
   its module shrinking ~90%. `evals/AGENTS.md:13-15` and root `AGENTS.md`
   baseline references need synchronized edits.
3. **Two real sinks are missing from the 14.** `worker-filesystem-write`
   (`acp_runner.py:624-638` — Unrest writing child-supplied bytes into the
   workspace) and `codex-structured-config` (`acp_runner.py:242,270` —
   credential-alias stripping from `CODEX_CONFIG` before adapter handoff;
   declaring the adapter env wholly intentional silently authorizes removing
   this filter). `diagnostic-errors` (`capability_policy.py:385-448`) deserves
   a SEC-SINK ID rather than prose. Uncataloged in both documents:
   `server.py:485-492` returns `ToolError.message`/`str(details)` unredacted
   to the orchestrator (low severity — the orchestrator already holds those
   credentials — but real).
4. **Terminal-credential removal is a change, not a codification.**
   `acp_runner.py:909-913` builds the terminal environment with
   `include_credentials=True` today. The evidence matrix should label
   LEAN-PROVIDER-004 as a behavior cut with a before/after case.
5. **Keep the short-credential boundary guard.** Answering the contract's
   review question: unconditional exact substring redaction is *not*
   acceptable. `_credential_requires_token_boundaries`
   (`capability_policy.py:4631-4638`) applies word boundaries to sub-8-char
   token-like values, pinned by `tests/test_capability_policy.py:4046-4063`
   (`ZAI_API_KEY="KEY"` must not corrupt "MONKEY"). Industry scrubbing
   practice uses the same mitigation (minimum lengths / word boundaries —
   Logfire, Datadog Sensitive Data Scanner, Sentry). State the guard in the
   contract instead of removing it.
6. **`jsonschema` rationale is wrong.** Ledger row 42 attributes it to
   governance parsing; its only source import is the *retained*
   `repository_contract.py:23-24`. The removal conclusion survives (its use
   validates the root schemas, which also go), but the premise should be
   corrected, and the pinned `types-jsonschema` dev dependency added to the
   row. `markdown-it-py` attribution is correct (`governance.py:23-24` only).

## Recorded answers to the proposal's own open questions

- **Removed child-provider consumer:** none found. Only a small provider
  definition and capability-policy branch existed; the bundled role policy and
  all configuration, mission, and evidence records had no consumer reference.
  Removal is cheap either way.
- **External consumers of root schemas / governance commands:** none in-tree.
  `check-governance`/`check-commit` appear in no CI workflow, pre-commit, or
  tools; the four root schemas do not ship in the wheel (package-data is
  `bundled/**` only). Caveat: schema `$id` values point at
  `https://unrest.dev/schemas/...`, which cannot be verified locally.
- **Observer schema-v1 consumers:** none beyond `cli.py`. ADR-0002's
  Consequences line "existing schema-v1 observer consumers must adopt schema
  version 2" asserts a consumer the tree does not evidence; either name one or
  soften the line. This belongs in the ledger's Unresolved items.
- **Governance bootstrap:** no deadlock. Protected-surface enforcement is a
  maintainer documentation obligation (change-governance.md; the ADR template
  enforced by `test_documentation_contract.py`), not a machine gate;
  `check-governance`/`check-commit` are not in CI. Deleting the
  self-protection machinery is procedurally awkward but mechanically
  unblocked.
- **Reverse-dependency check:** clean. No retained LEAN-* assertion in
  `behavior-contract.md` depends on a deleted module; the runtime policy
  loader (`load_capability_policy:3834` → `build_role_environment:4079`) is
  genuinely separable from the static model.

## Minor notes

- The `--sensitive-inventory-fd` **number** is in argv
  (`acp_runner.py:1382-1383`); the contract's "not argv" should read "no
  credential values in argv."
- Worker/reviewer MCP subprocesses are spawned with piped stdout/stderr that
  is never drained (`acp_runner.py:1388-1389,1443-1444`); a chatty server
  could block on a full pipe buffer. Worth fixing during the compaction pass.
- Timing context: observer schema v1 merged to `main` hours before this
  proposal was drafted to replace it. That is consistent with ADR-0001's
  observe-before-optimizing sequence and with the 2026-08-08 telemetry review
  findings (shadow-order divergence, render-guard hard failure, dashboard
  readiness 3/5) — the v2 compaction discards exactly the surfaces that
  reviewed weakest.
- Rewrite-risk literature supports the chosen shape: incremental slices with
  deliberate feature shedding is the low-risk quadrant; the compare-then-
  delete treatment of the capability rewrite is a contained strangler-fig
  step. Slice 2 remains the concentration of risk and the gate on the −40%
  floor.

## Suggested acceptance order

1. Fix B1–B3 and the six major revisions in the proposal documents.
2. Preserve the later 2026-08-12 disposition: repository/package consumers
   were not found, while external publication and consumers remain unverified.
3. Then accept: the retained perimeter, evidence rules, measurement anchors,
   stop rules, and rollback triggers are otherwise in good shape and better
   specified than most compaction plans of this size.
