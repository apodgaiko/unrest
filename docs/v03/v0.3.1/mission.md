# Unrest v0.3.1 — FM-000 runtime activation and FM-010 baseline

## Normative status

This is the accepted v0.3.1 implementation brief. It activates all six FM-000
families: authority (ADR-0300), identity (ADR-0301), Inquiry (ADR-0302),
workspace (ADR-0303), evolution (ADR-0304), and compatibility (ADR-0305). The
ADRs, accepted index, supporting contracts, product, fixtures, and bundled
assets must agree. Active language calling them proposed, non-authoritative,
unindexed, unimplemented, or unable to issue/consume records must be removed or
clearly marked dated history. Documentation alone cannot satisfy this brief.

## Objective and public surface

Ship the complete usable foundation, then measure those exact release bytes.
The seven synchronous MCP tools remain unchanged: `start_project`,
`submit_plan`, `advance_project`, `end_mission`, `decide_attention`,
`inspect_project`, and `abort_project`.

v0.3.1 additively exposes MCP tools `submit_run`, `inspect_run`, `attach_run`,
`cancel_run`; `open_inquiry`, `inspect_inquiry`, `advance_inquiry`,
`pause_inquiry`, `resume_inquiry`, `cancel_inquiry`, `handoff_inquiry`;
`lease_workspace`, `inspect_workspace`, `return_workspace`,
`integrate_workspace`, `cleanup_workspace`; `open_campaign`,
`inspect_campaign`, `add_candidate`, `evaluate_candidate`, `review_candidate`,
`promote_candidate`, and `rollback_promotion`. The installed CLI adds only
`measure-baseline`. Every new MCP tool and `measure-baseline` has a same-named
callable in `unrest_harness.api`. Failures use the stable safe envelope
`{"error":{"code":<closed-code>,"message":<safe-message>}}`.

## Accepted behavior

- Inquiry's direct, evidence, critic, and analogy branches are structurally
  read-only and concurrently fanned out. Synthesis is a separate step, cites
  every outcome, and preserves dissent. Handoff transfers evidence only.
- Mutable workers use finite T1 Git-worktree leases from immutable bases. T1
  proves Git separation, not OS/process/network/secret/service confinement.
  Concurrent mutable workers require distinct worktrees. Parent integration is
  deterministic, compare-and-swap guarded, limited to declared disjoint writes,
  and fails on overlap or conflict.
- Evolution is offline. Author, evaluator, reviewer, promotion, integration,
  and rollback roles are distinct. Inputs freeze before candidates; all lineage
  and outcomes remain; promotion and rollback require explicit human decisions.
- Canonical records have authority only in authenticated local custody for the
  exact accepted local consumer catalog. Unsigned third-party authoritative
  export is rejected. No crypto dependency is added; signed authoritative
  export remains unsupported until a detached-signature suite is accepted.
- Canonical JSON v1 is a common grammar independent of schemas. Identity
  Catalog v2 preserves the original 18 kinds and adds Inquiry, Inquiry branch,
  Inquiry synthesis, Inquiry handoff, control operation, and campaign. Receipt
  Encoding v1 is independent of nine-family issuer/consumer authority.
- Prompts, source/report bodies, transcripts, and raw provider/command output
  are private artifacts. Public metadata and release bundles contain only
  allowlisted identifiers, digests, outcomes, timings, token counts, and cost.

## Exact FM-010 baseline

The baseline is exactly 20 sequential top-level case repetitions: P1 and P2
five times each, then E1 and E2 five times each. A repetition may make the
nested provider invocations required by its real lifecycle, so the derived
`provider_invocation_count` may exceed 20. Every nested invocation is recorded
with timing, tokens, reported cost, cache and outcome attributed to its parent
repetition and to the global ceilings. Each top-level repetition is capped at
20 minutes; total wall time is 200 minutes and reported provider cost is capped
at USD 50. Provider, model, and route are configured current defaults recorded
at freeze, not hardcoded. Repetitions use monotonic timing, cold durable roots,
no shared provider-response cache, and measurement concurrency one. Statistics
are median and MAD; MAD/median greater than 15% is inconclusive.

P1 creates a requested bounded artifact checked by SHA-256 and an exact text
invariant. P2 must receive one validator rejection/rework, then produce the
correct terminal artifact. E1 improves a tiny frozen text/config fixture and
passes exact tests. E2 is a seeded reward-hack/invalid candidate that the
independent evaluator must reject. The protected digest covers every tracked
candidate byte except `docs/v03/measurement/results/**`. Raw provider data is
private and never shipped; public results carry sanitized records and digests.

## Burden, validation, and release

Preserve Python 3.11+, no-extra install, all 14 schema-v1 cases, old CLI/MCP
behavior, and the `.unrest/`/`.unrest-runtime/` boundary. Add no required
service, database, migration, account, or ordinary setup. Provider measurement
is manual release work, never import/test/CI/install/first-run work. Focused
lanes target ten seconds. Run the full Python 3.13 source suite exactly once on
the frozen candidate, then package checks without repeating it. Keep `v0.3.0`
immutable; publish matching main/tag/assets and then fast-forward and reinstall
the user's editable local tool from those exact bytes.
