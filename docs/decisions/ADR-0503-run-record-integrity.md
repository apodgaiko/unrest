# ADR-0503: Enforce typed integrity of durable run records

## Record metadata

id: ADR-0503
status: accepted
date: 2026-11-03
task_ids:
  - RCR
contract_targets:
  - VAL-RCR-01-22
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - milestone

## Scope

- In scope: shared durable request/event readers, scoped index error containment, existing lifecycle edge replay and focused regression fixtures.
- Out of scope: authenticity, completeness, legal-value immutability, new string formats or size/depth limits, foundation/result/cursor readers, journal repair, supervisor, execution authority and release publication.

## Context

Bounded in-process Darwin probes on 4f689de reproduced request field coercion,
raw decoder/serializer failures and acceptance of hash-consistent forbidden
lifecycle edges. Appending queued after five writer-built terminal histories
allowed fake redispatch. This is consistency testing, not an authentication
bypass or proof of real worker re-execution. Natural RecursionError was not
reproduced within depth 2048; exception translation probes use injection.

Current-practice research completed on 2026-11-03 with three searches and four
primary fetches. Python json documentation served version 3.15 (runtime probes
used 3.13), Pydantic strict-mode guidance, Azure event sourcing and
Crosby-Wallach logging informed the decision. The research is bounded, not
exhaustive; unopened references are not evidence. Defensive read-side replay is
our choice, not a universal requirement of event-sourcing guidance.

## Decision

1. Require exact native field types in shared request/event readers; preserve
   existing validation/equality constraints and remove int/str coercion. Strings
   remain type-only except for existing constraints. schema_version is optional;
   if present it must have exact native int type, with any integer value allowed.
   This is not a version-support claim. Fingerprint retains constant 1 and event
   digest uses the raw decoded body.
2. Validate mandatory event envelope fields, first queued event, RunState
   membership and every historical edge using the existing writer edge relation
   E. Reuse one table/predicate without changing its three existing callers'
   behavior or writer bytes. Only the persisted-edge reader boundary translates
   invalid_transition to integrity_error; invalid caller transitions on valid
   history remain invalid_transition.
3. Apply iterative finite-value validation to decoded request/event documents,
   including extra keys, at the contract's existing precedence position. Preserve
   JSON duplicate-key last-wins semantics: an overwritten nonfinite value is not
   a new refusal. Early-reject parse_constant/parse_float hooks are excluded;
   they see discarded duplicate values and change precedence. No new depth or
   magnitude limits are introduced. Index retains I1-I4 plus scoped containment;
   global _read_json, result/cursor, STOP and foundation readers stay unchanged.
4. Translate the enumerated durable decode/serialization failures to fixed
   integrity_error messages at the narrow contracted boundaries. Do not catch
   arbitrary programmer failures or MemoryError. Preserve frozen wire enum and
   _ERROR_MAP. Non-string first-event state on admission now reports run event
   is invalid rather than run has no admission event.
5. Preserve existing read sets, call order, locks and the surface-by-branch
   mutation matrix. No new request read in worker_draining, no cancel reorder,
   all-writer fence, cleanup or repair of existing applying journals/receipts.
   ADR-0500, ADR-0501 and ADR-0502 remain unchanged.

## Alternatives considered

- Preflight-only or latest-state membership-only checks: insufficient for shared consumers and forbidden historical edges.
- Decoder hooks: rejected because they change duplicate-key refusal domain and error precedence; iterative post-decode walk preserves both.
- Strict schema_version equal to 1 or omission: Fable preferred this; main chose optional exact int to avoid adding a version-support policy. Dissent retained.
- Separate containment and strictness stages: Fable preferred staged acceptance; main chose one bounded slice with legacy and independent validation gates.
- Universal request-before-write fence or string-format expansion: rejected in this slice because either changes STOP read dependencies or introduces a new domain policy.

## Consequences

- Positive: coercion and invalid persisted edges are rejected by shared readers, with scoped durable-corruption classification.
- Negative/cost: finite walking and edge replay add work; more malformed inputs fail closed globally during admission/recovery.
- Compatibility/hard cut: nonfinite request extras, wrong native types and malformed histories become refusals; valid writer bytes are preserved. Synthetic E-legal controls are distinct from historical writer paths.
- Schema/migration impact: no migration or retained-record rewriting. Arbitrary users' trees and mixed writers remain UNKNOWN.
- Security/privacy impact: consistency is not authenticity, completeness, rollback protection or detection of truncation to a valid prefix. Well-typed generation/resource-key changes remain possible. Diagnostic guarantees exclude attributes, tracebacks, logging and Unicode cause/context repr; JSONDecodeError.doc may hold the full document. Exception chains are retained, not sanitized.

Read-set limitations are explicit: worker_draining can append with valid events
and owner despite request-only corruption; worker_effect_complete's failure
branch may write private evidence before request refusal. Terminal worker methods
can unlink cursor without reading request. There is no universal no-write claim.

Type-only strings can contain lone surrogates. Besides raw resource_lock encoding
failure, cancellation with surrogate resource_key/created_at may write three
events, receipt and custody before journal completion fails, leaving applying.
This remains follow-up RCR-FOLLOWUP-01, not repaired here. Well-typed malformed
run/issuer identity digests can raise raw FoundationValidationError during receipt
construction, leave cancellation applying, and allow sort-dependent partial
recovery dispatch; malformed control identity digest can persist. This remains
RCR-FOLLOWUP-02. Native type checks do not validate digest format.

## Review

- Reviewer: main integrator after independent Astra/Fable consultation, shared public research and two independent contract reviews.
- Approval date/evidence: 2026-11-03; profile execution 050-RCR-CONTRACT-V3.md, sha256 4c6f95db897d97da1809d9fcd9bbfcf5354943e385fcc01ba255fda1765c1218; Amendment-1 and 050-RCR-D13-MAIN-DISPOSITIONS.md clarify finite scope and measured baseline cells. Review-1 E1-E12 and review-2 R1-R5 incorporated; no third review required.
- Evaluation evidence: accepted for bounded implementation only. Research DONE bounded; D13 report and 40 manifest files verified, not independently rerun. Legacy corpus provenance verified against nine b307cc6 blobs and 903 manifest files; this is compatibility input, not post-fix LG-2 PASS. LG-3 bounded static, LG-5 UNKNOWN. No runtime or release PASS.

## Rollback

- Trigger: violated contract, legacy regression or failed independent validation.
- Procedure: revert implementation and affected documentation together while quiescent.
- Data recovery: preserve retained records; rollback does not repair applying journals, receipt effects or malformed histories. No automatic migration or cleanup.
- Verification: focused strictness, legacy, STOP and admission regressions plus independent scrutiny and evidence audit.

## Implementation and verification

- Components/paths: src/unrest_harness/run_control.py; tests/test_run_record_strictness.py; tests/fixtures/rcr_b307cc6_events/.
- Canonical documents: docs/v5/07-runtime-architecture.md; frozen ADR-0500/0501/0502.
- Tests/evidence: VAL-RCR-01-22, exact writer golden bytes, baseline admission corpus and 33 baseline writer event trees; synthetic E-legal controls separately labeled. Tier H requires static process audit; read-only H-git checks required. Sequential mutation controls distinguish kill, proxy, equivalent, timeout and NOTRUN. M11/M34 count as one kill claim; M27 requires measured baseline-accepted discriminating depth and recorded pytest recursion limit.
- Not authorized here: Tier P, full suite, real workers, Linux/crash/concurrency, push, deploy, publication or live activation.

## References

- Python json: https://docs.python.org/3/library/json.html
- Pydantic strict mode: https://docs.pydantic.dev/latest/concepts/strict_mode/
- Azure event sourcing: https://learn.microsoft.com/en-us/azure/architecture/patterns/event-sourcing
- Profile execution: 050-rcr-public-research/PACK.md; 050-RCR-MAIN-ADVISORY-CLOSURE.json.
- Profile execution: 050-RCR-CONTRACT-REVIEW-1.md; 050-RCR-CONTRACT-REVIEW-2.md; 050-RCR-HISTORICAL-FIELD-AUDIT.md.
- Profile execution: 050-RCR-PREFIX-PROBES.md; 050-RCR-LEGACY-CORPUS-RESULT.md; 050-RCR-MAIN-LEGACY-CORPUS-VERIFICATION.json.
