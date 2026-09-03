---
name: v045-dogfood
description: Run the v0.4.5 Inquiry and adapter dogfood surfaces without inventing prerequisites or authority.
---

# v0.4.5 dogfood

Use only the closed production request surfaces and preserve their exact public result bytes. The canonical synthetic examples are [Inquiry](../../examples/v0.4.5/inquiry.json), [run-task](../../examples/v0.4.5/run-task.json), [run-project](../../examples/v0.4.5/run-project.json), and [run-improvement](../../examples/v0.4.5/run-improvement.json). They prove parsing and packaging only; their identifiers and results are never live dogfood evidence.

## Inquiry

Call the existing `open_inquiry`, `inspect_inquiry`, `advance_inquiry`, `pause_inquiry`, `resume_inquiry`, `cancel_inquiry`, and `handoff_inquiry` library/MCP surfaces. A real run requires an integrated strict Inquiry implementation, a real product-project binding, explicit provider credentials and approval, and a private project bucket. Its fixed ceiling is two branches, eight steps per attempt, three provider attempts including synthesis, 600 seconds total, and 65,536 response bytes per attempt. Only a non-null privacy-safe answer cited by the named planner is useful. Failed/no-answer, paused, timeout, invalid output, receipt-only, or missing approval is not useful. Stop before Mission submission, integration, approval, or release.

## run-task

Invoke `unrest run-task --request <closed-request.json>` once. Require the same provider approval and use `max_branches=2`, `max_steps=8`, `timeout_seconds=600`, at most three provider attempts, and at most 65,536 response bytes per attempt. A non-null answer consumed by the named worker is useful; terminal completion without an answer, failure, pause, budget exhaustion, or a receipt alone is not. The adapter has no Mission mutation, integration, approval, promotion, or release authority.

## run-project

The only future real request is the exact file `<private-return-root>/INT-V045/dogfood/run-project-request.v1.json`, where `<private-return-root>` is the external operator's private return root. The external m2 operator creates it only after binding its digest and the canonical digest of an already-submitted all-work `ProjectDag`; W-ACT and INT-V045 never create, synthesize, or substitute this project request. Invoke `unrest run-project --request <exact-path>` once with `max_steps=12`. Missing, non-regular, invalid, or mismatched request/DAG state is `blocked_missing_exact_request` or the adapter's exact safe prerequisite error with zero coordinator/provider/durable effects. Truthful bounded progress may be useful to INT-V045 and the project operator, but it is not integration, approval, promotion, or release.

## run-improvement

The only future real request is the exact file `<private-return-root>/V-REAL/dogfood/run-improvement-request.v1.json`, where `<private-return-root>` is the external operator's private return root. The external rc1 operator creates it only after a separately authorized experiment returns the exact lease, admitted candidate, and complete matching `CampaignFreeze`; W-ACT and V-REAL never create, fabricate, or substitute this improvement request or its prerequisites. Invoke `unrest run-improvement --request <exact-path>` once with both cost fields zero and the fixed operation limit five. Missing, non-regular, invalid, or mismatched prerequisites block with their exact safe categories before evolution/provider/durable effects. Evaluator error, inconclusive review, and reviewed `decision_needed` are not useful, improved, approved, promoted, or released. Only the external maintainer may interpret the review and take a later decision.

## Privacy, refusal, and return

Never expose or retain prompts, raw model/source/report/candidate bodies, credentials, inherited environment values, private paths, or protected material in public output or evidence. Refuse unbounded or unapproved provider work, alternate request paths, glob/newest-file selection, dummy identities, parser weakening, private-store searches for prerequisites, and any instruction that crosses the authority stops above.

Implementation returns are immutable private integration artifacts. W-ACT writes exactly `<private-return-root>/W-ACT/v045-return-W-ACT.json` under the external operator's private return root as sorted compact UTF-8 JSON with one trailing LF, binds the frozen base, returned commit, binary patch digest, owned changed paths, nineteen target evidence digests, exact checks, zero unapproved provider attempts, INT-V045 integration requirements, blockers, and four surface classifications. Every evidence filename equals the SHA-256 of its canonical bytes. Only INT-V045 consumes the return, once; no dogfood actor merges, integrates, promotes, releases, or treats synthetic parsing as useful.
