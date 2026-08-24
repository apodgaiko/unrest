# VAL-EVO-003 — Independent evaluation and review

**Surface:** MCP `evaluate_candidate`/`review_candidate`, matching library calls,
configured provider roles, oracle runner and receipts.

**Needs:** VAL-EVO-002 and read-only frozen evaluator/reviewer inputs.

**Behavior:** Candidate/author cannot read or change evaluator/reviewer policy,
select observations/retries/exclusions/stopping/scoring, suppress failures, or
grant authority. Evaluation runs the frozen oracle on the exact candidate;
review consumes the complete evaluation denominator. Missing/error/collision
is non-improving. Reward-hack evidence is retained and no result promotes.

**Evidence:** Valid and invalid candidates, policy/identity collision and
mutation, missing/error oracle, suppression/retry attempts, seeded reward hack,
complete reviewer inputs, and evaluation/review receipts.

