# VAL-RCP-002 — Nine-family authority and freshness catalog

**Surface:** receipt catalog, installed verifier, and local durable custody.

**Needs:** VAL-RCP-001 and accepted authority roles.

**Behavior:** Exactly `cleanup_receipt.v1`, `evaluation_receipt.v1`,
`integration_receipt.v1`, `patch_receipt.v1`, `promotion_receipt.v1`,
`review_receipt.v1`, `rollback_receipt.v1`, `run_receipt.v1`, and
`workspace_receipt.v1` define unique issuers, subjects, dependencies, outcomes,
consumers, expiry and revocation rules. Freshness derives only from integrity,
external issuer authority, exact dependencies, revocation and expiry; time,
order, success, or self-assertion cannot create it.

**Evidence:** Every family in fresh/stale/revoked/unverifiable states; wrong
issuer/consumer, self-authorization, missing/extra dependency, upstream stale,
expiry, revocation watermark, failed outcome, and correction tests.

