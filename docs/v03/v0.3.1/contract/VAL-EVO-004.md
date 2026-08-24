# VAL-EVO-004 — Human promotion transaction

**Surface:** MCP `promote_candidate`, matching library call, Git and artifacts.

**Needs:** VAL-EVO-003, VAL-WS-003, and explicit human grant.

**Behavior:** Only a human grants promotion of one exact candidate against one
exact predecessor with fresh evaluation/review/patch evidence. Parent authority
stages, validates and atomically accepts before integration/promotion receipts.
Stale/mutated/missing evidence, failed validation, pre-accept crash, or receipt
failure cannot select or reapply a candidate; post-accept recovery reconciles
the exact durable transaction.

**Evidence:** Success plus each mutation/failure boundary, exact parent trees,
human grant, CAS, receipts, effect count and restart reconciliation.

