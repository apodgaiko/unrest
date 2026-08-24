# VAL-AUTH-001 — Sole Mission mutation authority

**Surface:** MCP, CLI, and `unrest_harness.api`.

**Needs:** VAL-FND-001 and a real project fixture.

**Behavior:** Every Mission-changing path, including run completion, workspace
integration, campaign promotion, rollback, and measurement attachment, reaches
the single Mission coordinator/store authority. Inquiry, workers, evaluators,
evidence, telemetry, identities, receipts, and chronology cannot mutate
Mission truth or the accepted point.

**Evidence:** Real public calls with before/after durable bytes, source call
graph and reverse edges, plus bypass attempts from every adjacent component.

**Fail:** Static ADR/source-string assertions alone cannot pass.

