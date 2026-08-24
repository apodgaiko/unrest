# VAL-INQ-004 — Evidence-only handoff

**Surface:** MCP `handoff_inquiry`, matching library call, and handoff artifact.

**Needs:** VAL-INQ-003 and a named local consumer.

**Behavior:** Handoff binds Inquiry, question, branch denominator, synthesis,
dissent, limits, retention and consumer identities. It never starts/owns a
Mission, leases/integrates a workspace, adds/promotes a candidate, or mutates
accepted state. Repeated identical handoff is idempotent evidence issuance.

**Evidence:** Valid handoff, repeated issuance, wrong/stale branch, synthesis,
authority and consumer mutations, and byte-identical Mission/accepted point.

