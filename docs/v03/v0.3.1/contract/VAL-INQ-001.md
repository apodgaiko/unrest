# VAL-INQ-001 — Inquiry lifecycle and budgets

**Surface:** MCP `open_inquiry`, `inspect_inquiry`, `advance_inquiry`,
`pause_inquiry`, `resume_inquiry`, `cancel_inquiry`, matching library calls,
and durable Inquiry state.

**Needs:** VAL-ID-002, VAL-RUN-002, and configured provider capability.

**Behavior:** Inquiry is separate from Mission and supports the named lifecycle
across restart. Every branch has a finite budget and durable answered, failed,
cancelled, paused, or budget-exhausted outcome; invalid transitions and budget
extension without external authority fail before dispatch.

**Evidence:** Every valid/invalid transition, restart, timeout, provider error,
cancel boundary, budget exhaustion, retention, and Mission byte comparison.

