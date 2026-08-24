# VAL-RUN-001 — Generic asynchronous public admission

**Surface:** MCP `submit_run`/`inspect_run` and matching `unrest_harness.api` callables.

**Needs:** VAL-ID-002, VAL-RCP-002, VAL-SURF-001, and unchanged synchronous tools.

**Behavior:** `submit_run` accepts exactly the six operations and exact unchanged
argument schemas frozen in `public-surface.v1.json`, durably records a unique
control-operation/run identity before dispatch, and returns the catalog
`RunSummary` with `state="queued"` within one second. `inspect_run` uses the
exact catalog request/result and is read-only. Catalog resource/idempotency keys
govern competing admission; an exclusive operation never dispatches twice.

**Evidence:** Two server connections, timestamps, durable records, operation
and idempotency mutations, active-ID equality, controller invocation/effect
counts, completion receipt, and stable safe errors.
