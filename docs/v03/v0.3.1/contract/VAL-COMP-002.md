# VAL-COMP-002 — Exact additive public surface and stable errors

**Surface:** installed CLI, orchestrator MCP schemas, and `unrest_harness.api`.

**Needs:** frozen v0.3.0 help/tool schemas, VAL-FND-001, and VAL-SURF-001.

**Behavior:** Existing seven synchronous MCP tools and their schemas remain
unchanged. New MCP/library/CLI names, exact request/result schemas, defaults,
lifecycle enums, resource/idempotency keys, and stable errors equal
`public-surface.v1.json`; runtime introspection cannot broaden them. Existing
error behavior is not relabeled.

**Evidence:** Differential v0.3.0 help/tool JSON, strict catalog-to-MCP/library/
CLI schema equality, callable signatures, real success for every family, and
every catalog stable-error class.
