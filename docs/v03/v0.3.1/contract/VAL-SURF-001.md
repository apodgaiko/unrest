# VAL-SURF-001 — Frozen independently implementable public surface

**Surface:** `public-surface.v1.json`, installed MCP schemas, CLI schema, and
`unrest_harness.api` callables.

**Needs:** accepted `mission.md` names and frozen v0.3.0 synchronous schemas.

**Behavior:** The catalog is the preimplementation oracle for exactly 23 new
same-named MCP/library methods plus CLI/library `measure-baseline`. It closes
every request/result object, required/default field, lifecycle enum,
idempotency field, resource key and stable error. `submit_run` supports exactly
`start_project`, `submit_plan`, `advance_project`, `end_mission`,
`decide_attention`, and `abort_project`; operation arguments equal the existing
synchronous schemas, and admission returns a queued `RunSummary`. No runtime-
derived schema may silently amend the catalog.

**Evidence:** Strict JSON/JSON-Schema validation, deterministic byte regeneration,
exact method/callable set equality, resolved references, independent positive/
negative request/result vectors per method, default/enum boundaries, resource/
idempotency collisions, and generated MCP/CLI schema diff.

**Oracle:** `docs/v03/v0.3.1/public-surface.v1.json`.

