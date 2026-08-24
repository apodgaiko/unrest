# VAL-ID-002 — Exact Identity Catalog v2 and schemas

**Surface:** installed catalog, schemas, fixtures, and library constructors.

**Needs:** VAL-ID-001 and the original 18-kind v1 catalog.

**Behavior:** Catalog v2 preserves v1 kinds `accepted_working_point`,
`artifact`, `base`, `budget`, `candidate`, `context`, `environment`,
`evaluator`, `evidence`, `policy`, `provider_configuration`, `review`,
`route_profile`, `run`, `secret_set_version`, `seed`, `workload`, and
`workspace_lease`, and adds exactly `inquiry`, `inquiry_branch`,
`inquiry_synthesis`, `inquiry_handoff`, `control_operation`, and `campaign`.
Each has one closed versioned schema, ASCII domain, dimensions, consumers, and
constructor; v1 vectors remain unchanged.

**Evidence:** Catalog equality, schema/constructor coverage, v1 golden vectors,
one material mutation per 24 kinds, cross-kind replay rejection, and package
asset discovery from an unrelated cwd.

