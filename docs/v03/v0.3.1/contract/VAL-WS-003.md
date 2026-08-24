# VAL-WS-003 — Deterministic parent-only integration

**Surface:** MCP `integrate_workspace`, matching library call, Git parent authority.

**Needs:** VAL-WS-002 and explicit human integration grant.

**Behavior:** Only the parent authority stages, validates, and compare-and-swaps
the exact predecessor. Concurrent mutable workers occupy distinct worktrees.
Declared disjoint returns integrate in stable `(lease_id, patch_digest)` order;
overlapping paths, conflicts, stale predecessor, scope escape, validation
failure, or child self-merge/push fail with the parent unchanged. No heuristic
merge or claimed disjointness bypass is allowed.

**Evidence:** Two concurrent disjoint workers, repeatable order/result, overlap
and conflict, stale CAS, self-integration, crash before/after accept,
validation failure, parent trees, and integration receipts.

