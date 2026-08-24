# VAL-WS-001 — Honest T1 Git-worktree leases

**Surface:** MCP `lease_workspace`/`inspect_workspace`, matching library calls,
Git, and durable leases.

**Needs:** VAL-ID-002 and a real temporary Git repository.

**Behavior:** A finite lease creates one owned Git worktree from an exact clean
immutable base with declared repository write paths, process/resource budget,
owner and expiry. Identity survives restart. T1 asserts Git separation only;
it does not assert OS, process, network, credential, service, database, port,
or external-effect confinement.

**Evidence:** Exact base/child paths and hashes, dirty/symbolic/stale base,
duplicate/expired lease, restart, out-of-scope/protected write detection, and
explicit inspection of the truthful isolation label.

