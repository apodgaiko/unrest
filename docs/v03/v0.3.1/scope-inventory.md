# v0.3.1 scope and capability inventory

| Area | Targets | Release result |
| --- | --- | --- |
| Activation | VAL-FND-001 | Six accepted, indexed, active FM-000 families; no active proposal contradiction. |
| Authority/custody | VAL-AUTH-001/002 | Sole Mission mutation authority and exact failure custody. |
| Identity/receipts | VAL-ID-001/002, VAL-RCP-001/002 | Common grammar, exact Catalog v2, receipt bytes, authority and freshness. |
| Security/export | VAL-SEC-001/002 | Private/public split and local-only unsigned authority. |
| Public surface | VAL-SURF-001 | Exact preimplementation schemas for 23 MCP/library methods plus measure-baseline. |
| Async | VAL-RUN-001/002 | Submit/inspect/attach/cancel, durable identity and restart. |
| Inquiry | VAL-INQ-001..004 | Lifecycle, fan-out, synthesis, evidence handoff. |
| Workspace | VAL-WS-001..004 | Honest T1 leases, return, integration, cleanup. |
| Evolution | VAL-EVO-001..005 | Freeze, retention, independent review, promotion, rollback. |
| Compatibility | VAL-COMP-001..003 | Schema, exact surface, roots/package/Python. |
| FM-010 | VAL-MSR-001..007 | Exactly 20 top-level repetitions, attributed nested provider calls, four exact oracles, safe publication. |
| Burden | VAL-BUR-001/002 | No required setup/service; bounded routine verification. |
| Release/update | VAL-REL-001/002 | Matching remote v0.3.1 and verified local/global install. |

The failure inventory includes invalid bytes/schemas, stale/revoked/wrong
authority or consumer, unsigned export, duplicate admission, cancellation and
restart at every effect boundary, branch failure/dissent, Git scope escape,
overlap/conflict/orphans, evaluator collision/suppression/reward hacking,
stale promotion/rollback, provider timeout/cost/wall/noise, protected drift,
private-data leakage, partial publication, package/remote/install mismatch, and
any remaining active claim that FM-000 is proposal-only.

After the shared identity/receipt/authority/run foundation lands, Inquiry and
workspace may run in parallel in distinct worktrees. Evolution follows
identity plus workspace return/integration. Measurement starts only from the
frozen candidate. Mutable lanes declare disjoint ownership and integrate in a
fixed order; overlap fails instead of invoking an implicit merge policy.
