---
id: ARCH-INDEX-001
status: active
applies_to:
  - docs/architecture/*
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_repository_contract.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Architecture and normative documentation index

## Purpose

Provide one locally legible entry point to the retained Lean Core architecture,
specifications, decisions, and repository-development contract. ADR-0002
withdraws the former repository governance language and duplicate root schemas.

## Canonical specifications

- [Task-list product contract](../../specs/task_list/PRODUCT.md)
- [Memory v2 and storage product contract](../../specs/memory_v2/PRODUCT.md)
- [Runtime architecture](../v5/07-runtime-architecture.md)
- [MCP surface](../v5/08-mcp-surface.md)
- [V5 implementation plan and completion map](../v5/10-implementation-plan.md)

## Machine-readable architecture

- [Component map](component-map.json) — deterministic component ownership and
  specification/test edges.
- [Stable ID registry](id-registry.json) — retained runtime invariant,
  security, and compatibility identifiers used by locally useful annotations.
- [Packaged role-capability policy](../../src/unrest_harness/bundled/policies/role-capabilities.v1.json)
  — runtime authority loaded by the product and finite repository checker.
- [Repository contract](repository-contract.md) — the finite deterministic,
  read-only development command.

Machine-readable JSON files are canonical UTF-8 JSON: sorted keys, stable
record order, two-space indentation, and one trailing newline.

## Decisions and accepted scope

- [ADR index](../decisions/index.md)
- [ADR-0002](../decisions/ADR-0002-lean-core-v0.2.md) — accepted Lean Core v0.2
  compaction perimeter.
- [Batch 0.5 accepted scope package](../proposals/batch-0.5/README.md)

No decision is accepted merely because an ID appears in prose. Its accepted
ADR must resolve from the decision index.

## Canonical templates

- [Task packet](../templates/task-packet.md)
- [Implementation plan](../templates/implementation-plan.md)
- [Architecture decision record](../templates/adr.md)
- [Change closeout](../templates/change-closeout.md)

## Public contract

`unrest check-repository` validates only the finite duties in the repository
contract: required files, retained references, component ownership, loadable
packaged runtime policy, and required CI commands. It does not regenerate a
historical baseline, validate duplicate root schemas, interpret commit or pull
request policy, prove static capability effects, compare evidence history, or
protect its own implementation recursively.

## Invariants

- `ARCH-ASSET-001`: persisted and generated inventories have stable order.
- Permanent runtime annotations use IDs from the retained registry.
- Durable project records remain under `.unrest/`; runtime cursors remain under
  `.unrest-runtime/`.

## Required verification

```bash
uv run unrest check-repository
uv run pytest -q tests/test_documentation_contract.py tests/test_repository_contract.py
```

At a completed implementation slice, also run the milestone checks in the root
`AGENTS.md`.

## Known limitations

The repository command validates source state and CI wiring. It does not
approve, promote, deploy, or roll back changes.
