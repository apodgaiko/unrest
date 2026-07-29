---
id: ARCH-INDEX-001
status: active
applies_to:
  - docs/architecture/*
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_repository_contract.py
related_decisions: []
schema_version: 1
---

# Architecture and normative documentation index

## Purpose

Provide one locally legible entry point to canonical specifications,
machine-readable architecture records, decisions, policies, and workflow
templates. A link here is navigation; normative authority comes from each
document's metadata and the policy below.

## Canonical specifications

- [Task-list product contract](../../specs/task_list/PRODUCT.md)
- [Memory v2 and storage product contract](../../specs/memory_v2/PRODUCT.md)
- [Runtime architecture](../v5/07-runtime-architecture.md)
- [MCP surface](../v5/08-mcp-surface.md)
- [V5 implementation plan and completion map](../v5/10-implementation-plan.md)

## Machine-readable architecture

- [Component map](component-map.json) — deterministic component-to-path,
  specification, test, invariant, and decision edges.
- [Protected-surface policy](../../policy/protected-surfaces.yaml) and
  [schema](../../schemas/protected-surfaces.schema.json) — strict human-review,
  evaluation, rollback, and governance self-protection requirements.
- [Normative-document policy](normative-documents.json) — canonical document
  inventory and strict frontmatter rules.
- [Stable ID registry](id-registry.json) — invariant, security, and
  compatibility records.
- [Annotation policy](annotation-policy.json) and
  [annotation guide](annotations.md) — approved permanent comment vocabulary.
- [Removal registry](removal-registry.json) — issue and removal-condition
  records required by structured TODOs.
- [Repository contract](repository-contract.md) — the canonical deterministic,
  read-only repository and CI validation command.

Machine-readable JSON files are canonical UTF-8 JSON: sorted keys, stable
record order by ID/kind, two-space indentation, and one trailing newline.
Generated or edited output must be byte-identical when source enumeration is
reversed.

## Decisions

- [ADR index](../decisions/index.md)
- [Change governance](change-governance.md) — proposal, protected review,
  conventional commit/trailer, and schema-evolution contract.

No decision is considered accepted merely because an ID is mentioned in prose.
It must appear in the ADR index and its canonical document must resolve.

## Canonical templates

- [Pull request](../../.github/PULL_REQUEST_TEMPLATE.md)
- [Task packet](../templates/task-packet.md)
- [Implementation plan](../templates/implementation-plan.md)
- [Architecture decision record](../templates/adr.md)
- [Change closeout](../templates/change-closeout.md)

These are the canonical copies. Product prompts may render task or handoff
content, but do not become competing documentation templates.

## Public contract

Every Markdown document selected by
[`normative-documents.json`](normative-documents.json) must:

1. start with parseable `---` YAML frontmatter;
2. contain exactly the required metadata fields;
3. use a unique ID, supported status, and supported integer schema version;
4. use repository-relative, resolving `applies_to` and `verified_by` entries;
5. reference only accepted, resolving ADR IDs;
6. keep all relative Markdown links and anchors resolving.

## Invariants

- `ARCH-ASSET-001`: machine-readable inventories and discovery surfaces have a
  stable deterministic order.
- `ARCH-BASELINE-001`: legacy observations do not become normative through
  documentation.
- Permanent source annotations resolve through the linked registries.

## Failure modes

Missing documents or anchors, duplicate IDs/canonical paths, unsupported
metadata, absolute or escaping paths, unresolved component edges, unknown
annotation IDs, malformed TODOs, and generated JSON drift invalidate the
repository contract.

## Change protocol

Add a normative document to the policy and this index in the same change.
Register new stable IDs before using them in code. Register an ADR before a
`WHY` annotation. Register both issue and removal condition before a structured
TODO. Update component edges and focused tests with path or ownership changes.

## Required verification

```bash
uv run unrest check-repository
uv run pytest -q tests/test_documentation_contract.py
```

Then run the common repository gate.

## Related decisions

See the [ADR index](../decisions/index.md). It currently contains no accepted
repository ADR.

## Known limitations

The command validates repository state and CI source. It does not approve,
promote, deploy, or roll back protected changes.
