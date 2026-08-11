---
id: ADR-INDEX-001
status: active
applies_to:
  - docs/decisions/*.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Architecture decision record index

## Purpose

Provide the canonical registry for repository ADR IDs and accepted status.

## Accepted decisions

- [ADR-0002: Define the Lean Core v0.2 compaction perimeter](ADR-0002-lean-core-v0.2.md)

## Public contract

An ADR is usable by `WHY[ADR-ID]`, normative metadata, or the component map only
when:

1. its ID is unique and listed under **Accepted decisions**;
2. its canonical Markdown file resolves in this directory;
3. the document follows the canonical
   [ADR template](../templates/adr.md);
4. its status is `accepted`;
5. its review and acceptance evidence are recorded.

Draft, proposed, superseded, and rejected decisions do not authorize behavior.

## Invariants

- One canonical document exists per ADR ID.
- Supersession is explicit in both old and new records.
- Decision documents contain concise rationale and evidence, never transcripts
  or hidden reasoning.

## Failure modes

Duplicate IDs, missing documents, unsupported status, dangling supersession, or
an accepted claim absent from this index invalidates the repository contract.

## Change protocol

Copy the canonical template, allocate the next four-digit ADR ID, obtain the
required review, and update this index plus affected normative metadata and
component edges in one change.

## Required verification

```bash
uv run pytest -q tests/test_documentation_contract.py -k decision
```

## Related decisions

- [ADR-0002](ADR-0002-lean-core-v0.2.md)

## Known limitations

Earlier implementation without a registered ADR does not acquire decision
authority retroactively.
