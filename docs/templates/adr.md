---
id: TPL-ADR-001
status: active
applies_to:
  - docs/templates/adr.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Architecture decision record template

Use filename `ADR-NNNN-short-title.md` and replace every placeholder.

## Record metadata

id: ADR-NNNN
status: proposed | accepted | rejected | superseded
date: YYYY-MM-DD
task_ids:
  - TASK-ID
contract_targets:
  - VAL-AREA-NNN
supersedes: []
superseded_by: null
evaluation_tier: []

## Scope

- In scope: `<bounded behavior, components, and paths>`
- Out of scope: `<adjacent behavior deliberately unchanged>`

## Context

`<Observed problem, constraints, primary evidence, and why a decision is needed.>`

## Decision

`<The chosen rule or architecture in concise, externally reviewable terms.>`

## Alternatives considered

- `<Alternative and concrete trade-off>`

## Consequences

- Positive: `<outcome>`
- Negative/cost: `<outcome>`
- Compatibility/hard cut: `<behavior or none>`
- Schema/migration impact: `<version, recovery, or none>`
- Security/privacy impact: `<authority and data handling>`

## Review

- Reviewer: `<maintainer or none>`
- Approval date/evidence: `<date and durable locator>`
- Evaluation evidence: `<commands and concise results>`

## Rollback

- Trigger: `<condition>`
- Procedure: `<command/change>`
- Data recovery: `<steps or none>`
- Verification: `<exact check>`

## Implementation and verification

- Components/paths: `<component IDs and paths>`
- Canonical documents: `<IDs/links>`
- Tests/evidence: `<commands and artifacts>`

## References

- `<Issue, specification, prior ADR, or evidence path>`
