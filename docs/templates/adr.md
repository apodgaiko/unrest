---
id: TPL-ADR-001
status: active
applies_to:
  - docs/templates/adr.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Architecture decision record template

Use filename `ADR-NNNN-short-title.md` and replace every placeholder.

## Record metadata

<!-- GOV-FIELD:decision-id -->

id: ADR-NNNN
status: proposed | accepted | rejected | superseded
date: YYYY-MM-DD
task_ids:
  - TASK-ID
contract_targets:
  - VAL-AREA-NNN
supersedes: []
superseded_by: null
protected_surfaces: []
evaluation_tier: []

<!-- GOV-FIELD:task-ids -->
<!-- GOV-FIELD:contract-targets -->

## Scope

<!-- GOV-FIELD:scope -->

- In scope: `<bounded behavior, components, and paths>`
- Out of scope: `<adjacent behavior deliberately unchanged>`

## Context

`<Observed problem, constraints, primary evidence, and why a decision is needed.>`

## Decision

`<The chosen rule or architecture in concise, externally reviewable terms.>`

## Alternatives considered

- `<Alternative and concrete trade-off.>`

## Consequences

- Positive: `<outcome>`
- Negative/cost: `<outcome>`
- Compatibility/hard cut: `<behavior and stable reason code>`
- Schema/migration impact: `<version, fixtures, recovery, or none>`
- Security/privacy impact: `<authority and data handling>`

<!-- GOV-FIELD:compatibility-schema -->

## Protected-surface review

- Protected categories: `<sorted policy category IDs or none>`
- Required reviewers: `<release-maintainer and security-maintainer or none>`
- Review evidence: `<links/paths>`
- Evaluation evidence: `<strongest applicable tier and results>`

<!-- GOV-FIELD:protected-surfaces -->
<!-- GOV-FIELD:human-reviewers -->
<!-- GOV-FIELD:evaluation-evidence -->

## Rollback

- Trigger: `<condition>`
- Procedure: `<command/change>`
- Data recovery: `<steps or none>`
- Verification: `<exact check>`

<!-- GOV-FIELD:rollback -->

## Implementation and verification

- Components/paths: `<component IDs and paths>`
- Normative documents: `<IDs/links>`
- Tests/evidence: `<commands and artifacts>`

## References

- `<Issue, specification, prior ADR, or evidence path>`
