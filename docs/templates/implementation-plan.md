---
id: TPL-PLAN-001
status: active
applies_to:
  - docs/templates/implementation-plan.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Implementation plan template

## Plan identity

- Plan ID: `<stable id>`
- Status: `<draft | accepted | implemented | superseded>`
- Base SHA: `<exact SHA>`
- Contract targets: `<VAL-* IDs>`
- Owner/reviewers: `<implementation owner and accountable reviewers>`

## Objective and success criteria

`<Observable outcome and evidence-backed completion definition.>`

## Current behavior and evidence

`<Primary-source findings, runnable surfaces, baseline/oracle, and known defects.>`

## Scope and non-goals

- In scope: `<bounded capabilities and paths>`
- Non-goals: `<explicit exclusions>`

## Surface and file map

| Surface/component | Current path | Planned change | Verification |
| --- | --- | --- | --- |
| `<surface>` | `<path>` | `<change>` | `<test/flow>` |

## Invariants, compatibility, and security

- Stable IDs/ADRs: `<records>`
- Persisted schema/migration: `<version, compatibility or hard cut, recovery>`
- Protected surfaces: `<policy categories and required review>`
- Security/privacy: `<authority, credentials, redaction>`

## Dependency and execution order

```text
<deterministic task graph>
```

## Implementation steps

1. `<Coherent change>` — proof: `<focused check>`.

## Rollback

- Trigger: `<failure condition>`
- Procedure: `<command/change>`
- Data/schema recovery: `<steps or none>`
- Rollback verification: `<exact check>`

## Verification and evidence

- Focused: `<commands and observations>`
- Real surface: `<flows>`
- Full gate: `<commands>`
- Evidence artifacts: `<paths>`

## Risks, decisions, and follow-ons

- Risks/unknowns: `<items or none>`
- Required decisions: `<ADR/maintainer choice or none>`
- Required follow-ons: `<items or none>`
- Optional follow-ons: `<items or none>`
