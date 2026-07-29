---
id: TPL-TASK-001
status: active
applies_to:
  - docs/templates/task-packet.md
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Task packet template

## Task identity

- Task ID: `<stable task id>`
- Mode: `<work | validate | integration>`
- Base SHA: `<exact approved SHA>`
- Contract targets: `<VAL-* IDs or none with reason>`
- Assigned skill: `<skill name>`

## Objective

`<One bounded observable outcome.>`

## Read first

- Effective guidance: `<root-to-leaf AGENTS.md chain>`
- Specifications/ADRs/policies: `<canonical links>`
- Relevant prior evidence: `<paths or none>`

## Current behavior and evidence

`<Proven current state, commands, files, and known defects.>`

## Scope

- In scope: `<files, surfaces, artifacts>`
- Non-goals: `<explicit exclusions>`
- Public or persisted interfaces: `<schemas, CLI, MCP, storage, config, or none>`

## Invariants and risks

- Stable IDs: `<INVARIANT/SECURITY/COMPAT/ADR IDs>`
- Compatibility/migration: `<requirements or none>`
- Protected surfaces/reviewers: `<categories and accountable humans/roles or none>`
- Security/privacy: `<authority and redaction constraints>`

## Implementation requirements

1. `<Required deliverable.>`

## Verification and evidence

- Focused commands/flows: `<exact commands and expected observations>`
- Full gate: `<exact commands>`
- Real surface: `<CLI/MCP/storage/artifact flow or none with reason>`
- Evidence paths: `<declared artifacts>`

## Handoff requirements

Use the canonical [change closeout](change-closeout.md). Report exact exit codes,
files changed, contract-target mapping, remaining risks, and required versus
optional follow-ons.
