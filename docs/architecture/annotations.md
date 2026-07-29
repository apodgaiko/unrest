---
id: ARCH-ANNOTATION-001
status: active
applies_to:
  - src/**/*.py
verified_by:
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Permanent annotation vocabulary

## Purpose

Keep rare, non-obvious source comments stable and resolvable without turning
source into a conversation or a second specification.

## Public contract

Approved structured annotations are:

```text
INVARIANT[ID]
SECURITY[ID]
COMPAT[ID]
WHY[ADR-ID]
TODO[#issue; remove-after=condition]
```

The annotation begins a normal source comment, is followed by a colon, and
states the concise constraint or rationale. Continuation comment lines are
allowed. Ordinary comments remain allowed when they do not impersonate a
structured annotation.

## Resolution

| Form | Required record |
| --- | --- |
| `INVARIANT[ID]` | `kind=invariant` entry in `id-registry.json` |
| `SECURITY[ID]` | `kind=security` entry in `id-registry.json` |
| `COMPAT[ID]` | `kind=compatibility` entry in `id-registry.json` |
| `WHY[ADR-ID]` | accepted ADR in `docs/decisions/index.md` |
| `TODO[#issue; remove-after=condition]` | matching issue and removal-condition entries in `removal-registry.json` |

Register the record first. A dangling annotation is invalid even when its prose
sounds reasonable.

## Invariants

- Use annotations only for a durable invariant, security boundary,
  compatibility constraint, accepted architectural reason, or bounded removal
  task.
- Do not narrate obvious code or copy a normative rule into many comments.
- Temporary task notes belong in the task handoff or change closeout.
- Do not include chat roles, agent identity, conversations, hidden reasoning,
  speculative monologue, prompts, or private source excerpts.
- The machine-readable policy classifies rendered CommonMark comment tokens,
  so list/quote prefixes and emphasis cannot disguise an attribution. Exact
  configured provider/agent labels followed by `:` or `says:` are rejected.
  Unlisted attribution labels are also rejected when their rendered body uses
  configured private-agent context such as private implementation reasoning or
  hidden model notes. Reasoning-tag classification is structural: configured
  tags plus tag names rooted in analysis, reasoning, thinking, thought,
  scratch, or monologue are rejected in opening, closing, attributed, and
  self-closing forms. The configured lists are stable policy vocabulary, not
  an exhaustive name allowlist. Ordinary technical prose that merely names
  providers or discusses reasoning remains valid.

## Failure modes

Unknown annotation kinds, missing brackets/colons, wrong registry kinds,
unaccepted ADRs, unregistered TODO issues/conditions, or banned conversational
content categories fail the repository contract.

## Change protocol

Vocabulary changes require an accepted ADR, synchronized updates to
`annotation-policy.json`, registries, this document, scanner tests, and any
affected source comments.

## Required verification

```bash
uv run pytest -q tests/test_documentation_contract.py -k annotation
```

## Related decisions

No accepted repository ADR currently changes this vocabulary.

## Known limitations

An annotation records a concise durable reason, not the full decision. Follow
the stable record for context and evidence.
