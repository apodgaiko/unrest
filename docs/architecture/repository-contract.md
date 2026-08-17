---
id: ARCH-REPOSITORY-CONTRACT-001
status: active
applies_to:
  - .github/workflows/ci.yml
  - AGENTS.md
  - docs/architecture/component-map.json
  - src/unrest_harness/repository_contract.py
verified_by:
  - tests/test_repository_contract.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Lean repository contract

## Purpose

Keep one small, deterministic, read-only source-checkout command for the
development duties retained by ADR-0002.

## Required files and references

The finite required-file and reference inventory is maintained in the mission
checker catalog and implemented directly in `repository_contract.py`. Relative
Markdown links and frontmatter paths from required Markdown documents must be
repository-relative, non-escaping, and resolve to a file or a non-empty glob.

## Component ownership

Component IDs are unique and sorted. Every retained product Python file is
owned by at least one component path. Every component path matches, and every
listed specification and test resolves. Cross-cutting ownership may overlap.

## Runtime policy

The exact packaged `role-capabilities.v1.json` is loaded through the runtime
Pydantic policy model. Provider, role, and profile records remain unique;
credential names remain finite; wildcard forwarding is authority rather than
credential identity; and the safe profile does not inherit ambient values.

## CI wiring

CI keeps Python 3.11 and 3.12 import/help lanes and a Python 3.13 primary lane
with Ruff, mypy, one full source-suite run, this repository command, build,
distribution inspection, and installed-wheel validation from an unrelated
directory. Commands in a job or step guarded by a constant-false expression do
not count. The deliberately finite expression grammar is boolean literals,
`!`, `&&`, `||`, and parentheses; expressions containing any dynamic term are
not treated as constant. Commands inside a line-bounded literal
`if false; then` ... `fi` block without nested or alternate branches also do
not count. This is not general shell or GitHub expression evaluation.

## Diagnostics

Failures use exactly these bounded codes with a repository-relative path or
component record ID and no source body or environment value:

- `LEAN-REPO-MISSING`
- `LEAN-REPO-REFERENCE`
- `LEAN-REPO-COMPONENT`
- `LEAN-REPO-POLICY`
- `LEAN-REPO-CI`

## Explicit non-goals

The command performs no baseline generation, broad root-schema validation,
governance or commit-message interpretation, static source/sink proof,
evidence-history comparison, recursive CI self-protection, or write operation.

## Required verification

```bash
uv run unrest check-repository
uv run pytest -q tests/test_repository_contract.py
```
