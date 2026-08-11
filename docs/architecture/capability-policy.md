---
id: ARCH-CAPABILITY-001
status: active
applies_to:
  - src/unrest_harness/acp_runner.py
  - src/unrest_harness/bundled/policies/role-capabilities.v1.json
  - src/unrest_harness/capability_policy.py
  - src/unrest_harness/cli.py
  - src/unrest_harness/config.py
  - src/unrest_harness/coordinator.py
  - src/unrest_harness/providers.py
  - src/unrest_harness/server.py
  - src/unrest_harness/storage.py
verified_by:
  - tests/test_acp_runner.py
  - tests/test_capability_policy.py
  - tests/test_lean_provider_security_runtime.py
  - tests/test_server.py
  - tests/test_storage.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Finite role capability policy

## Runtime authority

[`role-capabilities.v1.json`](../../src/unrest_harness/bundled/policies/role-capabilities.v1.json)
is the only packaged capability document. Its strict version-1 model defines
filesystem roots, process availability, environment projection, network
declaration, and approval behavior for the orchestrator, worker, validator,
and terminal-reviewer roles. Unknown fields, versions, profiles, roles, roots,
and unsupported provider combinations fail before child creation with bounded,
value-free diagnostics.

Every `unrest-server` mode resolves the capability profile, policy version, and
unsafe-development opt-in before constructing FastMCP. Orchestrator startup
additionally resolves all four provider roles before dispatcher or reviewer
construction. Expected startup-policy rejection emits one fixed, value-free CLI
diagnostic without a traceback.

Safe mode is the default. The unrestricted development profile requires both
`UNREST_CAPABILITY_PROFILE=unsafe-development-unrestricted` and
`UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED=1`. The wildcard in that profile grants
forwarding authority; it is never a credential name.

Callback paths and terminal working directories are resolved canonically
against the role's read or write roots. Traversal, absolute outside paths,
symlink escapes, and nonexistent-parent escapes are rejected. These checks are
application authority checks, not an operating-system subprocess sandbox.
There is no network-denial claim.

## Finite known-value boundary

The complete credential-name inventory is:

- `ANTHROPIC_API_KEY`
- `ANTHROPIC_AUTH_TOKEN`
- `CODEX_API_KEY`
- `GLM_API_KEY`
- `OPENAI_API_KEY`
- `ZAI_API_KEY`

Only non-empty values selected through those declared names (or a caller's
equally explicit declared-name list) become known credentials. Safe adapter
environments contain only declared forwarded, credential, and internal names.
Explicit unsafe adapter environments may inherit other ambient values, but the
finite known set remains distinct. Terminal and ordinary MCP-server children
exclude known credentials in both profiles.

The exact inventory is transported to worker and reviewer MCP servers through
a bounded inherited file descriptor. Values never appear in argv or ordinary
child environment. Inventory JSON is deterministic and accepts no alternate
payload shape.

Known values are removed recursively from actual structured keys and values
and from text across every stream split. Short token-like values under eight
characters require token boundaries: `KEY` is protected in `KEY;`, while
`MONKEY`, `KEY-label`, and `.KEY` are unchanged. Longer or punctuated values
are protected wherever embedded.

The reviewed Unrest-owned sink inventory is finite:

1. ACP callback results
2. ACP callback and permission errors
3. progress callbacks and event text
4. captured adapter stderr and failure diagnostics
5. terminal output and snapshots
6. Unrest-authored ACP/MCP messages
7. worker handoff JSON and returned reports
8. validator handoff JSON and evidence text
9. terminal-review handoff JSON
10. attempt, review, and decision Markdown mirrors
11. state, task, attention, config, and attempt runtime JSON
12. CLI stdout and stderr
13. Unrest-owned log records
14. generated provider/MCP/bootstrap configuration
15. child-supplied ACP workspace writes
16. structured Codex configuration
17. capability/provider/request diagnostics and MCP tool errors

The implementation centralizes these surfaces through exact structured or
streaming redaction and atomic storage primitives. This inventory is an
explicit maintenance boundary, not a claim that arbitrary future writes are
mechanically discovered.

## Deliberate limits

Lean Core does not infer credentials from arbitrary names, entropy, payload
shape, nested-looking strings, or structured text. It does not parse or redact
partial, encoded, hashed, encrypted, reordered, or otherwise transformed
values. In particular, repeated base64 encoding of a known value remains
visible while the exact value is removed. This is the accepted v0.2 security
behavior cut.

Static source graphs, AST effect analysis, semantic digests, model or sink
assets, transform enumeration, mutation-completeness suites, and recursive
repository assurance were retired by ADR-0002. Runtime authority and black-box
boundary tests are the evidence for this finite contract.

## Stable contracts

- `COMPAT-CAPABILITY-POLICY-001`: policy evolution uses an explicit integer
  version and bounded provider/role/version/capability diagnostics.
- `SEC-CAPABILITY-001`: child authority resolves before startup; callback,
  process, environment, protocol, and persistence behavior cannot exceed the
  explicit role and exact inventory.
- `SEC-SENSITIVITY-PROVENANCE-001`: only finite explicitly declared names
  establish exact known-value identity; payload contents never do.

## Verification

```bash
uv run pytest -q tests/test_capability_policy.py \
  tests/test_lean_provider_security_runtime.py tests/test_acp_runner.py \
  tests/test_server.py tests/test_storage.py
uv run unrest check-repository
```
