# Lean Core security contract and sink inventory

Status: accepted 2026-08-09 as the security scope for ADR-0002.

All seventeen `SEC-SINK-*` rows below have individual candidate results and
collecting pytest nodes in
`docs/release/lean-core-v0.2-evidence-crosswalk.json`; no aggregate sink result
stands in for a missing row.

## Proposed contract

Safe mode is the default. Unrestricted provider settings are emitted only after
one explicit exact unsafe-development opt-in. Malformed or unsupported
provider, role, profile, filesystem, environment, terminal, or permission
requests fail before a child starts and do not echo rejected values.

In safe mode, Unrest constructs each adapter environment from explicit
forwarded names, selected provider/role credential names, and internal runtime
names; unrelated ambient variables are not inherited. Explicit unsafe mode may
use broad forwarding/inheritance, but wildcard forwarding is authority only and
never a credential identity. Both profiles retain a finite provider/role
credential-name set. Values from that set are supplied only to the adapter and
are excluded from terminal children unless a separate future authorization is
designed and approved.

ACP filesystem callbacks resolve requested targets canonically and enforce
role-specific read/write roots. Terminal working directories receive the same
containment check. These checks are not an operating-system sandbox and do not
confine arbitrary subprocess side effects. Lean Core provides no network-denial
guarantee.

A known credential is a non-empty raw environment value associated with the
finite credential-name set for the selected provider and role.
Except for intentional delivery to that adapter and the bounded inherited-FD
inventory channel, known credential occurrences are removed from the named
Unrest-owned sinks below. Redaction covers actual structured keys and values
and strings spanning stream chunk boundaries. Token-like values shorter than
eight characters require token boundaries (`KEY` is a credential occurrence in
`"KEY"`, but not in `"MONKEY"`); longer or non-token-like values match
wherever embedded.

The explicit `unsafe-development-unrestricted` profile has a wildcard policy
today. Lean Core defines `*` as forwarding/inheritance authority only, never as
a credential name, and replaces wildcard credential identity with the finite
provider/role set. Undeclared ambient secret-like values inherited only because
unsafe mode is broad remain outside the redaction guarantee.

Lean Core does not detect unknown credentials, provider-internal credentials
absent from the inventory, partial values, hashes, encodings, encrypted values,
reordered values, or other transformations. A child that receives a credential
is trusted with it; Unrest does not prevent intentional exfiltration.

## Intentional credential-bearing channels

| Channel | Allowed content | Constraint |
| --- | --- | --- |
| Selected provider adapter environment | Finite known credential values; explicit unsafe mode may also broadly inherit other ambient values | Safe mode is a constructed projection; unsafe wildcard forwarding is explicit authority, not credential identity |
| Private inherited file descriptor from adapter launcher to worker/reviewer MCP server | Bounded exact-value inventory used for redaction | Descriptor number is in argv; credential values are not in argv, environment, logs, or persistence |
| In-memory redaction inventory | Exact selected credential values | Lifetime bounded to the relevant process/session |

No other Lean Core channel is intentionally credential-bearing.

## Protected Unrest-owned sinks

| Sink ID | Surface | Required treatment |
| --- | --- | --- |
| SEC-SINK-CALLBACK-RESULT | ACP callback results | Redact recursively before emission |
| SEC-SINK-CALLBACK-ERROR | ACP callback and permission errors | Redact; use bounded value-free diagnostics where possible |
| SEC-SINK-PROGRESS | Progress callbacks and event text | Streaming exact-value redaction before callback invocation |
| SEC-SINK-ADAPTER-STDERR | Captured adapter stderr and failure diagnostics | Streaming exact-value redaction before log/report inclusion |
| SEC-SINK-TERMINAL-SNAPSHOT | Captured terminal output and snapshots | Streaming exact-value redaction before return or persistence |
| SEC-SINK-ACP-WIRE | Unrest-authored ACP/MCP messages outside intentional inventory transport | Redact structured keys and values before serialization |
| SEC-SINK-WORK-HANDOFF | Worker handoff JSON and its returned report | Redact before accepted cursor replacement |
| SEC-SINK-VALIDATE-HANDOFF | Validator handoff JSON and per-target evidence text | Redact before accepted cursor replacement |
| SEC-SINK-TERMINAL-HANDOFF | Terminal-review handoff JSON | Redact before accepted cursor replacement |
| SEC-SINK-DURABLE-MIRROR | Markdown attempt/review mirrors and decision records | Redact centrally before atomic write |
| SEC-SINK-RUNTIME-CURSOR | State, task, attention, config, and attempt JSON | Redact centrally before atomic write |
| SEC-SINK-CLI | CLI stdout/stderr, including status and configuration diagnostics | Redact or emit bounded codes without sensitive values |
| SEC-SINK-LOG | Unrest-owned log records | Redact before logger call; do not log the inventory |
| SEC-SINK-BOOTSTRAP | Generated provider/MCP/bootstrap configuration | Contain credential names or references only, never raw values |
| SEC-SINK-WORKSPACE-WRITE | ACP filesystem writes of child-supplied bytes | Redact before Unrest writes into the authorized workspace path |
| SEC-SINK-CODEX-CONFIG | Structured Codex configuration before adapter handoff | Construct from supported fields; never copy ambient credential aliases |
| SEC-SINK-DIAGNOSTIC | Capability/provider/request diagnostics, including MCP `ToolError.message` and `details` | Prefer bounded codes; redact message and structured details before emission/envelope serialization |

The accepted implementation must centralize these sinks behind a small number
of output and persistence primitives. It must not claim completeness for
arbitrary future writes outside the inventory.

## Required new inventory plumbing

The central safe-mode mechanism is not present on current `main`. Storage
accepts an optional inventory, but coordinator calls to `save_attempt` and
`save_terminal_review` omit it, and the CLI atomic text writer invokes payload-
derived redaction without an explicit inventory. The capability rewrite must:

1. create one explicit inventory from the selected finite provider/role names
   in both profiles; `*` never contributes an inventory value;
2. keep it in the owning process/session and pass it to coordinator-owned
   attempt, terminal-review, runtime-cursor, and durable-mirror writers;
3. require it at protected orchestration writes that can contain child- or
   environment-derived content rather than silently deriving it from payload;
4. redact CLI/config/bootstrap writers and MCP error envelopes against the same
   process-local inventory;
   and
5. prove an orchestrator-written attempt JSON and Markdown mirror remove a
   reflected sentinel.

This is replacement implementation work, not a property inherited by deleting
the semantic detector, and its lines count against the capability budget.

## Runtime authority retained

- Safe and explicit unrestricted provider configuration for Claude and Codex.
- Fail-closed provider/role/profile resolution before child startup.
- Separate read/write filesystem roots for ACP callbacks.
- Canonical containment, including traversal and symlink escape rejection.
- Structured subprocess invocation without an intermediate shell.
- Terminal cwd containment and undeclared environment-injection rejection.
- Role-specific process enabled/disabled state. If the accepted command matrix
  remains only wildcard-or-disabled, replace the command-list abstraction with
  that simpler boolean contract.
- Exact environment forwarding and selected provider/role credential names.
- Bounded inherited-FD inventory transport.
- Recursive redaction of real structured objects and streaming strings.
- Atomic redacted text/JSON persistence.

## Repository assurance deliberately removed

- Static repository source graph and sink catalog.
- AST effect, alias, callback, control-flow, and semantic-digest proof.
- Mutation suites claiming completeness of that analyzer.
- Arbitrary credential-name inference and entropy classification.
- Parsing strings as nested JSON, TOML, URI, or Python-format structures.
- Any claim that all possible future output calls are mechanically cataloged.
- Any claim that filesystem callback roots confine subprocess side effects.
- Any network-denied role or provider profile until real enforcement exists.

## Runtime security behavior deliberately withdrawn

- Base64, hexadecimal, percent, mixed, or repeated transform detection and
  redaction, including the current streaming semantic-redaction path.
- Detection of credential-bearing strings not present in the selected safe-mode
  inventory.
- Terminal inheritance of provider credentials; removing that authority is an
  intentional strengthening and compatibility cut, not a description of
  current behavior.

Existing tests that prove transformed-value removal must be inverted or
replaced with evidence that one documented transform remains visible. Merely
deleting those tests would conceal the runtime behavior change.

## Minimum evidence matrix

1. Safe/unsafe startup matrix for Claude and Codex, including malformed and
   conflicting ambient configuration.
2. Provider/role environment projection showing unrelated ambient values are
   absent.
3. Adapter credentials present only for the selected provider/role and absent
   from terminal/MCP-server ordinary environments, with a reference/candidate
   before-and-after case for terminal credential removal.
4. Bounded inherited-FD credential values absent from argv, logs, and
   persistence; the descriptor number in argv is allowed.
5. Filesystem read/write/traversal/symlink/nonexistent-parent matrix.
6. Terminal process-disabled, outside-cwd, undeclared-environment, and malformed
   structured-request cases.
7. Exact structured redaction in nested mapping keys and values, short values
   at token boundaries, non-corruption of `MONKEY` by `KEY`, and embedded
   longer values.
8. Streaming redaction at every split point, including overlapping values and
   final flush.
9. One sentinel reflected through every protected sink and absent from every
   returned or persisted artifact, including child-supplied workspace bytes,
   structured Codex config, diagnostics including MCP `ToolError`, and orchestrator-
   written attempt and terminal-review mirrors.
10. One transformed sentinel intentionally remains outside the guarantee so
    the test proves the reduced claim rather than accidentally retaining it.
11. Unsafe-mode evidence proving finite known credentials remain inventoried,
    excluded from terminals, and redacted, while undeclared broadly inherited
    values are explicitly outside the guarantee.
12. Chatty worker/reviewer MCP server output above pipe capacity cannot block
    bounded completion or shutdown.
13. Installed-wheel safe startup and handoff-redaction scenario from an
    unrelated working directory.

## Resolved review decisions

- Terminal credential removal is a v0.2 runtime/compatibility hard cut.
- Callback roots are not a subprocess sandbox and no network-denial guarantee
  exists.
- The inventory remains on the inherited-FD topology, with process-local
  threading added for orchestrator-owned writers.
- The short token-boundary guard remains part of the exact-value semantics.
- Wildcard unsafe forwarding is authority only; both profiles retain a finite
  provider/role credential set and terminal exclusion for that set.
- The sink inventory has seventeen IDs: workspace writes, structured Codex
  config, and diagnostics (including MCP tool errors) augment the original
  fourteen.
