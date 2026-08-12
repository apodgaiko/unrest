# Lean Core deletion and replacement ledger

Status: accepted 2026-08-09 as the hard-cut ledger for ADR-0002.

## Rule

A product mechanism, test, schema, policy, or document is deleted only when its
current guarantee is either retained through named replacement evidence or
explicitly withdrawn in the accepted v0.2 decision. Moving the same mechanism
to another maintained first-party path does not count as deletion.

## Accepted ledger

| Area | Current role/guarantee | Proposed disposition | Replacement or withdrawal evidence |
| --- | --- | --- | --- |
| `baseline.py` and `evals/baseline/` | Reproduce and validate one historical product baseline; four bundled sink anchors name baseline functions | Delete atomically with baseline-specific sink anchors and affected repository-contract sections | Preserve only lifecycle/restart scenarios that remain in the behavior contract; Git retains historical implementation; the intermediate `check-repository` must pass |
| Baseline regeneration inside `check-repository` | Prove deterministic historical fixtures on every repository check | Withdraw | No current runtime behavior depends on regeneration |
| Baseline bindings in `repository_contract.py`, `capability-sinks.v1.json`, `capability_policy.py`, `test_capability_source_graph.py`, `test_capability_closed_model.py`, and `test_repository_contract.py` | Keep static baseline regeneration/egress references closed across CI | Remove/update atomically in the baseline slice | Exact source-graph expectation and all omission/mutation IDs change together; then-current `check-repository` passes before merge |
| `repository_contract.py` broad validator | Validate repository identity, documentation, CI topology, schemas, generated output, evidence, capability proof, and self-enforcement | Replace narrowly | Implement small direct helpers for guidance, important references, component ownership, packaged runtime policy loadability, and installed-wheel CI wiring; do not rehome the generic governance/CommonMark machinery, and count replacement LOC |
| `governance.load_component_paths` and CommonMark helper imports retained by the narrow checker | Retained-to-deleted import edge from `repository_contract.py` | Replace explicitly, not rehome | Narrow stdlib/data-shape helpers local to the checker; no generic protected-surface or CommonMark parser |
| `governance.py` policy engine | Protected selectors, commit trailers, schema packets, workflow templates, evidence records, custom Markdown interpretation | Delete | Human maintainer review plus ordinary focused CI; retained product invariants move to direct tests/docs |
| `tests/test_governance.py` | Exercise the withdrawn governance policy engine, schemas, trailers, and Markdown DSL | Delete with `governance.py`; do not rehome | Direct retained documentation and repository checks live in `tests/test_documentation_contract.py` and `tests/test_repository_contract.py`; the executable crosswalk records `LEAN-REPOSITORY-001` |
| Public `check-governance` | Render and validate governance policy | Remove | v0.2 migration note |
| Public `check-commit` | Enforce structured commit trailers | Remove | v0.2 migration note; repository hosting policy may remain external |
| Mandatory commit trailers and PR/ADR mini-languages | Repository self-governance | Withdraw | No replacement DSL |
| Static CI-topology and recursive self-protection proof | Prove repository checks cannot be bypassed through checked source | Withdraw | Direct CI configuration and maintainer review |
| `capability-security-model.v1.json` and schema | Closed transform/semantic-role derivation model | Delete | Narrow exact-known-value security contract |
| `capability-sinks.v1.json` and schema | Catalog and bind every claimed capability-derived sink, including baseline anchors | Delete | Remove baseline entries in the baseline slice; delete the remaining static catalog with the capability-assurance slice; finite human-readable retained sink inventory plus black-box tests |
| Capability source graph, AST egress analysis, and semantic digests | Mechanically prove declared repository effect closure | Delete | No static completeness claim |
| `test_capability_source_graph.py` | Mutation and alias/control-flow completeness for static analyzer | Delete with analyzer | Retained runtime boundary tests only |
| Static sections of `test_capability_closed_model.py` | Bind model/sink assets and mutations | Delete with model/sink assets | Runtime policy loader/provider startup tests remain |
| Arbitrary credential-name and entropy inference | Detect undeclared secret-like values | Withdraw | A finite selected provider/role credential-name set remains in safe and unsafe profiles; `*` is forwarding authority only and never inventory identity |
| Structured-looking-string parsing and transform enumeration | Runtime detection/redaction of nested, encoded, and derived credentials | Withdraw as a runtime security behavior cut | Finite exact-known occurrences remain protected in both profiles using the documented short-token guard; actual structured object traversal remains |
| Transform/mutation portions of `test_capability_policy.py` | Prove current runtime transformed-secret redaction, including triple-base64 at every split | Replace/invert with the withdrawn behavior | Per-sink structured and streaming exact-value tests plus a documented transformed sentinel that remains visible |
| Role capability policy runtime loader | Resolve explicit runtime authority | Retain and simplify | Provider/role/profile startup matrix and installed-wheel loadability |
| Canonical ACP path checks and terminal cwd checks | Limit callbacks/cwd to explicit roots | Retain | Direct path and subprocess-request matrices; explicit non-sandbox limitation |
| Environment and credential projection | Limit ambient child authority; current terminal environment includes credentials | Retain and narrow with a behavior cut | Selected finite credentials reach adapters in both profiles; none reach terminal children by default; explicit unsafe adapter inheritance may include other ambient values outside the credential guarantee |
| Orchestrator inventory propagation | Optional storage inventory exists, but coordinator/CLI protected writes omit it | Add replacement work | Explicit safe inventory reaches attempt/review mirrors, cursors, CLI/error envelopes; black-box orchestrator-written sentinel case |
| ACP worker filesystem writes, structured Codex config, diagnostics, and MCP tool errors | Runtime outputs not fully represented in the original 14-sink draft | Retain and protect | Add SEC-SINK-WORKSPACE-WRITE, SEC-SINK-CODEX-CONFIG, and SEC-SINK-DIAGNOSTIC; the diagnostic ID includes MCP `ToolError` message/details, for seventeen total sinks |
| Worker/reviewer MCP stdout/stderr pipes | Piped subprocess output is currently not drained and can block | Replace with bounded lifecycle handling | Chatty-child completion/shutdown contract; replacement LOC counts against capability slice |
| `runtime_observability.py` schema version 1 | Detailed read-only projection, timing, anomaly, shadow scheduler, aggregation | Replace with schema version 2 | Compact project and `--all` real CLI contract |
| Shadow scheduler and detailed timing reconstruction | Advisory scheduler parity and attempt timing | Withdraw | Runtime coordinator remains authoritative; no ETA or liveness claim |
| Observer compatibility aliases and nested count models | Preserve unpublished/foundation object shape | Delete | No compatibility promise |
| `test_runtime_observability.py` detailed projection corpus | Prove schema version 1 and all defensive projections | Replace | Compact schema-version-2 state, containment, privacy, aggregation, and read-only tests |
| `tests/test_documentation_contract.py` (1,029 LOC) | Imports governance/repository helpers and enumerates 24 documentation targets | Replace narrowly/delete withdrawn cases | Direct tests for the small retained documentation/reference checker; synchronize every deleted index target in the same slice |
| `tests/test_repository_contract.py` (3,160 LOC) | Proves the broad repository contract proposed for ~90% reduction | Replace narrowly | Focused tests for the retained checker duties and intermediate-slice validity; delete withdrawn topology/schema/evidence/static-proof cases |
| Root `AGENTS.md` and `evals/AGENTS.md` baseline guidance | Names baseline fixture authority and baseline workflow | Edit with baseline removal | Preserve the rule that historical/legacy evidence is not a normative behavior oracle without referring to a deleted installed baseline surface |
| Baseline-linked architecture index, component map, normative/release documents, and `test_baseline.py` references | Keep stable IDs and links pointed at the current baseline surface | Update/delete atomically with baseline | No accepted document, registry, guidance file, or retained test points at `evals/baseline/` or deleted baseline code |
| Root `evidence/` detailed release history | Store raw benchmark, logs, manifests, rollback transcripts, and repeated bindings in product tree | Remove from current tree | Concise release conclusion, commands, hashes, artifact locator, and Git history |
| Per-mission `.unrest` evidence | Supply current mission validation/terminal-review artifacts | Retain | Explicitly outside root evidence cleanup |
| Duplicate root JSON schemas generated from internal models | Repository-checker/docs/test self-validation; not packaged in the wheel | Delete after explicit compatibility decision | The 2026-08-12 audit found no in-tree or packaged consumer; external publication is unverified, so no broader absence is claimed and the accepted hard cut stands |
| `jsonschema==4.26.0` | Validate root schemas in `repository_contract.py`; tests also import it directly | Remove after every direct source/test root-schema consumer is deleted or rewritten | Accept that a transitive distribution may remain; removal is not caused by governance parsing |
| `types-jsonschema==4.26.0.20260518` | Type support for the typed `jsonschema` source consumer | Remove with the last typed source import | Verify lockfile/direct-dependency state after the narrow checker lands |
| `markdown-it-py` direct runtime declaration | Support governance CommonMark parsing | Remove after governance/parser consumer deletion | The narrow checker uses direct lightweight rules rather than rehoming the parser |
| Unsupported third child-provider support across provider/CLI/ACP/capability code, documentation, and tests | Documented and tested optional ACP compatibility surface; no deployed/configured in-tree consumer found | Remove as a maintainer-approved compatibility hard cut | Claude/Codex matrix; update public docs and delete provider-specific tests/literals while preserving only the cheap shared abstraction |
| Installed-wheel lifecycle module | Validate installed package outside source checkout | Retain | Build/archive/provenance/startup/lifecycle checks |

## Test disposition rules

- Rehome a scenario before deleting its historical fixture when the scenario
  proves a retained lifecycle, restart, storage, provider, package, or security
  behavior.
- Delete analyzer/governance mutation tests in the same slice that withdraws the
  corresponding guarantee.
- Do not retain compatibility shims solely to keep withdrawn tests green.
- Do not preserve test count as a metric.
- Require total test LOC to fall across the completed batch, not in the initial
  contract-test change.

## Evidence disposition rules

- Keep one concise release document and one small machine-readable summary only
  when they record a current conclusion, command, hash, compatibility decision,
  or rollback locator.
- Store raw CI output and benchmark intermediates in bounded mission evidence,
  CI artifacts, or release attachments with an explicit retention policy.
- Deleting evidence from the current tree is repository-context cleanup; it
  does not count toward installed production Python, wheel, or Git-history size.

## Review disposition audit (2026-08-12)

- The current tracked source, tests, package inputs, direct dependencies, and
  accepted release carriers were audited in
  `docs/release/lean-core-v0.2-review-audit.json`.
- No retained baseline scenario is backed only by the deleted baseline
  generator; retained identifiers are bound to collecting candidate tests by
  `docs/release/lean-core-v0.2-evidence-crosswalk.json`.
- No in-tree or packaged consumer of the deleted root schemas or observer-v1
  aliases was found. External publication and consumers are unverified; this
  is the explicit compatibility disposition, not an absence claim.
- The removed legacy child provider has no supported provider, CLI, package,
  issue-template, or retained
  contract surface. External reliance is unverified and does not authorize a
  compatibility shim.
- Raw release artifacts remain external mission/CI/release-attachment material;
  only the concise current conclusion, audit, crosswalk, and rollback locator
  remain in the product tree.
