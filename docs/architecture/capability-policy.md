---
id: ARCH-CAPABILITY-001
status: active
applies_to:
  - schemas/capability-security-model.schema.json
  - schemas/capability-sinks.schema.json
  - schemas/role-capabilities.schema.json
  - src/unrest_harness/acp_runner.py
  - src/unrest_harness/bundled/policies/capability-security-model.v1.json
  - src/unrest_harness/bundled/policies/capability-sinks.v1.json
  - src/unrest_harness/bundled/policies/role-capabilities.v1.json
  - src/unrest_harness/capability_policy.py
  - src/unrest_harness/cli.py
  - src/unrest_harness/config.py
  - src/unrest_harness/providers.py
  - src/unrest_harness/repository_contract.py
  - src/unrest_harness/server.py
  - src/unrest_harness/storage.py
verified_by:
  - tests/test_capability_closed_model.py
  - tests/test_capability_policy.py
  - tests/test_capability_source_graph.py
  - tests/test_cli.py
  - tests/test_documentation_contract.py
related_decisions: []
schema_version: 1
---

# Role capability policy

## Purpose

Define the one versioned source of filesystem, process, network, credential,
environment, and approval authority for orchestrator, worker, validator, and
terminal-reviewer roles.

## Canonical policy and schema

The packaged
[`role-capabilities.v1.json`](../../src/unrest_harness/bundled/policies/role-capabilities.v1.json)
document is the runtime source of truth. Its strict
[`role-capabilities.schema.json`](../../schemas/role-capabilities.schema.json)
snapshot rejects missing and unknown fields. Version `1` contains two named
profiles:

- `safe`, the default;
- `unsafe-development-unrestricted`, the only unrestricted profile.

Each profile contains four complete role objects. Runtime never constructs a
validator or reviewer by inheriting a worker object.

All three packaged capability JSON documents are decoded with duplicate-member
rejection at every object depth before model validation. Duplicate members are
invalid even when their values are equal; ordinary last-member-wins JSON
semantics never apply to authority, model, or sink declarations. Source and
installed-wheel loaders emit the same bounded, value-free `CAP-POLICY-001`
diagnostic for malformed JSON, duplicate members, missing or unknown fields,
and unsupported schema versions.

The packaged
[`capability-security-model.v1.json`](../../src/unrest_harness/bundled/policies/capability-security-model.v1.json)
is the closed Batch 0 derivation model. Its strict
[`capability-security-model.schema.json`](../../schemas/capability-security-model.schema.json)
enumerates every supported transform, semantic role, provenance join,
unsupported/exhaustion behavior, and exact ceiling. The packaged
[`capability-sinks.v1.json`](../../src/unrest_harness/bundled/policies/capability-sinks.v1.json)
and strict [sink schema](../../schemas/capability-sinks.schema.json) enumerate
every runtime, protocol, diagnostic, artifact, and package sink reachable from
the sensitive-value inventory. Repository validation binds every sink record
to its exact implementation and enforcement anchor. Its AST effect model
classifies stream and descriptor writes, serializer-to-stream calls, logging,
dynamic callback emission, ACP wire writes, and canonical writer delegation
independently of local variable or import spelling. Every effect owner must be
a cataloged canonical sink or an exact version-1 delegation omission. Primitive
effects inside omissions are pinned as a multiset, so an omission cannot gain
an alternate writer. Reversible codec operations are likewise bound to their
declared transform owner; an additional codec or transform fails closed.
The catalog's version-1 `reachable_source_sha256` field retains its original
wire name but pins a deterministic semantic projection, not whole Python
source files. Roots are sink and omission implementations plus Python paths in
the canonical `COMP-CAPABILITY` record. Repository-local imports and executed
package initializers enter transitively; external modules and unimported files
do not. Every discovered local path resolves against the repository before
entry, so imported modules and executed package initializers that escape through
symlinks fail closed. Invalid, duplicate, missing, unresolved, or escaping
component records fail closed. The projection records each capability-relevant effect's owning
implementation, effect family, and resolved primitive, including writers,
serializers, callbacks, descriptor channels, canonical delegations, supported
codec calls, unsupported codec families, and reverse slices. Lexical symbol
flow resolves imported, locally assigned, bound-method, callback, and
container aliases, neutral lambda wrappers, and constant-name `getattr`
references, including names reached through scoped constant propagation or a
module's constant-key `__dict__`, `__dict__.get(...)`, or `vars(...)` mapping;
narrow lexical flow also preserves capability callables stored in literal
list/tuple slots, constant-key dictionaries, and singleton sets when acquired
through a single-assignment string/integer subscript or `next(iter(...))`.
Nested literal slots are resolved recursively, and simple tuple/list
destructuring is followed only when target and value shapes match exactly,
including protected leaves assigned directly into attribute or subscript
state. Starred or dynamically shaped unpacking remains outside this model.
Dynamic container contents, reassigned indices, and arbitrary dynamic indices
are not evaluated. Returning any resolved capability
slot is recorded as a callable-escape effect even without local invocation.
When a statically modeled literal container itself escapes through a return,
state assignment, or external call argument, every protected callable in its
known nested slots is recorded under the corresponding capability family.
Nested local callback
wrappers and lambda/default-argument captures are linked
to their enclosing output-callback parameter. Direct callback returns,
returning a wrapper result, registering, or storing a known callback or
capability callable are recorded as effects.
Serializer-to-stream, descriptor-writer, reversible-codec entry points,
reverse slices, joined reversals, and `bytes`, `bytearray`, `list`, or `tuple`
materializations of `reversed(...)` are explicit reviewed families, so a new
family member or owner fails closed instead of depending on one preferred
spelling. Dynamic member names on protected capability modules are recorded
conservatively; dynamic names on unrelated objects stay outside the projection
until their resolved callable enters a protected flow. Sorted records,
including multiplicity, are canonical-JSON encoded before hashing. A new or
moved capability effect therefore requires catalog review, while unrelated
arithmetic, predicates, data attributes, ordering, control flow, comments,
and formatting do not. Explicit omission records cover the few reviewed
non-sensitive effects whose syntax overlaps a protected family.
The same canonical JSON also contains path-bearing completeness records for
data-bearing calls that do not resolve to local Python implementations. A
custom Python 3.11-3.13-stable AST representation preserves callable and data
structure while ignoring locations, comments, formatting, type comments and
ignores, absent empty fields, and comprehension predicates. Comprehension
payload expressions and iteration sources remain data-bearing structure. Call
projection is independent of how the
result is used: discarded, returned, assigned, awaited, and calls nested in
ordinary expressions have identical capability records. External calls,
unknown object methods, bound aliases, and constant-name `getattr` are covered
without a method-name allowlist; explicit effects retain their precise
diagnostics.
Adding an implementation effect, adding an omission, or deleting either side
of a declaration fails repository validation.
`unrest check-repository` runs those same strict loaders against the three
checked-in packaged documents, including the role policy, and also validates
each document against its canonical schema. Governance classification alone is
therefore not evidence that a protected capability asset's contents are valid.

## Resolution and provider support

Policy version, profile, provider, and role resolve before any MCP or ACP child
starts. Providers declare supported policy versions, profiles, roles, callback
enforcement, and network modes. An unsupported combination fails with
`CAP-POLICY-001` and includes provider, role, version, and capability.

Claude and Codex support all four roles. Hermes supports ACP child roles but
does not support the orchestrator role because Unrest has no Hermes host
configuration surface on which it can enforce safe initialization. All current
orchestrator selectors (`--agent` and `--orchestrator-provider`) therefore
expose only Claude and Codex. Hermes remains available through the
`--worker-provider`, `--validator-provider`, and `--terminal-reviewer-provider`
child-role selectors, and initialization does not generate a Hermes
orchestrator prompt. All current providers support `network=allow`;
`network=deny` is rejected because the adapters cannot enforce it. Prompt text
is never accepted as network confinement.

## Safe and unsafe provider settings

Safe initialization writes Claude `permissions.defaultMode=default` or Codex
`sandbox_mode=workspace-write` plus `approval_policy=on-request`. Safe Codex
ACP children use initial mode `agent`. Ambient unrestricted provider controls
are removed or overridden; malformed provider configuration fails.

Unrestricted execution requires the conspicuous CLI flag
`--unsafe-development-unrestricted`. The generated MCP environment then carries
both:

```text
UNREST_CAPABILITY_PROFILE=unsafe-development-unrestricted
UNREST_UNSAFE_DEVELOPMENT_UNRESTRICTED=1
```

The two values must appear together and the opt-in must be exactly `1`.
Misspelled, malformed, mismatched, absent, or unknown unsafe settings fail
closed. Only this profile may emit Claude `bypassPermissions` or Codex
`danger-full-access`, `approval_policy=never`, sandbox-disable hints, and
`agent-full-access`.

## Filesystem and terminal enforcement

Root names resolve to canonical existing workspace, project-record,
deliverable, or explicit unsafe host roots before startup. ACP reads and writes
re-resolve their targets. Writes resolve the deepest existing ancestor before
creating parents. Absolute, traversal, symlink, and nonexistent-parent escapes
are rejected. A root grants read and write separately.

ACP terminal creation:

1. checks process authority and command declarations;
2. resolves the requested working directory inside a readable root;
3. rejects undeclared environment injection;
4. launches the structured command and arguments without a shell;
5. uses the role's minimal environment instead of copying the host.

The callback policy does not claim kernel-level confinement for arbitrary child
process side effects. A future network-denied or stronger process profile must
declare and prove provider or operating-system enforcement before support is
advertised.

## Environments, credentials, and diagnostics

Safe role environments are deterministic intersections of declared forwarded
names, declared credential names, and role-specific internal runtime names.
ACP agents and their terminal children receive only credentials whose names
are declared for the role.

Every environment value follows one sensitivity-classification pipeline:

1. **Parse and normalize.** The classifier records the source name, declared
   credential provenance, raw value, and deterministic structural contexts.
   Component grammar is tokenized into literal names, assignment markers, and
   atomic placeholders before URI or list delimiters are interpreted. Parsed
   sensitive fields carry their named evidence, rather than a reclassified
   boolean, into every structured and reversibly decoded descendant.
   Hierarchical, empty-authority, relative, and opaque URI-like values do not
   require a scheme or non-empty authority to participate. Their userinfo,
   authority-adjacent userinfo, path segments, matrix parameters, query fields,
   and fragment fields become the same named-field representation used by JSON
   and TOML mappings. Plain PATH-like and delimited list values retain their
   aggregate and expose each element before reversible derivation.
2. **Derive within bounds.** A breadth-first traversal follows only strict
   UTF-8 JSON, syntactically valid TOML, percent decoding, hexadecimal text,
   and standard or URL-safe base64 decoding. Container elements and URI field
   values re-enter this same traversal, so nested or repeatedly encoded
   component values are not a separate code path.
3. **Recognize templates.** Complete `${name}`, `{{name}}`, `{name}`,
   positional and Python conversion/format variants such as
   `{password!r:>12}`, `<token>`, and `<secret>` values are recorded as
   template evidence, including strict percent-escaped forms. One structured
   AST, produced and validated with the standard formatting parser/formatter,
   represents literal text, field roots, attribute/index traversal,
   conversions, and recursively nested format specifications. This preserves
   every stdlib-valid index string, including `{` or `}` inside brackets, and
   applies the stdlib automatic/manual numbering rule across the complete
   format string. Delimiters inside a valid field are atomic for URI, PATH, and
   list decomposition, including a first template element followed by relative
   PATH entries. Atomicity is not opacity: field roots, attribute/index
   strings, conversions, format-spec literals, and nested fields re-enter
   bounded credential inspection. Literal-surrounded, malformed, incomplete,
   over-nested, invalid-conversion, and mixed-numbering forms are not promoted
   to templates. Credential tokenization follows path, matrix, query, fragment,
   cookie, and list delimiters, so a cookie or session field cannot consume
   credential-free placeholders from adjacent components.
4. **Extract credential evidence.** Declared provenance, structural name
   evidence, sensitive mapping/URI fields, private keys, authorization
   material, JWTs, cookies, and credential-bearing connection values contribute
   concrete evidence and exact derived tokens. Entropy can support an already
   credential-bearing source but is never sufficient alone.
5. **Aggregate monotonically.** Evidence is a join of declared, name,
   template, concrete credential, and bounded-unknown dimensions. The join is
   order-independent: concrete credential evidence dominates template
   evidence, and neither a benign descriptor nor a later sibling can erase it.
   Unknown or exhausted derivation fails closed only when the join already
   contains concrete sensitivity provenance.
6. **Project once.** The final verdict is `safe`, `template-only`,
   `sensitive`, or `sensitive-unknown`. Safe runtime projection, callback
   redaction, and profile-independent persisted configuration consume that
   verdict and its sorted provenance tokens; they do not reclassify individual
   URI components.

This staged model is intentionally component-neutral. Earlier symptom-level
repairs coupled finite name families, template early exits, component-specific
URI checks, traversal ceilings, and alias fallbacks. Each repaired example
therefore exposed the next unjoined evidence source. The single aggregate
makes precedence explicit and lets a new parser or reversible representation
add evidence without changing projection semantics.

Name structure recognizes credential values, qualified private/key/auth and
shared-access/auth signature material, credential
files/caches/cookies/configuration, and connection carriers across separators,
compact forms, arbitrary qualifiers, and versions; it is evidence, not an
allowlist of reproduced names. Ordinary endpoints,
public-key paths, templates, hashes, tokenizer/model/policy metadata, secretary
data, and unauthenticated connection locations do not become sensitive from a
coincidental word or encoded shape. A concrete credential anywhere in a
semantically named URI field—including path, matrix, query, fragment, or
userinfo—remains concrete even when another field is a complete template.

Every non-empty sensitive source contributes both its exact value and any
sensitive derived leaf values found in structured content. Those provenance
tokens are compared with every projected value. Short word-like values require
non-identifier boundaries to avoid corrupting ordinary labels; longer or
punctuated values are recognized wherever embedded, including overlapping and
prefix/suffix aliases. An exact value is retained only when the projected name
is a policy-declared credential name carrying that same declared value;
payload-only aliases never authorize themselves. Unrelated forwarded,
internal, or terminal-injected values containing either source or derived
sensitive material are omitted. Multiple declared credential names may
intentionally carry the same exact value.

The deterministic derivation traversal reconstructs JSON and syntactically
valid TOML strings, mappings, and lists, decomposes PATH-like and delimited
containers without discarding the aggregate, and follows strict percent,
hexadecimal-text, and standard or URL-safe base64 wrappers, including
padding-free repeated and mixed layers.
TOML detection requires an assignment or table shape; base64 padding is never
treated as TOML evidence. Inspection has eight independently counted ceilings:
256 KiB of UTF-8 bytes per text, 24 semantic levels, 4096 visited semantic nodes, 24
reversible transforms per derivation path, 1 MiB of decoded text, 2 MiB of
aggregate work, four nested Python-format AST levels, and 4096 generated
expansion nodes. Each ceiling accepts its exact bound and fails closed before
emitting partial output at bound plus one. Exhaustion fails closed only after
sensitivity evidence such as a
sensitive structured field, credential-bearing source name, declared
credential provenance, or concrete credential payload has been observed.
Sensitivity evidence is monotonic across visited nodes and sibling branches:
a later ordinary depth, node, text, decoded-byte, or work ceiling cannot clear
earlier concrete evidence. A concretely sensitive source that reaches a
ceiling remains bounded fail-closed provenance, so a possible unvisited
derived leaf or alias is omitted or redacted at runtime, callback, metadata,
and generated-configuration boundaries. This conservative alias rule is not
activated when traversal has seen no concrete sensitivity provenance.
When candidate traversal reaches its own depth ceiling, the bounded fallback
continues toward a possible unvisited source leaf by decoding the remaining
candidate wrappers; it never encodes the candidate farther away from the raw
source representation. Candidate-side exhaustion therefore cannot discard
source-side concrete provenance.
Structural edges advance semantic depth without advancing transform count;
visited nodes and generated expansion nodes are separate counters; decoded and
aggregate work are measured independently in UTF-8 bytes. The first rejected
bound-plus-one node receives a bounded classification pass, allowing explicit
sensitive material at that edge to enter the canonical inventory without
admitting an over-bound traversal node.
Direct cyclic mappings, lists, or tuples are classified as
`cyclic-container`. Canonical artifact/protocol redaction rejects them with
`CAP-BOUNDARY-001 classification=cyclic-container`; the diagnostic includes no
container key, value, representation, or interpreter exception text.
Python format indexes remain stdlib-valid when their string key contains an
opening or closing brace. Each brace-delimited reversible wrapper inside an
index assignment is therefore a concrete `format-index` descendant carrying
the assignment provenance. Repeated padding-free URL-safe-base64 aliases
cannot hide behind legal index text, while credential-free fields remain
ordinary.
Traversal reports an actual credential match separately from a bounded unknown;
depth, node, size, decoded-byte, or work exhaustion never synthesizes a match
to an arbitrary supplied credential. Malformed, oversized, node-heavy, or
deeply encoded benign content is preserved even when it has high entropy.
Codex's ambient structured configuration is filtered by the same provenance,
including mapping keys, values, and list entries, while ordinary non-sensitive
configuration remains deterministic. Empty credentials remain ordinary values
under the existing credential and redaction policy.

Generated MCP configuration has a separate, profile-independent provenance
boundary: every environment entry containing a non-empty credential value,
directly or after the bounded fixed-point reconstruction, is omitted before
Claude JSON or Codex TOML is persisted,
including an otherwise authorized credential name. Reversible decoding accepts
only strict UTF-8 forms. Child MCP servers therefore do not receive provider
credentials or sensitive derived values, and the explicit
unrestricted-development opt-in never disables generated-artifact filtering.
The unrestricted profile still retains its declared inherit-all behavior for
runtime agent and terminal execution authority, including ambient
credential-bearing aliases; this execution authority is independent of
persistence.

Credential values are redacted before progress, errors, stderr, or synthesized
handoffs can be logged or persisted. ACP outbound requests, callback results,
errors, cancellation-adjacent diagnostics, and terminal output cross a
cataloged boundary before JSON-RPC serialization. Worker and validator handoff
JSON, durable attempt Markdown, terminal-review JSON/Markdown, decisions,
closeout, and runtime state all delegate to the same atomic artifact boundary.
That boundary first constructs one `SensitiveValueInventory` from every
reachable textual key and leaf, then applies deterministic structured
redaction. A credential derivative embedded in an otherwise benign report is
replaced without changing the surrounding benign text, and JSON remains
reloadable. Recursive callback and persisted JSON redaction covers mapping keys
as well as values. Unchanged
mapping keys retain their exact spelling. When two sanitized keys would be
equal, changed keys receive the first available `#N` suffix after all natural
and unchanged keys are reserved; allocation follows sorted source keys without
emitting them, and string-keyed mappings are emitted in lexical order. Thus
redaction neither overwrites an innocent entry nor leaks a credential-bearing
key, including when a pre-existing key already uses a redaction placeholder or
collision suffix. Boundary-aware stream redaction retains possible credential
prefixes, overlapping values, and incomplete UTF-8 across agent and terminal
chunks until the text is either replaced as a complete value or proven
unrelated. Identifier text surrounding a short value is preserved, including
permitted environment key names. Empty or unset credential values do not
redact key names or ordinary output. Dispatcher crashes do not serialize raw
exception text.

## ACP approvals

Permission requests are matched against the role's allowed ACP tool kinds.
Allowed operations select only a supplied `allow_once` option. Forbidden
operations select only a supplied `reject_once` option. Missing, malformed, or
unsupported option sets return `cancelled`. Every option must have a non-empty
ID and name, a recognized kind, and an ID unique across the request; the
policy-selected kind must identify exactly one option. An arbitrary first,
ambiguous, or persistent allow option is never selected.

## Initialization and migration

Initialization is idempotent and marks only settings fields Unrest owns.
Reruns replace managed fields and MCP blocks while preserving unrelated host
settings. A safe or stricter unmanaged Codex root authority setting remains
user-owned while the missing `sandbox_mode` or `approval_policy` setting is
added to the managed block; reruns are byte-identical. The exact historical
Claude settings document and exact historical Codex preamble emitted by older
Unrest versions are recognized as managed legacy forms and migrated to safe
values. Similar unmanaged unrestricted settings are rejected, not silently
rewritten.

## Invariants

- `SEC-CAPABILITY-001`: child authority resolves and fails closed before
  process startup; callback access and environments cannot exceed the resolved
  role.
- `SEC-SENSITIVITY-PROVENANCE-001`: declared, name-proven, and payload-proven
  sensitivity is joined monotonically after deterministic grammar-tokenized
  parsing—including one stdlib-validated structured Python format AST whose
  field/index/conversion/spec descendants remain inspectable—bounded
  derivation, URI/structured-field normalization, and independent template
  recognition; sensitive field evidence propagates to every decoded
  descendant, concrete evidence dominates templates, candidate-side exhaustion
  decodes toward bounded sensitive sources, and ceilings fail closed for
  possible derived aliases only after concrete evidence without inventing
  matches or suppressing ordinary over-limit values absent that provenance.
- `COMPAT-CAPABILITY-POLICY-001`: capability policy evolution uses an explicit
  integer version and stable provider/role/version/capability errors.

## Required verification

```bash
uv run pytest -q tests/test_capability_policy.py tests/test_acp_runner.py \
  tests/test_acp_sandbox.py tests/test_cli.py tests/test_server.py
uv build
```

Install the wheel in an isolated environment from an unrelated directory, load
the bundled policy resource, run both entry-point help surfaces, and probe one
safe default plus one unsupported child profile without launching a child.
