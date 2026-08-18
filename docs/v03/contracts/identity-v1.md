# Proposed Identity.v1 canonicalization contract

Status: proposed, non-authoritative, and unindexed. This contract supports
[ADR-0301](../../decisions/ADR-0301-identity.md), inherits authority from
[ADR-0300](../../decisions/ADR-0300-authority.md), and does not alter current
v0.2 serialization or identity.

## Catalog boundary

The frozen proposal foundation registry contributes exactly these 11 material
dimension IDs, in sorted order:

1. `base_revision`
2. `budget_envelope`
3. `candidate_digest`
4. `capability_policy_digest`
5. `context_digest`
6. `environment_digest`
7. `evaluator_digest`
8. `route_profile_digest`
9. `seed`
10. `workload_digest`
11. `workspace_lease_id`

The
[identity catalog](../../../tests/fixtures/v03_decisions/identity/identity-catalog.v1.json)
copies that list without amendment and defines these 18 public identity kinds:
accepted working point, artifact, base, budget, candidate, context,
environment, evaluator, evidence, policy, provider configuration, review,
route/profile, run, public secret-set version, seed, workload, and workspace
lease. The kind catalog supplies each ASCII domain name, exact required
dimensions, normalization policy, and consumer set. It is exhaustive for this
foundation decision.

`RunIdentity.v1` is the replay boundary and binds all 11 foundation dimensions,
plus `accepted_working_point_digest`, `provider_configuration_digest`, and
`secret_set_version_id`. A specialized identity is independently addressable,
but its digest does not relax Run composition.

## Canonical JSON v1

### Accepted data model

The input is a closed, schema-versioned JSON object. Permitted scalar types are
Unicode strings, booleans, and integers in the inclusive interoperable range
`[-9007199254740991, 9007199254740991]`. Objects and arrays may contain only
those scalar types, objects, or arrays. Null is forbidden in semantic identity
and receipt records. Floats, decimals, exponent notation, non-JSON numeric
tokens, and byte strings are forbidden.

Every schema declares exact required keys and sets unknown fields to fail.
Optional semantics use one of these closed tagged objects:

```json
{"state":"absent"}
{"state":"present","value":"declared-type-value"}
```

Omission, null, an empty string, and `{"state":"absent"}` are four different
inputs; only the declared tagged form is valid when a field is optional. Maps
used as sets must first be represented as sorted arrays under their schema.

### Parsing and normalization

1. Read bytes as strict UTF-8. Reject a BOM, malformed UTF-8, duplicate object
   keys at any depth, and trailing non-whitespace bytes. Whitespace may be
   accepted only during input parsing; stored bytes must be canonical.
2. Reject lone UTF-16 surrogate code points after JSON escape decoding and
   reject any string or key not in Unicode NFC. Normalization is validation,
   not repair: a producer must submit the normalized spelling.
3. Validate the closed schema before hashing. IDs use their kind's ASCII
   prefix and exact case. Digest strings are lowercase
   `sha256:<64 lowercase hex>`. Repository paths use `/`, have no empty, `.`,
   or `..` segment, and are relative. External locators use their separately
   declared canonical public form.
4. Content fields are represented only by a typed content digest and declared
   media type/size when required. Do not copy content into the identity.

### Encoding

After validation:

1. Emit object members in Unicode code-point key order. Preserve array order;
   schemas that model sets require producers to sort by the declared stable
   key before this step.
2. Emit `true`, `false`, and shortest-form decimal integers literally. Emit
   strings with `"` and `\` escaped; use `\b`, `\t`, `\n`, `\f`, and `\r`;
   use lowercase `\u00xx` for the remaining U+0000 through U+001F controls;
   and emit all other Unicode scalar values literally. Do not escape `/` or
   otherwise ASCII-fold Unicode.
3. Insert no insignificant whitespace. Encode as UTF-8 without BOM and append
   exactly one LF byte (`0x0a`). These are the canonical payload bytes.
4. Stored canonical JSON bytes are exactly the output of step 3. Consumers
   compare received bytes to a fresh canonical encoding and reject, rather
   than repair, any mismatch.

### Fingerprint preimage

An identity fingerprint preimage is the byte concatenation:

```text
ASCII("unrest.identity-fingerprint.v1") || 0x00 ||
ASCII(identity_kind) || 0x00 || canonical_payload_bytes
```

`identity_kind` is the exact ASCII domain in the identity catalog. The digest
algorithm is SHA-256; text form is `sha256:` followed by 64 lowercase
hexadecimal digits. Algorithm, canonical grammar, and domain are one versioned
contract. A different kind over identical JSON yields a different digest.

The
[canonical vectors](../../../tests/fixtures/v03_decisions/identity/canonical-vectors.v1.json)
contain payload bytes, full preimage bytes, and digest text. They must be
recomputed from structured input by an implementation independent of the
fixture producer. Copying the expected digest is not verification.

## Equality, composition, and mutation

Two identities are equal if and only if kind, schema version, canonical payload
bytes, and computed digest are equal. A consumer verifies all four; it never
uses a convenient subset. A composite identity lists typed child identity
digests, never free-form summaries of their inputs.

The
[mutation fixture](../../../tests/fixtures/v03_decisions/identity/dependency-mutations.v1.json)
contains exactly one mutation for every one of the 18 public identity kinds.
Each starts from a valid baseline, changes only the named dimension, and must
produce inequality. The 11 foundation mutations are a required subset and may
not be weakened by adding derived kinds.

Candidate content such as patch, prompt, skill, tool, or profile material is
represented by an allowed public bundle/artifact digest. The bytes themselves
are not identity metadata. Changing any bundle member changes that digest and
therefore the candidate and run identities.

## Public configuration and secret-set identity

A provider configuration identity includes only schema-enumerated public
fields such as provider family, public endpoint/profile/model identifiers,
route policy, and supported public feature flags. Credential values,
authorization headers, environment values, private endpoints, account data,
and derivatives are excluded.

`SecretSetVersionIdentity.v1` is an opaque public identifier allocated by the
configuration authority. It contains issuer namespace, set name, and monotonic
or content-independent public version. The version must not be computed from,
contain, encrypt, encode, truncate, or hash any secret. Evidence consumers can
compare the opaque ID but cannot resolve secret values through this interface.

The
[secret-safety fixture](../../../tests/fixtures/v03_decisions/identity/secret-safety.v1.json)
enumerates rejected categories and permitted provenance using non-sensitive
sentinels. Construction is allowlist-first; post-hoc redaction is not an
acceptable preimage-building procedure.

## Failure semantics

Parsing, schema validation, normalization, canonical byte comparison, domain
comparison, or digest mismatch fails before identity use. Errors expose only a
stable code and public JSON path. They must not include rejected values,
surrounding input, prompts, source bodies, reports, or command output.

Duplicate keys, floats, exponent numbers, unsafe integers, lone surrogates,
non-NFC strings, ambiguous absence/null, unknown fields, BOMs, alternate key
order, whitespace, alternate escapes, or missing/extra LF are independently
invalid. No “best effort,” coercion, latest-version, or nearest-kind fallback is
permitted.

## Compatibility and rollback

This domain is not the current v0.2 JSON encoding and not the proposal
future-mission handoff self-digest domain. Future adapters must state which
domain they consume and cannot relabel bytes. Current schema-v1 readers are
unchanged and no generic migration reader is introduced.

Before acceptance, rollback is rejection/deletion of the new draft artifacts.
After a future implementation, stop new issuance and disable v1-dependent
consumers while retaining already issued identities/receipts under policy; the
current Mission-only core remains operable.

## Verification obligations

1. Strictly parse every identity fixture with duplicate-key rejection.
2. Assert the frozen 11-dimension list and 18-kind catalog exactly, with sorted
   unique IDs and complete Run composition.
3. Recompute every payload, preimage, and digest independently and compare all
   stored hex/text fields.
4. Run every prohibited-encoding case separately and observe its declared
   stable error code.
5. Mutate each identity dimension independently and prove inequality.
6. Scan every changed product/handoff artifact using forbidden field/category
   rules, then manually inspect each canonical preimage allowlist.
7. Resolve every relative Markdown link and anchor in this owned slice.

Passing verifies only this proposal artifact. It does not accept ADR-0301,
implement `IF-FINGERPRINT`, or authorize a receipt issuer.
