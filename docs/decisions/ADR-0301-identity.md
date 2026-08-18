# ADR-0301: Bind v0.3 identity and evidence to canonical public inputs

## Record metadata

id: ADR-0301
status: proposed
date: 2026-08-18
task_ids:
  - W-IDENTITY-EVIDENCE
contract_targets:
  - VAL-ID-001
  - VAL-ID-002
  - VAL-ID-003
  - VAL-ID-004
supersedes: []
superseded_by: null
evaluation_tier:
  - focused-fixture
  - focused-link
  - independent-vector-recomputation
  - adversarial-leak-review

## Authority status

This record is an unindexed, non-authoritative proposal. Authorship, its date
or filename, bundle inclusion, passing vectors, and chronology do not accept or
integrate it. Only a downstream maintainer may accept and canonically integrate
a specific version through the authority boundary in
[ADR-0300](ADR-0300-authority.md). This record issues no integration receipt.

## Scope

- In scope: public identity kinds and dimensions, canonical bytes and digest
  domains, receipt families, issuer/consumer/dependency semantics, freshness,
  revocation, outcomes, artifact/deviation/cost fields, integrity, and secret-
  safe metadata.
- Out of scope: accepting this record, runtime implementation, storage engine,
  cryptographic key custody, public CLI/MCP shape, workspace isolation,
  evaluator quorum, promotion authority, migration, or changing current v0.2
  records.

## Context

The other proposal families need reproducible identity and freshness without
letting digests, timestamps, or evidence become authority. This record closes
the shared encoding and dependency semantics while leaving operational custody
and retention choices with their proper future owners.

## Current v0.2 truth

At product object `96d5c0f0b240bd3373809546d7aecc1e407f837b`,
[ADR-0002](ADR-0002-lean-core-v0.2.md) and the accepted
[architecture index](../architecture/index.md) govern. Current persisted
Mission records use their existing schema-v1 serialization and identifiers.
Current Unrest has no accepted `IF-FINGERPRINT`, content-addressed v0.3 receipt
store, candidate/evaluator/review identity, evidence freshness graph, or
secret-set-version identity.

The future-mission handoff protocol has its own proposal-local canonicalizer.
It is an input and useful precedent, not current product behavior and not the
identity domain defined here. Nothing in this draft changes either current
schema-v1 bytes or that protocol.

## Proposed decisions and dispositions

| Decision ID | Disposition | Proposed rule |
| --- | --- | --- |
| ID-D01 | proposed | Version `IF-FINGERPRINT` as a strict canonical JSON subset plus an identity-kind domain separator and SHA-256 digest. Stored bytes and digest preimages are exact and independently reproducible. |
| ID-D02 | proposed | Bind the complete frozen foundation dimension catalog and the 18 public identity kinds in the identity contract. A change in one material dimension produces a distinct identity and cannot reuse dependent evidence. |
| ID-D03 | proposed | Version nine append-only receipt families from the frozen foundation registry. Every receipt binds issuer authority, subject, dependency digests, non-authoritative time metadata, outcome, artifacts, deviations, cost, integrity, freshness policy, disposition, and consumers. |
| ID-D04 | proposed | Compute freshness by exact dependency comparison, revocation and expiry policy. Chronology never establishes authority or freshness, and an old receipt remains an immutable historical statement after becoming stale or revoked. |
| ID-D05 | proposed | Admit only named public configuration and opaque public secret-set version identifiers. Raw, encoded, encrypted, transformed, or hashed secret values, prompts, source bodies, reports, and unrelated command output are forbidden from identities, receipts, fixtures, evidence metadata, and handoffs. |
| ID-A01 | rejected | Hash arbitrary JSON, rely on library-default serialization, allow coercion, or treat semantically similar but non-canonical stored bytes as valid. |
| ID-A02 | rejected | Use timestamps, latest-file selection, sequence, successful outcomes, or a producer's self-assertion as freshness, issuer authority, or causality. |
| ID-A03 | rejected | Include a secret value or its hash to make a run reproducible. Hashing a secret creates a comparison oracle; it does not make the value public metadata. |
| ID-A04 | deferred | Cryptographic signature suite, trust-root distribution, rotation, and key revocation. This draft requires versioned integrity and permits detached public signature references but does not select key custody. |
| ID-A05 | deferred | Retention duration and physical receipt-store format. The semantic record is append-only; storage and policy owners must later specify retention without rewriting outcomes. |

## Identity composition

The [identity contract](../v03/contracts/identity-v1.md) freezes two related,
non-interchangeable catalogs:

1. the 11 `identity_dimensions` copied exactly from the frozen proposal
   foundation registry; and
2. 18 public identity kinds needed to type those dimensions and the additional
   evidence, review, accepted-working-point, provider-configuration, run, and
   public secret-set boundaries required by this decision.

The machine-readable
[identity catalog](../../tests/fixtures/v03_decisions/identity/identity-catalog.v1.json)
is the exhaustive composition oracle. `RunIdentity.v1` binds all 11 foundation
dimensions plus the accepted working point, provider configuration, and public
secret-set version. Specialized identities bind their declared inputs and are
then referenced by digest; consumers must not replace a typed digest with a
similarly spelled string from another domain.

Identity is equality of kind, schema version, canonical payload bytes, and
digest. IDs and paths use their declared normalized form before hashing; content
is represented by a content digest, never copied into metadata. An optional
value uses an explicit tagged form (`{"state":"absent"}` or
`{"state":"present","value":...}`); JSON null and omission are not
interchangeable values.

The
[dimension mutation fixture](../../tests/fixtures/v03_decisions/identity/dependency-mutations.v1.json)
changes exactly one dimension at a time. Every identity mutation has
`equal: false`; receipt mutations partition all nine receipt families into
`stales` and `remains_valid`, so no unclassified family can disappear between
the cracks.

## Canonical bytes and fingerprints

The exact grammar, encoding, preimages, and validation order are specified in
the [identity contract](../v03/contracts/identity-v1.md#canonical-json-v1).
In summary:

- parse strict UTF-8 without BOM, duplicate keys, non-JSON tokens, floats,
  exponent notation, unsafe integers, lone surrogates, or non-NFC strings;
- allow only objects, arrays, strings, booleans, and integers in
  `[-9007199254740991, 9007199254740991]`; semantic identity and receipt
  records forbid null and require exact fields;
- sort object keys by Unicode code point, retain declared array order, use the
  specified JSON escapes, emit other Unicode scalars literally, add no
  insignificant whitespace, encode UTF-8, and append exactly one LF;
- hash `unrest.identity-fingerprint.v1\0`, the ASCII identity kind, a NUL, and
  the canonical payload bytes for fingerprints; and
- hash `unrest.receipt.v1\0`, the ASCII receipt kind, a NUL, and canonical
  receipt bytes after removing exactly the top-level `receipt_digest` member
  for receipt self-integrity.

Stored identity payload and receipt bytes must themselves be canonical. A
consumer does not normalize and forgive non-canonical storage. The
[golden vectors](../../tests/fixtures/v03_decisions/identity/canonical-vectors.v1.json)
record canonical/preimage hex and SHA-256 results; independent recomputation is
required. Their negative cases independently reject every prohibited encoding
class rather than combining several failures in one sample.

## Receipt dependency and freshness model

The complete nine-family field and consumer graph is in the
[receipt contract](../v03/contracts/receipt-v1.md) and
[receipt catalog](../../tests/fixtures/v03_decisions/identity/receipt-catalog.v1.json).
All families share the closed common record:

- receipt kind/schema/ID and immutable append-only disposition;
- issuer identity and separate issuer-authority decision reference;
- typed subject kind/ID/digest;
- a sorted dependency list of typed identity or upstream-receipt digests;
- issue/observation time as metadata with `chronology_is_authority: false`;
- typed outcome and terminal disposition;
- sorted artifact references, declared deviations, and a bounded cost record;
- versioned content integrity and explicit detached-signature state; and
- freshness policy, expiry state, revocation reference state, and named
  consumers.

Freshness is a derived view, never a receipt mutation. A consumer first
recomputes canonical bytes/integrity, verifies the issuer's authority for the
receipt family, and validates the closed record. It then compares every bound
dependency with the consumer's exact current dependency set. A missing, extra,
unavailable, wrong-kind, or mismatched dependency yields `stale` or
`unverifiable` as specified; an authorized revocation yields `revoked`; trusted
expiry may make a receipt stale. No timestamp or later successful event can
make it fresh again. Re-evaluation emits a new receipt.

Evaluation, review, integration, and promotion receipts that participate in a
promotion must bind the identical candidate and accepted-working-point
digests. A rebase, edit, evaluator/reviewer change, or dependency mutation
cannot be explained away as metadata. Issuer, evaluator, reviewer, integrator,
promotion, and rollback authority remain those of
[ADR-0300](ADR-0300-authority.md); this record describes their evidence, not
their right to decide.

## Secret-safe metadata

The [secret-safety fixture](../../tests/fixtures/v03_decisions/identity/secret-safety.v1.json)
contains classification sentinels only—never example sensitive contents. The
following are inadmissible in every identity, preimage, receipt, decision
fixture, product document, evidence index, and handoff artifact:

- secret values and encoded, encrypted, transformed, truncated, or hashed
  derivatives of secret values;
- prompts, private context text, source-file bodies, reports, transcripts, or
  raw model/tool/command output; and
- ambient environment, unrelated filesystem, process, network, or command
  metadata.

Admissible provenance is narrowly enumerated: public algorithm/schema IDs,
public route/model/profile IDs, public capability/evaluator/workload/environment
configuration digests computed only from their allowed public fields, public
artifact content digests, and opaque versioned `secret_set_version_id` values
issued by the named configuration authority. A secret-set version identifies a
public configuration generation; it is not derived from secret material and
cannot be resolved to values through the evidence interface.

Implementations must construct metadata from an allowlist, not redact a broad
capture after collection. Unknown fields fail closed. Diagnostic evidence may
record a bounded error code and public field path, never the rejected value.

## Authority, preconditions, outcomes, compatibility, and rollback

- Authority: downstream maintainers decide acceptance; issuer and consumer
  authority is cross-linked to ADR-0300 and never inferred from possession of a
  digest or receipt.
- Identity: exact kind, schema version, domain, canonical bytes, and digest;
  receipt subjects and dependencies are typed references, not untyped hashes.
- Preconditions: acceptance plus canonical schema integration precede runtime
  use; a receipt additionally requires a valid issuer grant and complete
  current dependencies.
- Error/cancellation/recovery owner: the producing subsystem owns failed
  construction; the receipt-store owner preserves/rejects bytes; the named
  consumer owns its freshness decision; ambiguous authority or unavailable
  dependencies fail closed to the route defined by ADR-0300.
- Terminal disposition: construction is appended or rejected; receipt outcomes
  are family-specific and immutable; freshness is `fresh`, `stale`, `revoked`,
  or `unverifiable` without rewriting history.
- Compatibility effect: none today. Current v0.2 persistence, IDs, envelopes,
  and handoffs are unchanged. Future implementation introduces new v1 records
  and explicit adapters rather than silently reinterpreting old bytes.
- Rollback: before acceptance, reject/remove only this draft family. After a
  future implementation, stop issuing new v1 records, retain already issued
  evidence under policy, disable consumers that require it, and keep the
  current Mission-only no-extra path; rollback never forges freshness.

## Alternatives considered

- ID-A01 through ID-A03 are rejected because ambiguity, chronology, and secret
  comparison oracles defeat reproducibility and privacy.
- ID-A04 and ID-A05 are deferred because key custody and retention are separate
  operational authorities; the record exposes their required versioned seams.
- A general canonicalization standard was considered. A deliberately small
  closed JSON subset was selected because it can be reproduced with the
  standard library and fails unsupported values instead of guessing.

## Consequences

- Positive: evidence cannot be replayed across an unrecorded material change.
- Positive: two independent implementations can reproduce the exact bytes and
  digests without a new dependency.
- Negative/cost: producers must enumerate public inputs, preserve immutable
  receipts, and recompute freshness rather than treating timestamps as truth.
- Compatibility/hard cut: none in current v0.2; future consumers must opt into
  the new versioned domains.
- Schema/migration impact: new records only; no heuristic legacy reader.
- Security/privacy impact: allowlisted public metadata and secret-set version
  IDs replace broad capture. Some convenient debugging material is
  intentionally excluded.

## Open questions

- `ID-Q01` / `ID-A04`: which signature suite, trust-root distribution,
  rotation, key custody, and revocation design can satisfy authoritative
  receipt consumption.
- `ID-Q02` / `ID-A05`: which retention policy and physical receipt-store
  format preserve append-only semantics without rewriting outcomes.

Both remain deferred. The
[foundation integration contract](../v03/contracts/foundation-integration.md#disposition-and-open-question-inventory)
records their downstream ownership and cross-family dependencies.

## Review

- Reviewer: none
- Approval date/evidence: none; proposed and unindexed
- Evaluation evidence: strict fixture parsing, independent vector
  recomputation, mutation partitions, leak classification, and link checks
  only; no runtime acceptance exists

## Rollback

- Trigger: ambiguous canonical bytes, an unbound material dimension, omitted
  receipt family/consumer, chronology-derived freshness, issuer self-authority,
  or forbidden material in metadata.
- Procedure: reject and remove the new identity draft, contracts, and fixtures;
  do not modify accepted v0.2 sources.
- Data recovery: none; this proposal creates no runtime data.
- Verification: confirm the accepted index and current schema-v1 behavior are
  unchanged.

## Implementation and verification

- Components/paths: future identity/evidence packages only; this task changes
  FM-000-owned documentation and decision fixtures.
- Canonical documents: current [runtime](../v5/07-runtime-architecture.md),
  [storage](../../specs/memory_v2/PRODUCT.md), and
  [MCP](../v5/08-mcp-surface.md) remain authoritative.
- Tests/evidence: strict duplicate-key parsing, catalog completeness,
  independent golden-vector hashing, one-dimension mutation partition checks,
  forbidden-key/value-class scans, and relative-link/anchor resolution.

## References

- [Authority proposal](ADR-0300-authority.md)
- [Identity.v1 contract](../v03/contracts/identity-v1.md)
- [Receipt.v1 contract](../v03/contracts/receipt-v1.md)
- [ADR-0002](ADR-0002-lean-core-v0.2.md)
- [Architecture index](../architecture/index.md)
