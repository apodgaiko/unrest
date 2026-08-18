# Proposed Receipt.v1 dependency and freshness contract

Status: proposed, non-authoritative, and unindexed. This contract supports
[ADR-0301](../../decisions/ADR-0301-identity.md), uses
[Identity.v1](identity-v1.md), and inherits issuer, integration, promotion, and
rollback authority from [ADR-0300](../../decisions/ADR-0300-authority.md).

## Complete receipt-family catalog

The frozen foundation registry defines exactly these nine families:

1. `cleanup_receipt.v1`
2. `evaluation_receipt.v1`
3. `integration_receipt.v1`
4. `patch_receipt.v1`
5. `promotion_receipt.v1`
6. `review_receipt.v1`
7. `rollback_receipt.v1`
8. `run_receipt.v1`
9. `workspace_receipt.v1`

The machine-readable
[receipt catalog](../../../tests/fixtures/v03_decisions/identity/receipt-catalog.v1.json)
is exhaustive. For every family it declares the sole permitted issuer-authority
class, subject kind, mandatory identity and upstream-receipt dependencies,
outcome vocabulary, artifact rules, freshness/expiry rule, integrity/signature
policy, terminal dispositions, and named consumers.

## Closed common record

Every receipt is a closed object with these required members:

| Field | Semantics |
| --- | --- |
| `receipt_id`, `receipt_kind`, `schema_version` | Stable logical ID, one catalog family, and integer `1`. |
| `receipt_digest` | SHA-256 self-integrity over the exact receipt preimage below. |
| `issuer` | Typed public issuer identity digest and actor/component ID. |
| `issuer_authority` | External authority class plus exact public decision/grant reference. The issuer cannot self-create authority. |
| `subject` | Typed subject kind, stable public ID, and identity/content digest. |
| `dependencies` | Sorted unique closed records of dependency kind, public ID, digest, and role. Upstream receipt dependencies use their receipt digest. |
| `observed_at`, `sequence`, `chronology_is_authority` | RFC 3339 UTC metadata, safe integer ordering aid, and literal `false`. Time/sequence never proves cause, freshness, or authority. |
| `outcome`, `terminal_disposition` | One catalog outcome and its immutable terminal meaning. No missing/null success aliases. |
| `artifact_refs` | Sorted typed public artifact ID/digest/media-type/size references; never artifact bodies. |
| `deviations` | Sorted declared deviation code, authority decision reference, scope, and effect on interpretation; an empty array means none. |
| `cost` | Declared unit/currency schema, safe integer quantities, accounting boundary, and completeness (`complete`, `partial`, or `not_applicable`). Missing cost cannot improve an outcome. |
| `integrity` | Mechanism ID, digest algorithm/domain, canonicalization version, detached-signature state, and public key/signature artifact references when required. No signing secret enters metadata. |
| `freshness_policy` | Policy ID, exact dependency mode, expiry form, revocation authority class, and unavailable-dependency behavior. |
| `append_only_disposition` | Literal `immutable`; correction/supersession appends a new typed record and never edits this one. |
| `consumers` | Sorted catalog consumer IDs. A producer cannot add itself as an authority consumer. |

Null is forbidden. Optional signature, expiry, or revocation references use the
explicit tagged absent/present form from Identity.v1.

## Receipt preimage and stored bytes

Validate and encode the full receipt with
[Canonical JSON v1](identity-v1.md#canonical-json-v1). To compute
`receipt_digest`, require the top-level member to exist, then remove exactly
that member. A nested member with that spelling is ordinary schema data. Encode
the remaining closed object canonically and construct:

```text
ASCII("unrest.receipt.v1") || 0x00 ||
ASCII(receipt_kind) || 0x00 || canonical_receipt_without_digest_bytes
```

Hash with SHA-256 and encode as lowercase `sha256:<64 hex>`. Insert that result
as `receipt_digest`, encode the complete object canonically, and store exactly
those bytes. Verification repeats the process and byte-compares the received
stored form. Receipt family is part of the domain; cross-family replay fails.

The
[canonical vectors](../../../tests/fixtures/v03_decisions/identity/canonical-vectors.v1.json)
include a complete receipt preimage, self-digest, stored canonical bytes, and
an integrity mutation. A digest proves byte integrity only. Issuer authenticity
comes from the separate issuer-authority check and, when the catalog requires
it, a verified detached signature reference under a future accepted suite.

## Issuance and outcomes

The family issuer verifies its exact authority grant, subject identity, and
complete dependency set before appending. Authority possession for one family
does not authorize another. A failed operation still emits its family outcome
when evidence is available; a missing receipt never aliases success.

Artifact references bind immutable public identity and content digest. Declared
deviations narrow interpretation and cannot waive a mandatory dependency,
authority, integrity, correctness, or safety floor. Cost is evidence, not
authority; unknown or partial accounting remains visibly partial.

Cancellation appends a cancelled/partial/error family outcome as allowed by the
catalog and follows the owning recovery route in ADR-0300. It never deletes an
earlier receipt. Correction, retry, rebase, re-evaluation, re-review,
reintegration, or rollback creates new identities and receipts.

## Freshness algorithm

A named consumer derives one of `fresh`, `stale`, `revoked`, or `unverifiable`
for a receipt/reference/current-state triple:

1. Strictly parse, schema-check, recompute integrity, and compare stored bytes.
   Failure is `unverifiable`, never stale-success.
2. Resolve the receipt family and verify the exact issuer identity and external
   issuer-authority decision. Missing, unavailable, stale, mismatched, or
   unauthorized authority is `unverifiable`.
3. Verify subject kind/digest and obtain the consumer's complete current
   dependency set for the family. Dependency records are compared by kind,
   public ID, role, and digest. Missing, extra, duplicate, wrong-kind, or
   mismatched dependencies are `stale`; unavailable required data is
   `unverifiable`.
4. Apply an authorized append-only revocation record. A matching revocation is
   `revoked`; absence is not proof of freshness unless the policy's revocation
   view is available at its declared watermark.
5. Apply the declared expiry rule with a consumer-trusted clock. Expiry can
   make a receipt `stale`; `observed_at`, `sequence`, file order, and the time
   of a later success can never make it fresh.
6. Return `fresh` only if every preceding check passes. The original receipt is
   unchanged and remains a historical statement about its original subject.

There is no transitive shortcut: when a dependency is an upstream receipt, the
consumer verifies both its digest and its own derived freshness if the catalog
marks it `must_be_fresh`. A new upstream receipt does not mutate the old one; it
causes the downstream comparison to stale until a new downstream receipt is
issued.

## Material mutation matrix

The
[dependency mutation fixture](../../../tests/fixtures/v03_decisions/identity/dependency-mutations.v1.json)
classifies policy, base, accepted working point, route/provider, evaluator,
reviewer, workload, environment, workspace lease, candidate, context, seed,
budget, artifact, public secret-set version, and upstream receipt changes.
For every row, `stales` and `remains_valid` are disjoint and their union is all
nine families. `remains_valid` means only that the named dimension is not a
dependency of that family; other integrity, authority, freshness, expiry, and
revocation checks still apply.

Pre-application `PromotionDecisionGrant.v1` consumes fresh evaluation and
review receipts plus the exact patch return; it MUST NOT consume an integration
or promotion receipt. After parent application atomically changes the accepted
point, `integration_receipt.v1` binds that durable result. Only the
post-application `promotion_receipt.v1` consumes the fresh integration receipt,
evaluation, and review records for the identical candidate and resulting
accepted point. Any material change blocks the affected later step. No receipt
authorizes the earlier action that creates it.

## Family-specific integrity and signature policy

All families require `sha256-content-digest-v1`. The catalog also declares
whether `detached-signature-ref-v1` is `deferred_optional` or
`required_before_authoritative_consumption`. Integration, promotion, rollback,
and external-authority review consumption require a future accepted detached
signature or equivalently authenticated issuer mechanism before they can serve
as authoritative evidence for a later decision. They never authorize their own
already-completed operation. This draft does not choose an algorithm or key
store; until
that decision exists, those receipts may be fixture-verified as evidence but
cannot satisfy an authoritative consumer.

A signature record exposes only public suite ID, public key ID/version, and a
detached signature artifact reference. Private/signing key material and its
hash are forbidden. Signature verification never replaces canonical digest or
issuer-authority verification.

## Secret safety and bounded errors

Receipt construction uses the same allowlist and
[secret-safety fixture](../../../tests/fixtures/v03_decisions/identity/secret-safety.v1.json)
as Identity.v1. Artifact references do not license embedding artifact bodies.
Outcome, deviation, cost, and error fields use finite codes/public quantities;
they exclude prompts, source bodies, reports, transcripts, raw command/model/
tool output, environment dumps, and secret values or derivatives.

An invalid input error records only stable code, receipt family, and public
field path. Quarantined bytes remain outside evidence metadata and handoff
artifacts.

## Compatibility and rollback

These are new proposal-only receipt families, not current handoff receipts and
not current schema-v1 Mission persistence. Future adapters must name the exact
domain and cannot relabel or heuristically migrate existing records.

Before acceptance, rollback is rejection/deletion of this draft set. After a
future implementation, stop issuance/consumption, retain immutable history
under policy, and use the current Mission-only no-extra path. Disabling receipt
consumption cannot convert stale or unverifiable evidence into acceptance.

## Verification obligations

1. Strictly parse the catalog/vectors/mutations with duplicate-key rejection.
2. Assert the exact nine-family registry and complete common fields, unique
   issuer, subject, outcomes, dependencies, consumers, dispositions, integrity,
   signature, expiry, and revocation policy for every family.
3. Recompute receipt canonical bytes, domain preimage, digest, and stored bytes
   independently; reject the integrity mutation.
4. Assert each material mutation partitions all nine families and matches the
   catalog dependency graph, including upstream receipt freshness.
5. Verify candidate equality across evaluation/review/integration/promotion
   consumption and reject one-field mismatch independently.
6. Inspect all preimages and scan every changed product/handoff artifact for
   forbidden categories; hashing a secret must be an explicit rejection case.
7. Resolve every relative Markdown link and anchor in this owned slice.

Passing verifies only artifact consistency. It does not accept ADR-0301,
authenticate an issuer, satisfy a Mission gate, or issue an integration
receipt.
