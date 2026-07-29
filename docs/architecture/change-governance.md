---
id: GOV-CHANGE-001
status: active
applies_to:
  - .github/PULL_REQUEST_TEMPLATE.md
  - docs/templates/adr.md
  - policy/protected-surfaces.yaml
  - schemas/protected-surfaces.schema.json
  - src/unrest_harness/governance.py
verified_by:
  - tests/test_governance.py
related_decisions: []
schema_version: 1
---

# Change governance

## Purpose

Define the typed proposal, review, evaluation, compatibility, and rollback
record required for repository changes. This is a review contract. It does not
implement a promotion service, authorize deployment, or claim that protected
promotion is enforced at runtime.

## Public contract

[`policy/protected-surfaces.yaml`](../../policy/protected-surfaces.yaml) is the
version-1 source of truth for protected categories. Its checked-in
[`JSON Schema`](../../schemas/protected-surfaces.schema.json) and typed model in
[`governance.py`](../../src/unrest_harness/governance.py) reject unknown fields,
coercion, missing categories, empty requirements, escaping or ambiguous
selectors, agent/provider approvers, and weakened self-protection.

Every protected category requires both accountable team roles:
`release-maintainer` and `security-maintainer`. Agents and providers may
propose, implement, or evaluate a change, but they cannot satisfy either
approval role. Human approval evidence is external to this repository until a
later promotion runtime consumes it.

`strongest-applicable` means every listed tier that the changed surface and
available local infrastructure can exercise must run. A tier may be omitted
only with a stable, reviewable non-applicability reason; convenience, time, or
an agent/provider assertion is not such a reason.

### Protected selector grammar

- `component` names one exact `COMP-*` record in the canonical component map.
- `path` names one exact repository-relative POSIX path.
- `path-prefix` names one repository-relative directory prefix ending in `/`.
- Wildcards, absolute paths, `..`, backslashes, empty selectors, unknown
  components, and cross-category overlaps are invalid.
- Resolution returns zero or one sorted category. More than one is
  `GOV-POLICY-PATH-AMBIGUOUS`.

The policy covers coordinator semantics, storage migrations, capability
policy, evaluation or holdout controls, future promotion policy, future
rollback controls, and governance self-protection. Future promotion and
rollback implementation must live under the selected prefixes or update this
policy under its own protected review.

### Conventional commit grammar

The first line is:

```text
type(scope)!: lowercase imperative summary
```

`scope` and `!` are optional. Allowed types are `build`, `chore`, `ci`, `docs`,
`feat`, `fix`, `perf`, `refactor`, `revert`, and `test`. The subject is at most
72 characters, begins its summary with lowercase text, and has no trailing
period.

The final paragraph contains each trailer exactly once and in this order:

```text
Task-ID: <stable task ID>
Contract-Targets: <sorted VAL-* IDs or none>
Decision-IDs: <sorted ADR-NNNN IDs or none>
Protected-Surfaces: <sorted policy category IDs or none>
Human-Reviewers: <sorted accountable role IDs or none>
Evaluation-Evidence: <artifact/command reference or none>
Schema-Change: <versioned schema-change packet path or none>
Rollback-Plan: <procedure/evidence reference or none>
```

Ordinary changes still carry all trailers and use `none` where the field does
not apply. For protected changes, `Protected-Surfaces` must equal deterministic
path resolution, both human/team reviewer roles are required, and evaluation
and rollback cannot be `none`. A change under `schemas/` also requires a
schema-change packet.

The CLI surfaces are:

```bash
unrest check-governance \
  --policy policy/protected-surfaces.yaml \
  --component-map docs/architecture/component-map.json

unrest check-commit \
  --message-file .git/COMMIT_EDITMSG \
  --changed-path policy/protected-surfaces.yaml \
  --policy policy/protected-surfaces.yaml \
  --component-map docs/architecture/component-map.json
```

Failures render stable `GOV-*` codes before repository-relative context.

### PR and ADR records

The canonical [pull-request template](../../.github/PULL_REQUEST_TEMPLATE.md)
and [ADR template](../templates/adr.md) use unique `GOV-FIELD` markers. They
require scope and stable IDs, protected-surface disclosure, accountable human
reviewers, strongest-applicable evaluation evidence, compatibility/schema
impact, and rollback. Markers and content inside Markdown comments or fenced
examples are not operative fields. CommonMark container ancestry is binding:
quoted or outer-list examples cannot supply top-level headings, field markers,
or field bodies. Canonical top-level bullet fields remain operative, but a
second enclosing container does not. Removing or duplicating an operative
marker invalidates the template with a stable diagnostic.

### Schema evolution

Every schema change uses a version-1 typed schema-evolution packet with:

- a strictly increasing `from_version` and `to_version`;
- explicit `backward-compatible` or `hard-cut` behavior and a stable reason
  code;
- `reader_strategy: explicit-version`; heuristic readers are forbidden;
- sorted previous/current fixture records, each naming a repository-relative
  path, exact schema version, and SHA-256 content hash;
- a `compatibility_proof` record whose behavior is
  `old-fixtures-readable` for a compatible change or
  `unsupported-version-rejected` for a hard cut, with one typed evidence
  record for every declared previous-version fixture;
- typed migration, recovery, and rollback evidence records.

A hard cut must identify rejected versions in its fixtures and tests. A
compatible change must prove old supported fixtures remain readable. Neither
mode may use the other mode's reason-code family, reuse one fixture as both the
previous and current version, reuse identical fixture content under another
path, infer versions from shape, silently fall back to a broader reader, or
substitute placeholder claims. Every evidence record names its mode, fixture
path/version/hash, exact one-line command or check, enumerated observed result,
zero exit code, passed status, and a repository-relative artifact path plus
SHA-256. Fixture paths are normalized beneath `tests/fixtures/`; evidence
artifacts and repository-owned check scripts are normalized beneath
`evidence/`. Validation resolves exact path case, rejects symlinks and missing
files, hashes actual bytes, and enforces one consistent path-to-hash and
hash-to-path relationship. Each operation uses a distinct allowlisted check
bound to its artifact; the check runs without a shell command string and its
actual exit must match the recorded zero exit. Unsupported executables, direct
`true`/`false`, missing checks, and command output cannot establish proof or
enter diagnostics. Shell check files are accepted only when every operative
line is a read-only regular/readable/nonempty file test; mutation, redirection,
expansion, pipelines, and arbitrary subprocesses are rejected before
execution. Compatibility, migration, recovery, and rollback artifacts are
distinct. Future, deferred, cosmetic, prose-only, or structurally
self-consistent but file-unbacked claims cannot inhabit that typed proof shape.

## Invariants

- `ARCH-GOVERNANCE-001`: protected path/category resolution and diagnostics
  are deterministic.
- `SEC-PROTECTED-REVIEW-001`: agents and providers cannot satisfy accountable
  review or protected promotion.
- `COMPAT-SCHEMA-EVOLUTION-001`: schema readers use explicit versions, with
  tested compatibility or an explicit hard cut and recovery path.
- Governance policy, its validators, CI, schemas, evaluation oracles/holdouts,
  and its promotion/rollback declarations protect themselves.

## Failure modes

Unknown policy fields or versions, weak reviewers or evaluation, missing
rollback, path escape, selector ambiguity, unknown components, self-protection
removal, malformed commit subjects/trailers, missing protected evidence,
non-incrementing schemas, absent fixtures, and heuristic readers fail closed
with stable `GOV-*` diagnostics.

## Change protocol

1. Resolve changed paths through the current protected-surface policy.
2. Fill the PR template and any required ADR or schema-evolution packet.
3. Run the strongest applicable evaluation tiers and record evidence.
4. Obtain both accountable human/team reviews for protected changes.
5. Verify the rollback procedure before promotion is requested.
6. Change the policy/model/schema together; because they are self-protected,
   weakening any one follows the same protected review path.

No step above performs promotion. Release promotion remains blocked until a
separate runtime or maintainer workflow verifies the required approval and
evidence.

## Required verification

```bash
uv run pytest -q tests/test_governance.py tests/test_documentation_contract.py
uv run unrest check-repository
uv run unrest check-governance \
  --policy policy/protected-surfaces.yaml \
  --component-map docs/architecture/component-map.json
```

Then run the common repository gate.

## Related decisions

None. Proposed decisions use the canonical ADR template and enter the accepted
ADR index only after accountable review.

## Known limitations

Batch 0 supplies policy, strict models, deterministic resolution, templates,
and checks. It deliberately does not add deployment, promotion, canary,
holdout-execution, or automatic rollback runtime.
