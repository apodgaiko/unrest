---
id: ARCH-REPOSITORY-CONTRACT-DOC-001
status: active
applies_to:
  - .github/workflows/ci.yml
  - docs/architecture/*.json
  - policy/protected-surfaces.yaml
  - schemas/*.schema.json
  - src/unrest_harness/repository_contract.py
verified_by:
  - tests/test_repository_contract.py
related_decisions: []
schema_version: 1
---

# Repository contract

## Purpose

Provide one lightweight, deterministic, read-only command for the repository
identity and governance checks that must run in every supported Python CI lane:

```bash
uv run unrest check-repository
```

The command discovers the Git toplevel from the current directory. It writes
only its JSON success report to standard output or stable diagnostics to
standard error; it does not write beneath the repository root.

## Validated surface

The command checks:

- Git-owned, regular-file `AGENTS.md` guidance and the canonical root-to-leaf
  hierarchy;
- CommonMark-parsed operative headings, comments, fences, setext/ATX forms,
  preserved container ancestry, template multiplicity, and normative Markdown
  anchors; blockquoted or outer-list examples cannot satisfy top-level
  template/workflow requirements;
- Python source/test comment and docstring references parsed with one anchored
  grammar for normalized, exact-case `docs/` or `specs/`
  repository-relative `.md` paths plus an optional complete fragment;
- strict version-1 frontmatter, canonical document paths, stable ID sources,
  annotation records, removal records, component edges, and baseline
  defect/legacy non-normativity through
  `historical-record-policy.json`: exact candidate manifest IDs and
  classifications are rejected only when linked into one of its finite active
  registry roles without an exact separate current-contract authorization
  tuple. The version-1 role identity, registry path, collection field, record
  filter, and scalar/list value field are pinned by the repository contract;
  changing any locator is itself invalid and cannot redirect historical-role
  enforcement. The exact authorized role/reference pair is also recognized by
  the role's frontmatter, stable-ID, component-edge, template,
  evidence-location, and canonical-order checks; the exception does not admit
  uncataloged historical references, unrelated roles, or arbitrary stable-ID
  forms. Arbitrary historical prose is not classified;
- `annotation-policy.json`'s open structural identity-attribution grammar over
  its exhaustively supported Markdown/HTML label, attribute, and tag
  containers, using HTML entity decoding, Unicode NFKC, format-control removal,
  case folding, and punctuation-independent tokens; arbitrary prose, comments,
  fenced examples, link destinations, and unrelated confidential terms are
  not classified;
- `template-heading-policy.json`'s required canonical/template headings:
  operative top-level ATX and Setext headings share normalized rendered
  visible-label identity, while raw HTML headings, explicit anchor aliases,
  links with a different visible label, non-canonical sections, block quotes,
  nested lists, and code containers do not satisfy or duplicate a field;
- `evidence-policy.json`'s exhaustive protected fields, records, and commit
  trailers. A positive record requires an allowed check bound to an existing
  SHA-256-identified artifact, an observed result from the mode's finite
  enumeration, declared exit zero, and a fresh successful execution. Typed
  limitation/history records remain explicitly non-passing. Free prose outside
  a cataloged location neither satisfies evidence nor receives an evidence
  classification;
- the protected-surface policy, accountable roles, evaluation requirements,
  rollback requirements, and self-protection controls;
- every `schemas/**/*.schema.json` file against its declared supported
  metaschema;
- the Pydantic-generated protected-surface schema, canonical architecture JSON,
  and the complete forward/reverse Batch 0 baseline output;
- the versioned capability sink catalog in both directions: declared sink and
  omission anchors must resolve, while the AST effect model assigns every
  reachable stream/descriptor write, serializer-to-stream call, log emission,
  dynamic callback, ACP wire write, request, and cancellation to a canonical
  sink or exact delegation omission. Primitive omission effects are pinned,
  and reversible codec operations must remain inside their declared transform
  owners;
- all three checked-in packaged capability documents through their runtime
  strict loaders and canonical schemas. Role policy, security model, and sink
  catalog reject missing or unknown fields, unsupported versions, and
  duplicate object members at any depth (including equal-valued duplicates)
  before ordinary JSON decoding could collapse them. Semantically equivalent
  serialization drift also fails the canonical sorted UTF-8 JSON check;
- the exact command's presence before build in every Python test/build job and
  matrix, with effective (post-include/exclude) versions exactly matching
  project classifiers, reachable dependency chains, and no conditional or
  continue-on-error path that skips or softens a supported lane. Test,
  coverage-driven pytest, option-bearing build/package/publish, and equivalent
  Python module commands are classified from tokenized shell commands rather
  than exact command strings. Static dependency failures include any explicit
  nonzero `exit` and path-qualified `false`.

Diagnostics use `REPO-*` or the protected policy's stable `GOV-*` reason code
and a repository-relative location. Inputs and diagnostics are sorted before
reporting, so reversed source enumeration produces identical bytes.

## Dependency boundary

`jsonschema==4.26.0` is a direct runtime dependency because the command must
validate checked-in schemas against their declared metaschemas, not merely
parse them as JSON. The exact pin makes this CI contract independent of a
transitive dependency resolver change. `markdown-it-py>=4.0.0` is a direct
runtime dependency because operative Markdown structure follows its CommonMark
token stream rather than repository-specific fence and heading heuristics. No
documentation site generator is required.

## Invariants

- `ARCH-REPOSITORY-CONTRACT-001`: one read-only command deterministically
  validates repository identity, references, governance, schemas, generated
  output, and its own CI enforcement.

## Failure modes

Missing or symlinked guidance, unresolved files or anchors, unknown or
conflicting IDs, invalid frontmatter or annotations, broken component edges,
component-induced protected-policy ambiguity, protected-catalog
reclassification, weakened protected policy, invalid protected evidence,
unauthorized historical role links, malformed or non-exact historical
authorizations, redirected historical role locators, unsupported or malformed
schemas, generated drift, and
uncataloged reachable output/request/callback/cancellation channels,
missing/substituted/late/incomplete-version CI invocation exit nonzero.
Absolute-looking, non-normalized, repeated-separator, wrong-case, missing, or
partial source references exit nonzero; external URL references remain
external. Duplicate required template headings or YAML keys, quoted/listed
example fields, conditional CI invocation, supported-version matrix exclusion,
unreachable or statically failing dependencies, alternate Python test/build
matrices without enforcement, option-bearing build/publish ordering, and
tolerated repository-contract failures also exit nonzero.

## Change protocol

Update this document, its component and stable-ID records, the command, focused
mutation tests, and CI source in one coherent change. Add a new generated
artifact only with a deterministic renderer and drift check. Add a schema
dialect only by explicitly registering its validator and testing an invalid
schema against that metaschema.

## Required verification

```bash
uv run pytest -q tests/test_repository_contract.py
uv run unrest check-repository
```

Then run the common repository gate.

## Related decisions

None.
