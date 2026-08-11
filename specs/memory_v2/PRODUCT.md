---
id: SPEC-STORAGE-001
status: active
applies_to:
  - src/unrest_harness/config.py
  - src/unrest_harness/storage.py
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_storage.py
  - tests/test_terminal_review.py
related_decisions:
  - ADR-0002
schema_version: 1
---

# Memory v2 and storage product contract

## Purpose

Define project identity, durable mission records, orchestrator-only runtime
cursors, atomic persistence, workspace discovery shims, and closure artifacts.

## Public contract

Each project has a bucket at
`$UNREST_PROJECTS_DIR/<project-id>/` (default
`$UNREST_HOME/projects/<project-id>/`) with two roots:

```text
<bucket>/
├── .unrest/          durable, agent-readable mission record
└── .unrest-runtime/  orchestrator cursor and worker handoff transport
```

The workspace remains the product checkout. Unrest may expose project skills
and guidance through host discovery shims, but project state lives in the
bucket.

## Invariants

- `ARCH-STORAGE-001`: durable records and runtime cursors remain separate.
- `ARCH-WRITE-001`: text and JSON writes use a sibling temporary file followed
  by `os.replace`; JSON is UTF-8, two-space indented, and newline terminated.
  Failures before replacement reject the write and preserve the prior target.
  Once replacement is visible, a directory-fsync error does not turn the new
  generation into a caller-visible rejection. Every writer supplies its
  lexical trusted persistence root. The root and each existing component from
  it through the destination parent must be a real directory under `lstat`,
  never a symlink or another non-directory; this is checked before parent or
  temporary creation and again before replacement. Lexical containment is
  structural and the write path is never replaced by a resolved redirect.
- `ARCH-CLOSURE-001`: `closeout.md` is written only after a successful terminal
  review or an explicit acknowledged-gap transition.
- `SEC-REVIEW-ROOT-001`: terminal-review deliverable roots are canonicalized and
  confined to the normal workspace product surface or the current mission's
  evidence subtree.

## Layout

Durable `.unrest/` records:

```text
brief.md
AGENTS.md
MEMORY.md
decisions/<NNN>-<slug>.md
skills/<name>/SKILL.md
missions/<mission-id>/
  contract/<assertion-id>.md
  attempts/<spawn-ts>__<task-id>.md
  regressions/<assertion-id>.md
  terminal-reviews/<spawn-ts>.md
  evidence/
  closeout.md
```

Runtime `.unrest-runtime/` cursors:

```text
project.json
state.json
attention.json
missions/<mission-id>/
  tasks.json
  task-state.json
  contract-state.json
  attempts/<spawn-ts>__<task-id>.json
  terminal-review-config.json
  terminal-reviews/<spawn-ts>.json
```

`project.json` stores project ID, canonical workspace path, creation time,
current mission, and optional Codex work-node model/effort overrides.

## Lifecycle and state

Project state is a strict discriminated union:

- `draft`
- `mission_planning` with a mission ID
- `mission_running` with a mission ID
- `attention_needed` with public `{id, report}` items
- terminal `done`, `failed`, or `aborted`

Internal attention records additionally store kind, mission ID, and optional
task ID. Those fields are stripped from the public envelope.

Mission IDs are `mission-<three-digit-sequence>`. Decision files use the next
numeric Markdown prefix discovered in the durable decision directory. Attempt
filenames retain `<spawn-ts>__<node_id>` for on-disk compatibility; `node_id`
means task ID in current handoffs.

## Attempts and mirrors

Workers write strict `WorkHandoff` or `ValidateHandoff` JSON to the runtime
attempt path. Each current handoff carries the dispatch `attempt_id`; restart
accepts it only when both `node_id` and `attempt_id` match the running task and
its `last_attempt` generation. The store persists a Markdown mirror under the durable mission.
Terminal review follows the same JSON-runtime/Markdown-durable split.

Current attempt-kind reading treats a payload containing `items` or `passed` as
a validation handoff. This is classified `observed_legacy`, not a schema
evolution mechanism. New schema versions must use explicit versioning rather
than expanding this heuristic.

## Workspace discovery shims

At project creation and synchronization:

- `.agents/skills`, `.claude/skills`, and `.codex/skills` expose the aggregate
  project skill bucket;
- an existing real skill directory is preserved and receives only missing
  bucket files;
- a directory containing only byte-identical bootstrap skills may be replaced
  by a symlink to the bucket;
- an existing workspace `AGENTS.md`, whether regular or symlink, is never
  overwritten;
- `AGENTS.md` is symlinked to the bucket only when the workspace has no entry.

Repository-owned guidance must therefore be a tracked regular file before
project initialization; an ignored external symlink is environment state, not
valid repository guidance.

## Failure modes

- Missing project or task-list paths raise `FileNotFoundError`; callers convert
  relevant failures to stable tool errors or terminal state.
- A malformed or provenance-mismatched attempt becomes a bounded failed handoff
  and attention record; it never clears the running task as successful.
- Atomic replacement preserves an existing regular file's mode and removes the
  unique sibling temporary file on write, content-fsync, or replace failure.
  The parent directory is fsynced after replacement as a best-effort durability
  step. If that post-replace sync fails, the call still accepts the already
  visible generation so its outcome agrees with restart-visible bytes.
- A missing ordinary directory below the trusted persistence root is created
  component by component. A symlink or non-directory root, parent, or ancestor
  rejects the write before a target or temporary file is created; direct
  symlink and nonregular targets are likewise rejected.
- Invalid terminal-review roots fail before reviewer dispatch.
- Broken, unsafe, or escaping symlinks in a declared review root are rejected.
- A false or crashed terminal review produces durable evidence and attention;
  it does not write a closeout.

## Change protocol

Persisted shape changes require an explicit schema/version decision,
before/after fixtures, recovery behavior, rollback evidence, and updates to
this document. Do not add heuristic compatibility readers. Preserve durable
records during abort and failure.

## Required verification

```bash
uv run pytest -q tests/test_storage.py tests/test_terminal_review.py \
  tests/test_coordinator.py
```

At a completed implementation slice, also run the milestone checks in the root
`AGENTS.md`; this focused storage check does not consume the single
frozen-candidate full-suite checkpoint.

## Related decisions

ADR-0002 removes installed baseline generation without changing schema-version-1
storage readability.

## Known limitations

Terminal-review root checks are canonical preflight plus prompt policy for a
trusted reviewer; they are not an OS filesystem sandbox. Historical attempt
kind observations are not a normative compatibility oracle.
