# Governed S1: admitted criteria delivery

Governed S1 lets an orchestrator admit a mission's contract criteria once and
have every work and validation prompt of that mission rendered from the admitted
bytes instead of the mutable authoring files. It also records, per dispatched
attempt, an owner-observed execution scope and a transport witness of each
governed `session/prompt` write. Identity ownership that makes "a fresh
mission" checkable is accepted by
[ADR-0507](../decisions/ADR-0507-governed-identity-ownership.md).

S1 is opt-in per mission. A mission that never calls `submit_governed_plan`
behaves exactly as before; the only added cost is an absence probe of at most
three `lstat` calls per step. S1 makes no claim about model consumption,
assessment, terminal review, older binaries, same-UID tampering, power loss or
foreign writers.

The implementation lives in `governed_records` (record grammar, strict JSON,
write-once publication, classification, capture, identity, scope and witness
records) and `governed_admission` (the three lifecycle operations, the dispatch
gate and the inspector). Neither module imports `continuation_*`,
`run_control` or `supervision`.

## Lifecycle tools

Three orchestrator lifecycle tools are added next to the seven Mission tools.
They are tool-local: their codes are not foundation catalog errors and neither
public catalog changes.

| Tool | Effect |
| --- | --- |
| `submit_governed_plan(project_id, mission_id, task_list, governed)` | Synchronous admission of the current planning mission; returns a `governed_admission` receipt, not an envelope. The same idempotency key and task list replay the receipt without writes. |
| `abandon_governance(project_id, mission_id, governed_abandon)` | Writes one `abandoned.json`; the mission continues under the legacy renderer. Deletes nothing; refuses while an execution scope is open. |
| `inspect_governed(project_id, mission_id, section, cursor)` | Lock-free read of `summary`, or a page of `criteria` (64), `task_gate` (256) or `executions` (8). Pages are not a snapshot; output is at most 512 KiB and is refused, never truncated. |

Admission and abandonment take the existing project mutation lock without
blocking (`project_busy`, `project_lock_error`); a missing or non-regular
`project.json` is `not_found` with no write. Inspection takes no lock, runs no
recovery and writes nothing.

Through RunControl, the private codes are projected by the unchanged
`runtime_executor._payload` to the public `invalid_argument`; the private code
stays in `private_tool_error`.

## Layout

```text
<bucket>/.unrest/identity/{init.json, ready.json, missions/mission-NNN.json|.consumed}
<bucket>/.unrest/missions/<mid>/governed/
  admission/<A>/{criteria/<aid>.v1.md, manifest.json, post-images/*, intent.json, commit.json}
  executions/<attempt>/{opened.json, outcome.json, closed.json, submissions/<W>/<stage>.json}
  abandoned.json
```

Every governed record is canonical JSON (sorted keys, ASCII, compact, one
trailing newline), parsed strictly (no duplicate keys, floats or non-finite
constants; bytes must equal the canonical re-encoding; closed field sets).
Publication is write-once: a `.tmp-<hex32>` file is written and fsynced, then
hard-linked to its final name; an existing equal file is reused, an unequal one
is `artifact_identity_conflict`. Governed paths are never replaced or renamed.
Every record passes an identity-redaction guard against the protected
inventory before publication.

Write paths require `GOVERNED_FS_CAPABLE`: the `dir_fd`, `follow_symlinks` and
`fd` support listed in `governed_records._compute_capability`. Without it an
existing governed tree classifies `UNAVAILABLE/platform_unsupported` and new
admission refuses `governed_platform_unsupported`; the absence probe does not
depend on it. The predicate proves API presence, not filesystem behavior.

## Admission

`submit_governed_plan` validates the request, takes the lock, checks identity
(the project must be `ELIGIBLE` with an unconsumed reservation for the mission),
classifies, then captures each `contract/<id>.md` candidate through exactly one
file descriptor. Captured bytes are canonicalized (CRLF to LF, trailing
whitespace stripped, one final LF); BOM, NUL, lone CR and invalid UTF-8 refuse
`criterion_invalid_encoding`, empty `criterion_empty`, and 65 536 bytes or more
`criterion_too_large`. The candidate set is the `parse_contract_dir` set with
the same detail strings; non-regular candidates and more than 256 criteria are
declared stricter refusals. A redactable criterion refuses without echoing it.

A freshness shape screen (`governed_mission_not_fresh`) then requires no
runtime mission directory, only `contract/`, `governed/` or residue under the
mission directory, and `project.json` naming this mission as current. Success
of the screen is not a history claim.

The task list, task state, contract state and state buffers are built once and
are byte-identical to legacy `submit_plan` output (contract-state compares as
JSON). Publication order is: staging members, `intent.json`, the four product
files (tasks, task-state, contract-state, state) with readback, then
`commit.json`. No envelope is built.

Replay classifies the admission family only (`classify(..., admission_only=True)`),
which never opens, stats or scans `governed/executions`. Replay with the same key and an
equal manifest identity returns the receipt with `replayed=true`; a different
list is `admission_retry_mismatch`, a different key `governed_already_admitted`,
an ambiguous family `governed_admission_unresolved`, an abandoned one
`governed_abandoned`. At most 16 admission directories may exist; the
seventeenth attempt refuses `governed_limit_exceeded` before `mkdir`.

Legacy `submit_plan` refuses `governed_admission_present` for an orphan,
ambiguous or committed admission and `governed_admission_unresolved` for an
unclassifiable tree. Absence, empty residue and a valid abandonment keep the
baseline behavior.

## Classification and dispatch gate

`classify(store, project_id, mid)` returns an admission status (`NONE`,
`AMBIGUOUS`, `COMMITTED`, `ABANDONED`, `UNAVAILABLE`) with a closed reason, and
an executions status (`absent`, `ok`, `unavailable`). A staging directory without
`intent.json` is `NONE/orphan_staging_present` only while `state.json` is
`mission_planning` for that mission; otherwise it is `AMBIGUOUS`. Every
committed criterion is re-read once per step and checked against its manifest
digest; the bytes read are the buffers used for rendering, and nothing is
cached between steps. One health pass reads at most 85 283 078 bytes of file
content. The bound covers file content only: directory enumeration, entry
counts, metadata and system calls are not bounded, and it is not a latency or
memory bound.

`MissionCoordinator._step_mission(mid)` classifies first, before loading the
task list or any reconciliation, and uses that `mid` for every later read,
binding, gate evaluation and write.

| Classification | Step |
| --- | --- |
| `NONE` | legacy dispatch (`LegacyNoAdmission`) |
| `ABANDONED`, executions usable | legacy dispatch (`LegacyAfterAbandon`) |
| `COMMITTED`, executions usable | `GovernedBound` per request, or idle as below |
| `AMBIGUOUS` | idle `governed_admission_unresolved` |
| `UNAVAILABLE/platform_unsupported` | idle `governed_platform_unsupported` |
| other `UNAVAILABLE`, executions unavailable | idle `governed_content_unavailable` |

A committed mission is delivered only on the controller routes
(`governed_delivery_route=True`) and only to a dispatcher declaring
`supports_governed_delivery`; otherwise the step idles
`governed_route_unsupported` or `governed_dispatcher_unsupported`. The CLI
project adapter keeps the default route and therefore never delivers a
committed mission. A selected task whose target was not admitted (for example
added by a patch) idles the whole selection `governed_content_unavailable`.
`DispatchRequest.governance`, `run_node(governance=)` and the coordinator
dispatch helpers have no default.

## Execution scopes and witnesses

For each governed attempt the coordinator opens `executions/<attempt>` before
the task state is saved (single dispatch, validation batch and isolated batch),
refusing the whole set `governed_witness_unavailable` before any `mkdir` when
4096 scopes would be exceeded. On an isolated batch every lease is cancelled
and cleaned up with no serial fallback. The owner closes every opened scope in
`finally`: `outcome.json` only when the owner observed the dispatch result
(`completed`, `failed`, `synthetic`, `cancelled`), then `closed.json`
(`owner_joined` when the role effect started, else `not_launched`).

A failure or crash after `mkdir executions/<attempt>` and before `opened.json`
(an I/O error or a redaction conflict while publishing it, or process death)
is permanent and fail-closed: every later step idles
`governed_content_unavailable`, `abandon_governance` refuses
`governed_content_unavailable`, and only `abort_project` remains. No recovery,
retry or repair is provided; hand edits are outside the proof.

`ACPClient.send_prepared` is used for both governed `session/prompt` calls
(initial and continuation). It registers at most four witnesses per scope,
publishes `prepared` before the first byte, writes the same bytes legacy
`_write` would, and records `not_submitted`, `write_completed`, `write_error`,
`response` or `local_failure` synchronously in the event-loop thread. A failed
stage publication never replaces the original exception. Witness sets are
classified by an ordered rule: stages without `prepared`, then conflicting
stages, then a ten-set table (`unknown`, `not_submitted`, `response_observed`,
`transport_write_completed`). A witness is never evidence of model
consumption. Unlike legacy `send_request`, `send_prepared` checks
`stdin.is_closing()` before writing and records `not_submitted`; this is a
governed-only divergence, not a legacy-equivalence claim.

## Identity

`start_project` claims the bucket with an exclusive `mkdir` before any other
effect (`project_id_collision`), then — on capable hosts — writes
`identity/init.json`, reserves `mission-001`, creates the project and publishes
`identity/ready.json`. A crash leaves an incomplete bucket that nothing cleans
up or retries. An exception after the project record is published (for
example while publishing `ready.json`) does not mean that no project was
created: a direct caller sees the original exception, and the RunControl
executor does not project a non-`ToolError` exception into a public error. A
blind retry creates a different project; creation is not idempotent. Projects
created without this sequence (including every project created on an
unsupported host) remain `LEGACY`; nothing retrofits identity later. A failure
after `identity/` exists classifies `IDENTITY_UNAVAILABLE`, never `LEGACY`.

`classify_identity` is four-way: `LEGACY` only when `lstat` of `identity` is
`ENOENT`; `INITIALIZING` without `ready.json`; `ELIGIBLE` with a valid complete
footprint; `IDENTITY_UNAVAILABLE` otherwise (including more than 4096
reservations). Next-mission allocation happens once per decision batch: legacy
projects keep the count allocator; initializing and eligible projects reserve
`1 + max(index)` (gaps allowed, reuse never); unavailable identity refuses
`mission_identity_unavailable`, an existing name `mission_id_reserved`, and 4096
existing reservations `mission_identity_capacity_exhausted`, each before any
decision effect. The 4096 limit counts reservations including orphans: a
decision batch rejected after its reservation (for example an invalid patch)
still consumes it; reservations are never rolled back or reused.

Legacy `submit_plan` runs, inside the existing project lock:

1. the governed refusal for the mission's admission state;
2. the identity gate: `LEGACY` skips steps 3 and 4 and runs step 5;
   any `IDENTITY_UNAVAILABLE` (unsupported host with identity, unreadable,
   corrupt or over-capacity footprint, an unknown I/O outcome) and
   `INITIALIZING`/`ELIGIBLE` without a reservation of the mission refuse
   `mission_identity_unavailable`;
3. read-only contract and task-list validation, with no directory creation:
   `stat` of `contract/` failing `ENOENT` (including a dangling `contract`
   link) validates an empty contract (`invalid_task_list` /
   `empty_contract`); a directory, following links as the baseline does, is
   parsed and validated with the baseline codes and details; an existing
   non-directory refuses `invalid_contract_dir` whose `contract_dir_missing`
   detail is the logical `contract/`; any other `stat` error propagates as
   raised;
4. option R: create-or-verify `identity/missions/mission-NNN.consumed`
   (exclusive `link`, equal bytes replay). Any failure or unknown outcome
   refuses `mission_identity_unavailable`; a marker that reached the disk stays;
5. the baseline `ensure_contract_dir`, parse, validation and writes.

R is reachable only after `stat` observed a directory and the read-only parse
and validation passed (an empty contract always refuses); nothing claims the
contract is unchanged until step 5, and any later refusal or failure keeps R
(the mission is consumed).
Validation refusals before R create neither R nor directories. R makes later
governed admission of that mission refuse `governed_identity_unavailable`, also
after a lost runtime directory or a stale `mission_planning` state, and in
either order of R and `ready.json`. Earlier lock-time recovery of the project
is outside this no-effects statement.

Declared differences from the baseline submit (no mkdir before R): a missing
contract is `empty_contract` even where the baseline `mkdir` would have failed
(`EACCES`, `EROFS`, `ENOSPC`); a non-directory `contract` is
`invalid_contract_dir` instead of `FileExistsError`; a dangling `contract` link
is `empty_contract` instead of `FileExistsError`; scan errors hidden by the
existing parser stay hidden. Raw `stat` exceptions keep their paths; no broad
privacy guarantee is made. Link following is preserved only for `contract/`
under a regular, accessible `missions/<mid>`; it is a property of step 3, not of
the whole submit. The rules of step 3 apply only when step 3 is reached.

Limited compatibility change from the pre-governed baseline, for both `LEGACY`
and identity cohorts: the no-follow governed classification refuses a
non-regular `missions` or `missions/<mid>` (link, dangling link, non-directory,
no search permission) before steps 2-5 run, so no marker, contract directory or
submit write is produced, also not inside a link target. Legacy submit refuses
`governed_admission_unresolved`; legacy dispatch of such a mission idles (see
the dispatch gate table). Link following does not apply to `missions` or
`<mid>`; the trusted `.unrest` anchor and its ancestors are handled separately,
and the end-to-end outcome for a dangling `.unrest` anchor is not established.
Legacy compatibility therefore holds only while `missions` and `<mid>` are
absent or real, accessible directories.

| `missions/<mid>` | Pre-governed baseline submit | Governed S1 submit, every cohort |
| --- | --- | --- |
| link to a directory | proceeds through the link (may create `contract/` in the target) | `governed_admission_unresolved` |
| dangling link | `FileExistsError` | `governed_admission_unresolved` |
| regular file | `NotADirectoryError` | `governed_admission_unresolved` |
| directory without search permission | `PermissionError` (observed at euid 501 on one host) | `governed_admission_unresolved` |

A `missions` link or regular file is refused the same way. No repair is
provided; such a mission stays non-submittable and non-dispatchable until the
tree is fixed outside the product.

## Codes

Admission, abandon and inspect: `governed_request_invalid`,
`governed_already_admitted`, `admission_retry_mismatch`,
`governed_admission_unresolved`, `governed_content_unavailable`,
`governed_abandoned`, `governed_already_abandoned`, `governed_not_present`,
`governed_admission_present`, `governed_scope_open`,
`criterion_invalid_encoding`, `criterion_empty`, `criterion_non_regular`,
`criterion_too_large`, `criteria_set_too_large`,
`criterion_contains_redactable`, `governed_limit_exceeded`,
`artifact_identity_conflict`, `governed_metadata_redaction_conflict`,
`governed_platform_unsupported`, `governed_io_unavailable`,
`governed_output_unavailable`, `governed_mission_not_fresh`,
`governed_identity_unavailable`.

Identity (`start_project`, `decide_attention`): `project_id_collision`,
`mission_id_reserved`, `mission_identity_unavailable`,
`mission_identity_capacity_exhausted`.

Step idle details: `governed_admission_unresolved`,
`governed_content_unavailable`, `governed_dispatcher_unsupported`,
`governed_route_unsupported`, `governed_witness_unavailable`,
`governed_platform_unsupported`. Runner errors: `governed_render_refused`,
`governed_witness_unavailable`.

## Known limitations

- Protection covers local process crashes and the participating writers only.
  Deleting the whole `identity/` directory makes a project `LEGACY`; deleting
  or editing governed records by hand is not detected in general, and no
  identity repair exists.
- A file changed between classification and an inspector stage read is not
  reported as `concurrent_change`.
- `assessment`, terminal review and RunControl worker delivery of governed
  missions are not covered; terminal review still reads authoring files.
- Target filesystem behavior of `link`, `dir_fd` and `O_NOFOLLOW` operations is
  only observed on the development host.

## Required verification

```bash
python -m pytest -q -p tests.governed_no_launch tests/test_governed_s1_*.py
```
