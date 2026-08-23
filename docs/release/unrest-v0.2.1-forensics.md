# FM-000 and FM-010 release forensics

Status: factual release input dated 2026-08-23. Counts below were recomputed
from primary project/runtime records; they are not claims copied from prior
attempt reports.

## Method

For each exact project root, task definitions are the entries in
`.unrest-runtime/missions/mission-001/tasks.json`. Attempt reports are direct
regular `.unrest/missions/mission-001/attempts/*.md` files. Each report's
front-matter `node_id` is joined to exactly one task `id` and its `type` in the
runtime task graph; retries remain separate attempts. All three joins are
complete: there are no duplicate task IDs, missing node IDs, unmatched IDs, or
joins to a type other than `work` or `validate`. Decisions are top-level
`.unrest/decisions/*` files. Wall bounds run from `project.json.created_at` to
the filesystem mtime of `state.json`; they describe elapsed project lifetime,
not active CPU or provider time.

| Mission evidence root | Outcome | Task definitions | All attempts | Work attempts | Validator attempts | Decisions | Wall bound |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `/Users/aleksandrpodgaiko/.unrest/projects/20260818T155446Z-fm-000-foundation-authority-and-compatibility-specification-miss` | done; committed proposal groundwork | 206 | 106 | 56 | 50 | 51 | 39.87 h |
| `/Users/aleksandrpodgaiko/.unrest/projects/20260818T155514Z-run-unrest-plugin-unrest-personal-as-one-complete-separate-missi` | aborted FM-010 research | 61 | 38 | 14 | 24 | 24 | 10.47 h |
| `/Users/aleksandrpodgaiko/.unrest/projects/20260819T100227Z-r2-prerequisite-unrest-hardening-mission-after-preserving-and-ab` | aborted custody/hardening detour | 468 | 214 | 111 | 103 | 66 | 99.87 h |

In prose: FM-000 used 206 task definitions and 106 attempt reports; original
FM-010 used 61 task definitions and 38 attempt reports; R2 used 468 task
definitions and 214 attempt reports. Each attempt-report total includes work and
validation reports. In particular, 106 and 214 are top-level attempt-report
totals containing both work and validation reports; neither number is a
validator-only count. The earlier `validator reports` label conflated the total
population with one task type. The attributable validator-only populations are
50, 24, and 103 respectively; their work populations are 56, 14, and 111.

## Findings

FM-000 produced commit `2b17a613b99ef182c9bae18b8171efc17e8fe8d2` and a
successful result manifest. Its ADRs remain proposed; it did not implement or
accept v0.3 runtime behavior. FM-000 also rebound five v0.2 release carriers to
its then-current tree. v0.2.1 restores those five files byte-for-byte from tag
`v0.2.0` and gives the live candidate distinct carriers.

Original FM-010 has no canonical handoff or commit. Its checkout remains at
`96d5c0f0b240bd3373809546d7aecc1e407f837b` with untracked research paths; the
nominal `FM-010` handoff directory exists but contains no files. It is untrusted
research, supplies no accepted baseline or release evidence, and its proposed
v0.3 measurement behavior is not implemented here.

The operationally useful finding was narrower. After an MCP client timeout, a
fresh Unrest server could overlap a still-running server against the same
project. That duplicate-server incident admitted overlapping ACP dispatch and
made a live attempt appear missing to the newer controller. v0.2.1 keeps the
per-project OS lock through the controller worker's true lifetime even when the
public await is cancelled; it does not add a custody or reconnect protocol.

The attempted recovery became a runaway repair topology: 468 task definitions,
214 work-and-validation attempt reports, 66 decisions, nearly 100 hours of wall
life, and a large dirty custody implementation without a canonical handoff or
commit. None of its custody chain, telemetry, capability-policy, or
general-thinker behavior is accepted or implemented in v0.2.1. The measured
lesson is to cap repair topology and stop after repeated contract/validator
failure instead of treating more nodes as more confidence.
