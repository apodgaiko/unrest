---
id: ARCH-MCP-001
status: active
applies_to:
  - src/unrest_harness/controller.py
  - src/unrest_harness/server.py
verified_by:
  - tests/test_documentation_contract.py
  - tests/test_server.py
related_decisions: []
schema_version: 1
---

# MCP surface

## Purpose

Define the four structurally isolated MCP server modes, their tools, typed
handoffs, state preconditions, and error payloads.

Experimental reuse/cohort dispatch and native approval recovery are disabled
by default. Genuine native approval, ACP live reuse and final-candidate timing
remain **UNVERIFIED** under the accepted 0.4.6 release risk. Controlled local
MCP tests prove bounded local behavior only; a native acknowledgement means
queued, not executed. See the [release note](../release/lean-core-v0.4.6.md).

## Public contract

`unrest-server` accepts
`--mode orchestrator|worker|validator|terminal-reviewer` and
`--transport stdio|streamable-http|sse`. Each mode constructs a separate
`FastMCP` instance and registers only its role's tools.

Server startup suppresses FastMCP's optional banner and its synchronous version
update check. Configuration and policy validation still precede server
construction; MCP initialization, lifespan and tool processing are unchanged.
This applies to stdio and HTTP transports.

### Orchestrator mode

Orchestrator mode retains the seven v0.3.0 Mission methods byte-for-byte and
adds the 23 methods frozen in
[`public-surface.v1.json`](../v03/v0.3.1/public-surface.v1.json). The additive
methods are `submit_run`, `inspect_run`, `attach_run`, `cancel_run`; Inquiry
open/inspect/advance/pause/resume/cancel/handoff; workspace lease/inspect/
return/integrate/cleanup; and evolution open/inspect/add/evaluate/review/
promote/rollback. Every additive MCP method delegates to the same
`FoundationTools` method as its same-named installed-library callable.

| Tool | Preconditions | Observable result |
| --- | --- | --- |
| `start_project` | Non-empty brief; existing absolute workspace; overrides valid for selected worker provider. | Creates project and `mission-001`; returns `mission_planning`. |
| `submit_plan` | `mission_planning`; contract files already written. | Validates and persists the task list; returns `mission_running`. |
| `advance_project` | Existing project, normally `mission_running`. | Blocks through dispatch steps until attention, terminal, idle, or `max_steps`. |
| `end_mission` | `mission_running`; no runnable work or ready gate. | Runs terminal review; returns `done` or attention. |
| `decide_attention` | `attention_needed`; one decision per open item. | Records decision and returns the next state. |
| `inspect_project` | Existing project. | Pure read with full textual task view. |
| `abort_project` | Existing project and non-empty reason of at most 4096 UTF-8 bytes. | Rejects an oversized reason before terminal writes; otherwise preserves evidence, seals abort where possible, and returns the same bounded `aborted` reason. |

All successful calls return the typed envelope:

```json
{
  "projectId": "…",
  "state": {"state": "…"},
  "projectRoot": "…/.unrest",
  "harnessRoot": "…/<project-id>",
  "dag": "text task view or null"
}
```

Tool failures return:

```json
{
  "error": "stable_code",
  "message": "bounded explanation",
  "details": ["validation_code: detail"]
}
```

The seven legacy methods keep that error shape. Additive methods use the
closed stable envelope `{ "error": {"code": "…", "message": "…"} }` and
the code vocabulary in the frozen public catalog. Provider/source/report/
prompt bodies and secret values or hashes never enter it.

### Worker mode

Worker mode registers only `end_node`. Runtime configuration comes from:

- `UNREST_NODE_TYPE`
- `UNREST_NODE_ID`
- `UNREST_HANDOFF_PATH`

Work calls provide `done`, `report`, and optional `request_attention`.
The tool atomically writes one strict JSON handoff and returns an instruction
to stop. Missing path or task ID is a hard runtime error.

### Validator mode

Validator mode has the server identity `unrest-validator`, accurate
`Mode: validator` instructions, and registers only `end_node`. It shares the
worker mode's strict node-completion implementation and handoff transport, but
does not inherit worker identity, instructions, or authority. Validation calls
provide `done`, `report`, optional `request_attention`, one `items[]` verdict
per assigned target, and aggregate `passed`.

### Terminal-reviewer mode

Terminal-reviewer mode registers only `submit_terminal_review`. It reads
`UNREST_TERMINAL_REVIEW_PATH`, atomically writes `{done, report}`, and instructs
the reviewer to stop. `done=true` is a closure recommendation consumed by the
coordinator; the tool itself does not seal a mission.

## Invariants

- `ARCH-MCP-001`: tool authority is separated by server construction, not
  prompt convention.
- `SEC-MCP-001`: worker, validator, and reviewer modes cannot call orchestrator
  lifecycle tools through their server.
- `ARCH-STATE-001`: durable project mutations delegate directly to the
  controller's single nonblocking OS-lock and recovery boundary; same-project
  mutation contention fails fast with `project_busy`, while different projects
  remain independently admissible. Ordinary direct controller inspection and
  standalone supervision use blocking/default acquisition; MCP and attached
  inspection use the trusted read-only live projection. Controller work
  executes in a thread.
- Durable `submit_run` admission and synchronous Mission methods converge on
  the same per-project OS mutation lock and the same `ProjectController`;
  run custody is not a second Mission authority.
- Ordinary supervision's coordinator owns the monotonic advisory policy clock.
  Its 30-second ticks may advance elapsed time for active or stopping attempts;
  elapsed time never decreases. A published `waiting_at_checkpoint` row keeps
  its elapsed time and other semantic fields unchanged until a new semantic
  checkpoint or bound steering, resume or terminal transition. Policy evaluation continues privately while
  waiting and issues no additional checkpoint requests. Poll writes compare the
  entire observed row under the existing snapshot lock; a concurrent semantic
  publication wins and the poll retries from fresh state on its next tick.
  Read-only project and attached-run inspection both expose stored rows; neither
  samples a clock or refreshes a checkpoint. Waiting and lock-contention
  deadlines, request caps and public wire keys are unchanged.
- `COMPAT-ENVELOPE-001`: envelope field names and strict typed handoff fields
  are compatibility boundaries.

## Failure modes

- Wrong lifecycle state returns `wrong_state`.
- Controller-detected contention returns `project_busy`; lock-path or
  acquisition faults return `project_lock_error`. Recovery begins only after
  successful admission.
- Invalid plans, patches, and decisions return stable top-level errors plus
  stable validation details.
- Invalid worker overrides fail before project creation.
- Missing worker/validator/reviewer environment paths fail instead of inventing
  output.
- Exceptions in production dispatch/review are handled by the runtime as
  persisted failure evidence.

## Change protocol

Adding or changing a tool requires updates to this document, the server
registration tests, installed-wheel help/smoke checks, and the component map.
Do not expose orchestrator tools on worker, validator, or reviewer servers.
Schema incompatibility requires an ADR and explicit version/error behavior.

## Required verification

```bash
uv run pytest -q tests/test_server.py tests/test_models.py \
  tests/test_acp_runner.py
uv build
uv run python tools/check_distribution.py dist
```

The distribution checker must prove complete archive membership and bytes,
safely extract the sdist, and execute all 15 protected
`tests/test_persistence_schema_v1.py` cases from that extracted tree. Its
package module, test module, cwd, and effective `sys.path` provenance must
exclude the checkout. For packaging changes, also install the wheel and run
`unrest-server --help` plus `python -m unrest_harness --help` from an unrelated
directory. These are post-build package checks; the full source suite runs
exactly once at the frozen-candidate release checkpoint and is not repeated
after build.

## Related decisions

No accepted repository ADR currently changes this surface.

## Known limitations

The approved base's provider configuration could implicitly select unrestricted
execution. This document records the MCP shape only; it does not bless that
historical behavior.

### Targetless work completion

The `unrest.v045.node-completion.v1` carrier permits `targets=[]` for work
assigned no contract targets, including measurement work requesting attention.
The carrier must exactly match the assigned target set: targeted work cannot
omit targets or invent substitutes. Validator carriers still require at least
one target. Attempt, task type, scope, return and evidence identity checks,
the single structural-refusal repair allowance, and finalized handoff
immutability remain required. A targetless completion does not validate a
contract or bypass a gate.

Once a node handoff exists, subsequent `end_node` calls return
`{"recorded": false, "code": "completion_finalized"}` without changing its
bytes or consuming a structural-refusal allowance, including after role-server
restart. The first persisted handoff owns the attempt's outcome.

Concurrent role processes serialize completion and refusal handling using a
persistent per-handoff lock inode in the runtime attempt directory. Kernel
ownership is released on process exit; the lock file must not be removed while
callers can exist. Different attempt paths use independent locks. Inside that
boundary, the complete redacted handoff is flushed and fsynced privately, then
published by a no-replace hard link. Only the publisher reports success.
Interruption before publication leaves no accepted carrier; interruption after
publication (including a lost response) leaves the immutable final carrier.
Restarted or malformed late calls cannot consume refusal state after publication.
An interrupted cleanup may leave a private temporary or refusal marker; neither
can override the final carrier. Generic durable writes retain replace semantics.

First-use parent and allowed-root creation tolerates another process creating a
regular directory; each newly encountered entry is checked with `lstat` after
creation or a competing-create error. Symlinks (including dangling links), files,
and invalid roots remain rejected. Refusal initialization and cleanup validate
the same trusted persistence boundary before chmod, enumeration, or unlink.
Under the attempt lock, malformed consumed-quota markers remain present until
their complete private replacement is atomically installed. Process death during
canonicalization cannot grant another warm refusal. These guarantees concern
process interruption, not hardware power loss or hostile concurrent ancestor
replacement.

Candidate desktop validation can use the external
[disposable provenance observer](../../tools/V046_DESKTOP.md). It binds a unique
synthetic `inspect_project` response to the serving process and candidate
without adding public tools or fields. Preparation is inactive; certified
installation and supported client refresh precede actual desktop acceptance.

## Native approval recovery addition

The packaged catalog adds exactly the orchestrator-only mutating
`review_approval(run_id, denial_id)` tool to the existing 31 methods. Its strict
opaque request contains no approval, actor or event. Only actual
request-associated host form elicitation can select one retained native denial.
Default-off `UNREST_APPROVAL_RECOVERY=0|1` enables bounded waiting only for an
admitted asynchronous ordinary attempt. Public run status stays `running`.
Existing schemas and other role catalogs retain their meanings. Blocking and
missing/expired context report unavailable; they never direct a denied-action
rerun. See [native approval recovery](../architecture/approval-recovery.md) for
privacy, settlement, expiry, cancellation, one-use routing and acceptance limits.


## Offline startup

All MCP transports suppress the dependency startup banner. Starting an Unrest
HTTP/SSE server must not query PyPI for FastMCP updates; startup needs only the
selected local interface and its declared provider-independent configuration.
Provider operations remain explicit task execution, separate from server startup.
