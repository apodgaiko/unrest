# Provider review denial capture

Ordinary Codex worker and validator attempts latch explicit Guardian denials from
their bound managed ACP transport. This is the first denial-reporting slice;
native human appeal is default off. The bounded opt-in asynchronous path is
defined in [native approval recovery](approval-recovery.md); genuine host/provider
evidence remains required before approval recovery can be accepted. Recorded prose consent, a planning decision, and a review-shaped
tool result are never provider authorization. Capability and sandbox policy are
unchanged. Experimental retained-session and terminal-review routes are not
admitted as supported native appeal routes by this implementation.

## Transport and completion

The parser follows Codex 0.160.1 generated
`ItemGuardianApprovalReviewStartedNotification` and
`ItemGuardianApprovalReviewCompletedNotification`, and codex-acp 1.1.0's
`createGuardianApprovalReviewToolCall` and `createGuardianApprovalReviewToolCallUpdate`:

- Creation uses `kind=think`, `title=Guardian Review`, the
  `guardian_assessment:<reviewId>` tool-call ID and direct `rawInput`.
- Updates use the same registered tool-call identity and direct `rawOutput`.
- A completed review without a prior start is a creation with the completed
  payload in `rawInput`.
- Ordinary MCP completion uses `{result, error}` in `rawOutput`. The capture
  never traverses this wrapper, arbitrary tool output, or agent prose.

Envelope recognition precedes identity validation: a Guardian creation with
the exact title/kind remains recognizable when its call ID is missing, nonstring
or wrongly prefixed. A prefixed creation carrying the direct provider fields
also remains recognizable if its title/kind is malformed. Unregistered updates
carrying the direct provider envelope are invalid, including missing/nonstring
IDs; they cannot establish a review without a start. MCP's
`{server, tool, arguments}` input and `{result, error}` output wrappers are
excluded when no conflicting direct managed signature is present. Exact
Guardian title/kind or direct review fields override a contradictory wrapper.

Recognition runs before JSON-RPC response correlation. Only the fixed frame,
params and update positions are examined; result bodies, wrapper contents and
prose are never searched recursively. Recognizable misplaced envelopes or
missing/wrong RPC version, method or session-update discriminator block as
invalid context. Presence of any RPC `id`, `result` or `error` invalidates a
managed notification, including null or structured IDs and pending-ID collisions.
A recognized blocked frame never resolves a pending future or schedules an
ordinary callback. Inner payload, identity and discriminator validation still
runs for correctly framed notifications.

The reader accepts newline-delimited objects and lists of objects, processing
list entries in order. Already-read review frames are captured synchronously,
including after a prompt response in the same list/read drain and before EOF.
This does not promise detection of frames a provider sends after the owned
transport has already closed. The first block remains authoritative; publication
failure remains bounded and cannot authorize a later success.

Session identity must match the created ACP session and supplied provider thread.
Turn and review identities must remain consistent. At most 64 reviews and 128
ASCII characters per provider identifier are accepted for one prompt. Unknown,
malformed, conflicting or oversized authorization context blocks with an
unavailable/invalid outcome; it does not count as an explicit denial or approval.
Approved, pending, timed-out and aborted reviews remain distinct from denial.
An approved event cannot clear an earlier denial.

Capture runs synchronously in wire order before progress observers, whose errors
are intentionally swallowed. The typed blocked result interrupts the pending
prompt and refuses subsequent managed capability callbacks. Owned process cleanup
still runs. The result overrides a passing or missing worker handoff, including
restart reads and validator evidence consumption. It does not claim detection of
arbitrary semantically equivalent commands or confinement of native background
processes.

## Storage and restart

`ProjectStore` writes a bounded internal `unrest.provider-review-block.v1` record
under `.unrest/missions/<mission>/provider-reviews/`. It associates only provider,
project, mission, node, attempt, session, supplied thread/turn/review identities
and a fixed outcome. No command, prompt, source body, credentials, rationale,
provider transcript, action digest or approval marker is persisted in this record.
Within a running capture, ephemeral digests detect contradictory duplicate events.

A non-resumable cursor under `.unrest-runtime/missions/<mission>/provider-reviews/`
is written before prompting. Successful nonblocked completion removes it; blocked
attempts retain it as an integrity reference, never a resumable process handle.
A missing durable record with a retained cursor means interrupted/unavailable,
not permission to retry. Corrupt, oversized or mismatched records also block.
Persistence failure retains the in-memory blocked result and the preexisting
cursor. Complete loss of both storage trees is not recoverable provenance.

## Operator workflow

`inspect_project` shows a fixed provider-review-blocked explanation and the
existing mission/node/attempt reference. The private attempt report explains that
prose consent is not an override and native recovery is unavailable. Reinspection
and restart do not ask for the same consent again. Existing public models, role
MCP catalogs and error-code vocabulary are unchanged.

The existing text `frontier` retains the bounded node/attempt/outcome and fixed
explanation after an independent repair patch, including repeated restarted MCP
inspection. Runnable independent tasks still receive `advance_project` advice.
When the retained block prevents otherwise-ready closure, advice is `none`, never
the impossible `end_mission`. Inspection does not create new attention or change
task state, and an active pre-prompt cursor alone is not displayed as a denial.

Generic continue/retry and steering cannot release this block. A planning patch
may append independent repair work; it cannot cancel, supersede or reset the
blocked node. The original denial and failed verdict remain, and mission closure
refuses while that block remains. Abort retains its ordinary meaning. This is not
a native appeal picker, an approval RPC, or permission for one retry.

Ordinary `advance_project(project_id, max_steps)` validates the complete retained
provider-review inventory under the existing project mutation owner before
workspace skill synchronization, running-attempt recovery, gates, readiness
selection or fresh allocation. Only after the entire inventory validates, a
validated originating block on a stale `pending` node restores its status to
`failed`; `last_attempt`, dependencies and attempt/block/report/cursor bytes
remain unchanged. Independent ready work can dispatch, while descendants of the
failed node remain blocked. Repeating advance or restarting is idempotent. Both
additive patch paths retain the failed node. Single, validation-batch and isolated
work-batch boundaries recheck eligibility before allocation and retained blocks
before invoking the dispatcher.

Malformed, missing-counterpart, mismatched or conflicting carriers refuse before
reconciliation or launch. A synthetic unavailable-reader result is never a
validated origin authorizing a state rewrite. A newer `last_attempt` cannot hide
an older block: a generation conflict refuses. Completed native continuation
receipts retain their existing completion meaning but cannot authorize a fresh
dispatch of the originating node. Running-attempt recovery remains compatible
with a not-yet-written handoff or Markdown mirror; stale pending reconciliation
requires the typed originating handoff.

For a previously reset node, use read-only `inspect_project`, verify the installed
runtime and exact retained origin, then use ordinary `advance_project`; no task
selector or manual cursor edit is needed. A new repair installation must be a
separate wheel environment with its interpreter, module bytes, configuration,
provider command and live `tools/list` response bound to that artifact. Test this
sequence in an unrelated working directory with controlled providers before any
separately authorized original operation. Never replace a running editable server
and assume it has loaded the new bytes. Controlled fixtures prove local guard
behavior, not genuine provider acceptance or historical serving provenance.

The bounded records retain identities and outcomes, not action bodies or rationale.
Their absence here does not establish absence in every provider retention tier.
Missing invocation telemetry is not a continuous launch ledger; it is written
after a prompt returns. Historical evidence gaps remain separate from this guard.

The opt-in native recovery implementation retains this original denial and
records a separate bound disposition; ordinary continue/retry/steering still
cannot clear it. Actual human participation and live reviewer acceptance remain
mandatory separate evidence. Controlled local protocol tests establish local
capture and lifecycle behavior only; no external reviewer decision is claimed.

## Ordinary transport failure and owned cleanup

Ordinary worker, validator and terminal-review MCP readiness checks bind the
owned child to the TCP readiness stage. Startup failures distinguish observed
child exit from deadline exhaustion; attribution contains only the fixed stage
and reason, numeric PID and exit status captured before cleanup. A cleanup
termination status is not an observed startup exit. Startup diagnostics omit
argv, stream bodies, prompts and credentials. TCP readiness alone does not prove
MCP initialization or provider readiness. The existing 15-second readiness
budget and targetless completion semantics remain unchanged. Startup failure or
cancellation drains the owned child and stream readers; cleanup errors do not
replace the primary exception or cancellation. Original failed observations
remain evidence even when a later isolated check passes.

Malformed JSON (including parser recursion failure) and response IDs with invalid
JSON-RPC types stop the ordinary reader with a fixed, body-free diagnostic.
Numeric response IDs retain ordinary correlation, including JSON `1.0` for
request `1`; string and null IDs remain unmatched. Containers and booleans are
invalid IDs and cannot alias request IDs.
Unparseable input supplies no trustworthy denial identity. The existing capture
records invalid context without inventing review details, or retains the
interrupted cursor when transport fails before capture is established.

Worker, validator and terminal-review finalization drain every owned cleanup
step even when progress flushing, reader settlement or client cleanup fails.
A retained asynchronous owner finishes cleanup under repeated caller cancellation;
the primary failure or cancellation survives subsequent cleanup errors. Terminal
children, pending requests, agent streams/process and MCP streams/process are
all finalized, using the existing bounded process waits. A transport failure
cannot be erased by a previously written passing handoff or terminal review.
Request producers settle before the final terminal inventory is captured and
drained; settlement failure does not skip that drain. Terminal-review progress
observer exceptions retain their warning-only behavior with credential redaction,
so a successfully saved review remains usable. Observer cancellation and actual
transport or ownership failures still fail the review and drain owned resources.
These local lifecycle guarantees neither retry a refused request nor satisfy
independent approval or release gates.
