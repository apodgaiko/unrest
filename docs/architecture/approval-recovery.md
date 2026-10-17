# Native human approval recovery

Native recovery is default off. `UNREST_APPROVAL_RECOVERY` accepts exactly `0`
(default) or `1`; other values refuse startup. The flag retains an observed
provider denial for review. It grants no approval or execution authority.
Genuine native denial, human form/response, originating-context operation
acceptance and continuation remain **UNVERIFIED** under the accepted release
risk. Controlled local forms and callbacks prove only bounded local behavior.
Genuine ACP reuse and final-candidate timing are also **UNVERIFIED**.
Only an admitted asynchronous `advance_project` RunControl worker can enable
retention. Public run status stays `running`; the pending phase is internal.
Blocking `advance_project`, terminal review, experimental reuse and other
providers keep safe unavailable recovery. Never automatically rerun a denied
or content-filtered action to get an approval-capable context.

## Supported context and transport

The ordinary Codex rust-v0.160.1 backend, the exact desktop
rust-v0.162.0-alpha.17.2 backend described below, and unmodified codex-acp 1.1.0 adapter
are pinned by complete executable/bundle hashes in `approval_recovery.py`.
Unknown pins and unsupported launch layouts refuse before prompting. The
opt-in asynchronous configuration boundary preserves the existing role-policy
allowlisted provider launch environment, including the original backend and
configuration selection. Each agent still applies its existing role policy.
Default-off asynchronous launches retain their original environment behavior.
No host/global adapter, provider configuration, permissions or launcher is edited.

A private per-attempt relay is selected at initial launch. It starts the original
backend with the adapter's original argv and effective environment; only the
relay selection is restored to the original `CODEX_PATH` for that backend.
It owns this backend stream from creation, rather than substituting another
route after denial. All adapter request IDs are remapped into an owned namespace;
native responses are consumed privately and cannot resolve adapter requests.
Server-initiated requests remain separately correlated. Frames, inflight maps,
control messages and write backpressure are bounded. Malformed JSON, duplicate
keys, foreign context, unknown replies, collisions or multiple denials refuse.
Raw native events and provider stderr are never written by the relay.

Only the owned backend reader can establish the event. It binds observed
thread/turn startup, review start and terminal denial, immutable action/context,
and original backend process identities. ACP Guardian notifications provide a
second matching latch; caller-provided tool data or event-shaped prose cannot
create an appeal. The original native API trusts client event JSON and does not
authenticate past denial or consume a replay nonce. Unrest therefore owns these
checks. This is a trusted-process boundary, not a claim of OS isolation.

## Settlement, selection and privacy

The owner cancels the active ACP session turn through `session/cancel`, waits
for the prompt response and matching native `turn/completed`, and settles owned
ACP callbacks with transport readers still live. The relay also refuses native
submission with any unresolved adapter request or backend callback. Failed/delayed settlement,
committed `end_node`, cancellation and owner loss make recovery unavailable.
The denial remains authoritative over a passing handoff.

The first captured denial establishes one fixed monotonic retention cutoff:
300 seconds, capped by an already-applicable deadline. Ordinary attempts have
no otherwise-established general deadline. Review, submission and continuation
must fit that original cutoff; no phase resets it. Expiry erases captured memory
and closes the owned transport. An expired/lost context cannot be revived from
runtime cursors or durable records.

Read-only project inspection uses its existing bounded `frontier` text to name
`run_id` and `denial_id` for a pending selection. That reference is advisory:
availability is rechecked by the owner and host. It contains no action data.
The orchestrator-only mutating `review_approval` tool accepts exactly these two
opaque IDs. No boolean approval, actor, event JSON, replacement action or generic
native RPC is accepted. The existing 31 tool schemas, other role catalogs,
public run enum, tasks, handoffs and attention schemas are unchanged. Frozen
v0.3.1 catalog files remain historical; the packaged catalog is authoritative
for this sole additive v0.4.6 tool and its strict request/result definitions.

The actual request-associated `Context.elicit` form displays exact bounded JSON
for the captured action and thread/turn/review/context identities. The human
must affirm `confirm_one_submission=true`. Decline, cancel, absent form
capability, wrong IDs, timeout, disconnect or malformed response submits nothing.
A concurrent duplicate cannot open another form or consume the selection twice.
Workers and validators have no access to this tool. Continue/retry/steering and
inspection remain non-authoritative.

Command and execve actions with local absolute cwd are supported. Missing patch
contents, MCP arguments, process-input provenance or unsupported conversion
make other action variants unavailable; there is no guessed reconstruction.
Oversized, credential-bearing, misleading bidi/control or otherwise unsafe
presentation refuses rather than redacting an ambiguous action. Known finite
credentials and common secret representations are checked independently of the
finite credential inventory. Display admission uses a bounded static grammar,
not a list of credential flags for arbitrary tools. The supported programs are
`printf`, `echo`, `cat`, `ls`, `pwd`, `true`, `false` and a limited `curl` grammar.
`printf` takes a literal format and values (an option-like format requires `--`);
`true` and `false` take no arguments. Supported no-argument short switches are
`echo: neE`, `cat: bnsvETu`, `ls: alhRtdrS1`, `pwd: LP` and `curl: sSfLI`.
Clusters are parsed character by character; any unknown switch refuses.
Supported long switches are `cat: --number, --show-all`,
`ls: --all, --human-readable` and
`curl: --silent, --show-error, --fail, --location, --head`.
An explicit `--` ends option parsing. Curl operands must be static HTTP(S) URLs
without userinfo, query or fragment; argument-taking switches, headers,
configuration files and authentication options are unsupported.

Shell words are inspected after quote removal and concatenation. Simple commands
may be joined by `|`, `&&`, `||` or `;`. Only leading `LANG`/`LC_ALL` assignments
with `C`, `POSIX`, `C.UTF-8` or `en_US.UTF-8` values are supported. Other inline
assignments, wrappers (`env`, shells, interpreters), arbitrary tools and unknown
options refuse, including sshpass, OpenSSL, database and authentication CLIs whose
credential conventions are outside this grammar. Credential names, URI userinfo
and passphrase-source prefixes (`pass:`, `env:`, `file:`, `fd:`, `stdin:`) refuse
independently of the supported tool. Short credential options cannot hide inside
clusters or attached/separate values. Expansion, substitution, redirection,
heredocs, comments, multiline commands and malformed quoting are unsupported.

Execve requires an argv[0] naming the captured program and uses the same program
grammar; shell wrappers refuse. Literal arguments retain their exact boundaries
and punctuation in the human JSON. Admission never reconstructs, evaluates or
redacts an action. This grammar interprets syntax only: it cannot prove arbitrary
unlabelled opaque literals are not credentials, inspect referenced file contents,
or authenticate an executable's semantics from its name. Known finite credential
values still refuse everywhere in the captured display. Unsupported syntax refuses
rather than inviting uninformed review.
Exact review data appears only in the host form
and private memory/control transport, never routine tool results or evidence.
Rationale, prompts and transcripts are omitted from the display.

## One submission and one continuation

After an accepted form response, the original owner rechecks cancellation,
cutoff, unused state, live backend/relay binding and committed completion. It
holds the same stable nonblocking completion carrier as `end_node` around the
final check and native submission; bounded contention refuses without blocking
transport readers. Selection is consumed before any native write.

The relay exposes only `thread/approveGuardianDeniedAction`, using the original
captured event converted by the pinned source mapping. ACK means queued native
operation, not completed injection or successful action execution. The owner
requests at most one ACP continuation in the same originating thread. The
relay excludes replacement threads, steering and a second continuation. FIFO
ordering, exclusive quiescence and the acknowledged queue insertion place that
continuation after the override handler. There is no sleep, synthetic marker or
additional provider polling barrier used as an injection proof.

Timeout, disconnect, cancellation, late/ambiguous response, re-denial or loss
remains blocked/uncertain, with zero automatic resubmissions. Durable records
retain the original body-free denial and safe bound appeal dispositions. A
`completed` disposition means the continuation settled and transport cleanup
passed; it neither proves the action ran nor grants replay authority. Crash
before this disposition leaves the original block authoritative. Cleanup closes
control/listener/adapter/MCP resources and waits for the owned relay/backend
processes, with bounded termination escalation and retained first failures.
The opt-in worker HTTP MCP process watches its actual parent identity and exits
on owner loss; default-off launches retain their existing entry point. The relay
removes its two fixed private carriers on control EOF. Safe stale runtime
selection references can survive abrupt death but cannot revive missing memory
or a removed socket, and never authorize a retry.

## Source-bound protocol mapping

The mapping follows rust-v0.160.1 `tui/src/chatwidget/protocol_requests.rs:70-165`
and `protocol/src/approvals.rs:131-257`: camelCase notification review fields map
to snake_case `GuardianAssessmentEvent`; `reviewId` becomes `id`, `turnId`
becomes `turn_id`, terminal timing/status/decision/risk/authorization/rationale
are preserved, absent optional fields are omitted, and command source
`unifiedExec` becomes `unified_exec`. The TUI mapping deliberately omits
`target_item_id`, plugin and model-context fields. The allowlisted captured action
is copied, never replaced by MCP arguments.

`app-server/src/request_processors/thread_processor.rs:2503-2521` deserializes
this event and queues the core operation. `core/src/session/mod.rs:962-1020`
queues both override and next-turn input. The single submission loop and awaited
handler in `core/src/session/handlers.rs:420-435,634-687`, followed by
`core/src/session/inject.rs:170-188`, establish the idle FIFO sequencing used
here. Generated installed-binary schemas are additional mapping evidence;
they do not authenticate origin or prove provider outcome. Controlled delayed
handler tests establish the client's ordering, not genuine provider acceptance.

The desktop rust-v0.162.0-alpha.17.2 executable is admitted only by its complete
SHA256 `0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28`.
The older two pins remain supported. Its source is bound to official tag commit
`740e5af33c71225640e0c1c1555c514c2c93ab74`. The official aarch64 package has
SHA256 `f05b8447bae71d556050fd4066ea4cd066a7b8881ca9c086b88215e7d3d76264`;
its executable has SHA256
`9b47aa34d14c35d87fbe2702fc6c4163d965b30fd88b3defd19e80e780f40d8d` and is
not an additional admitted pin. Both executables are 246,046,384 bytes. Complete
byte comparison includes every Mach-O header and load command and excludes only
the single parsed `LC_CODE_SIGNATURE` region at offset 244,122,288, length
1,924,096, ending exactly at EOF. All 244,122,288 remaining bytes match, with
SHA256 `887ce8a15dc230087462f6fa9efd277d26a54d45b6c9e1e5fe6673b3fc485a6b`.
Independent macOS strict signature verification, an Apple-anchored requirement
for OpenAI OpCo, LLC (`2DC432GLL2`), and notarized Developer ID assessment
establish vendor provenance of the differently signed desktop executable.
Signature metadata alone is insufficient; trust failure or any other byte
difference prevents admission. Runtime admission still hashes the entire file;
it never strips signatures, compares versions or repeats this provenance method
to admit unknown executables.

At that commit, `app-server-protocol/src/protocol/v2/item.rs:776-850` and the TUI
conversion at `tui/src/chatwidget/protocol_requests.rs:70-165` preserve the
existing command/execve mapping. New optional `review_reason` defaults to None;
`model_context` is skipped in serialization. Neither requires a new native
field. Unsupported action variants remain unavailable. The turn/start path
through `app-server/src/turn_processor.rs:528-733`,
`core/src/codex_thread.rs:578-590`, and `core/src/session/turn_input.rs:222-432`
reaches the same submission queue as override. The single awaited dispatch in
`core/src/session/handlers.rs:435-694` and idle injection in
`core/src/session/inject.rs:169-188` preserve the conditional FIFO reasoning:
exclusive ownership, proven quiescence and an acknowledged override must precede
one same-thread continuation. This source proof and local fixtures do not prove
human authority, provider acceptance or action execution.

## Acceptance and rollout

Local controlled tests, source checks and isolated wheel checks establish
implementation readiness only. Real acceptance requires visible desktop host
form presentation, an actual human response, a genuinely observed denial in the
retained original provider context, native operation acceptance, renewed review,
same-thread action outcome, budget and cleanup evidence. A fake backend, accepted
protocol response or capability advertisement does not qualify as that evidence.

No genuine provider or model run, historical denial revival, filtered validation
replay, startup timing spend or global installation follows from enabling this
flag. Historical timing and live/lease evidence stay bound to their original
candidate. The new imports, catalog bytes and opt-in launch path require an
independent final applicability disposition; no unchanged-timing claim is made.
Keep the frozen full source-suite release checkpoint reserved. Separate genuine
host/provider validation and release approval gates remain pending.
