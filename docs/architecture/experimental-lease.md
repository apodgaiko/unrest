# Experimental retained Codex leases

The experimental API is disabled by default and separate from ordinary dispatch,
ordinary task completion and public role MCP catalogs. `LeaseLane` requires
`trusted_process=True`, provider `codex`, an admitted shared `PilotLedger`, and
an explicit `provider_package` directory, and verified complete package/executable
pins before constructing processes. Experimental Claude and
unknown providers reject. Missing selection, controls, capacity or budget rejects
before dispatch. `status()` reports `os_write_isolation=unverified` and live
acceptance unverified. Genuine ACP reuse and native approval, and final-candidate
timing, remain **UNVERIFIED** under the accepted release risk. Controlled local
tests prove bounded local behavior only. Product implementation is not acceptance.

## Trust and limits

Use trusted workloads in disposable directories. This is not an adversarial
sandbox. Strong OS write isolation, parked/background direct writes, inherited
service/exception authority and comprehensive unknown-descendant termination are
unverified. Digest equality detects observed divergence; it cannot prove absence
of a transient write followed by restoration. Broker rejection is not OS write
prevention. The old default-deny research profile is retained as historical code;
neither this API nor the probe invokes it.

## Actual retained route

One caller-owned asynchronous event loop spans the episode. `LeaseLane` owns a
retained session owner for W0/V0, permits exactly one correction/recheck on their
original ACP session IDs and managed-process generations with new ordinals and
capabilities, then permits at most one fresh W1/V1 generation. Only a bound
validator `reproducible_product_defect` permits that transition. Conflict, missing
authority, scope expansion, unknown/malformed handoff, stale candidate, unexpected
turn order and failures in the fresh generation stop dispatch with attention.
Pass promptly closes both retained roles. `final=True` admits one fresh validator
only and consumes one of the two final reservations. The two-lane coordinator,
entitlement selection, authored-order integration and full target coverage gates
remain the integrating caller's responsibility; this module is not a scheduler.

For each generation the controller directly launches and registers the backend
app-server and codex-acp adapter. `CODEX_PATH` points the adapter at a fixed transport
relay, not at a second backend. The guarded provider route adds supported
configuration attestation, exact-thread/served-model observations, and a narrow
per-turn approval restriction from the pinned adapter's read-only/on-request
preset to read-only/never; see `experimental-cohort.md`. The relay accepts exactly `app-server`, one
private authenticated loopback attachment and no reconnection. The controller
owns actual backend and adapter process handles, their transport/watch tasks,
relay lifetime socket and the private HTTP server. Registration remains owned
through cancellation and late return. No guessed PID or process census is used.

Real construction uses `_acp_subprocess_env`, the ordinary supported subscription
HOME/config route, with requested `gpt-6-astra`/`medium`, forced ChatGPT login,
read-only mode, no shell tool and no permission fallback. It does not copy auth
files, invoke an OS sanitizer or acquire new credentials. API-key environment
aliases are removed. Pinning/configuration is not proof of live subscription or
served model identity; independent live validation must observe those before its campaign. Existing
user configuration remains an ambient trusted-process limitation.

The adapter receives the actual private authenticated HTTP MCP server in
`session/new.mcpServers`. Each turn uses that session's `session/prompt` and
contains its immutable identity, fresh turn capability, bounded UTF-8 candidate
content (256 KiB total), and the caller's task/validation instruction. The real
provider must call `replace_file` and `complete_turn` on that registered server.
The controller does not forge completion from ACP `end_turn`. Narrow callbacks
accept only correctly bound `session/update`; filesystem, terminal and permission
callbacks never delegate to ordinary handlers. The broker exposes no executor,
process launch, grant/current-token operation or ordinary `end_node`.

Pins (Darwin arm64 setup):

| Component | Version | SHA256 |
|---|---|---|
| Official Codex package backend | 0.160.1 | `09fa44fdc37a5fc70dc1ace31235f90468a2e193d0e85f7552eab068ea2582be` |
| codex-acp script | 1.1.0 | `878d6a3d825725d0a579305a3e206c7bbb5724a95751b4e3e86af8030cdee758` |
| Node | 22.22.0 | `913b144fdb40638b1acef7974ab3c33fbd527cc0974cb5da467ab1e6ac51b4d4` |

Real callers must supply `provider_package=Path('/absolute/package/location')`.
There is no package default, PATH search or application-bundle fallback. The
location must have no symlink ancestors (on macOS use `/private/tmp`, not `/tmp`).
Keep the full layout of the official
[Codex rust-v0.160.1 release](https://github.com/openai/codex/releases/tag/rust-v0.160.1)
asset `codex-package-aarch64-apple-darwin.tar.gz`; archive SHA256 is
`f73527ee09c6db869acbb37b709866b339ea74ef91d2de255e9c74ec960c6314`.
`experimental_provider` freezes all 42 regular-file hashes, lengths and modes,
including adjacent helpers, libraries and resources. Only the exact derived
directory layout is admitted. Missing/extra files or directories, changed bytes
or modes, hardlinks, symlinks and special files reject. Checks use held directory
descriptors and no-follow opens, before lane/generation-root creation and again
before each backend launch. The executable runs in place, preserving its package
layout. Preserve package permissions when extracting or relocating it.

The official archive checksum supplies provenance. Neither the official binary
nor the installed application binary passed local strict Apple signature
verification; no Apple-signature or tampering claim follows from these checks.
Keep the selected package under trusted custody for the episode: checking is not
an atomic filesystem/exec transaction and does not prevent transient changes or
hostile replacement after observation. Resolve the installed codex-acp symlink
before supplying `adapter`; its associated Node binary remains pinned separately.
Adapter and Node pins are checked again at launch.
A `fixture` argument selects only the exact pinned product fixture, which never
reads subscription credentials or launches a provider. Its thread/start verifies
MCP registration and its turn/start performs actual HTTP MCP edits/completions
through the same adapter, relay, owner and broker boundaries. Fixture evidence is
controlled-process evidence, never real-provider continuity proof.

## Candidate and broker boundary

`TurnIdentity` binds lane, role child, handoff, ACP session, process generation,
positive integer ordinal, full scope and input digest. Wire scope is a JSON array;
library scope is a sorted unique tuple of safe flat names. Wrong identity fields,
stale credentials, ordinal aliases, expired capabilities and validator mutation
are rejected. A generation cannot change session, child, handoff or scope.

`TurnBroker` accepts only a full flat directory of regular single-link files,
1 MiB per file. It rejects Git directories, links, traversal, replaced directory
inodes, undeclared files and special types. Held directory descriptors anchor
operations. Do not point it at a Git worktree or weaken these limits to do so.

The caller supplies `expected_candidate` from its initially sealed materialized
input. Initial sealing compares to that identity once. Every subsequent grant,
validation boundary, content read, completion and successful cleanup compares to
the retained expected hashes. Only a controller-observed authorized replacement
advances them: the predicted manifest changes exactly that file's hash and must
match the observed full manifest. Unexpected active-turn or parked changes cannot
become a new baseline or be blessed by completion, even if the caller supplies
the changed digest. Divergence revokes authority, quarantines and stops dispatch.

One lock covers authorization, mutation, fsync, publication, revocation and
close. Parking drains any admitted operation before acknowledging. Completion
uses the granted canonical identity and no-replace hardlink publication from a
fsynced private temporary. It is immutable per turn. Failed/uncertain mutations
or publication revoke and quarantine; committed bytes or published records may
remain. Revocation is not rollback. An existing records root cannot restore
capabilities. Records omit content, prompts and capabilities. Expected broker
refusals are bounded MCP errors without dependency traceback output.

The [disposable coordinator](experimental-cohort.md) uses `experimental_candidate` to observe and verify its
restricted committed Git fixture, input declarations, base and output boundary;
materialize declared flat inputs in a separate broker root; and retain both the
observer manifest and the distinct flat-content digest. It must verify the
original observer identity before/after validation, before serial integration
and final acceptance. The broker digest is not a Git/target-coverage identity.
Git materialization, output collection, recovery and integration stay controller
owned. The observer's Git/link/traversal/type limits remain unchanged.

Experimental turn identities may bind an ordered target tuple. Validator
`complete_turn` then requires exactly those targets in its boolean `verdicts`
map; a passing disposition requires every target true. Worker verdict maps are
empty. The no-target lease probe retains its original completion behavior.
The private experimental tool schema changes only; ordinary role tools do not.

## Shared campaign and lifecycle

One exclusive-create append/fsync `PilotLedger` spans all roles, lanes, final
validators and episodes. Do not create a ledger per lane or episode. One
independent validator owns the live campaign. Existing journals refuse restart;
a crash never restores entitlement. The provider label distinguishes controlled
runs from the pinned real provider/model configuration.

The coordinator explicitly selects deadline-bounded drain before its campaign halt
or from the scoped first-owned-halt provenance described below.
Only already-sent tickets can use that drain path; reserved tickets cannot send
after halt and no new session/admission is permitted. The original minimum
turn/episode/campaign deadline remains binding through acknowledgement. Successful
acknowledged custody processing retains the original episode/campaign lifetime;
it does not reset the ticket or impose a second turn cutoff. Successful stopped
drain retires synchronously before clearing sent-active eligibility. A prior owner
failure stays quarantined, and an unrelated ledger halt cannot be retroactively
authorized for drain. Standalone lease owners keep
their prior immediate-halt behavior. Both paths require focused lifecycle
revalidation when changed.

An owned ledger journal operation records the identity of its retained controller
owner if that operation causes the first halt. This scope holds the ledger lock
only across synchronous session binding, reservation, send recording or finish;
it never spans an asynchronous turn. Journal write/fsync failure and uncertain
finish share this provenance. A later operation cannot claim an unrelated earlier
halt, and explicit stop or lifetime expiry does not manufacture ownership.
The coordinator may use this causal identity to authorize unaffected already-sent
siblings under their original bounds. Closed storage and actual lifetime expiry
still refuse drain; storage failure is never acknowledgement success.

Acknowledgement success is published only after the actual journal write/fsync
returns and the original minimum cutoff is rechecked under the same owned lock.
At or beyond that cutoff, the ledger marks the ticket uncertain and records the
causal halt before appending a corrective uncertainty record. The earlier ack
remains in journal history; it is not rolled back. If correction write/fsync
fails, `turn_not_acknowledged` remains the primary failure with the bounded
`journal_unavailable` cause. Existing journal bytes never confer restart or
resumption authority, including when correction could not be made durable.
This classifies a returned filesystem operation; it does not promise interruption
of a stalled syscall. Timely acknowledgement followed by late custody remains
subject only to the original episode/campaign bounds described above.


| Episode | Early sequence | Fresh finals | Maximum |
|---|---|---|---|
| P1 | W0,V0 | 2 | 4 |
| P2 | W0,V0,W0 correction,V0 recheck | 2 | 6 |
| P3 | W0,V0,W0 correction,V0 recheck,W1,V1 | 2 | 8 |
| C1 | Wa,Va,Wb,Vb | 2 | 6 |

Reservations consume allowance before transmission, are never refunded, and
include the immutable candidate-bound turn identity. Concurrent reservations are
bounded by `min(capacity,4)`; retained sessions are separately capped at four.
Two final slots are held before episode admission. Early turns cannot consume
them, final phase cannot return to early work, and episode closure requires two
final turns and no outstanding session/turn. Maxima total 24. A turn lasts at
most 300 seconds, an episode 1800 seconds, and the shared aggregate clock 5400
seconds without reset between episodes. A failed/ambiguous send consumes its
reservation and stops all further sends; already sent outcomes can be recorded
without refunding uncertain attempts. No transparent retry exists.

Parked backend/adapter EOF, bridge or broker loss, deadlines, cancellation and
restart invalidate resumability. One retained cleanup task terminates/escalates
and actually waits on owned handles, closes transports, drains tasks and checks
relay lifetime. Registration and all async cleanup barriers are bounded. If a
signal races cooperative exit, only a successful actual handle wait resolves
uncertainty. Signals never follow observed reap. Failed or uncertain cleanup
persists quarantine, retains the root and halts the shared ledger before further
dispatch. Unknown descendants are not proven owned or terminated. Hard controller
kill cannot run cleanup; filesystem syscall stalls have no hard deadline promise.

## Reproducible local checks and independent pilot setup

Run from the checkout on Python 3.13 with locked dependencies and the pinned
installed adapter/Node. Loopback permission is required. Each probe root must be
new; preserve failed roots and journals. The replacement probe contains no
sanitizer or real-provider launch route:

```bash
uv run --locked python tools/probe_v046_lease.py --trusted-process --controlled \
  --episode P2 --root /private/tmp/lease-p2-unique --output /private/tmp/lease-p2.json
uv run --locked pytest -q tests/test_experimental_lease.py \
  tests/test_experimental_session.py tests/test_experimental_retained.py \
  tests/test_experimental_relay.py
```

P1/P2/P3 select the corresponding controlled sequence including two fresh final
validators. `--disposition conflict` (also missing_authority, scope_expansion,
unknown, malformed_handoff) in P2 yields attention/exit 2 with no correction.
Omitted opt-in rejects before root creation. The controlled C1 concurrency test
runs two independent disposable lanes against one ledger; it does not implement
or establish coordinator integration. Output binds completion identities,
registered broker observations, full-scope unchanged control bytes and owned
handle exit. `provider_turns=0` is explicit.

A separate no-launch readiness route constructs the actual real `LeaseLane`
with `fixture=None`, then closes it without `_start()` or `turn()`. It requires an
explicit package and resolved adapter and rejects process-launch attempts using
a Python audit hook. Its disposable journal is labeled readiness-only; it never
replaces or resets the independent live campaign ledger. Example (set paths to
your verified package and adapter; temporary locations are setup only):

```bash
uv run --locked python tools/probe_v046_lease.py --trusted-process --readiness \
  --provider-package "$PACKAGE" --adapter "$ADAPTER" \
  --root /private/tmp/lease-readiness-unique --output /private/tmp/lease-readiness.json
UNREST_TEST_PROVIDER_PACKAGE="$PACKAGE" uv run --locked pytest -q tests/test_experimental_provider.py
```

Readiness reports zero owner starts, launch attempts, turn reservations and sends.
It is not authentication, app-server compatibility or live continuation proof.
The package test's real-construction case requires the explicit environment
variable; without it the hermetic path-safety tests run and that one case skips.
Stale real campaign labels reject before journal creation; a controlled campaign
cannot admit a real lane. Existing journals cannot resume or gain a fresh budget.

After local gate and combined cohort/startup freeze, independent live validation
uses the disposable coordinator's explicit package-selected campaign command.
It creates exactly one real-provider `PilotLedger` and runs P1/P2/P3/C1 inside
one event loop, preserving authored entitlement, sealing, integration and fresh
final coverage. The standalone lease probe is a focused boundary diagnostic;
it is not a substitute for coordinator composition or a second live campaign.

Prepare independent P1 passing input, P2 reproducible in-scope defect/correction,
P3 repeat-defect/fresh-generation input and C1 disjoint two-lane input using the
frozen oracle. Freeze source, lock, provider and candidate identities before
starting. Record actual served provider/model and ACP/process continuity,
corrected full-scope recheck, fresh finals, all consumed sends/deadlines and
cleanup. Never substitute these local fixtures for real acceptance. Workers
spend zero live turns; LEASE001/006 live evidence remains solely independent live validation's work.

## Pinned provider startup admission

Startup emits one `mcp_servers` inline-table override containing every inherited
registration's `enabled=false`. Codex rust-v0.160.1 parses only the right-hand
side as TOML and splits CLI keys on literal dots. A later root override replaces
the earlier CLI-layer value; configuration layers then merge recursively. Server
names (including dots, quotes, backslashes and Unicode) are quoted inside the
single value. Other inherited server fields survive that merge. Thread controls
use the same nested values; the private broker is still added only at the
existing authenticated thread-registration phase.

Preflight accepts the exact forced-ChatGPT requirements projection:
`allowedLoginMethods=["chatgpt"]` and every other pinned nullable field present
as null. Missing, extra or unsupported policy fields/values refuse. This API
omits policy families and cannot prove comprehensive policy absence. Unsupported
local requirements/legacy-managed files must be absent and their absence remains
sealed; unresolved MDM, enterprise and legacy layers refuse. Supported
session/system/user/project layers require exact discriminants, field shapes,
version and authorized source paths; selected profiles refuse. Packaged defaults
are excluded by the pinned layers API. An unknown layer cannot gain authority by
naming a declared file. Empty `skills.config` may be omitted by typed serialization;
null and missing nonempty rules refuse.

Initialization admission shares the original absolute startup/inference cutoff
described below; initialize-only uses its single finite setup cutoff. Neither
path gets a separate phase allowance. Admission permits at most 32 received
frames and 262144 total received bytes, including newlines. Private request
responses may use that total bound per frame; the initial adapter frame,
forwarded initialize response and notifications retain 65536 bytes including
newline. Counters never reset between private requests. Only backend-origin
notifications may carry `emittedAtMs`: absent, null or a signed 64-bit integer.
Booleans, floats, strings, overflow and timestamps on adapter messages, requests
or responses refuse. This metadata cannot affect deadlines, identity or authority.
Preflight accepts exactly three notification methods:

- `account/updated`: optional/nullable pinned auth and plan enums. Admission still
  requires managed `chatgpt` auth; a supplied plan must match the final account.
- `configWarning`: required string summary, optional/nullable string details/path
  and range. A range requires start/end positions with unsigned 64-bit line/column;
  zero and reverse ranges are valid. Warning strings and paths are inert data.
- `remoteControl/status/changed`: required string serverName/installationId and
  status, optional/nullable string environmentId. Only `disabled` is admitted;
  connecting, connected, errored, unknown and malformed states refuse.

Unknown fields, requests, other preflight methods, mismatched reply IDs,
malformed/duplicate JSON keys, mixed result/error envelopes and overflow refuse.
Original accepted notification/initialize bytes and relative order are buffered
privately and released in one write/drain only after complete admission; private
configuration replies are never forwarded and refusal releases nothing.
After admission, account changes still refuse and remote status retains the same
disabled-only check before forwarding, synchronously revoking broker authority
and stopping/quarantining the owner on failure. Later grants and sends refuse.
Each Bridge-owned forwarding pump records the original failure, synchronously
invokes loss/revocation, then re-raises the same exception before its task can
complete or a queued sender resume. This covers either direction's restriction,
observation, read, write and drain failures, including unexpected cancellation.
Diagnostic callback failure cannot skip revocation or replace the pump exception.
Intentional Bridge closing suppresses this failure reporting/revocation.

Intentional owner shutdown revokes authority, accounts for pending launch
registration, and synchronously calls `Bridge.begin_shutdown()` on every owned
bridge before adapter teardown. Late adapter registration marks every currently
owned bridge before stopping that adapter; a late backend's own close also marks
its bridge. Registration uncertainty still quarantines. The irreversible,
idempotent marker only sets classification state: it does not cancel tasks,
close writers, refresh deadlines, or change bounded session/cancel and
adapter-before-backend cleanup order. `Bridge.close()` marks as a fallback.

Only native transport read/write/drain/write-eof/close operations may complete
normally on `BrokenPipeError` or `ConnectionResetError` observed after that
marker. The boundary is exception observation, not physical fault origin.
Restriction, observation, EOF and diagnostic callbacks remain outside that
classification; their failures, timeouts, cancellation, generic connection or
other OS errors, and policy/protocol refusals retain their failure behavior.
Previously failed pump tasks and first-failure diagnostics are never cleared or
reclassified. `ConnectionCleanup` stays strict: pending tasks, writer waiters,
process reap and lifetime barriers must still complete within their existing
bounds, and any uncertainty still quarantines.

EOF retains synchronous loss and half-close behavior. Repeated loss shares the
existing owned cleanup, and first-failure diagnostics remain immutable and
body-free. This boundary cannot retract bytes already written before failure.
Runtime frames are bounded and buffered through complete observation before
forwarding; legitimate turn notifications retain their existing policy rather
than the three-method preflight allowlist. Observed disabled status does not
prove continuous absence of remote activity. No remote RPC or removed feature
flag is used. The adapter can convert warnings to ACP text; controlled full-path
canary checks must cover all persisted diagnostics, journals and logs, including
warnings delivered to an existing session during a turn.

Pinned notification schemas: [server envelope](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/app-server-protocol/src/protocol/common.rs),
[account](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/app-server-protocol/schema/json/v2/AccountUpdatedNotification.json),
[warning](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/app-server-protocol/schema/json/v2/ConfigWarningNotification.json),
and [remote status](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/app-server-protocol/src/protocol/v2/remote_control.rs).

IDs and all pinned controls compare both type and value, including nested arrays
and maps; numeric aliases cannot satisfy booleans. The turn rewrite changes only
the `on-request` approval value to `never`, retaining all other bytes. Read-only
sandbox and network denial remain mandatory. Controlled fixtures independently
model the relevant pinned CLI parser, recursive merge, typed serialization,
requirements projection and asynchronous notification ordering. Tests traverse
actual relay streams, the pinned adapter and private MCP mutation/completion;
these prove controlled integration, not live provider compatibility.

Pinned source references: [CLI value parser](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/utils/cli/src/config_override.rs),
[literal key insertion](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/config/src/overrides.rs),
[layer merge](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/config/src/merge.rs),
[wire schema](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/app-server-protocol/src/protocol/v2/config.rs),
[skill serialization](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/config/src/skills_config.rs),
and [initialization routing notifications](https://github.com/openai/codex/blob/rust-v0.160.1/codex-rs/app-server/src/request_processors/account_processor/workspace_routing.rs).

## Bounded startup diagnostics and initialization-only probe

Experimental owners retain at most 32 phase events per role, the first failure's
fixed stage/category, and at most 16 distinct cleanup categories separately.
Stages are task-local: concurrent bridge progress cannot relabel an owner failure.
The initial exchange records `initialize_frame_wait`, `initialize_frame_received`
(after a bounded valid initialize frame), `initialize_write_wait`, `initialize_write_complete`
(after drain), `initialize_response_wait`, and `initialize_response_received`
(after a matching valid response). Receipt does not imply successful admission.
An owned expired timer carries a fixed `timer_scope`: `provider_preflight`,
`acp_initialize_session`, `owner_launch`, `broker_start`, `bridge_auth`,
`lifetime_connect`, or `bridge_connect`.
Nested timeouts retain their original scope; external cancellation is not a timer
expiry. Uninstrumented TimeoutError has no claimed scope. The first failure still
wins, even if an enclosing timer subsequently expires; cleanup remains separate.
No process status is inferred from a pending response or EOF. Direct owned reap
is reported separately after cleanup and cannot prove a prior spontaneous exit.
The initializer labels this output `initialization-boundaries-v4`.
Bridge admission records transport, timeout and refusal failures before owner
shutdown can obscure them. Broker startup also re-raises its original failure
after recording any close failure separately. Categories preserve known literal
provider and lease refusal codes using a fixed vocabulary; unknown refusal
arguments and arbitrary exception classes become `lease_refused` and `exception`.
The v4 shape is unchanged. Protocol refinement adds only the fixed categories
`provider_protocol_json_invalid`, `provider_protocol_envelope_fields`,
`provider_configuration_response_id_mismatch`, `provider_configuration_error_response`,
`provider_notification_unsupported` and `provider_notification_invalid`. These
identify current rejection branches, never the unknown frame from a historical
failure. No dynamic method/key names, IDs, timestamps or body hashes are recorded.
Admission read refusals use six fixed categories in branch-priority order:
`provider_configuration_reader_limit` for `readline` ValueError (before counters
advance), then `provider_configuration_eof` for empty input,
`provider_configuration_unterminated_frame` for missing trailing newline,
`provider_configuration_frame_bound` for returned length above the applicable
frame allowance (65536 for initial/forwarded frames, 262144 for private replies),
`provider_configuration_frame_count_bound` above 32 frames, and
`provider_configuration_aggregate_bound` above 262144 bytes. Returned lengths
include the newline. The private backend Python 3.13 StreamReader limit is
262143, comparing content before the newline: a 262145-byte LF frame fails
in the reader. It governs stdout and stderr for the process lifetime and can
buffer beyond its line limit; it is not a whole-process RAM guarantee. A
returned private response above the old 65536 limit now reaches count/aggregate
checks. Oversized notifications within the private allowance are rejected after
those pre-parse checks and envelope parsing; they are never forwarded. Counters still advance on every returned read and remain shared across
the initial adapter frame and all backend replies and notifications, without
resetting between requests. The historical `provider_configuration_protocol_bound`
literal remains recognized, but cannot identify a prior failure's branch.
The bounded compatibility exception adds no counts, IDs, body metadata or fields
to the v4 shape and preserves first-failure/cleanup ordering.

After full private admission returns, the role observer seals an immutable copy
of its effective configuration digest, exact cwd and existing sealed-input
verification callable. No configuration/account body is retained. A single
startup adapter `config/read` with exactly `includeLayers: true` and that cwd
may arm the response exception before its pipe write. IDs must be strings or
integers (never booleans, floats or null); bootstrap outstanding IDs are tracked
by strict type/value identity, with duplicate refusal and capacity 32. Completed
ordinary IDs may be reused. The consumed configuration ID remains reserved for
duplicate response/request rejection after bootstrap tracking is discarded.

The exception is unavailable before sealing, eligible afterward, pending after
the one request, and permanently spent after a terminal response, failure, stop,
cancellation, EOF or thread start. Pending thread start refuses. Without an
adapter config request, private admission suffices and thread start retires the
unused allowance. A matching terminal reply consumes it even when small, an
error or malformed. Success requires the strict backend envelope, matching typed
ID, result without error, config/origins objects and nonempty layers, verification
of sealed inputs, and equality with the admitted whole-result SHA256 using
`json.dumps(result, sort_keys=True).encode()` exactly. Origins, raw layers and
versions participate; there is no normalization or rebaseline.

Normal runtime remains 65536 payload bytes (65537 including LF). Only while
pending may one backend frame buffer up to 262144 including LF. Unrelated
responses and notifications retain the ordinary limit. Complete frames are
processed sequentially, retiring the allowance before examining a coalesced
successor or suffix. No fragment or unverified response is forwarded; successful
responses preserve original wire bytes. Adapter frames never gain an exception.
Synchronous owner revocation retires eligibility before a queued sender can write.
No exception strings, provider/config/account bodies, prompts, environment or
credentials belong in diagnostic records. Coordinator attention snapshots include
these records; classification grants no authority and does not make a failure
successful. Cleanup uncertainty still quarantines and stops dispatch.

The independent initializer is `tools/probe_v046_startup.py`. It requires explicit
`--trusted-process --one-initialization-attempt --provider-package <package>
--adapter <adapter> --root <new-disposable-root> --output <new-result-file>`.
Programmatic calls require literal boolean `True` for `trusted_process` before
creating any setup root or owner; truthy non-booleans refuse. The caller's
selection is forwarded unchanged to supported provider admission.
Its supported ProviderConfig, pinned owner and bridge route performs initialize,
effective configuration verification and ACP session creation, then closes. It
never calls `session/prompt`, `turn/start` or model tools, reserves no turn and
grants no broker mutation capability. A dedicated initialization-only journal
and exclusive root/result creation prevent reuse of that attempt's artifacts.
There is no campaign invocation, resume, reset or automatic retry. A new root is
not authorization for another attempt; only the independent validator with an
explicit one-attempt authorization may launch the real backend.

Startup and inference share one original absolute 300-second turn cutoff,
captured before role launch and capped by existing episode/campaign lifetimes.
Provider preflight and ACP initialize/session creation inherit that same cutoff
across tasks; there is no separate 30/31-second cap or phase reset. Initialize-only
gets one absolute 300-second setup cutoff, capped by its finite ledger lifetime,
without any prompt entitlement. Expiry fails and quarantines without retry.
Stop and the original cutoff are checked before reservation, grant and actual
prompt send, including after synchronous admission callbacks. Final-turn reserves
never extend wall time. Broker/auth/connect and owned cleanup bounds are unchanged.
Cleanup may finish after operational expiry; all actual elapsed setup and cleanup
still consumes the original episode/campaign clocks and creates no later eligibility.

Private per-role SQLite and genuine native backfill remain prerequisites. No
snapshots, shared writable database, retained caches, auth routing, pins, flags,
policy or permission changes are part of the deadline propagation. Native first
backfill may consume most or all of the turn allowance. This is neither a readiness
guarantee nor a performance improvement. Output reports verified configuration and
identity only when observed, plus actual setup/cleanup elapsed and owned reap/close
outcomes. Initialization alone does not prove continuation or strong OS isolation.
Earlier failed attempts retain their original bounds, outcomes and spent status.

Diagnostics also retain monotonic elapsed seconds for the bounded phase events.
Before owned cleanup, a synchronous snapshot reads only cached direct backend
and adapter return codes (null means unknown), stdout EOF, and the existing
backend stderr drain's saturated 65536-byte count, truncation flag and EOF.
Adapter stderr remains discarded. EOF means the reader has reached EOF, not a
process-exit diagnosis. Collection adds no reads or waits and retains no stderr,
arguments, environment, configuration, exception text or stacks. Post-cleanup
reaping cannot rewrite these observations or establish an internal backend wait.

## Controlled local ACP transport

`ControlledTransport` is an internal source-test selection. It accepts only the
separately pinned `controlled_python_acp.py` fixture and pinned Python interpreter,
with the fixed `--controlled-local-acp-v1` argv. Admission requires literal
`controlled=True`, no provider package, and exact file bytes; pins are checked
again before role registration and adapter execution. No native constants or
ordinary provider launchers are replaced. Omitted selection retains native adapter
and Node pins even when a controlled backend fixture is present.

The interpreter pin is captured once from the executing CPython 3.13+ test
runtime at module import, before transport admission: its exact executable path,
resolved path and SHA256 bytes form an immutable process-instance binding.
Selection cannot supply an expected digest or a different executable, including
an identical copied binary. Both path identities and bytes are rechecked before
each backend and adapter launch. The binding works on the supported Ubuntu
Python 3.13 lane without a platform-specific executable constant; local platform
selection controls do not establish actual remote CI success. The fixed ACP
fixture digest and argv, literal controlled admission and native pins remain
separate requirements.

The cancellation-aware local fixture is byte version
`f5134a2d79b348b70b05a66566ff65d0049f102665200a22f3a6fcbd1c4f58be`.
It supersedes warning-capable byte version
`206d6fe32de1d959c234e604940dff339d13b08cc4c6a665d1316048b8bb62fe`,
which incorrectly emitted `turn/interrupt` during idle initialization cleanup.
It supersedes the incomplete local fixture
`f1ba9190d15a88893bdf3864c895be07fc6623d3302fc97fff1656e1b7e7ce13`,
which refused `configWarning`. This changes neither the original backend fixture
nor native adapter/Node pins. The fixed invocation remains
`--controlled-local-acp-v1`; callers cannot select a digest or arbitrary command.

After production Bridge admission/observation, the local adapter independently
validates the closed warning envelope, signed timestamp, summary/details/path
types and unsigned range positions, within the existing 65536-byte notification
bound. It converts summary and nonempty details to an ACP
`session/update` agent text chunk for its sole established session. Path/range
are inert and omitted from the chunk. Before session creation there is no
recipient, matching the pinned native source's registered-session routing.
Cancellation and adapter teardown retire warning delivery; malformed, unknown
or late notifications and invalid session identities refuse. Remote status
notifications are independently limited to the same closed disabled-only schema;
production Bridge validation still owns synchronous revocation before forwarding.
Warning content remains ephemeral in the owner callback and must not enter
persisted diagnostics, logs or journals.

Read-only correspondence is the pinned adapter's `CodexClient.notify`,
`CodexEventHandler.createConfigWarningEvent` and `createAgentTextMessageChunk`:
unscoped notifications route to registered sessions, and summary/details become
text. Local wire/callback tests exercise the separate backend, authenticated
Bridge and real owner. This correspondence does not execute the native converter.
Idle cancellation retires warning delivery without sending a backend turn RPC.
An outstanding prompt, including a pending `turn/start`, remains interruptible.
The ACP reader continues accepting cancellation while awaiting the independent
backend pipe and observes request-task errors immediately; invalid session
identity terminates the adapter instead of silently losing the refusal.
Read-only native `interruptSessionTurn` / `getInterruptibleTurnId` corroborates
the distinction between no turn, an active turn and a pending start. Actual
native cancellation execution remains UNVERIFIED. The changed cancellation
path requires the original controlled functional timing/ordering cases to be
checked again with their unchanged parameters; historical C1 results alone do
not establish this version. No new timing matrix or native acceptance follows.

Selection propagates through ProviderSetup, campaign, Coordinator, SyntheticSession,
LeaseLane correction/rotation and fresh final owners, and the programmatic startup
probe. The command-line live startup probe does not expose this selection. Each
role still registers a separate backend first and adapter second, authenticates
its real Bridge, retains the lifetime socket and uses production ACPClient and
the private authenticated experimental broker. The local adapter identifies
itself as `controlled-python-acp/local-1`; its backend performs actual `replace_file`
and `complete_turn` calls. Experimental completion never calls ordinary `end_node`.

Actual broker receipt precedes PilotLedger ACK or uncertain journal durability;
coordinator admission and Custody sealing follow acknowledgement, and independent
validation follows sealed candidate readiness. Journal write/fsync faults retain
quarantine, consumed entitlements, first cause, unchanged sibling cutoff and
owned-child closure. Supporting configuration claims bind directly to
ThreadObservation fragment bytes, typed IDs, outstanding capacity, one-shot
response eligibility, lifecycle and EOF/cancel retirement, or to
ProviderConfig.admit_bridge withholding, exactly one forwarded initialize and
verified effective seal. Configuration response allowance is not inference time.

Controlled wire results establish bounded local behavior only. Native warning
conversion, large reply interpretation and served configuration/session conversion
execution remain UNVERIFIED. Preserve native byte/source correspondence, all
original failure evidence and native no-launch pin controls. The controlled source
checkpoint needs exact finite child-exec registrations, inherited guard coverage
and actual owned wait/exit proof; no blanket Python exemption is valid. Full-suite,
archive/extracted persistence, installed lifecycle, desktop and downstream release
requirements remain unchanged. Strong OS isolation, unknown descendants and
transient mutation detection retain their existing unverified limits.


## Resource acquisition and session lifetime

TurnBroker owns both directory descriptors. Its constructor releases every
acquired descriptor if directory creation or either open fails. PilotLedger owns
its exclusive journal descriptor and releases it when the initial durable append
fails, preserving `journal_unavailable` and the journal bytes already written.
Neither constructor removes existing records or restores authority after failure.
Repeated close calls release each descriptor at most once.

A session acquires its broker and then its ledger. A ledger acquisition failure
rolls back the broker before propagating the original failure. A supplied campaign
ledger is borrowed: session acquisition and unstarted finalization neither close
nor halt it. `close_unstarted()` releases only constructor-owned resources without
requiring an event loop. Once startup has acquired asynchronous resources, callers
must await `close()`; its existing cancellation, child registration and numeric
wait obligations precede descriptor release. A completed async close may be
followed by repeated synchronous finalization safely.

The controlled session fixtures retain their synchronous factory return values
and explicit transport selection. A synchronous pytest finalizer protects the
pre-body and event-loop-setup failure paths; the same pytest finalizer
uses the original test runner to await close for started owners before the
runner is released. Runner setup precedes session acquisition for async tests. Direct
factory callers remain responsible for explicit finalization.
