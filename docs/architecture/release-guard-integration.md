# Release guard integration

The target is 0.4.7. `.github/release-guard` is the sole release guard; the former
`.github/release-source-guard` and its CI consumers are removed. Historical
failures and review denials retain their original meaning. Removal or replacement
of guard machinery does not reverse a denial or authorize its replay.

Experimental features remain disabled by default. Genuine native-provider
approval, ACP reuse and final-candidate timing remain **UNVERIFIED**. Controlled
source tests do not establish genuine provider acceptance.

## Scope and size

The guard contains execution and IPC effects. Ordinary in-process Python is
trusted: frames, closures, object labels and generated code do not authenticate
callers. Hostile-Python isolation is not claimed. Unchanged product tests certify
application behavior, including protocol authorization, refusal, completion,
credential redaction, persistence, integration and cleanup.

Enforcement has a 10,000 physical-line ceiling. Native code, policy, generators,
generated enforcement, workflows and external enforcement dependencies count.
Tests are measured separately. Moving, packing or renaming code does not reduce
that scope. `size_budget.py` reports current bytes and lines; an independent
closure review must check external dependencies. Neither size nor component
checks certify a release.

`tools/check_distribution.py` is retained test support. Its disclosed runner seam
requests execution and grants no permission. Reports using `--test-support
 tools/check_distribution.py` retain its complete bytes, hash, line count and
combined total. Permission or containment logic added there must be reclassified
as enforcement.

## Execution and cleanup

`source_host.py` prepares measured source, locked dependencies, runtime and guard
support. Inputs become read-only in private mount, network and IPC namespaces.
Tests run as UID20000 without capabilities. The independent observer runs as
UID20001 with DAC_READ_SEARCH and SYS_PTRACE. No external network interfaces or
routes, ambient sockets, credentials or generic provider authority are supplied.

The native entry installs its audit hook before Python initialization. Protected
observer-owned mode0444 profiles bind executable/source/support bytes, exact
argv/env/cwd, current process birth and parent, credentials, mount identities,
execution domain and inherited descriptors. Profile files are bounded at65,536
bytes; authenticated control requests retain their8,192-byte bound.

A family builder independently reconstructs each finite proposal. Caller labels
select no permission. Current byte/vector/custody checks and kernel exec stops
bind the actual child before its body executes; Python entries also require
native body READY. Unknown or forbidden effects poison the run even if a test
catches the exception. No generic interpreter, shell, Git or provider allowlist
follows from a declaration. Every descendant needs independent admission.

Signals require a finite cleanup route and an owned live child with matching
birth/token/generation. Original-parent terminal wait4 and independent kernel
terminal observations establish cleanup. Before resuming wait4, the observer
checks the waiting thread and positive owned child PID. Foreign, wildcard and
unregistered Python waits fail even if WNOHANG would return0 or ECHILD could be
caught. Linux pid_t is decoded as signed32. Independently admitted native Git/uv
classes alone retain their bounded wait-any/prefork-poll exception; polling
cannot retire or admit a child.

No Python return code receipt supplies parent-wait proof. Tracer or fallback
cleanup does not stand in for the original parent. Existing SIGKILL thread-group
terminal handling does not fabricate a missing process exit or parent reap.
Native status86 retains its refusal meaning. Case completion still requires all
expected children, consumed intents, actual statuses and original-parent joins.

## IPC admission model

Socket construction and adoption remain restricted. DNS, datagrams, arbitrary
families and Unix pathname connection effects remain forbidden. Each TCP bind
or connect requires independently selected case/actor authority. A listener
registration binds current Birth/UID, descriptor identity and literal loopback
address. Each connect reacquires that exact owned listener and a fresh unbound
client descriptor, checks owner readiness/generation, and consumes finite quotas.
Shared listeners never transfer another server's authority. Case and owner
retirement revoke future admissions; owner retirement still requires the actual
parent wait. Reconnecting always needs a new admission.

After admission, ordinary Python and the kernel own stream IO. The guard does
**not** certify application accept, reciprocal accepted-FD identity, every later
FD alias, queued payload bytes, EOF-only drains or application authorization at
each read/write. It no longer sends per-payload, connected or accepted RPCs, nor
wraps file IO or multiprocessing Connection callbacks. No socket payload RPC is
parked during SIGKILL cleanup. Removing that RPC removes the artificial guard
race; it does not supply or waive any original child cleanup assertion.

Unix self-pairs retain actual reciprocal acquisition at creation. Multiprocessing
retains exact inherited FIFO/socket identities, directions, ownership, child
readiness, finite child/tracker entries and actual waits. New inheritance or a
replacement descriptor is not admitted by a stream operation.

ROOT HTTP reaches only the selected case's actual broker listener, under its
finite connection quota. FastMCP private objects, bearer-token internals and
contextvars no longer serve as a second authorization oracle. Product tests keep
their actual authentication, refusal and context-lifetime assertions.

Source-result schema v3 records listener/routes and connection-admission counts,
with `application_payload_proven=false`. Its original-parent wait evidence is
unchanged. Historical v1/v2 records retain their own proof model; v3 does not
reinterpret or upgrade them.

## Finite launch families

Family builders retain original programs and parameter identities. Literal or
repr-only rendering never evaluates arbitrary test expressions. Acquired pytest
roots, repository paths and prepared inputs retain their owned generations.
Ordinary wrappers preserve real constructor, pipe, status and cleanup behavior.

Controlled ACP uses the explicitly selected separate Python adapter/backend,
authenticated Bridge and production owner. Omitted selection remains native and
retains native pin refusal. Configuration inputs remain byte-bound. Native
conversion/acceptance and final timing remain unverified.

Console dispatch uses exact pytest/unrest/unrest-server image paths. The latter
two execute actual generated installed scripts with current complete bytes and
project/installed registration checks. Stock uv0.11.8 retains its actual measured
first/nested environment transformations and one exact installed-console child.
`UV_NO_PROJECT=1` disables synchronization without the redundant warning-producing
`UV_NO_SYNC`. Both console-to-uv and uv-to-original-parent waits remain required.

Archive checking, extracted persistence and installed bodies use actual prepared
candidate bytes. Copied-source credential tests acquire the actual owned copy
into an immutable snapshot; only its source-path operand is translated. Pending
fixture provenance does not count as completed: real body READY, exit0 and
parent wait are required. Source, installed and extracted provenance remain
separate. These leaves grant no provider or descendant launch.

Readiness leaves retain original deadlines, redaction and drain assertions.
Their one literal probe grants neither payload-certification nor accepted-peer
proof. Terminal leaves retain every credential-transform parameter and exact
program/env/cwd; native optional-null controls admit only `/usr/bin/true`.

Git retains finite authored command forms, repository/worktree custody, exact
argv/env/cwd and bounded stdin data, hook/remote/helper restrictions, and actual
parent/descendant waits. Object IDs are exactly40 lowercase hex characters;
revision expressions are only fixed authored forms. Paths retain owned slot and
backlink constraints, and integration-message/date operands retain their bounded
formats. No generic Git option or executable permission follows.

The guard no longer certifies commit/tree/date semantic dependency graphs or
original Python stdout-object continuity. Product tests certify correct refs,
integration, rollback and authority. Actual command status is retained; ordinary
commands no longer get an implicit exit-zero requirement from a value producer.
Native helpers and completion queries keep their explicit zero-status checks.
Source-result records mark `git_value_provenance_proven=false`; this grants no
external review acceptance and does not reinterpret older records.

Additional foundation, project, improvement and activation Git fixtures use the
same repository admission. Exact collected case IDs declare repository slots,
original setup argv and setup/call phase. Their complete source files are pinned;
owned pytest directory generations cannot change between slots. Plain-init
foundation fixtures acquire either `main` or `master` once and reject a changed
HEAD branch. Proposals must match that acquired branch. These declarations grant
no native provider execution or new application-level Git proof.
The two activation CLI routes reuse the stock-uv image and single console-child
admission. Their request files are bounded JSON at exact owned fixture paths;
request semantics remain the original product tests' responsibility. Existing
invalid/task request-byte checks remain. Mixed Git/uv cases retain every actual
parent wait and separately require the exact uv/console child count.

The foundation async error cases reuse the library-module child domain for one
exact `run_worker` entry and retained request identity. Executor, generation,
private home, argv and environment stay fixed; approval recovery is off, stdio
is null, and no descendants or provider launch is declared. Actual parent wait
is required. `RunControl` retains the real handle and joins terminal workers;
it does not turn a durable PID record into ownership.
Bare fixture Git commands are executed through the measured `/usr/bin/git`
image directly, avoiding undeclared PATH probes when stock-uv support adds a
runtime bin directory. Command arguments and original product assertions remain.

Stdio containment has one common rule: descriptors 0–2 must be `/dev/null` or
FIFOs currently held by the actual parent, or the identical regular file already
used for the same numbered parent stdio descriptor. This retains redirected
parent stdio, including test capture. Sockets, arbitrary character devices and
substituted regular files remain refused. The original HTTP fixture retains
its separately acquired, exact owned log-file exception. Extra inherited MP
resources remain independently bound. Original null/inherited/merged stream
shape is an application-test assertion, no longer an additional guard claim;
actual process identity, READY and original-parent waits are unchanged.

Child bootstrap validates its authenticated observer-issued execution entry and
membership in the externally selected inventory. Full-discovery references are
loaded and byte/source/dependency checked. The finite builder and uniquely
consumed intent remain the authority for issuing a child profile; collection
membership grants no launch. Duplicate child-side role/case and focused-group
catalogues are removed. Actual identity, parent, argv, environment, mounts,
inherited descriptors, execution pins and READY checks remain.

Controlled and bootstrap TCP listeners use one same-case owned-listener admission.
The observer acquires the literal loopback FD/cookie and enforces finite per-case
listener and connection quotas, READY, fresh clients and listener reacquisition.
Existing client classes remain closed. An ACP relay tuple remains exact bounded
application input; its ports must name acquired same-case root listeners, and its
complete environment is bound again at exec. Nonces no longer confer authority.
The guard no longer certifies broker/bridge/lifetime pairing, handshake nonce
correspondence or listener ordering; original product tests retain those checks.
Backend-first child admission, owned launch-home checks, native review refusal,
actual original-parent waits and private network/Unix-control separation remain.
Advisory port probes never become listeners. MCP slot ownership and its explicit
retirement remain separate. Python application-context wrappers are removed;
only finite multiprocessing hook installation remains after discovery.

Three original ACP invalid-format startup cases reuse ordinary native-fixture
admission: the exact no-op sleep child and a case-owned mode-0700 file with the
original non-executable-format bytes. The relative argv is preserved; the exec
attempt is measured against the acquired cwd and pinned absolute file. Expected
ENOEXEC retains generation zero and the actual numeric parent wait; it never
fabricates Python READY or protocol completion. Provider configuration and native
pin-refusal cases remain unchanged.

Unused Python instance/namespace introspection is removed with the retired
application-context wrappers. Its obsolete guard-only model controls are removed;
original product tests are unchanged. The manifest round-trip verifier is now a
test-local oracle, retaining all byte/schema/race controls. Production uses the
unchanged bounded capture/validation primitives and authenticated input references;
no production admission or enforcement imports that test oracle.

Launch descriptors are trusted output of the selected finite builders, not a
second input language. Proposal ingress owns primitive, NUL, UTF-8, environment-key
and canonical-cwd rejection; authenticated JSON frames retain their existing byte,
depth and work bounds. Authored relative executable/argv spelling and legal empty
environment names remain. The separate MP route still reconstructs its exact
stdlib templates and observer-owned environment. Descriptor construction retains
payload-kind interpretation, inline-body hashing, executable digest checks and
external script/module pin requirements, with deterministic environment ordering.
Its duplicate producer-side tuple and aggregate-budget codec is removed. Negative
controls exercise actual ingress/frame rejection and unchanged byte/exec binding.

## Verification and retired model controls

Every original product/source test and its real completion, status and cleanup
assertions remains. Guard controls retain unknown-launch, foreign/PID-reused owner,
non-loopback/DNS, ambient inherited FD, stale listener, sticky caught refusal,
quota/retirement, invalid profile and missing-parent-wait negatives.

The unused TCP empty-EOF query is removed; native socket controls retain real
cookie/FD acquisition, payload reads and actual child waits without claiming
application accept or EOF certification.

Model-only controls for queued-send/accepted-ticket joins, post-connect payload
reauthorization, EOF-only drains, parked payload cancellation, and Git semantic
producer/stdout-object chains are retired with
those claims. Their historical source and outcomes remain in Git. New controls
assert finite fresh listener admission, continued wait requirements and the
absence of application-payload claims. This is an explicit changed proof model,
not a claim that the removed controls passed under a new implementation.

Focused groups prove components only. Normal full discovery and all bodies on
Python3.13, without exclusions, remain the frozen source checkpoint. Build/archive
membership and complete bytes, safe extracted-tree all15 persistence cases,
unrelated-cwd installed lifecycle and fail-closed startup, independent validation,
desktop/CI, publication and protected local update remain required. Separate USER
policy and unrelated untracked data must be preserved. No release certification
follows from a selected group, collection-only run or current size report.
