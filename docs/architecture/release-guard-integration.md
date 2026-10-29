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

Socket construction and adoption remain restricted. TCP effects are literal
IPv4 loopback inside the independently verified private network namespace. DNS,
datagrams, arbitrary families and source Unix pathname/abstract bind/connect
remain forbidden. The private control pathname retains its independent kernel
peer authentication and current registration/token checks.

Anonymous AF_UNIX/SOCK_STREAM self-pairs need no observer receipt. The guard no
longer certifies their creation history, reciprocal peer lineage or case-owned
pair graph. When an exact multiprocessing declaration passes a socket FD, the
observer independently duplicates that actual parent file description using
`pidfd_getfd` and measures its UID, inode/device, access flags, unnamed local/peer
addresses, domain/type and SO_COOKIE. The immutable inherited row binds those
facts to the admitted parent's PID and birth ticks. Child bootstrap checks the
actual inherited descriptor; the observer independently reacquires the child's
same description at core READY before BODY_READY. Duplicates close immediately,
without I/O or flag changes. Creation-time SO_PEERCRED is a UID/GID constraint,
not proof of live reciprocal peer lineage. Observer privileges do not change.

Ordinary Python and the kernel own stream I/O. There are no per-payload,
connected/accepted or anonymous-pair receipt RPCs. Original product tests retain
authentication, readiness, protocol, payload and cleanup assertions. Evidence
marks retired TCP/pair claims unproven and retains actual numeric parent waits;
older evidence is never reinterpreted or upgraded.

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
parent wait; admission retains the exact per-case uv/console launch quotas.

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

Child bootstrap authenticates its observer-issued execution entry and checks
actual process/parent identity, argv, environment, mounts, inherited descriptors,
script bytes and READY. The uniquely consumed intent binds role and selected
case before profile issuance. Normal collection is sealed and source/dependency
bound once at the root. Re-decoding that same inventory in every child grants
no authority and is removed; private-profile custody and exact consumed-intent
checks remain mandatory. The full console's operation choice is bound at kernel
admission and its normalized argv is compared to the private profile; the
consumer does not reconstruct that choice again. Archive provenance retains its
separate original-path exclusion checks.


Controlled/bootstrap relay and HTTP ports are bounded application operands in
the complete admitted argv/environment. Network isolation and literal-address
checks provide containment; product tests establish listener/readiness and
protocol behavior. Backend-first admission, owned launch-home checks, native
review refusal and actual original-parent waits remain. Advisory port probes
confer no authority. Only finite multiprocessing hooks remain after discovery.

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
non-loopback/DNS, ambient or replaced inherited FD, sticky caught refusal,
finite launch quotas, profile custody and missing-parent-wait negatives.

Native socket controls verify actual inherited cookies/descriptors, named-socket
refusal, birth replacement and duplicate-handle cleanup. Application accept and
EOF are product-test obligations.

Model-only controls for queued-send/accepted-ticket joins, post-connect payload
reauthorization, EOF-only drains, parked payload cancellation, and Git semantic
producer/stdout-object chains are retired with
those claims. Their historical source and outcomes remain in Git. New controls
assert finite fresh listener admission, continued wait requirements and the
absence of application-payload claims. This is an explicit changed proof model,
not a claim that the removed controls passed under a new implementation.

Selected diagnostics prove components only. Normal full discovery and all bodies on
Python3.13, without exclusions, remain the frozen source checkpoint. Build/archive
membership and complete bytes, safe extracted-tree all15 persistence cases,
unrelated-cwd installed lifecycle and fail-closed startup, independent validation,
desktop/CI, publication and protected local update remain required. Separate USER
policy and unrelated untracked data must be preserved. No release certification
follows from selected diagnostics, collection-only runs or the size report.


RunControl's original lifecycle tests reuse the library worker entry with exact
case, operation, run identity, generation, environment and worker-count bounds.
The one `executor_fixture` import compiles only the source bytes acquired through
nofollow file descriptors and checked against the original pinned test fixture;
its original path and inode generation remain bound through import. No owned cwd
is appended to the import path and cached bytecode is never used. The restart
case alone admits its exact one sleeping descendant, owned by the admitted worker
and retaining its actual numeric parent wait. Cancellation (exit two following TERM), crash and explicit SIGKILL cases
keep their authored per-worker-ordinal statuses; ordinary completion remains exit zero plus READY.
The main script profile now derives from the admitted effective vector rather
than a parallel role-to-script catalogue; the delayed-backend auxiliary script
retains its independent pin.


The TCP boundary is the run's distinct network namespace, verified before source
execution to contain only loopback and no external gateway or usable external
route. The namespace identity is bound into every authenticated child profile
and checked again at kernel exec admission and native bootstrap. Sources retain
zero capabilities and `no_new_privs`. Python TCP effects permit only literal
IPv4 loopback and bounded numeric ports; DNS and other destinations fail sticky.

Per-case TCP peer ownership, listener FD/cookie reacquisition, connection/listener
quotas, preceding port-reservation causality and TCP route-retirement proof are
retired guard claims. Dynamic HTTP and relay ports remain bounded application
operands in the complete admitted argv/environment. The original readiness,
Bridge, private preflight, MCP, completion and cleanup tests establish application
behavior; no controlled result becomes native provider acceptance. Evidence
explicitly records these TCP claims as unproven. Guard-only controls for the
retired graph are replaced by literal-effect controls and a real root Linux
namespace control that excludes a host loopback service, exchanges local bytes,
drops source capabilities and performs the actual parent wait.

Exact inherited Unix-description checks, the peer-authenticated control
pathname, immutable native/script/argv admission,
finite launches, READY and original-parent numeric waits remain mandatory.
Filesystem Unix sockets receive no general allowance. Every original product
case and assertion remains, including the strengthened RunControl joins.


Git containment no longer certifies fixture operation ordering, observed branch
value continuity, the completion repository's whole-content immutability or HEAD
value correctness. Original Git/product tests retain those assertions. The guard
keeps exact authored command forms, phase/environment/cwd, native image, acquired
repository generations, linked-worktree backlinks, closed routing configuration,
helper identities and original parent/helper waits. Only main/master update refs
explicitly authored by each fixture remain eligible. Completion queries still
require their consumed server owner and finite query slot.


Workspace/evolution Git now has one authoritative complete-argv matcher. Dynamic
OIDs, dates, owned paths, refs and commit input are validated in their matched
positions. The separate inverse grammar, forward reconstruction and duplicate
rollback-label reconciliation are removed. Closed case/operation declarations
still select the eligible forms before matching; complete environment/cwd and
kernel exec identity checks follow. Literal vector fixtures live only in tests
and are excluded from native support; they confer no launch authority.


The tracer retains actual kernel identity, birth, exec, exit, signal and numeric
wait records. Per-stop CPU clocks and diagnostic resume counters are removed;
they were telemetry rather than admission or completion evidence. Mixed-user
cleanup controls inject their failure at the actual retained-stop ledger, then
retain all original drain and actual-parent-wait assertions. Test failure stacks
and original encrypted evidence are unchanged. No performance or provider final
timing claim follows from the smaller tracer.


New-session admission uses the registered kernel parent/birth and the actual
observed transition from the parent's original group/session to child PID group
and session. Observer-generated admitted/registered/lifecycle dictionaries are
removed: they repeated values from that same registration and supplied no
independent witness. The actual identity, group, one-transition and READY gates
remain; genuine provider review/approval evidence is a separate unchanged scope.


Content acquisition owns file/path/type/link/mode/size/race checks. Its captured
manifest is encoded deterministically under the existing byte limit without a
second schema decoder. Native bootstrap authenticates the protected manifest's
complete bytes against its bound SHA before projecting source pins; it retains
the native-record/readonly-generation agreement. Git/native preparation still
measures the actual inputs before source admission. A source cannot create a new
valid manifest by declaring its own hash; the hash comes from the protected
observer profile. Test-only roundtrip oracles still remeasure files and compare
canonical bytes, including malformed/coherently rehashed fixture negatives.


Protected source profiles are parsed once by `native_entry.acquire`, under the
observer-owned directory/file identity, mode, link and stable-read checks. Their
consumer no longer decodes the producer's schema, canonical path, digest format
or execution-descriptor shape again. The observer still constructs execution
descriptors from exactly one consumed launch intent. The consumer checks actual
entry event/arguments, script/data bytes, executor-fixture custody, process and
parent identities, credentials, environment, cwd, namespaces, readonly mounts,
CPython flags and inherited descriptors. Authenticated producer data never
replaces these live comparisons. Controlled configuration rendering similarly
consumes its authored declarations; raw relay input remains validated.


The completed preflight54 development selector and its production collection
catalogue are retired. Normal unexcluded discovery still collects every original
preflight test; its nine real launch cases retain their exact declarations.
Non-launch cases use the observer's default zero-child rule and unknown process
requests still refuse. The frozen 54-case list is only a test collection oracle,
excluded from native support, and grants no launch or completion authority.


Candidate-input tests share the existing disposable Git repository/image/wait
boundary. Their 113 exact fixture consumers have nine setup commands extracted
only from the byte-pinned `repo` fixture. Additional writes and queries are closed
case/parameter-selected complete vectors, with full object IDs in the two dynamic
positions, exact environment and a finite ordinal. Canary cases admit only their
original final configuration write: no subsequent Git command or helper launch
is authorized. The repository's closed routing configuration is reacquired before
each Git launch, and its owned generation and every original parent wait remain
mandatory. These are controlled fixture tests, not provider acceptance evidence.


The candidate fixture explicitly disables Git automatic maintenance using its
closed per-command environment. Disposable input-integrity repositories do not
test maintenance; this prevents an incidental native child without granting any
new helper authority. Repository config mutations, input integrity/refusal
assertions and original case IDs remain unchanged. The prior missing-helper
failure is retained rather than relabelled as a pass.


RPC framing retains the receiver's bounded JSON decoder, kernel peer binding,
registration epoch, request ID/replay checks, closed method authority, exact
reply echo, deadline and sticky failure handling. Fixed constructor arguments
and authenticated observer-produced replies are no longer decoded again as
untrusted configuration in source-side wrappers. The sender still bounds its
encoded frame; the receiver still validates every incoming request.


The tracer uses the stopped ptrace task and its measured birth identity through
its actual terminal wait; it does not hold an unused pidfd for every observed
birth. Process measurement independently checks stable start ticks, and the root
must match the original acquired child. Transient pidfds still acquire inherited
Unix descriptors. Historical evidence retains the descriptor exhaustion caused
by holding handles until suite completion. A bounded native control runs 160
sequential children under a 96-descriptor limit, checks actual descriptor use and
every original numeric wait. Failure cleanup never infers missing waits.


READY has one protocol. The transport authenticates the current birth, token,
registration generation and unique request ID; the ledger transitions registered
to core-ready to body-ready under exact pins/seal, live-process and session checks.
An observer-generated second sequence/epoch protocol is removed. Kernel execution
generations remain independently bounded and stale or out-of-order READY refuses.
Historical body readiness remains available after exit for completion checks;
actual terminal and original-parent wait joins are unchanged.


Development and release execution use the same stock UV → fixed native pytest
console → normal collection/outcome path. The old selected-node root driver and
selector-only group catalogues are removed. A diagnostic selection is protected
metadata: canonical existing `tests/*.py` paths with optional original node text,
not pytest option tokens or path aliases. The one exact pytest suffix is shared
by launcher, native console and effective module argv checks. Selection confers
no process permission; closed case/argv/image/owned-root declarations still
admit every child, and unknown or forbidden launches still fail sticky.

Only an explicitly empty selection, non-collection mode and all successful
normal source outcomes can mark the unexcluded source checkpoint ready.
Selected diagnostics retain the short bounded deadline and cannot certify a
release. The archive's original fifteen-case extracted-tree oracle remains a
separate route. Cleanup RPC deadlines follow the authenticated active case on
both sides rather than a development group name. No contract reference cases
are silently inserted or assertions changed by selection.


Git operation eligibility derives from its one closed command grammar, subtracting
explicit workspace-only/setup operations for the narrower families. Ordered
fingerprints preserve the previous exact lists. The observer still selects the
case/family before the complete-vector matcher and verifies actual ownership,
image and waits. Expected-payload rendering keeps closed kinds, mode agreement,
inline hashing and external pins; producer-only reference-absence, script-path,
module-name and type decoders are removed. Proposal ingress and actual bootstrap
script/image remeasurement remain independent mandatory checks.


Waitid/SIGINFO telemetry and its observation-count limit are retired. Neither
WNOWAIT nor waitid-only reaping supplies retirement evidence. The real WNOWAIT
control retains its application assertions and subsequent actual terminal
waitpid result; a separate native negative shows waitid-only reaping produces
no original-parent wait4 join. Every admitted process still requires its numeric
original-parent terminal wait4 matched to the observed birth, exit and tracer
terminal status. Missing waits remain fail-closed.


Historical release checks use their original source-pinned cases and finite
readonly Git commands over the closed public projection. They cannot mutate a
repository, query other paths/revisions, or launch helpers. Each command retains
exact image/environment/cwd binding, one consumed intent and its actual original
parent wait before the next command. Historical cases use their own closed readonly command inventory.
The private source copy includes a fixed ignored egg-info marker so the existing
ignored-file exclusion assertion remains a real probe in the readonly source
suite; this generated test input is outside the candidate tracked-file binding.

The release-binding CLI case admits exactly its active/wrong manifest invocations
with script bytes, owned fixture generation, complete argv/environment and
expected statuses 0/1. Only those authenticated children may request the two
readonly inventory forms in the original empty repository. Its metadata must
retain the literal HEAD and empty objects/refs without config or aliases; no
helper or root-level Git authority follows from the nested route.


The guard does not certify a second expected child count for each source test.
Original pytest assertions and outcomes prove the test's execution expectations.
Finite admission declarations and their quotas remain unchanged. At case finish,
every issued intent must have been consumed and every actual actor must satisfy
its completion contract and independent original-parent terminal wait. Skipped
cases must launch no children. Completion-server status/session/READY checks and
package provenance remain mandatory; only the duplicate expected-count claims
and finish-only count calculators are retired.


Constructor-return RPC receipts are retired. Source wrappers retain local Popen
handles for owned signaling, while dependent launch gates require the consumed
intent's matching kernel Birth/token/case and actual execution generation equal
to registered generation 1. A consumed intent alone is insufficient because it
precedes successful exec. Pending execution holds the bounded RPC request; a
missing or foreign declaration still refuses. Historical successful execution
remains usable after exit, and all terminal/parent-wait obligations remain.


Normal pytest's runtime-first PATH exposed a legacy assumption in completion
fixtures: bare Git attempted a nonexistent runtime-bin path before the admitted
system image. Source wrappers now resolve the literal `git` executable directly
to `/usr/bin/git` for their existing launch-owner roles while retaining the
original argv. This selects no operation or case permission. The observer still
requires its complete finite declaration, image, environment, cwd and custody;
unknown requests refuse before fork. The denied PATH attempts remain evidence.


Measurement source fixtures have a separate finite Git family: the exact
source-pinned init/add/index-query forms in their owned `source` slot. Synthetic
protocol tests may carry only the original two mock-ACP command environment
values for index queries; those strings grant no process permission. Native
image, readonly home configuration, repository generation, per-case quota and
actual prior parent wait checks reuse the common Git boundary. Cold-workspace
and nested ACP launches remain separate declarations; this source-fixture slice
does not certify those paths or authorize live provider/benchmark work.

Cold measurement repositories are confined to the original two repetitions of
each genuine library test, one acquired run UUID and stable owned directory
generations. Setup has three exact forms; workspace/evolution operations reuse
the closed shared Git grammar and actual helper/wait custody. The evolution test
admits exactly its two original start-project RunControl entries with retained
request identity, fixed executor, complete environment and numeric status zero.
This enables its provider-free state machine; it grants no ACP or provider launch.


Immutable-input provenance belongs to the protected generation's issuer. The
host measures and seals the source/runtime/dependencies and verifies their
readonly mounts before dropping credentials. Every kernel exec is checked in
the observer's actual mount/network namespace, and child bootstrap still checks
its complete measured identity, namespace equality, zero capabilities and entry
binding. Children no longer reinterpret the same readonly mount inventory.
Archive acquisition still compares all original bytes, verifies every copied
byte and seals observer-owned files444/directories555. The observer retains and
rechecks the snapshot at exec; the leaf uses its already-bound snapshot cwd.
The second serialized full-manifest file and child-side snapshot walk are
removed. Cleanup/review JSON inputs likewise remain exclusive observer-owned
444 files in protected ancestry with exact issued argv; children do not rehash
those trusted issuer records. Mutable script compilation hashes and the
original executor loader remain mandatory. Actual namespace and mixed-UID
mutation negatives retain independent coverage of this custody boundary.


Provider configuration-search semantics are tested by the original configuration
suite. The guard no longer duplicates that suite's search-footprint inventory in
`configuration_inputs.py`. Exact selected case/backend bytes, complete argv and
environment (including disabled features/skills/MCP controls), owned cwd, actual
native identity and native no-launch negatives remain admission requirements.
This removes a second application-behavior oracle; it grants no provider launch,
permission override, alternative method or recovery of a denied review.


The project measurement test declares its original eight RunControl operations
across repetitions 01/06. Only the three advance workers receive the corresponding
six fixed work/validator node identities. Nested MCP/mock-ACP pairs bind the
actual worker Birth/token/exec, one owned project record, running node cursor,
exact attempt path, original targets, complete environment and isolated native
entry. Each prior pair must be actually reaped before the next node. MCP retains
its exact inherited pipe and local port; only the source-pinned mock script may
act as ACP. Mock exit0 and MCP exit0/authorized TERM/KILL retain explicit
completion checks. No native provider acceptance or live benchmark follows.

Unused digest tables left by retired focused-driver validation are removed from
controlled_cases/git_sites and unused startup/custody constants. They supplied
no runtime check. Active source-unit pins, generated backend postimage pins,
native/dependency identities and original ordered case maps remain enforced.

Owned process cleanup uses the same source roles that can construct declared
children. A local Popen handle and its observer-issued token are required before
a signal request; the observer independently verifies the exact parent birth,
active case, child token, permitted signal, and process-group identity. Installing
multiprocessing hooks is independent of this cleanup permission.

Cohort campaign cases share the existing controlled backend byte pins and exact
owner/role pair admission. The closed cohort table binds 35 campaign and 24
Git-only original cases to finite launch ceilings; its exceptional Git literals
apply only to their individual negative or integration cases. Custody Git waits
serialize each acquired repository generation, allowing distinct lane repositories
to seal concurrently. Every observed child still needs its actual completion and
original-parent wait at case closeout; this does not admit controller crash cases.

The real measurement project's local ACP mocks terminate through their owning
RunControl worker's authorized SIGTERM cleanup. Their actual numeric status stays
-15; completion requires authenticated body readiness and that exact signal in
the child's custody record. A missing signal, missing READY, unrelated nonzero
exit or missing original-parent wait remains a failure.

Native metadata is constructed once in a fresh protected host directory from the
original complete archive/member SHA256 pins. Each written member is reread for
its complete byte and size check before the fixed graph is made readonly. The
bind mount must expose that same measured directory generation, owned by root
with mode0555; the common mount inventory still verifies readonly coverage.
The duplicate arbitrary-tree walk after mounting is retired. Source children
cannot modify these inputs, and metadata remains data with execution forbidden.

Profile acquisition and content measurement now share held nofollow directory
descent and chain verification. Root ancestors retain their directory-generation
key; member ancestors retain the stricter timestamp-inclusive key. Native profile
reads use the same complete bounded regular-file acquisition with the existing
UID20001/mode0444 checks. No source code runs before this boundary. Unused
bootstrap properties and the unconsumed skip accumulator are removed; real skip
outcomes, original phases and constructor ceilings remain.

The original cohort stop-file tests stop sends after reservation or dispatch,
but initialize one owned controlled pair before the next send-boundary check.
Their admission ceiling therefore permits that single startup pair; the original
zero-prompt assertions still verify no turn was sent. This does not apply to the
intentional controller crash at reservation.

The four original cohort controller-crash parameters have a separate exact
controller descriptor. Its admitted body and environment are byte-bound to the
unchanged original case; only that consumed controller Birth/token can construct
its four setup Git children and (except at reservation) one controlled backend/ACP
pair. The controller must have authenticated READY and an original-parent wait73.
Reservation admits no transport child and has no exception.

For the other three parameters, the previously approved two-child exception uses
passive adoptive closeout. A protected observer request names only those two
registered READY children, after all four Git waits and controller wait73. The
host subreaper verifies each adopted PID's stable birth and actual parent before
an exact nonblocking wait, and atomically publishes a root-owned receipt. The
observer joins each raw receipt status to its traced terminal status within one
20-second deadline beginning at the observed controller wait. This never writes
an original-parent ledger join. Child numeric status and final timing remain
UNVERIFIED, and the evidence labels original-parent cleanup as unproven. There
is no successful-path signal or cancellation; expiry retains failed status and
the existing failure cleanup. Only these authenticated case-finish RPCs receive
22 seconds for transport; the provenance deadline itself remains20 seconds.

Observer-created actors retain the uniquely matched consumed launch intent by
reference. The lookup uses its monotonic ticket and object identity, then checks
Birth/token/case/role and consumed state. Completion and child-result handlers
reuse that binding instead of independently searching the intent collection.
Removing a ticket or changing its identity still invalidates the binding; all
existing READY, exit-code, authorized-signal and actual-parent-wait predicates
remain separate requirements.

Application exit-code interpretation belongs to the unchanged original source
tests. The guard no longer independently predicts RunControl's0/2/17 conventions,
multiprocessing target exits, binding CLI0/1, readiness23, ordinary UV refusal1,
or desktop/console/terminal success0. These were additional guard-only expectations;
not every original test asserted each interpreter number verbatim. Their removal
retires that guard claim rather than claiming those extra assertions still exist.
Admission ceilings formerly encoded by RunControl's exit list remain explicit
counts, and spawn target/resource quotas are unchanged.

Retirement still requires the consumed ticket's Birth/token/case/role binding,
actual guarded body execution (or native admission), a kernel terminal result,
and the matching original-parent numeric wait. Negative termination additionally
requires the exact recorded authorized signal. Only the previously supported
controlled/owned cleanup roles retain early-body cleanup; measurement ACP and the
RunControl descendant require READY. Native86 refusal and sticky guard poison
remain failures. Failed-exec proofs, plan exec generation, archive and installed
provenance, nested-pytest seals, completion-server transitions and the exact cohort
controller73 exception are retained. No source test, parameter, assertion or
refusal context is removed or selected out by this ownership change.

Preparation warms stock UV's interpreter cache once with its fixed version,
interpreter and cache paths. The duplicated preparatory environment probes are
retired; real root and CLI exec admission still compare the complete actual argv,
environment and binary pin. A cache miss grants no helper permission. Fixture
parameter axes preserve the complete ordered original map.

Bounded file acquisition now reads at most the pre-read size plus one byte using
the already-held nofollow descriptor. Exact length, complete hash, UID/mode/nlink,
post-read identity and held-ancestor checks remain. Hash-only reads use transient
memory proportional to that bounded file (up to64MiB for dependency inventory),
replacing the streaming counter; retained reads avoid a second bytearray copy.
All five replacement-during-read races still exercise the actual read boundary.

Observer validation failures now propagate through one fail-stop boundary into
OwnedTrace's bounded owned-process cleanup. Internal Ledger, Frame and Admission
objects have no reuse-after-caught-error contract; the former continuation and
local poison wrappers are retired. The source policy, native entry and tracer
retain their sticky refusal state, including refusals caught by application code.
Accepted sockets enter the observer's owned collection before capture, and each
source RPC closes its fresh frame in a finally block.

Private source-result v4 retains the initiating failure, all control and kernel
records, and the tracer's actual `trace_poison` value. Earlier evidence schemas
remain unchanged. Linux controls inject ledger, frame and admission failures at
the trace callback boundary and require actual bounded owned-root cleanup while
an unrelated child remains untouched. Buffered file-read race controls intercept
the actual fdopen/read boundary; FIFO negatives still refuse before that boundary.

All admitted MCP entries use the product's banner-free server entry, so the guard
no longer injects a FastMCP update-check environment variable. The original
observed and executed environment is identical. An Expected declaration carries
only concrete case/image/argv/environment/cwd/payload operands; the redundant
reply rule label is retired. Cleanup scenario translation uses the dispatcher's
independently selected cleanup role instead. No label grants execution authority.
Multiprocessing's conditional installation lives with its hook implementation.

Standalone extracted persistence certification and nested archive leaves share one
original-probe executor and report-phase verifier. Standalone execution retains
the root actor and its individual case-start/case-finish protocol, then seals the
root; nested execution retains its enclosing archive actor and archive-result.
The extracted tree imports the measured dependency copy of the original oracle,
with the original checkout passed as the excluded provenance root. Omitted corpus
and package negatives remain distinct and cannot produce a successful root seal.
