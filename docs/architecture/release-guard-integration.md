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

`tools/check_distribution.py` is the retained distribution oracle. The primary
release budget counts its complete file inside the same ceiling using
`--support tools/check_distribution.py`; it grants no execution permission through
its runner seam. The obsolete `--test-support` comparison mode is removed so it
cannot accidentally exclude this mixed-purpose file from the release gate.

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
Native status86 retains its refusal meaning. Case completion still requires every
admitted child, consumed intents, actual statuses and original-parent joins.

## IPC admission model

The network boundary is the verified private loopback-only namespace, not
per-role Python socket wrappers. Kernel admission permits contained IP stream
and datagram sockets, anonymous Unix stream/datagram/seqpacket IPC and route-netlink queries; excluded
families, raw IP and io_uring calls fail sticky. Python Unix pathname/abstract
bind and connect remain refused except the exact authenticated control connect.
Resolver calls use the actual system implementation inside this namespace.
The private control pathname retains its independent kernel peer authentication
and current registration/token checks.

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
argv/env/cwd and bounded stdin data, closed native/helper execution, and actual
parent/descendant waits. Object IDs are exactly40 lowercase hex characters;
revision expressions are only fixed authored forms. Paths retain owned slot and
canonical-directory constraints; commit-content operands remain bounded data. No generic Git option or executable permission follows.

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
fixtures permit the authored `main` or `master` reference forms; other fixtures
retain their fixed branch forms. Observed HEAD continuity is an application-test
responsibility. These declarations grant
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
and retaining its actual numeric parent wait. Retirement requires actual guarded
execution and the matching original-parent numeric wait; negative termination
also requires its recorded authorized signal.
The main script profile now derives from the admitted effective vector rather
than a parallel role-to-script catalogue; the delayed-backend auxiliary script
retains its independent pin.


The TCP boundary is the run's distinct network namespace, verified before source
execution to contain only loopback and no external gateway or usable external
route. The namespace identity is bound into every authenticated child profile
and checked again at kernel exec admission and native bootstrap. Sources retain
zero capabilities and `no_new_privs`. TCP/UDP and resolver traffic stay inside
that namespace. Dynamic application port operands remain bounded numeric values;
per-role address-family and literal-only resolver restrictions are retired.

Per-case TCP peer ownership, listener FD/cookie reacquisition, connection/listener
quotas, preceding port-reservation causality and TCP route-retirement proof are
retired guard claims. Dynamic HTTP and relay ports remain bounded application
operands in the complete admitted argv/environment. The original readiness,
Bridge, private preflight, MCP, completion and cleanup tests establish application
behavior; no controlled result becomes native provider acceptance. Evidence
explicitly records these TCP claims as unproven. Guard-only controls for the
retired graph are replaced by kernel/native controls and a real root Linux
namespace control that excludes host TCP/UDP services, exchanges local bytes,
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
repository generations, helper identities and original parent/helper waits.
Git configuration and linked-worktree backlink contents are application data
inside the private filesystem, not independently reconstructed routing proofs.
Only main/master update refs
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
is authorized. Its owned directory generation and every original parent wait remain
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
request identity, fixed executor, complete environment, actual guarded execution
and original-parent numeric wait.
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
act as ACP. Both children require authenticated READY, actual terminal status
and original-parent waits; negative termination requires its recorded authorized
signal. No native provider acceptance or live benchmark follows.

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
RunControl worker's authorized SIGTERM cleanup. The observed fixture behavior is
-15; completion requires authenticated body readiness and the exact authorized
signal for negative termination. A missing signal, missing READY or missing
original-parent wait remains a failure.

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

Frozen prepared distributions rely on the issuer's complete dependency-generation
measurement and the already-required read-only namespace mount. Consumers select
four fixed paths; they no longer repeat source/runtime/archive/installed/extracted
measurements after the seal. Preparation still performs the real build/install,
compares frozen source bytes before and after build, records complete member bytes,
and includes the receipt in the measured dependency generation. The observer still
reads the protected receipt for installed console-script pins. Snapshot acquisition,
original package/lifecycle tests, namespace checks and fail-closed launches remain.
The obsolete downstream-remeasurement assertions and unused manifest decoder are
retired explicitly; no original product test, parameter or assertion is removed.

The temporary guard diagnostic workflow is retired at freeze. Canonical CI retains
all guard pytest cases, the three bounded standalone native isolation controls,
full unexcluded Python 3.13 source validation, archive and installed lifecycle
checks, and always uploads encrypted native/source/archive evidence. Earlier
successful and failed diagnostic evidence remains private and unchanged.

The failed first unexcluded checkpoint exposed the two original inventory-FD
regressions as undeclared process families. Their declarations retain the exact
worker/reviewer modes, original private inventory pipe, literal Git setup/HEAD
commands, acquired pytest root, complete environments and actual parent waits.
The fixture disables optional detached Git maintenance explicitly; no Git helper
permission or original assertion is added or removed by that setup change.

Python readiness now has one authenticated BODY_READY acknowledgement after
actual profile/argv/environment/script validation and hook installation. For MP
children, independent inherited-description recensus precedes the one-time
registered-to-ready transition. Birth/token/current exec generation, completed
session transition, nonterminal state and exact empty payload remain mandatory.
The old intermediate handshake and issuer-hash echoes are retired; native Git's
pin comparisons remain. The native entry releases no candidate body before ACK.

Bounded JSON work validation belongs to frame decoding/encoding; internal launch
builders no longer repeat it. Inventory custody belongs to the immediately
following held-file read. Discovery records no synthetic empty skips list;
actual pytest outcomes still retain every real skip separately. Closed literal
client leaves retain exact source-unit/program bytes, ambient operands and quota
one; only the original SIGTERM-ignoring fixture gets a new session. Repeated
launch routing and directory retention share their existing exact validators.

The diagnostic workflow is temporarily restored while repairing the failed
checkpoint's missing families. Its selected runs never certify an unexcluded
source checkpoint or release; it will be retired again before final freeze.

Closed source-string templates share one renderer. Callers author ordered
expression/conversion/already-rendered-text rows from their existing trusted
values. The renderer accepts only string constants and JoinedStr, rejects format
specifications and unknown/reordered fields, and requires exact row exhaustion.
It evaluates no source expression and derives no permission rows from a template.

The three additional wire-helper consumers in provider_review_frames retain the
same pinned transport, inert scenario schema, sequential quota and actual waits.
Their 30 explicit original parameter nodes are checked against ordinary pytest
collection and the helper call sites. The five actual-runner scenarios remain a
separate family; their handoff/receipt schema is not admitted by the wire-only
boundary. The repository contract's two readonly status commands use its pinned
source owner and the existing public-history projection, without helper authority.

A trusted namespace supervisor primitive is being validated separately from
source certification. A childless root driver forks a holder, which creates the
PID namespace; its init mounts private procfs before executing its fixed host
callback. The outer driver remains outside that namespace and waits only for its
own child. Failed or interrupted waits never signal a PID already reaped, and the
first private failure record is retained. The native primitive control proves
real PPid1 adoption and numeric waits17/23. This primitive alone grants no source
case an adoption exception, resumed signaling scope or release eligibility.

The ordinary mock ACP declaration also covers the eight original full-job format
and credential-field parameters and the two concurrent startup parameters. The
observer derives task/attempt identities and public template canaries from pinned
source and the selected case; it acquires the owned pytest directory and retains
its inode generation. Native sleep retains exact inherited environment and argv.
Two sibling mock sessions have separate ordered identities and a quota of two;
this does not serialize their real protocol sessions or change test deadlines.

Source supervision now runs in that dedicated PID namespace. The outer host
prepares inputs and encrypts evidence outside it; it never interprets local actor
PIDs as host PIDs. The init process owns observer and adoptive waits, retains its
own fallback cleanup record, and fails certification if emergency cleanup was
needed. Source profiles and every exec resolution bind the actual PID namespace.
This topology change alone grants no new orphan or restart admission.

Launch catalogues contain only cases with admitted effects. Pure and preflight
negative cases remain in unexcluded pytest discovery and in the independent
negative controls; they use the global unknown-launch refusal. Their old
production catalogue copies and unreachable zero-child branches were retired.
No test is deselected, and adding a process to one of those cases still fails.

Five source-only server families (47 original parameters) share the two-command
Git fixture and bounded HEAD-query declaration. They gain no server or Python
child authority. After fixture setup, eight explicitly enumerated application
metadata environment keys may retain their observed values: Git does not use
them for execution, configuration, helpers or repository routing. Baseline and
all other environment keys remain exact; executable, argv, cwd acquisition,
sequence, query quota and actual exec environment equality are unchanged. Those
eight inert values are retained data, not independently predicted application
identities. This exception applies only to these native Git queries.

The five original matching-ID runner parameters reuse cleanup transport custody,
with their separately pinned approval fixture and exact Git commit arguments.
Their separate scenario schema admits only one inert response envelope, the
selected ordering, and the owned handoff/receipt paths. It retains bounded
protocol data without treating it as launch permission. Existing wire-only cases
still reject all handoff, receipt and frame-program fields. No external review
or denied-review retry is introduced by these controlled fixture cases.

Three further original HTTP families share the same role-server constructor:
completion refusal across orchestrator restart, targetless completion, and
completion target binding (15 parameters). Schedules retain distinct server
slots, role-only metadata, exact inert provider command strings (including the
original forbidden-child trap), and parent-local Git query bounds. Restart
inventory is the fixed native `ps -axo pid=,ppid=,pgid=` command, at most three
times after an admitted server; unlike supervision teardown inventory, these
original checks intentionally run while the server is live. No inventory result
can grant launch or signal authority.

The native constructor resolves only the fixed `git`, `ps` and `sleep` images
before CPython computes its PATH search. An audit-event argv translation occurs
too late to change Popen's saved executable search list; the failing native
inventory check exposed an undeclared PATH probe. This resolution seam grants
no permission: the independent observer still requires an authored case,
complete exact argv/env/cwd, executable bytes and a remaining quota.

The source inquiry/workspace/campaign result probe reuses the authored Git
workspace fixture and permits its one `start_project` RunControl worker. Its
original test intentionally observes the queued response. Before case closeout,
the guard additionally waits on that original parent's retained Popen handle
for at most five seconds and requires numeric success; a durable PID record or
process disappearance cannot replace this actual wait. No provider child or
additional RunControl operation is admitted by this fixture.

The substantive-defect probe also shares role-server custody: three exact Git
setup commands and two separately identified, pinned literal inline roles. The
work and independent validator attempts must already be running in the acquired
project/workspace; their original success, dissent and failed-gate assertions
remain intact. Queue closeout selects only the observer-tagged RunControl Popen
handle, excluding the fixture's already-waited Git handles.

Composed fixtures use an authored table of HTTP-parent slots, RunControl
operations, project slots, and explicit node/role sequences. A consumed worker
intent carries its selected sequence; a `decide_attention` worker has no node
permission. Targetless dispatch directly owns its node sequence in the HTTP
orchestrator. The shared ACP/MCP constructor binds the actual parent inventory
pipe, role environment, attempt and exact script/argv. Node module stdio is
selected from its observer-issued execution domain; root HTTP logs and new
sessions remain separate from nested MCP pipes and inherited worker groups.
Original cleanup polling bounds native inventory counts; inventory never grants
execution or signal authority. Restart adoption still requires its separate
proof before those cases can complete.

The composed wall-clock test contained one stale expectation from before the
accepted waiting-clock repair: it required a published waiting snapshot's elapsed
field to advance at 30 seconds. `docs/v5/08-mcp-surface.md` requires the complete
published waiting row to remain unchanged while policy time advances privately.
The test now compares the entire 30-second projection with its original waiting
row. Its real 60-second wait, timeout-continue result, later completion/refusal,
identity and cleanup assertions remain. This repairs the obsolete oracle; it
neither changes production timing nor certifies native-provider final timing.

Composed restart custody records namespace adoption separately from immutable
kernel birth and original-parent wait facts. Only the eight authored restart
workers can acquire a current-parent fact: their admitted generation and READY,
original parent's exit, unchanged UID/birth/session identity and actual PPid 1 in
the private PID namespace must agree. Peer authentication uses that current
parent only after acquisition; original ownership and original wait claims stay
unchanged. A new thread observes its leader's current kernel parent.

Upon the adopted worker's independent tracer terminal observation, the observer
requests a passive numeric wait from the actual namespace init. This happens
before original test teardown checks that the process group is empty. The
20-second closeout starts at terminal observation, never at adoption while the
worker legitimately runs. Root-owned receipts bind the same identity, namespace
and status, with the actual wait's monotonic timestamp inside that bound. A
later case-finish reuses the completed receipt without restarting the clock or
imposing that bound on the remainder of the original test. Case completion
joins the receipt with kernel exit and tracer terminal
status. The v5 result labels these init waits separately. Missing or mismatched
receipts, unknown adoption and emergency cleanup still fail certification.

A replacement HTTP server has no synthetic Popen handle for this worker. Its
separate resumed-signal request permits only an individual liveness probe or one
SIGTERM to the verified worker session. The admitted run/control/generation/home
and original worker identity grant scope; the owned cursor, using RunControl's
SHA256 run-id filename, only corroborates it. Every affected admitted group member
is rechecked before the signal is recorded. SIGKILL, foreign sessions and broader
resumption remain refused. Existing provider denials and UNVERIFIED limitations
are unaffected.

Authorized process-group signals are attributed to each already admitted live
member after checking its immutable ancestry, current birth and PID namespace.
Descendants in another session receive no signal fact. Original-parent and
resumed-server group cancellation share this census; the existing caller,
signal-kind and session-leader permission checks remain separate.

The composed adapter's three constant postimages and undeliverable shim use
authored exact-byte SHA256 declarations instead of runtime AST reconstruction.
The exact case selects the expected digest before any candidate bytes are read.
Acquired UID/mode, file-generation retention and compilation-time verification
remain. Supplementary tests derive all four digests independently from the
pinned original literals and postimages and reject cross-variant substitutions.
This removes runtime AST derivation for constant fixtures; root-dependent
templates retain their renderer and no generic Python body is admitted.
The readiness and owned-client leaves likewise select one of seven exact
constant program digests through their eight original case IDs. Other argv,
environment, root caller, cwd, role and quota checks stay independent; a valid
body from another variant or extra argv still refuses. Their supplementary
tests derive the literal programs from the original source rather than trusting
the declared hashes.
The terminal credential-redaction leaves bind their two constant programs and
their exact public canary environments the same way. Every role/profile/provider
parameter remains in the original tests; optional-null native `/usr/bin/true`
leaves retain their separate native image declaration. No raw credential or
additional terminal environment field follows from a matching program hash.

Multiprocessing admission uses a fixed set of original test modules, at most five
children and one tracker per case, and three to seven child descriptors. It no
longer predicts target labels, per-target quotas or application resource counts.
Target names were metadata, not an attestation of the unpickled program. Queue
endpoint graphs and resource-lifecycle behavior remain contracts of the unchanged
original product tests. The altered-stdlib-stop negative still admits no launch.
The guard binds exact native/stdlib entry bytes, argv, environment, cwd and parent.
The tracker retains its narrow reader/captured-stderr inventory and KCMP_FILE
open-file identity. Child bootstrap, tracker and sentinel must be three distinct
FIFOs with their original directions. Extra descriptors can only be measured
UID-20000 FIFOs, exact anonymous 4096-byte arenas, or unnamed Unix streams bound
to their cookie and actual owner birth. Complete child-side descriptor recensus,
authenticated tracker READY, generation checks and real numeric waits remain.
Neither the stdlib entry pin nor a matching target label attests pickle contents;
children acquire no subprocess or provider-launch authority.

Git commands no longer require a second intermediate wait-order model before
each subsequent command. Their independently acquired repository generations,
fixed command operands, mutation ordinals, parent roles, helper reservations and
quotas remain. The unique pending-launch join still serializes admission through
actual exec. Case finalization requires every admitted command and helper to have
its real numeric parent wait; helpers also retain the successful native status,
image pin, parent, case and execution generation checks. The guard does not
independently certify application-level Git call ordering or HEAD correctness.

Role-server finalization uses the same per-actor terminal and kernel-wait join as
other source children. Both HTTP and inline role servers retain their declared
success/intentional-crash/signaled-cleanup status checks. The separate recursive
server/query completion pass and intermediate application phase-wait model are
retired. Fixture custody is acquired again before any further Git command or
server launch; finished fixtures grant no later capability. Original concurrent
server, late-client and restart tests retain their actual ordering assertions.

A thread's observed exit stop and tracer terminal status can differ when a
subsequent group SIGKILL arrives. A terminal SIGKILL with an earlier member exit
may precede the exact group's leader exit observation. That terminal fact remains
pending corroboration: the later leader exit must match it. The earlier member
exit is never overwritten, no parent-wait evidence is inferred, and a missing or
mismatched leader exit cannot certify completion.

Role subprocess admission treats node names, mission IDs, attempt names and target
contents as bounded application data inside the acquired project. Case-selected
parent role/template budgets, actual parent birth/token/READY and complete
security-environment equality remain authority. Module roles come from the exact
module-mode template; ACP roles can consume only their separately authored parent
budget. MCP and ACP templates have separate counters, including pending intents;
neither obtains permission from being the last sibling to execute. Git query
permission uses the role stored by the observer, not a later metadata claim.

Task-state reads, active terminal-review snapshot searches and predicted target
content are retired from guard admission. The original product tests retain all
application state, node, target, timing and cleanup assertions. Scoped output paths
must retain their project/mission/directory/filename relationship without symlink
escape; assignment JSON remains bounded, duplicate-free and role-consistent.
Provider selectors, import paths, permissions, recovery switches, native images,
script bytes and inherited descriptors remain exact. All eight composed adoption
worker indices, operations, originating server slots and retained request/project
qualifications are unchanged. Original fixture-value constructors used only to
build guard-test inputs are retained in test_role_data_oracle.py; production
enforcement does not import that test oracle.

Tracee memory is read only while the kernel holds that owned task stopped. An
aligned PEEK proves the attachment before each read-only, CLOEXEC `/proc/TID/mem`
handle is opened; the handle closes before resume or exec. Page-bounded reads
replace the former eight-byte PEEK loop without changing string/vector limits,
exact wait-status bytes, exec admission or actual-parent wait evidence. Short
reads and access failures refuse; observer privilege grants no unattached read.

The source compartment starts in an empty filesystem root. It receives only
read-only measured source, support, dependencies and interpreter trees; the
system runtime and selected public system files; private owned scratch; the
observer's protected profiles/output; four fixed character devices; private
shared-memory scratch; and fresh read-only procfs in its private PID namespace.
The observer's original interpreter prefix names the same measured private copy,
so late standard-library imports cannot reopen the original host installation.
No containing host directory is bound to expose these children. The dedicated
fork discards inherited handles beyond standard I/O before acquiring compartment
I/O; a surviving handle refuses entry. The old cwd is discarded. Actual root
generation and read-only input mount identities are
recorded after entry and bound again before each source body.

Git admission no longer parses repository configuration, reconstructs linked
worktree backlinks, rejects application-created hooks/alternates/grafts, scans
completion Git member types/modes/links, or predicts the binding fixture's empty
metadata layout. Repeated reads of the immutable diagnostic home configuration
are removed; its protected construction and permissions remain. Original product
tests retain their configuration, object-integrity, refusal and mutation checks.

Filesystem effect containment is jail-wide disposable scratch, not independent
isolation of each repository's effects. Acquired repository/metadata generations,
canonical cwd slots, exact executable/argv/environment, finite per-case counts,
and actual original-parent/helper waits remain enforced. A hook or helper command
does not gain execution permission from Git data: its actual fork/exec must still
match the existing closed native-helper allowance, otherwise refusal poisons the
run. No remote operation or new command form is added. UV, native-refusal, review,
snapshot and adoption qualifications remain unchanged.

Standard I/O routing is application data inside that compartment. The observer no
longer reconstructs parent pipe inventories or checks which owned log received
stdout/stderr, and it retains no unused stdout inode receipt. Initial inherited
FD closure and prebody extra-descriptor census still protect observer custody;
the sensitive inventory and multiprocessing descriptor checks remain separate.
Product tests retain real output, pipe-drain and completion assertions. The guard
does not certify standard-stream routing or output-value provenance.

Git families share one native declaration and intent issuer. It compares the
complete argv/environment/cwd plus executable and stdin, then binds the measured
image and actual-parent intent through the existing ledger. Family adapters
still select command forms, original parameter/ordinal restrictions, repository
generations, actor roles, quotas and helper eligibility before issuance. The
shared issuer grants no new Git form, config key, provider route or descendant.

Within source socket Hooks, the exact primitive default constructor triple
`(-1,-1,-1)` is ordinary local construction or wrapping of an existing descriptor.
Per-case adoption eligibility and constructor-time inode matching are retired.
Available descriptors remain subject to compartment entry and inherited-inventory
checks; multiprocessing retains its independent open-file/cookie recensus.
Bind/connect and resolver restrictions are unchanged, as are session roles that
do not install these Hooks. Wrapping a descriptor grants no new connection route.

Storage-reader admission pins the original read-only program and the current
owned fixture's canonical regular target. It no longer predicts expected file
contents, nesting depth or relative-versus-absolute operand spelling. Those are
atomic-write contracts checked by the unchanged source tests after the actual
fresh-process read. Per-case reader counts, exact environment/image/flags and
current fixture generation remain; this permission grants no executable body
from file data and no access outside the acquired fixture.

Fresh inspection leaves likewise bind their original program and scoped canonical
home/project paths without parsing project JSON to predict its ID or workspace
value. The product owns malformed/missing-record behavior and the original
fresh-process reconstruction and sealed-patch assertions. Fixture generation,
path-alias refusal, exact program/environment and finite child counts remain.

Filesystem entry is the sole owner of selected input binding and mount census.
The earlier bind/remount/census before entry is removed. Trusted preparation maps
canonical destinations to measured source trees, including `/native` without
creating a host `/native` mount. Entry verifies that mounted native destination's
original device/inode, root owner and mode0555, then records complete read-only
mount IDs after chroot. Private mount propagation, network/IPC isolation, final
root identity and the measured-runtime alias remain unchanged.

Git enforcement and its host-only public-history input preparation now live in
`git_policy.py`. The former twelve Git modules are removed, without compatibility
facades. Family-prefixed declarations and functions keep their separate command
sets, parent roles, mutable counters and helper eligibility. Shared native image,
byte acquisition and intent issuance remain single functions. This consolidation
changes internal names and module boundaries, not launch permission or evidence
claims; fewer files alone is not a verified startup-performance improvement.

Commit-tree admission retains the exact command form and two full object IDs.
Its stdin and six explicitly named author/committer identity/date fields are
bounded primitive UTF-8 data; other environment additions remain forbidden.
Calendar parsing, fixed identity values, author/committer equality and sorted
lease-message interpretation are retired from guard admission. The original
integration test now observes the real forwarded subprocess call and actual
predecessor-date query, asserting the message order and all six identity values
after successful Git execution. Actual native/helper waits remain mandatory.

Git directory names no longer serve as application-role predictions. The case
and family operation inventories remain closed, but a Git cwd may be the
registered repository or a canonical owned directory strictly below its private
`.unrest-runtime`. Worktree add/remove targets must be strictly below that
runtime, never the repository or runtime root; physical target aliases are
refused before admission. The checkout-producing exact worktree-add form has one
canonical intent label regardless of integration/rollback directory spelling.
Only that consumed parent intent can reserve the same single pinned reset
helper. The no-checkout form gains no helper. Repository generation, exact argv,
environment, quotas, patch scope, real parent/helper waits and the separately
exact workspace-owned Python command remain enforced. The sandbox protects
external files; original workspace and evolution tests own scratch naming and
application-state correctness.

Observer-created archive and copied-source snapshots are fully verified during
acquisition, copied without source-owned aliases or retained write handles, then
sealed under UID20001 with directories 0555 and files 0444. Later consumers check
the canonical root generation and protected observer parent, rather than hashing
and walking every member again. UID20000/CAP0 cannot write, chmod, unlink, rename,
add a member or hardlink the sealed files; real filesystem controls exercise
these refusals. Detecting post-sealing mutation by the trusted observer/host is
retired from this claim. Acquisition-race, full byte/inventory comparison and
root-replacement refusals remain. This custody shortcut grants no launch right.

Process declarations share one complete argv/environment/cwd comparison and one
admission finalizer. Main source proposals, LaunchPlan preflight, controlled
review-wire, workspace-owned Python and multiprocessing use that same path.
Their classifiers, parent checks, finite quotas, native image selection, stdin
rules, descriptor acquisition and special result fields remain separate. The
matcher never infers an expected declaration from a request. Failed comparison
creates no intent, and a pending admission creates no fixture snapshot or token
binding. Existing module/native alias handling remains at ingress and exec
admission; it is not replaced by a generic executable allowance.

The native entry has an inactive compartment socket gateway for the planned
namespace-based model. Only an exact Py_True exported by the byte-pinned
bootstrap after validation and authenticated READY activates it. Existing
production bootstrap does not yet export that gate. Native diagnostic controls
exercise private TCP/UDP, libc address discovery, route-netlink and anonymous
Unix pairs, alongside sticky named-Unix and process-effect refusals.

The inherited seccomp program permits namespace-contained socket classes:
INET/INET6 stream/datagram with protocol0/TCP/UDP, Unix stream/datagram with
protocol0, and RAW route-netlink with protocol0. Other socket/socketpair attempts
stop the tracer and poison the result even if caught. All three io_uring entry
syscalls are also denied, closing their alternative socket-creation path.
Permitted traffic creates no additional tracer stops. Exec/wait observation and
all original-parent retirement requirements remain unchanged. These controls
establish no source checkpoint or native-provider acceptance by themselves.

Trusted setup adds 127.0.0.2 as a secondary address on the same private lo device.
This supports genuine glibc AI_ADDRCONFIG discovery: glibc excludes the literal
127.0.0.1 address when determining available IPv4, rather than treating every
address on lo alike. There is still only lo and no external gateway or usable
external route. Setup checks a fresh isolated namespace before changing it,
requires root, then repeats its interface/route census. The source retains CAP0.
The native positive control uses the actual libc resolver and its requested
flags; it does not substitute a result or waive a lookup failure.

The Python socket monkeypatch layer is removed. Guard-only tests of its retired
per-role IPv6, literal resolver and wrapper call restrictions are replaced by
actual native caught-refusal, kernel family/protocol, ordinary descriptor/IO and
private namespace controls. No original product test is removed or weakened.

The pinned `uv` startup uses an anonymous Unix `SOCK_SEQPACKET` pair. This
contained IPC class is admitted with protocol zero; IP seqpacket remains denied.


Disposable local Git fixture choreography is retired. An eligible active root
may use the closed union of existing local Git command vectors inside its
acquired pytest subtree, with canonical repository generations, exact image,
argv/environment/cwd comparison, finite quotas and actual parent waits. The
guard does not predict setup ordinal, fixture author identity, repository label,
measurement repetition directory or product branch result. Setup/call metadata
must still name the active original case. No arbitrary Git command, configuration
key, remote operation or native child is admitted. Historical public-source
queries remain separate and read-only. Worker launch sequences, nested ACP,
adopted process identities, review restrictions and cleanup remain independent.
All original product tests and parameters remain unchanged; guard-only tests of
the retired fixture-order and naming predictions are replaced by closed union,
case-directory custody, foreign-command and native execution controls.


Public-history input preparation now uses an explicit local fetch of the trusted
`apodgaiko/unrest` hosted-CI checkout's HEAD and six pinned historical tags.
Complete reachable public trees are admitted; minimal-tree object projection and
non-delta-pack claims are retired. This public-ancestry assumption does not apply
to arbitrary developer checkouts. The generated target carries no source hooks,
configuration, credentials, alternates or unrelated refs. Fetch disables lazy
upstream acquisition and automatic maintenance; the existing complete metadata
capture and 64 MiB member bound remain. Candidate historical queries stay
read-only and acquire no new executable permission.


Local Git eligibility is now bound to independently byte-pinned original test
modules and the active root case, rather than a second per-node fixture consumer
catalogue. This intentionally permits the same closed local Git data operations
throughout those fixed modules. The old node/slot observations remain only in
non-production tests to verify original collection; enforcement does not import
them. Three worker repository bindings, the one owned Python command, nested
measurement ACP and readonly history queries retain exact separate case rights.
All directory-generation, image/argv/environment, quota, helper and wait checks
remain; module membership grants no arbitrary Python or worker execution.


Historical Git query translation adds one command-scoped `safe.directory` for
exactly the sealed source cwd, whose root ownership intentionally differs from
the source process UID. Raw original argv/environment still match the declared
query; only its measured translated vector contains that exact exception. It is
not a wildcard, global config change, mutable-fixture exception or extra command.


Ordinary controlled-Python pair admission uses the existing overall ceiling of
20, rather than predicting the maximum pair count of each test history. Every
backend body/configuration association remains case-specific and byte-pinned;
a fresh owned cwd has one backend and one ACP attached to that actual backend.
Cohort campaign and crash bounds, reservation's zero-pair rule, startup failure's
no-ACP rule, signal rules and numeric wait dispositions remain exact. The unused
second network-topology quota is removed. Controlled custody Git retains its
existing eligible cases and closed commands under the shared local ceiling of
128; cohort/crash Git budgets are unchanged. Neither fixture matching nor these
resource bounds select controlled transport or admit native/provider execution.


Ordinary controlled fixture admission now selects from 27 independent literal
backend hash/filename pairs and four fully reconstructed local configuration
variants. Test-module eligibility no longer predicts which known body or variant
each test should use. No caller-supplied digest or arbitrary configuration enters
a declaration. A backend's selected variant is retained on its intent, and its
unique paired ACP must match it. Script acquisition remains bounded, no-alias
and UID-bound; native prebody validation checks the selected bytes again.
Cohort/crash cases remain on their exact catalogue, standard backend, variant 0,
parent rights, quotas and wait dispositions. Warning signal/replay sets and
startup-failure's no-ACP rule are unchanged. Matching these fixtures does not
select controlled transport, redirect native construction, or admit an adapter,
model/provider launch or review override. The ordinary controlled modules also
share the existing closed custody-Git forms and environment inside their owned
repositories, under the separate finite ceiling; no remote or arbitrary Git
command is introduced. Retired case associations remain only as test observations
and are excluded from native enforcement support.

### Shared inherited read-pipe acquisition

Cleanup inventory pipes and unnamed Unix streams use the same birth-bound
`pidfd_getfd` acquisition. The observer checks the retained process birth before
and after copying the descriptor, compares the copied device/inode with the
current remote descriptor, and closes both pidfds and copies on every path.
The cleanup pipe inspector requires the original UID 20000, FIFO type, and
blocking read-only flags. The child independently rechecks those properties,
the exact descriptor number and the complete inherited inventory before its body.
No bytes are read and no descriptor flags are changed during measurement.

The ordinary sleep fixture retains its exact `/bin` alias check and shares the
root-to-file native custody and byte measurement used for Git and other system
images. This removes a duplicate implementation, not an image or owner check.

Console admission no longer reasserts generated project/entry-point/MCP metadata.
The unchanged distribution and CLI tests own those result assertions. Admission
still chooses only the fixed console names and normalized paths, pins actual
installed script bytes against the immutable preparation receipt, and matches
exact argv, environment, cwd, native entry and parent. Metadata cannot substitute
another executable; the UV parent retains its independent child-script join.

Original fixture AST extraction relies on the independent literal SHA256 check
in `source_unit` before parsing. It no longer separately validates the known
syntax shape of those same pinned bytes. Runtime substitution names, order,
conversion and values remain checked by `render_string`; filesystem and launch
operands retain their independent validation. A changed fixture cannot supply
its own expected pin or reach extraction under the old pin.

Archive input acquisition retains canonical directory/member ownership, modes,
regular single-link files, byte bounds and acquisition-race checks. It no longer
stores a second archive content/generation manifest for exec-time comparison.
The unchanged original archive oracle checks the bytes it actually consumes;
extracted snapshot sealing, fifteen-case provenance, installed script receipts
and process/image/parent/wait admission remain independent requirements.

The supported CPython 3.13 Linux runtime supplies `os.pidfd_open`. The guard uses
that wrapper directly and retains operand/result/error checks. The alternate
libc syscall path for unsupported interpreter builds is removed; a missing
wrapper fails closed instead of selecting another ABI path.

The standalone collection-only diagnostic mode is retired. Normal discovery still
records every collected original case before running bodies, and release sealing
requires the complete outcome cursor and successful final pytest status. Merely
collecting cases has no completion operation. Focused original-source diagnostics
remain distinct from the full unexcluded checkpoint.

Public Git preparation retains the initial complete graph/anchor check, exact
HEAD and tag acquisition, and acquired-ref verification; it no longer asks Git
to prove the same immutable HEAD ancestry a second time after successful fetch.
