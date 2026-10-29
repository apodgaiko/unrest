# Release guard integration

The release target is 0.4.7. Historical evidence and `unrest.v046` identities
retain their original meaning. Experimental features remain disabled by default.
Genuine native-provider approval, ACP reuse and final-candidate timing remain
UNVERIFIED. A controlled source test does not establish provider acceptance.

## One enforcement implementation

`.github/release-guard` is the sole release guard. The former
`.github/release-source-guard` implementation is removed together with its CI
consumers. Its original failures and review denials remain in retained evidence
and Git history; deleting obsolete implementation does not reverse a denial.

Enforcement has a 10,000 physical-line ceiling. Policy, native code, generators,
generated enforcement, workflow glue and external enforcement dependencies count.
Tests are measured separately. Moving or packing code does not reduce the scope
of this ceiling. `size_budget.py` measures the current tracked snapshot; a
separate dependency-closure review establishes whether external support belongs
in that inventory. The existing `tools/check_distribution.py` is retained
release-test support: its disclosed optional runner seam requests execution but
grants no execution authority. Its complete path, bytes, hash and line count stay
visible through `--test-support tools/check_distribution.py`; reports separately
show enforcement, retained test-support and their combined total. All guarded
transport/domain code remains enforcement. Any future permission or containment
logic in that helper must be reclassified. A size report alone does not certify
a release.

Ordinary in-process Python computation is trusted. The guard does not inspect
Python frames, closures, globals, defaults or generated AST/code to authenticate
callers. Case, owner and target labels identify declarations; they do not prove
which Python code executed. Hostile-Python isolation is not claimed. Original
product tests and their real completion, status and cleanup assertions remain.

## Execution and cleanup boundary

`source_host.py` prepares measured source, locked dependencies, runtime and guard
support. An independent observer makes these inputs read-only in private mount,
network and IPC namespaces. Tests run as UID20000 without capabilities; the
observer runs as UID20001 with only DAC_READ_SEARCH and SYS_PTRACE.

The native C entry installs its audit hook before Python initialization. Each
profile binds current bytes, exact argv/environment/cwd, credentials, process
birth, parent, mount identities and the declared execution domain. Profiles are
observer-owned mode0444 files with a 65,536-byte limit. Control requests retain
their separate 8,192-byte limit.

Finite effect proposals are independently reconstructed by the observer. Kernel
exec stops bind the actual child, executable bytes and operands before the child
body runs. Endpoint permission requires the exact owned listener and reciprocal
socket/descriptor observations. Signals require an owned live child and an
explicit finite cleanup route. Unknown effects poison the outcome even when a
product negative catches the exception. One canonical observer-side proposal
builder supplies each declaration and preserves the same role, sequence, quota,
byte, descriptor and configuration checks for raw and wire requests.

Actual original-parent terminal wait4 and kernel terminal observations establish
cleanup. Before resuming wait4, the observer validates the waiting thread's stored
birth and parent group, plus the positive PID of an independently admitted owned
child. Invalid wildcard, foreign, or unregistered Python waits fail even when
WNOHANG would return zero or ECHILD could be caught. Linux pid_t is decoded as a
signed32-bit argument. Only independently admitted native Git/uv command classes
may use wait-any or poll a known owned fork before its exec admission. Such a poll
cannot retire a child or admit an executable. Terminal retirement still requires
one matching child birth/token, exit event, tracer terminal status and actual
original-parent wait4. Waitid/WNOWAIT, cached return codes and PID disappearance
cannot replace that join. The redundant Python per-wait receipt protocol is
retired; successful constructor-return ordering and Git pipe/input provenance
remain separate obligations. Source-result schema v2 names this kernel evidence
explicitly; historical v1 evidence keeps its original interpretation.
Adopted fallback cleanup is failure evidence. A nonleader thread terminal status
may match its own exit event or the independently observed exit of its stored
thread-group leader. Its birth and own exit must still match; thread waits never
enter original-parent child-reap joins. An interrupted connection can
retire as cancelled-unjoined only after its authorized termination and actual
parent reap; that does not prove application accept or descriptor close. Native
status86 always retains its refusal meaning.

Multiprocessing declarations cover the two original numeric-exit cases and
eight tracker-lifetime and ownership-negative cases. Seven permit one tracker
and no spawn target; the altered-stdlib-stop case permits no launch at all. Their tracker and child retain distinct FIFO identities, directions,
parent counterparts, native READY and actual waits. A captured stderr descriptor
is admitted only as a kernel-proven alias of FD2's anonymous mode0600 file;
inode equality alone is insufficient. No shared-memory arena or additional
multiprocessing target follows from these declarations.

## Primary CI and the full source checkpoint

Primary CI uses this guard for normal, unexcluded Python3.13 source discovery.
The fixed outer command is `env -u CODEX_PATH uv run pytest -q`. Stock uv0.11.8
consumes the independently locked dependency generation without resolving a new
environment during candidate execution. Its exact environment and executable
bytes are bound; a missing interpreter-metadata cache grants no helper launch.
The native `pytest` console entry identifies its actual `/proc/self/exe` image,
independently of uv's bare `pytest` argv0, and normalizes Python startup to
canonical-entry `-I -S -m pytest`; both the original kernel argv and normalized Python argv are
recorded and checked. Subsequent Python children use the canonical guarded entry.

The additive pytest plugin does not select or deselect tests. Normal discovery
produces the complete ordered inventory, sealed into a content-addressed,
observer-owned file bound to source and dependency hashes. Profiles carry only
its small reference. Large parameterized nodeids remain complete in that file;
control messages use an unambiguous SHA256 reference. Only matching oversized
`PYTEST_CURRENT_TEST` framework metadata is shortened for children. Original
nodeids, parameters and the root environment remain unchanged. The sealed full
inventory is retained with encrypted evidence. This avoids enlarging profile or RPC limits.

Ordinary assertion failures retain pytest's normal continuation and terminal
failure. Every observed case retains its setup/call/teardown outcomes. Original
skips remain explicit and are not native-provider acceptance. Forbidden effects
and incomplete cleanup remain fatal. Successful completion requires every
ordered case, no failed outcome or poison, successful pytest and uv statuses,
and the genuine uv-parent wait. No checkpoint is transferred from another SHA.

`full-collect` is a bounded normal-discovery integration proof. Its explicit
`--collect-only` argv and separate completion record cannot certify test bodies.
Other selected groups likewise remain component proofs. The source checkpoint
is accepted only from the actual complete unexcluded run of the frozen candidate.

## Distribution and installed lifecycle

The archive checker retains complete wheel/sdist member-byte comparisons, safe
extraction and the original fifteen-case persistence oracle. Its optional runner
injection changes process transport only. Primary CI runs that exact probe in a
fresh native guarded domain and retains the original provenance assertions:
package module, test module, cwd and effective sys.path must belong to the
extracted generation and exclude the original checkout. No second full source
run follows a build.

Primary CI also preserves unrelated-cwd installed CLI, bundled-policy discovery,
provider-independent functional lifecycle and fail-closed startup checks. Build
archives and checksums are uploaded only after these gates pass. Private native
source/archive diagnostics are encrypted for retention; they are not release
assets. Native integration, final dependency-closure review, the complete source
checkpoint, desktop/CI evidence, publication and protected local update must all
be verified before the release mission is complete.

The two resource-ownership IPC cases retain one tracker and one child each. The Event-only child inherits the original three pipes. The Queue/Event/Value child adds exactly two opposite Queue FIFO endpoints and one anonymous 4096-byte read/write arena, all rechecked by kernel identity before the child body. Labels remain metadata; the original test owns completion, cleanup and parent waits.

Controlled review-wire coverage uses the original 24 test cases and exact local approval fixture. Full pytest selectors and parameters remain intact; only transport identities are compact. Scenario acquisition is nonblocking, nofollow, descriptor-bound and byte-bounded. Its immutable snapshot allows only events, finite delay and raw protocol bytes, excluding the fixture's MCP and handoff branches. The duplicate-review case may launch two sequential, independently reaped children; all other cases may launch one. These controlled observations are not genuine provider review acceptance.

Queue-based multiprocessing declarations cover nine attention, patch, lock and supervision cases. Each target has an explicit resource order, quota and numeric exit disposition. The interrupted rename probe retains 73; only the abrupt lock holder retains -15 with its recorded signal. Status lookup uses the consumed child birth, token and case, so PID reuse cannot borrow another generation. The controlled wire cleanup retains either normal zero or its actual recorded SIGKILL result after the original five-second close deadline; no unrecorded signal or synthetic wait is accepted.

Duplex-Pipe spawn routes inherit one endpoint from an already admitted original-parent Unix pair. The sealed child record retains that pair generation; child bootstrap queries its held descriptor and cookie without opening a network family, and the observer independently checks peer and birth at core readiness. Later Connection file reads/writes recheck the inherited member even after the parent closes its duplicate. Explicit Connection callbacks receive the same descriptor mediation. Pair admission, socket creation/connect restrictions and original-parent reap obligations remain separate.

The native audit path skips unconditional Python callbacks for ordinary import and exec events. It captures the validated script filename as an owned immutable C reference and routes only matching compile events to the existing current-file and compilation-byte checks. Privileged effects, prebody admission and sticky refusal status remain enforced.

Ordinary Python tracing and profiling are permitted within the trusted in-process
boundary. They are used by real test barriers and grant no process, socket or
signal authority; those effects still require their independent native and
observer checks. The native fast-path control exercises both APIs as well as
ordinary imports and exec.

Project-lock process tests separate cold server startup from mutation latency.
Lock-only targets do not import the MCP server. Server-based targets signal an
explicit Event only after constructing the actual server, with a ten-second
startup bound; the original one-second result wait, per-call latency assertions,
lock-entry waits, child statuses and original-parent joins remain unchanged.
This test readiness signal is not a native guard READY record or release proof.

The retired declaration matcher and test-only Intent record are removed from
production. Literal rendering remains bounded; mutation negatives exercise the
actual observer's admission path. Synthetic pre-exec models remain test-only and
cannot authorize execution. Inherited descriptor classification queries the live
file type before consulting pair history: reuse of an old socket FD for the
current tracker FIFO cannot borrow or be rejected as the previous pair generation.
Actual socket inheritance still requires the current original owned pair.

The nine real HTTP supervision cases reuse MCP transport, as recommended by the
Astra architecture consultation. Their separate catalogue reconstructs the exact
local role fixture, environment, owned workspace and advisory port. These MCP
children inherit no sensitive descriptor and start a real new session; cleanup
MCP retains its one sensitive descriptor and existing lifecycle. HTTP output must
be the same owned regular log on stdout/stderr with null stdin. Provider command
strings in the fixture environment confer no provider execution authority.

Each HTTP case has a 64-connection enforcement resource ceiling, not a claimed
original or expected TCP count. Pinned MCP clients may reconnect. Every connection
still joins the same admitted live child birth, listener generation and port,
with reciprocal socket proof; unfinished tickets fail completion. The original
readiness, contention and cancellation deadlines remain in the original tests.
The exact native ps inventory runs once, only after the server's original-parent
reap, and requires zero status. Actual server zero or recorded TERM/KILL status is
retained. Root broker authentication contexts apply only to their separate
broker cases, not to unrelated MCP clients.

The literal loopback resolver accepts MCP transport's numeric ASCII bytes and
numeric service spelling, plus its passive/address-configuration flags. It still
returns only the literal IPv4 loopback tuple and never calls DNS. Hostnames,
service names, alternate families and protocols remain refused; bind/connect
still require their independently admitted endpoint generation.

Only `launch-proposal` accepts process operands. The obsolete `launch-intent`
method and observer wire adapter are removed; callers cannot submit authority
claims such as source lines, owners, image hashes or translated commands. The
observer reconstructs those declarations independently. Former wire mutation
controls now exercise actual proposals, including consistent inline-body changes,
unknown authority fields and zero-intent refusal. The small proposal test-data
builder is not imported by production and performs no enforcement.

The observer now carries its selected immutable command/declaration directly
through admission. It does not serialize and reconstruct the same Git, preflight
or custody command a second time, or compare its own generated source-line wire
fields. Git repository/worktree custody, causal input values, previous parent and
descendant reaps, stdout joins and producers remain mandatory. Preflight still
remeasures mutable owned scripts at each actual exec attempt. Kernel execution
matching, immutable profiles and parent waits remain independent checks.

HTTP fixtures use the same explicit `FASTMCP_CHECK_FOR_UPDATES=off` execution
setting as cleanup MCP. This disables the pinned dependency's unrelated PyPI
banner update query. The original caller environment and the resulting execution
environment are separately observed and bound. No external DNS, connection,
provider process or update download is authorized by this setting.

Three original speed-runner counter cases use product-first audit sequencing.
After normal collection imports the real product hook, a guard-owned Python tail
hook must acknowledge installation before native deferral is armed. In those
exact cases, the real product denial may raise and increment its own counter
before any effect. If it does not deny, the tail reissues the same event and
argument objects, with a thread-local recheck flag that forces unchanged native
policy first. Other cases/events retain native-first checks. No permission is
inferred from a counter or exception. Synthetic native controls require either
normal product-denial exit or caught fallback plus sticky86, with only the initial
exec observed; the original cases separately establish real product behavior.

Git checkout helpers compare their current image with the consumed original
parent command's executable pin. A removed process-global cache is not an input
to this proof. The helper retains its own birth, worktree/HEAD phase, actual native
parent wait and subsequent Python-parent/output join requirements.

Launch declarations use one immutable `Expected` record constructed by
`build_expected`. The former `Rule`/render intermediate, duplicated owner labels,
unused substitution contexts and declaration serialization are removed. Family
builders still select finite cases and independently acquire operands; admission
still compares the case, argv, environment and cwd, and exec-time content and
process-custody checks remain unchanged. The external payload reference is an
input distinct from the derived payload digest, including delayed wrappers whose
inline body and auxiliary script have separate pins. Cleanup terminal selection
still requires an inflight case; historical source-line numbers grant no authority.

The original speed-runner import/reload regression uses the existing fixed-inline
path. Its sole literal body is extracted from the byte-pinned original function;
its command, checkout cwd and inherited test environment are compared exactly,
including the original `PYTHONDONTWRITEBYTECODE=1` addition. Exactly one child is
permitted, with no descendant query authority, and the original assertions still
check one product audit-hook installation and the same controller after reload.

Controlled case declarations share explicit finite parameter axes and common
backend tuples. This factors repeated data only: all ten prior exported mappings,
including their insertion order and group frontiers, match ordered pre-change
fingerprints. Distinct backend postimages remain explicit. Runtime authority does
not read the test fingerprints or discover additional cases by prefix matching.

The 18 original preexisting-socket bound-alias parameters use that same isolated
entry. The only template substitution is the literal method name selected from
the closed original tuple; the parser accepts string constants and plain
`{method}` fields only. No evaluation, arbitrary formatting, descendant process,
DNS or new socket route follows. Original preflight-refusal, counter, evidence
and empty-payload assertions execute in each real isolated child.

Socket-descriptor preflight inspection adopts an existing descriptor through a
scoped Python initializer wrapper. A thread-local, single-use ticket binds the
exact socket object, explicit nonnegative integer FD and current device/inode/
mode/UID. The native audit callback rechecks and consumes it; initialization must
retain that FD and identity, and pending state is always cleared. Non-socket scan
inputs preserve `ENOTSOCK`. A bare `(-1,-1,-1)` constructor has no admission:
CPython converts negative defaults into a new Internet socket without `fileno`.
Adoption grants no new endpoint or payload authority.

Five original descriptor-preflight cases additionally permit one unbound stream
socket with the exact original Linux family (IPv4 or IPv6) and detachment boolean.
Their original programs and evidence assertions remain unchanged. Bind, connect,
DNS and transport payload still require independent existing authority. The
failed first alias run is retained; it is not replaced by its later repair proof.
Socket method wrappers preserve the original method name and bound receiver so
real product preflight can identify captured aliases. Wrapper names are metadata;
launch and transport authority remain independent of Python caller identity.
The same ordered-parity check covers factored bootstrap expiry/boundary axes and
preflight lookup/malformed-string axes, including every bootstrap delay and child
count; their runtime declarations and no-effect membership remain unchanged.

The remaining two formatted speed programs acquire `tmp_path` once through a
root-only active-case metadata operation after real fixture setup. The observer
pins the canonical owned directory identity and rechecks it at proposal and exec.
Only the original marker paths, fixture path and source-pinned HEAD/TREE literals
can enter the string templates. No general expression evaluator is used.

Their immutable translated command prepends one fixed helper that imports the
real product and installs product-first audit ordering, then runs the unchanged
original body. The exact captured-resolver alias probe calls the real original
resolver with its original operands: CPython's native audit event must reach the
product denial or the unchanged outer refusal before libc DNS. Separate native
positive/fallback canaries exercise that audit ordering. These are controlled
source checks, with no provider acceptance or DNS permission claim.
Raw marker-path substitutions additionally require the original pytest basename
prefix with an ASCII numeric suffix and a source-safe ASCII absolute path. Quote,
backslash, newline and foreign-name metadata are rejected before a launch intent;
canonical inode custody alone is insufficient for unescaped string insertion.

Bounded regular-file readers share the manifest acquisition implementation:
held nofollow ancestor descriptors, nonblocking member opens, complete bounded
reads, before/after identity checks and ancestor revalidation. Each caller keeps
its own owner, mode, size, empty-file, location, digest and schema requirements.
Runtime inventory still checks every directory, including empty directories,
and retains its existing ordered row digest. Inventory-only reads stream hashes
without retaining file bodies or hashing them twice. Native pre-profile entry
acquisition stays self-contained.

The speed result module fixture permits exactly five sequential pinned script
runs during its first original consuming case. Their four-variable environment,
fixture/schema inputs, candidate IDs and run-0 through run-4 output arguments
match the original fixture. The acquired `v04-speed-runs<digits>` directory keeps
one generation across all commands and is rechecked at exec. Later consumers
reuse the original module fixture; they receive no additional launch permission.
The real script, result schema, timing gates and actual parent waits remain.

Strict selected cases and normal full discovery share cursor, report and phase
accounting. Their outcome dispositions remain distinct: selected source checks
require every phase to pass; full discovery retains normal failed/skipped
reporting. Only the full release root can seal release completion.

The original two-node nested speed regression has a separate non-launching
`pytest-regression` role. It retains its enclosing process/case context and uses a
local cursor solely to verify the exact original selection and all six phase
outcomes. Its one-time child seal binds the consumed birth/token intent; parent
completion additionally requires native body READY, exit zero and actual parent
reap. It receives no descendant or release-root lifecycle authority. A fixed
bootstrap selects locked pytest plugins and a token-specific basetemp/cache,
preventing inherited release plugins or parent-directory cleanup from leaking
into this child. This leaf grants contract references no launch permission.
Nested declaration imports remain dependency-free during native `-I -S`
bootstrap. The pytest-derived plugin class is created only after activation has
installed the locked dependency paths; importing enforcement initializes no
asyncio runtime. Shared digest predicates and duplicate-key decoding retain the
same primitive and rejection semantics; inactive owner-label constants are gone.


Contract crosswalks bind their complete external `SCENARIOS` selections to actual
source-test reports in the same pytest session. Collection records every selected
manifest before fixtures run and moves contract consumers after source tests,
retaining relative order within both groups. A focused command must explicitly
include all referenced source selectors; selecting one parameter cannot certify a
bare-function obligation. Missing, deselected or duplicate cases, duplicate phases,
skips, failures, xfail/xpass and incomplete setup/call/teardown fail both the
consumer assertion and an independent session gate, including when its fixture
never runs. The release completion hook runs after other session-finish hooks and
checks the final session status before sealing success.

This retires redundant recursive reference pytest runs and their synthetic runner
probes. Their separate credential-filtered interpreter and 120-second subprocess
timeout are intentionally retired properties, not claims about same-session
execution. Real source cases and contract IDs/parameter declarations/local
assertions remain. Candidate-process, build/archive, extracted persistence,
installed lifecycle and the purposeful nested speed regression remain separate
process checks with their original behavior assertions.


The original functional desktop stdio case admits one pinned fixture `serve`
script in its canonical disposable pytest directory. Its distinct desktop role
may issue only one process-start query for its own authenticated birth/PID/token,
after body readiness, using the original isolated six-variable environment.
The `/bin/ps` spelling must resolve to the pinned root-owned `/usr/bin/ps` image;
the executable spelling and exact self-PID `lstart=` operands remain unchanged. The server starts
from the original HOME/PATH-only MCP environment. Directory generations are
retained through exec, stderr is the actual inherited descriptor and stdin/stdout
are parent-owned pipes. Both children require exit zero and actual original-parent
waits. This grants no provider launch, TCP endpoint or generic ps/Python command.
The original response, candidate, registration, process and cleanup assertions
remain unchanged.

Package build/install preparation uses a disposable copy of the measured candidate
and the measured stock uv/runtime under the existing reduced source credentials.
The isolated backend is measured from its actual fresh uv archive cache; it is
not claimed to be locked by `uv.lock`. Complete backend, archive and installed
member bytes are retained under the existing read-only dependency generation.
A provider checks the source/tool/runtime binding and those member inventories,
then returns only fixed artifact paths. It supplies no test outcome, checker
output or persistence result. Test-owned cwd/lifecycle state remains writable and
separate. Ordinary test runs retain their public uv build/install path.

The contract archive scenario now invokes the actual content oracle and safe
extraction directly, using structured results instead of subprocess-success text.
This removes its duplicate extracted-suite run. `check_distribution()` and its
CLI still unconditionally execute the extracted restart oracle after complete
content validation, and the membership-only mutation test targets that live call.
The original distribution success and extracted fixture/import failure tests keep
their real execution requirements. Prepared inputs alone certify none of them.

Extracted input snapshots use observer-owned custody. The acquisition primitive
compares the complete actual extracted tree against the prepared archive-derived
reference and the selected original mutation (none, omitted corpus, or moved
package). It rejects unknown members, links, special files, wrong owners,
changed bytes and acquisition races. New snapshot files are copied from the
acquired actual bytes, then sealed 0444 under 0555 directories owned by UID 20001
inside observer-controlled ancestry. Retention checks bind the root generation
and complete content/directory inventory. This establishes immutability to the
capability-free source UID 20000 without granting another mount capability.
Provenance must report the actual snapshot cwd and module paths; it may never be
rewritten to pretend execution used the caller's mutable extraction directory.

The distribution transport selects only the original executable-oracle cases and
installed package contract consumers. Checker, extracted-probe and installed
interpreter roles have separate case eligibility and child quotas. The fourteen
inert archive mutations bind canonical original filenames, file identities and
bytes at proposal and exec; those observations describe the admitted generation,
not immutable custody during parsing. They have no snapshot or descendant grant.
The positive checker alone can request its exact extracted snapshot and child.

The unchanged extracted probe reports its actual protected cwd, package, test and
sys.path provenance. Normal completion requires all fifteen setup/call/teardown
triples to pass and actual exit zero. The omitted corpus requires all fifteen
actual call failures and exit one. A moved package requires the actual
`ModuleNotFoundError` for `unrest_harness` before pytest starts and exit one.
Neither negative emits a successful fifteen-case seal. A caught guard refusal,
missing phase, unexpected import failure or wrong exit cannot substitute for an
oracle result. Authenticated result messages additionally bind the unique
consumed birth/token intent; terminal status and original-parent waits remain
separate completion conditions.

Installed provenance uses literal code with path arguments, executing from the
owned unrelated cwd. Its bootstrap excludes the source checkout before importing
product modules, and its installed site is the protected prepared tree. The
original lifecycle, restart, corruption and CLI behavior assertions still execute.
Local pytest cursors share their phase-accounting implementation while retaining
the enclosing actor/case authority; only the full release root can seal release
completion.

The hermetic environment regression retains its original inline pytest probe,
three exact inner tests and complete seeded HarnessConfig inventory. Its child
uses the same non-launching pytest role as the two-node speed regression; it
cannot start descendants or advance the outer case. The observer reconstructs
its byte-pinned literal body and adversarial environment, and requires all three
setup/call/teardown outcomes before accepting the child seal. The probe's own
parent-environment restoration assertions still execute normally.

The provider-session timeout fixture blocks SIGTERM before installing its parent
handler and spawning the child, publishes the real child PID while still blocked,
then restores the exact previous parent mask. The child inherits blocked TERM,
installs its stopped-marker handler and unblocks TERM. Thus an early product
group signal remains pending instead of killing the child before its handler.
There is no readiness polling, extra cleanup grace, group relocation or timeout
change: the original 0.3-second request, terminate/wait(0.5)/kill/wait(0.5), stopped
marker, numeric waits and adapter self-SIGTERM remain. A focused control sends real
group TERM during deliberately delayed child startup and proves marker plus wait0.

Atomic-write storage regressions retain16 original cases and17 actual fresh
interpreter reads. Each reader is bound to its original literal body, exact
state-file operand and owned pytest-directory generation. Relative operands stay
relative with the original changed cwd. The directory-fsync case retains two
sequential children; no read child receives descendant permission. The parent
still asserts the actual bytes, modes, cleanup and error behavior.

The journal's live-owner regression keeps its single literal sleep child and
inherited standard descriptors. It retains the original SIGTERM and numeric
parent wait, including a possible owned termination before body READY. This child
has no descendant authority; no zero exit is manufactured for its termination.

Fresh frontier reconstruction and stranded-recovery inspection retain three
actual child executions across two original cases. Each uses the byte-pinned
original inline program. Home and project operands must bind an owned fixture
generation and its actual persisted project ID/workspace record; syntax alone
cannot authorize a different project. The recovery CLI retains its exact home
and projects environment, changed cwd and redaction assertions. These read-only
children receive no descendant launch permission.

TCP acquisition has one held-descriptor path. The observer duplicates the exact
owned descriptor with pidfd_getfd, checks process birth before and after, and
queries TCP_INFO, SO_COOKIE, inode, UID and endpoints on that held file
description. Original-FD replacement still fails; empty CLOSE_WAIT requires its
independent zero-pending-byte/unchanged-cookie checks. The unused TCP table census
and its duplicate process-identity reader are retired. Unix reciprocal peer
identity still uses its existing netlink dump. Native socket control nodes retain
cookie/inode/UID, reciprocal endpoint, closed-FD and one-shot-listener assertions.
