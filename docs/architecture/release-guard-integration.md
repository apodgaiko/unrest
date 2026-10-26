# Release guard integration

The current release target is 0.4.7. Historical `unrest.v046` schemas, source
oracles and evidence retain their original identities. Experimental features
remain disabled by default; genuine native approval, ACP reuse and final-candidate
timing remain UNVERIFIED.

## Guard simplification in progress

The replacement enforcement implementation has a 10,000 physical-line ceiling;
tests are retained and counted separately. The ceiling includes policy, native
code, generators, generated enforcement and workflow glue. Relocating, packing
or delegating enforcement does not remove it from the count. Obsolete guard
implementation counts until removed. This ceiling is not yet satisfied.

`.github/release-guard/content_manifest.py` is the first standalone replacement
component. It measures an independently enumerated file inventory through bounded
nofollow descriptor reads, binds complete bytes and permission modes, and rejects
aliases, malformed records and observed replacement races. Consumers supply a
separate trusted expected digest and exact inventory. Content equality alone does
not establish that reference's authority, an immutable snapshot, launch permission
or a release certificate. The host must separately establish reference custody
and read-only source/runtime mounts before integration.

The replacement is not selected by any current execution workflow. Existing
guard, product tests, review restrictions and release gates remain effective
during construction. Removing historical implementation-shape checks requires
an independently reviewed crosswalk preserving their behavioral mutation cases.
No product-test timing parameter changes follow from the guard rewrite.

The standalone `linux_trace.py` replacement uses one SEIZE startup path with a
held pipe, kernel-bound fork/clone accounting and exact terminal waits. Failure
cleanup freezes and harvests births before PTRACE_KILL; CONT with an injected
signal is not treated as a kill guarantee. Pending births, mixed-user cleanup
without CAP_KILL, unrelated-child safety and original-parent wait assertions
have separate finite Linux controls. Local synthetic controls cannot certify
those kernel behaviors. The replacement control workflow is not the product
source checkpoint and does not activate the replacement in release execution.

`source_owner.py` prepares plain or pytest-rewritten source code once from
separately authenticated immutable bytes. Admission-side checks still inspect
live module/loader/globals, retained function bindings, actual frame freevars,
closure cells and ordered synchronous/await owners. Compiler and case authority
remain external prerequisites. Python frames do not identify an executing
FunctionType object: a directly called clone with identical code/globals/freevars
is not distinguishable here. Actual arguments and state must still be verified
by route-specific parameter/custody checks; retained defaults are insufficient.
The loader class reference is retained at trusted preparation, rather than
resolved again from mutable module globals during each admission. The explicit
`beartype-passive` mode covers only the observed Beartype source-loader class
with both `_module_conf` and `_module_name` absent from active configuration
(their actual values must both be `None`). This mode still compiles the acquired
bytes independently with ordinary CPython compilation. Metadata dictionaries
use the same bounded string-key snapshot as other live namespaces. Active
Beartype transformations and all other unprepared compiler modes remain refused.

`process_ledger.py` joins kernel and authenticated control facts incrementally.
It keeps logical process tokens separate from exec epochs, fences readiness at
observed exit, and requires the original parent's exact birth and actual waitpid
receipt alongside the ordered kernel wait4 facts. WNOWAIT and tracer reaps do not
retire descendants. The declared session exception changes only the registered
pgid/sid view after matching admission, registration and lifecycle witnesses;
original birth evidence remains intact. Socket custody and the production
control channel remain separate integration obligations.

`launch_policy.py` renders finite typed declarations and compares complete launch
observations. Executable identity is separate from `argv[0]`. Inline hashes come
from the exact rendered command; dynamic program holes require explicit quoting
or bounded integers. Script/module identities still need independent file/tree
custody. Parameter values, source owner/case and acquired-root generations must
be authenticated before rendering; copying observed argv into expected slots is
not validation. Exact environment pairs preserve duplicate detection, and zero
or multiple matching declarations refuse. The library neither admits a process
nor establishes that an observation came from the kernel.

`size_budget.py --root <checkout> --check` counts all maintained `.github` files,
including both guard generations, policy/assets and full workflow text. Test
files are reported separately. External enforcement helpers must be supplied
with `--support`; even test-named support then counts as enforcement. The report
always distinguishes numerical size from the separate dependency-closure audit
and release certification. A dormant smaller implementation cannot satisfy the
ceiling while the old implementation remains in the tree.

`full_bootstrap.semantic_manifest` binds sorted tracked source, guard, policy,
lock and workflow command bytes and modes. It excludes only the readiness carrier
from its own semantic digest. The host writes that immutable manifest separately
from the execution envelope. The envelope binds the actual run/head/workflow,
nonce, UID, input inode and private-directory identity, and bounded monotonic and
wall clocks. Consumers reacquire the physical inputs and compare the candidate
manifest; a new commit is not a recursive input to its own digest.

The protected source authority and runtime guard remain unchanged. The PRIMARY
compartment selects the dependency specialization with the finite owned
multiprocessing custody mixin. Only tracker/spawn registrations enter that mixin;
all other descriptor operations retain the original authority. A custody failure
poisons both the kernel trace and supervisor, and propagates the original error.

`phase_catalog.catalog()` supplies executable commands, output directories and
encrypted member names. The primary workflow's always-upload block is a generated
projection checked before a script binds. Package phases are included. The
production executor retains an acquired phase's preparation failure before exit;
invalid caller/argv refusals do not acquire or overwrite another phase's evidence.
Missing or incomplete records never authorize a checkpoint certificate.

The finite `release-v047-preflight-20261019-01` through `06` branches exercise the
supplementary job in the actual CI workflow. The ordinary checkpoint decision
refuses those branches before full source execution. The supplementary controller
uses the production image builder, mounts, source/observer UIDs, dependency cache,
physical candidate producer/consumer and `ci_shell` capsule executor. It runs
controlled ACP completion and exact multiprocessing ownership canaries, a caught
unknown-launch poison control, the existing package/installed producer-consumer
chain, and isolated early-preparation and terminal-custody failure cases. Evidence
is encrypted before upload. Original full-suite, distribution and installed-wheel
certification obligations remain downstream and unchanged.

A supplementary preflight result is not release certification. The frozen source
command remains `env -u CODEX_PATH uv run pytest -q`, unexcluded on Python 3.13.
No new native/provider campaign, missing-wait exception, generic Python admission,
cap increase or private plaintext upload follows from this workflow.

Source preparation admits the exact acquisition-ownership document together with
its pinned broker/session owners before scanning the original baseline. An
unrelated document or engine change still refuses. The historical snapshot-stage
failure has no exception attribution and remains UNKNOWN.

The acquiring host encrypts a named preparation-status record with a closed
exception code and hashed code location. A failed source-input subprocess supplies
a bounded named child error record before its parent refuses. Exception bodies,
paths and raw child stderr never enter public status metadata; an unrecognized
exception retains the code `unknown`. These diagnostics do not grant admission.

The CI host control plane disables implicit Python bytecode generation before
its first import. Host composition controls import the same finite support later
mounted read-only into source capsules; generating a host cache would make that
capsule correctly refuse `source_only_support_cache_poison`. This preparation
setting prevents that contamination. Existing cache files still refuse; no cache
is deleted or admitted, and source interpreter flags and payload environment
bindings retain their original checks.

The native startup profile keeps exec environment bytes separate from the exact
post-initialization environment. For the two byte-pinned controlled backend and
ACP fixtures with their original non-isolated interpreter flags and no locale
variables, pinned CPython adds `LC_CTYPE=C.UTF-8`. The profile binds precisely
that result; changed fixture class, path, line, bytes, flags or an existing locale
variable cannot select this projection. Original pre-exec environment, argv,
owner, session, descriptor and READY checks remain mandatory.

Durable guard READY events identify their process with `owner_pid`; endpoint
requests and process registrations use `pid`. The supplementary reducer joins
those distinct schema fields to the same authenticated child. A missing or wrong
durable owner cannot be replaced by a similarly named legacy `pid` field.

An admitted phase acquires an exclusive, owner/mode/type/identity checked private
evidence directory before reading physical candidate inputs. The producer owns
`primary-preparation`; the custom shell owns its catalog duty. An untrusted
context or command cannot acquire these roots. Input custody failure therefore
retains a closed encrypted preparation outcome without admitting source evidence.
The supplementary host matrix mutates current physical inputs and authenticated
host envelopes through the actual producer/consumer and custom shell, before any
payload launch. Its uploaded refusals must reduce alongside all eight original
supplementary scenarios.

Tracker acquisition rolls back its original pipe and actual tracker child if
post-launch descriptor inspection, duplication or inheritance setup fails. The
synchronous rollback verifies the same original pipe generation before using the
original CPython stop/wait implementation, including when duplication never
returned custody. Cleanup failures preserve the acquisition exception together
with the cleanup error. Current supplementary canaries inject all four boundaries,
check descriptor census, and bind each tracker to authenticated READY and a
numeric kernel-observed original-parent wait; no modeled wait is evidence.

The current Linux host owner control changes only the private input owner/group
from the admitted host to UID/GID 20000. Its mode remains 0600, so the kernel
refuses the host's nofollow open with PermissionError/EACCES before the later
fstat ownership check. The reducer requires that exact exception/errno and the
same inode, mode, link count, size and mtime, changed ctime, unchanged custody and
receipt, and exact owner transition. An arbitrary access error or a second
physical mutation cannot stand in for this control.

## Shared source dispatch and unpublished acquisition

A shared helper callsite does not determine its owner. Cohort selectors decline
shared release-binding helpers outside their exact case sets; the later closed
resolver must still bind current code, module globals, caller chain, argv and
environment. A reference child retains its outer custody case. An exact nested
repository-check owner additionally needs its original selected payload node and
current pytest call marker; that does not authorize other nested outcomes.

The two additional original lease literals remain separate from the protected
finite registry. Their extension binds the original production factory and
original owner or the explicitly named controlled guard method. Cleanup
quarantine and the spawn/registration barrier remain the original owner's
responsibility. Empty exec environments also require an exact primary startup
locale representation; factory admission alone does not establish startup
composition or release readiness.

A multiprocessing child whose PID has not returned from the guard's spawn
wrapper is still owned by that wrapper. If acquisition fails, the original
parent must reap that exact unpublished child and retain its numeric wait before
rethrowing the original failure. That rollback grants no wait exception, does not
adopt another process and does not clear global poison or extend READY deadlines.
SOURCE crash launches use the exact pre-body owned temporary-directory generation
and inherited environment, including pytest's exact current-call/version fields.
An arbitrary, aliased or replaced root cannot acquire authority from its spelling.

The two exact lease factory literals retain an empty exec environment. Their
CPython post-init locale representation is consumed separately: the immutable
factory owner, original literal/parameter, admitted argv digest, launch token,
parent, cwd, transformed bootstrap and runtime must join the source startup
consumption. Only that join with flags `[0, 0, 0]` maps the empty environment to
`LC_CTYPE=C.UTF-8`. An explicit locale variable, another environment key, mutated
binding or a class name alone gets no locale mapping. Existing exact controlled
fixture mappings retain their own original identities.

Source integration uses a separately byte-bound activation factory around the
unchanged SOURCE activation tree. It acquires the owned environment at root
startup and re-resolves only the lease factory under the inherited original
callback/token checks. The locale mapper reads the unchanged profile producer's
exact live code/globals/instance frame; unrelated callers cannot synthesize that
production context. All original primary-authority and activation AST protection
controls remain unchanged. The supplementary reducer distinguishes the five
successful original trackers from one explicitly injected post-READY rollback;
that sixth child requires its own numeric original-parent SIGKILL wait, preserved
exception and restored descriptor census.

The already registered line-218 ignoring child keeps the original registry,
fallback validation and source anchor. After that unchanged consumption, the
extension rechecks the exact production factory and emits only its startup join.
The two newly bound literals and the original ignoring literal each have a
separate controlled method identity; the latter proves SIGTERM refusal followed
by genuine SIGKILL settlement without broadening any wait exception.

Supplementary lease probes wait for both core and authenticated endpoint READY
before exercising teardown. This does not change an original case or guard
startup deadline. The two exact native Git inventory leaves retain the existing
native-leaf READY disposition, source/argv/custody checks and actual-parent waits;
the reducer requires their exact owner, two source lines and unchanged source pin
instead of demanding a Python endpoint from a native executable.

The supplementary SOURCE environment probe reads the actual acquired directory
generations under the production root. It requires their uid/gid20000 custody,
rejects the exact parent/aliased TMPDIR mutations without launching anything,
and restores the original environment before further guard methods run. The
consumer binds that proof to the current environment-support bytes.


## Nested execution ownership

Outer `case` remains the custody identity in every registration, READY receipt,
parent wait, and child bootstrap. The closed `execution_owner.py` extension
resolves a separate execution owner for an authenticated reference pytest child.
It joins the bootstrap token/class/outer identity, original reference source and
binding, the exact ordered node selection and original argv, the owned JUnit
path, the current selected marker, immutable owner code and module globals, and
a live original owner or its lexical nested caller. The marker alone has no
authority. Cohort routes and production plan selectors use that same resolution;
startup consumption repeats it through the separately pinned activation extension.
The protected original activation and runtime guard remain unchanged.

The finite shared physical sites are `server.py:266` (cohorts 2 and 3) and
`release_binding.py:36` (cohorts 3 and 4). A resolver declines a known shared
site owned by another exact selection; selected source/code/vector drift still
refuses. The complete original nested inventory is mapped statically to its
source owners; original source-case acceptance remains the later unexcluded
REL002 checkpoint.

Lease barrier admission derives the sole captured `popen(*args, **kwargs)` AST
call under the immutable original `paused_spawn` owner. Line 532 is an injected
raise; the actual original call is line 533. The guard verifies the exact live
callsite, immutable code, module globals, captured Popen identity, barrier,
arguments, cwd, empty environment and launch flags. The supplementary own-identity
`_lease_popen` counterpart traverses the same verifier. AST/unit controls prove
that binding and its negatives; they do not prove execution of the original test.

Supplementary nested-owner probes execute only their own finite guard-method
identities through the production inherited guard and startup consumption. Their
reduction requires equal descriptor censuses, authentic READY, genuine numeric
original-parent waits and no residue. They do not replace original source tests,
parameters, assertions, or any failed checkpoint evidence. Changed owner
composition invalidates affected old production proof until fresh bounded Linux
producer/consumer evidence and independent guard acceptance exist.

## Immutable producer source root

The primary producer binds one complete `/source` snapshot read-only. No writable
source-root tmpfs or per-child source bindings remain. Before container creation,
`source_root` moves the private tracked snapshot into an exclusive root-owned
physical directory below `/var/lib/unrest-source-custody` and makes its host
bind mount read-only. Original source file modes remain unchanged for the strict
acquisition readers. Worktree and `.git` roots keep UID20000 for stock Git ownership
checks; their immutable host mount prevents owner writes or mode changes. Its root-owned physical ancestors cannot
be renamed by the runner or source UID. The snapshot has no background writer.
The host verifies exact member bytes, modes, device/inode identities, ownership,
and physical ancestors immediately before dispatch. Host custody lasts until
container removal; cleanup unmounts before removing only that acquired directory.
A failed unmount retains the sealed backing. Container capabilities and security
settings are unchanged; no container remount permission is added.

Only `.venv`, `.wheel-venv`, `build`, `dist`, `unrest_harness-0.4.7`, `src/unrest_harness.egg-info`, `.pytest_cache`,
`.ruff_cache`, and `.mypy_cache` receive finite tmpfs overlays. Their empty
mountpoints exist before sealing. Dependency cache and temporary work remain in
`/work`. Strict Docker inspection binds the complete source mount and exact
closed overlay options and rejects extra overlays or writable source mounts.

Before guard activation or source execution, an own-identity Linux probe under
UID/GID 20000 checks actual mountinfo, read-only source/ancestor filesystems,
search permissions and every non-overlay source member's bytes and physical
identity. It observes denial of source-file writing, root creation, file/root
rename, and root/ancestor mode changes, then writes, reads and removes a canary
in every exact artifact overlay. The observer preserves these facts, runtime
bytes/version/flags and mount identities in the encrypted kernel evidence as an `immutable_source_root` primary record.
The closed top-level kernel schema and existing consumers remain unchanged.
This prerequisite is supplementary proof; constructor compatibility and fresh
integrated guard acceptance still precede any changed full-source certification.


Package build admission requires the setup-observed empty UID20000 `/source/dist`
tmpfs mount rather than an absent root. It records that exact device/inode/mode/
owner generation, and export requires the same root after the original native UV
query and four backend operations settle. Preexisting members, substituted roots,
wrong owner/mode or another filesystem refuse. No original test, native operation,
READY or actual-parent-wait requirement changes with this artifact invariant.

Archive and installed consumers transfer only the same authenticated two archive
members into the setup-observed empty `dist` mount. Generic caller-supplied output
paths retain their original absent-directory requirement. The installed producer's
original `uv venv --clear .wheel-venv` command receives its own initially empty,
executable tmpfs overlay; its argv and package lifecycle checks remain unchanged.

The pinned setuptools84 sdist producer creates the exact versioned release tree
`unrest_harness-0.4.7` at project root. Its bounded noexec overlay supports that
original build operation without making the source namespace writable. This is
one literal versioned artifact directory, not a prefix rule or source subtree.

The encrypted raw host source manifest uses the existing admitted
`source-pins.json` carrier. It retains bytes, modes, physical identities and host
mount flags; its exact digest joins the own-identity proof. The input descriptor
remains `/inputs/source-custody.json`. No archive member or consumer allowlist is
expanded for this retention.


### Checked child-relative constructor boundary

Only an already admitted ordinary Python SOURCE launch with original `cwd=None`
can consume the single-use constructor context. The checked activation installs
its saved stock `Popen.__init__` wrapper before the unchanged finite core captures
that constructor. At invocation, the wrapper authenticates the actual inner core
code/globals, registration, handle, token, original argv and exact options. A snapshot
after checked shared activation binds registration bytes, environment and argument
values to that handle; construction consumes it once without retaining the handle. The
static `child_relative.APPLICABLE` inventory enumerates existing Python classes;
it grants no admission. Explicit cwd and non-source contexts retain stock handling.

Method C passes `cwd='.'` to the stock constructor, retaining every other argument.
It requires the exact hosted CPython/stdlib/native implementation, unchanged source
credentials, no custom preexec or credential switches, and a searchable read-only
source cwd matching the host manifest and actual mount. No global spawn flag or
private execute-child implementation is replaced. Direct posix_spawn still refuses.
A non-None cwd selects the existing stock fork/exec path; the child resolves `.`
against its inherited cwd. A parent cwd change before the fork can affect that
inheritance. Parent inspection alone therefore does not prove the launch safe.

Before native pre-body admission, stopped-child custody joins the exact constructor
record to actual child cwd device/inode, source manifest, mount and launch binding. Observer-side procfs access does not
attest child search permission: the UID20000 child checks that itself before body
or READY, while object/mount facts must match the exact stopped-child binding.
A controller-owned receipt carries either verified facts or a retained denial. A
denied child exits86 before bootstrap/READY, allowing its genuine parent to collect
status while global poison remains set. A permitted child repeats the check before its original
bootstrap or any successful authenticated READY. Failed checks retain poison; stock
constructor/chdir errors propagate without swallowing or retry. This bounded method
does not claim universal cwd equivalence or native interception. Its own-identity
supplementary probe shares the production boundary; original source certification,
all-five independent checks and the release gates remain separate requirements.

A separate own native prebody denial control runs only in the existing positive
and poison TEST source capsules, before their source root starts. It uses the same
byte-pinned primary native entry and prebody consumer, an actual UID20000 child,
and its own controller-owned denied header. A dedicated coordinator uses the
existing observer credential transition; it does not change the primary bootstrap
parent or request additional capabilities. Its source-owned temporary inputs are
identity-checked and removed before the ordinary source setup continues. It claims no constructor admission or
original case identity. The unchanged kernel record stream retains its real exec,
prebody denial, actual direct-parent status86, closed descriptors and equal parent
census. No original source selection, scenario, consumer, policy or cap is replaced.

### Host snapshot acquisition and release

Host custody uses only a newly acquired random `source` snapshot under the
validated root-owned `/var/lib/unrest-source-custody` base. The host self-bind and
read-only remount preserve source bytes and modes; they grant no mount capability
to the capsule. Source root and Git metadata retain UID20000, with the remaining
source members root-owned. Canonical root, parent and member identities are
recorded before subsequent fallible acquisitions. Creation, move, partial owner
transitions, bind and remount each have an explicit phase. Same-device moves and
single-link regular files exclude shared or partially copied backing.

A capsule create intent has an unpredictable ownership label before Docker runs.
The inspected immutable capsule ID, label and exact read-only source binding join
that intent. The short source-bound preparation capsule also registers its labeled name before
launch and confirms absence after its original auto-removal. Stop reauthenticates
the ID and removes only that capsule. A successful
exact-name listing proves absence; Docker query or stop failures retain ownership
and prevent unsealing. No unrelated container is stopped by a reused name.

Release retains its record until verified absence of both source and random
parent. The root-owned canonical util-linux mountpoint executable is byte and
identity pinned for the lifetime: status0 means mounted, documented status32 means
not mounted, and all other results retain the backing and retry record. The
source manifest and base/parent/member identities are rechecked before unmount
and deletion. Cleanup removes individually recorded files and empty directories;
it never recursively removes an arbitrary path. Each pending deletion is recorded
before the syscall, so a reported error after a successful deletion can be
reconciled on a bounded retry. Partial owner transitions accept only the recorded
old/new owners with unchanged identity, bytes and modes. Substitution, unknown
members or lifecycle ambiguity refuse deletion.

The private coordinator log retains acquisition identities, phase transitions,
authenticated capsule absence, mount-query outcomes and verified zero-residue
release before encryption. Initiating and cleanup exceptions remain separate
members of an exception group when both occur. Fault controls exercise the same
helper, while actual Linux capsule-exit/unmount/deletion observations supply the
production cleanup proof. These records do not certify the original source suite
or replace independent validation.


The own lease-factory probe releases its barrier inside the executor lifetime.
An initiating failure publishes cancellation before cleanup snapshots the owned
handles. A constructor returning afterward closes its exact handle before any
endpoint or stdout stage; a published handle can be killed and waited before
executor shutdown to unblock its stdout reader. One cleanup lock serializes this
boundary with the own owner-close task; the original outer cleanup remains an
idempotent final boundary. All four modes, original assertions and original
wait durations remain unchanged. Cancellation does not admit a launch or supply
READY. An incomplete owned startup boundary remains a failure.

Private own-stage observations record monotonic time in the executing thread at
constructor, registration, endpoint, stdout and barrier stages. Future completion
is observed only after executor shutdown and an actual completed future; its
observation time is not a claimed worker completion time. Cleanup distinguishes
cached status from a new wait and retains FD censuses. Initiating, worker,
diagnostic-write and cleanup failures remain independent actual exception
objects; private failure metadata contains only role, type, errno and bounded
source-hashed frame locations, never messages, repr, locals or source bodies.
These diagnostics do not change consumer eligibility or any original policy.

Each own handle's poll, stop, wait and individual stdin/stdout/stderr close is an
independent cleanup action under that same lock. A poll or wait failure cannot
skip stream closure, and one stream's close failure cannot skip another stream.
The synchronous cleanup branch uses the same stream settlement. Failed actions
retain their original exception objects with separate roles; diagnostic writes
cannot interrupt these actions. A closed stream object is never retried by its
former numeric descriptor, which may already belong to an unrelated object.
An unsuccessful wait or an open stream records unsettled ownership; any retained
failure prevents successful mode settlement or a descriptor equality claim.


The finite child-relative own probe chains the current native profile observer
before inspecting only its exact saved-stock constructor frame. Existing guard
and constructor code, globals, launch token, handle, registration, options and
source pins remain authoritative. The scoped observer restores the exact prior
observer and cwd in finally, retaining independent restoration errors. A native
callback refusal propagates with its original exception identity.

Own wrong-cwd and search-permission faults run in separate production capsules
using the existing command, image, credentials, mounts and limits. Wrong cwd is
refused by the original primary source resolver at the real exec stop, before
child custody or a startup receipt exists; it must retain the denied syscall and
sticky poison. Search failure may stop in the stock child chdir before any exec
attempt. Only a newly owned work directory may have its mode changed. The host
retains the original failed capsules inside the existing encrypted negative
control member; neither failure becomes a successful source checkpoint.

The successful postfork own body uses an explicit pipe barrier. Its recorded
fork return precedes the child's body marker; the parent changes cwd while that
child remains blocked, then releases it. The child's retained cwd, earlier real
allowed custody and authenticated READY must join its genuine original-parent
wait. This does not claim the parent changed cwd before prebody verification.

Live multiprocessing readiness reads journal bytes through the last LF before
strict UTF-8 and JSON decoding. The trailing fragment remains pending, even if
it already looks like a complete JSON object; it supplies no endpoint authority.
Committed malformed records still fail through the original acquisition rollback.
The original endpoint/nonce/identity predicates, five-second deadline, writer
fsync and READY semantics remain unchanged. Terminal evidence requires complete
valid records; this live framing rule does not certify truncated final evidence.

### Type-check derived storage

The authenticated Linux `Type-check (mypy)` duty alone receives exactly
`MYPY_CACHE_DIR=/dev/null` in its initial capsule environment. Its original
`uv run mypy src` command, pinned mypy 1.19.1, options, coverage, diagnostics
and exit status remain unchanged. The original script/workflow binding and
reconstructed plan select this fixed configuration; an incoming cache override
is rejected. Existing exact child-environment comparison requires the setting
and rejects a missing value, another value or an additional key. Other duties,
including SOURCE, retain their exact environments and gain no launch authority.

This is a prospective support/configuration change requiring new semantic pins
and production proof. Global developer defaults and OS Independent product
support are unchanged. In pinned mypy, the null path disables metastore writes
and is not a directory, so the final `record_missing_stub_packages` directory
check also prevents its separate metadata write. `--no-incremental` alone does
not provide that guarantee. The earlier ENOSPC and duplicate CI runs remain
failures with their original attribution; their byte/inode cause and duplicate
origin remain unproven.


The existing terminal-redaction registration also binds its indirect ACP request
route. Admission checks the original request literal, live test and ACP handler
code/globals, client and policy identity, exact executable/argv/environment/cwd,
and authenticated owner/token. Other ACP calls gain no launch authority.

The primary dependency specialization records bounded read-only filesystem
identity and free byte/inode observations before dispatch, on the first poison
or trace error, and after trace settlement. These observations use the existing
encrypted native-source records; they change no mount capacity, permissions,
admission, deadline, poison, completion or parent-wait rule. Historical ENOSPC
occupancy remains unknown when it was not measured.

Operation settlement readers consume only complete LF-framed records from live
owner journals. An incomplete final write cannot supply a settlement or a wait;
a malformed committed record still refuses. Inherited operation references use this framing in the PRIMARY specialization;
the original finite operation and handle-wait implementation remains byte-identical. Unexpected binding exceptions retain
a bounded, body-free type/errno and support-code location diagnostic before the
original exception is re-raised; this diagnostic does not admit a launch or
replace any original failure.

The shared-input hook can run inside the original `admit` call before the guard
has assigned `registration`. Child-relative custody capture defers only at that
byte-current call instruction, with all later launch locals still absent. It
captures no facts and consumes no token there. Unknown phases refuse; the later
constructor still requires the original single-use custody and all saved
context checks. The Linux compartment controls exercise this ordering through
the actual unchanged guard constructor frame without launching a child.

The indirect terminal-redaction binding follows its three existing finite
reference selections: evidence crosswalk, provider security, and retained
boundaries. Each nested invocation must resolve to the same original leaf via
the pinned execution-owner resolver, including original selection order,
module bytes, payload/token custody and live code/globals. Outer parameter
labels do not grant authority. The terminal vector, handler, policy, cwd,
environment and runtime checks remain identical; no registry entry or native
provider route is added.

The original CLI import positive control can issue exactly one read-only Git
query of the frozen source root: `git -C <source> rev-parse --show-toplevel`.
Admission joins its authenticated original inline payload and live globals to
the source-pinned CLI callback and repository checker, and checks the selected
Git image. Other vectors, repositories, explicit cwd/environment substitutions,
Git environment redirects and changed payload/caller identities refuse. This
route does not authorize a general Git command family or any provider launch;
the existing native parent-wait and execution-custody gates remain required.

The full-source observer writes the first twelve original failed pytest reports
to the existing private stderr capture as they occur, with a 64 KiB bound per
report. This survives a later test hang that prevents pytest's terminal summary.
Report bodies stay inside encrypted evidence; public events retain outcome
metadata only. The observer changes no report, item, timeout, assertion, or exit
status. A diagnostic write error cannot replace the original result.

For the existing local terminal-redaction registration only, the primary profile
records stock CPython's post-initialization `LC_CTYPE=C.UTF-8` addition when the
original exact two-key fixture environment has no locale. The complete immutable
registration, source pin, literal vector, interpreter flags, and synthetic
credential digest must match. Exec consumes the unchanged original environment;
the post-init environment is independently exact. This is no new launch route or
provider permission, and every other environment difference still refuses.

The primary source namespace carries a closed public Git projection rather than
an empty object directory with a dangling HEAD. It contains the exact current
commit graph, current tree/index, FM000 tree, and the byte-pinned v0.2.0, v0.2.1, v0.3.0, v0.3.1,
v0.4.0 and v0.4.5 tag/tree objects required by unchanged history tests. The producer
verifies the packed object set with no external deltas. Runner Git configuration,
hooks, remotes, alternate paths, replacement refs and unrelated history trees are
not copied. Normal immutable-source custody covers the resulting pack, index and
refs. No source test or Git query result is synthesized.

Only the full-source environment appends the existing `/native/bin` data location
to PATH for stat-only launcher preflight in ordinary mocked-startup tests. Its
byte-pinned adapter metadata already exists in the image; the Darwin Node image
stays nonexecutable, and the kernel/finite guards grant no native adapter launch.
This preserves early launch-error checks while allowing tests of a later startup
failure to reach their original mocked child. Metadata presence remains distinct
from transport selection and genuine native-provider acceptance.

For the nine unchanged ordinary cleanup startup negatives, the original nested
mock supplies an inline child without a `--port` argument. Its exact frozen
caller, parameter, body, runtime, and source binding join the live `mcp_port`
argument to the existing child-token endpoint plan. This supplies no listener or
connection permission: the supervisor still requires an actual owned listener
for a connection and returns a genuine refusal while the planned child has none.
The source observer completes endpoint authentication at the original guarded
constructor return, within that constructor's existing five-second READY budget,
before the original half-second readiness probe starts. The child birth,
parent, UID, boot, session, token, nonce, manifest and guard pins must match.
No original test, probe deadline, process status, wait assertion, provider
selection, or review decision changes.

Terminal locale normalization consumes the actual admitted event, rather than a
registry declaration. It joins the original synthetic two-key environment to the
same consumed token, parent, transformed argv, bootstrap, runtime, source pin and
original canonical workspace under the owned temporary root before describing stock CPython's post-init `LC_CTYPE` addition. Exec
still receives the exact original environment. Public Git metadata remains
covered by source custody; no extra raw archive member is emitted and the strict
evidence consumer continues to reject unknown members. Earlier invalid archives
and failed outcomes remain failures.
The compiled profile predicate forwards that exact guard-path
`initialize_inner` return when the existing source observer is installed. It
forwards the original frame, event and result; other guard internals keep their
existing predicate. The observer still authenticates the frozen constructor and
nine-case ownership before using the event. Compiled predicate controls run in
the isolated control image before the original source suite.

Full SOURCE setup writes a fresh, read-only `.gitconfig` only in its disposable
home. `maintenance.auto=false` and `gc.auto=0` keep original Git commands from
spawning incidental automatic workers. No original command, repository commit,
test parameter, or assertion changes; explicit maintenance retains its existing
finite authority. Other capsule modes and all user/global homes are unchanged.
An existing configuration or an inconsistent SOURCE plan refuses setup rather
than overwriting data. Real Git controls verify the original empty commit, clean
status and absence of an automatic child, before the source suite.

Cleanup certification enumerates every original owner of the local fixture:
twelve recorded transport cases, fifteen repeated-cancellation/fault cases and
three saved-review observer cases. The last family additionally binds the
original frozen observer function to the actual terminal-review lifecycle
callback, runner, store and attempt. Its role and progress/receipt/raw scenario
are exact; it receives no Git authority. The fault family's
separately created runner task must be the current task owned by the live frozen
test frame. Role, fault, source/fixture bytes, exact scenario, owned workspace,
launch plan argv and environment all remain required. The same existing local
adapter class is reused; no provider, generic Python, Git or class-prefix route
is added. Original assertions, process waits and deadlines remain unchanged.

The source-authority extension preserves the original supervisor instance,
sockets and callback references. Its base executable AST remains unchanged.
Every census rereads all current journal bytes; only immutable line metadata
is reused for identical bytes. Append handling compares the complete current
byte prefix, reuses only closed-line validation and always reparses the last
physical line. Prefix replacement or truncation invalidates that reuse. No
size/mtime trust, stale fallback, mutable
parsed-row cache or cached authorization verdict is permitted.

The original refresh loop receives every forbidden row, every unresolved Python
registration, every newly observed timing marker, and all lifecycle witnesses
when a registration remains unresolved. It still performs the original kernel
identity and ownership decisions. Only rows for which that same loop has no
effect under its current deduplication state are omitted from this census.
Malformed metadata falls back to the complete original loop, preserving error
and effect order. Differential controls compare state, kernel calls, repeated
poison effects and errors against the unchanged original implementation across
append, replacement, truncation and deduplication-state changes.

The tick retains a snapshot of the complete current byte acquisition. The
original policy handler receives its entire ordinary JSON list except for the
`payload`, `socketpair`, `listen`, `connected`, `ready`, `poison` and
`source_response_output` branches: their sole
journal read is the unchanged authentication predicate. Those branches may
receive all current READY rows in their original order, with fresh mutable
values, while the original predicate still chooses and verifies the first
matching row. No authentication verdict or kernel observation is cached.
Malformed metadata, nonportable JSON values, changed decoder policy, low
recursion margin or mutable rows exposed outside the READY projection retain
the complete list and its original error behavior. Repeated authentication
within one acquisition reuses that acquisition's mutable READY objects, including
any intervening mutations, without expanding unrelated journal rows. A later
acquisition still reads every current byte and creates distinct mutable objects. Every current byte is still read; the original
refresh loop still applies all poison and registration effects. Every other
handler keeps the full list, except `connect`, whose original journal reads
inspect READY and admitted rows. Its projection includes both kinds in original
order; the original handler still performs admission, identity and listener
checks. Switching projection kinds after mutable rows have been exposed falls
back to the complete current list. Planning, custody and drain retain the full list; planning also passes it to
the unchanged birth-bound listener retirement predicate.
Materialization preserves per-snapshot object identities but shares no mutable
JSON values with another acquisition. Authentication, native ownership,
receipt decisions, clocks, waits and deadlines remain original. Census
telemetry includes byte acquisition, indexing and the original refresh work;
it cannot conceal the observer's own cost. Idle census controls establish no
old-row decoding without treating these controls as source certification or
native provider acceptance.

Negative startup planning applies only to its nine exact original probe cases.
Another cleanup test using the same frozen inline literal retains the original
launch decision and receives no negative-probe plan or network permission.

The full unexcluded source command alone has a finite 2 GiB disposable `/work`
and 3 GiB container memory budget. This replaces the observed exhausted 512 MiB
workspace, without changing test assertions or deadlines. Other duties retain
their previous limits. Inspected capacity, paths, ownership, read-only source,
network isolation and capabilities must still match the exact selected plan;
no additional mount, executable or native/provider authority follows.

Two original resource-ownership tests intentionally run failing pytest sessions
in process. Their exact frozen caller, generated source, empty observer, phase,
arguments and owned path distinguish those sessions from the release session.
They keep pytest's original execution and failure result without registering the
outer collection/certificate observer twice. Root collection, XML and result
accounting remain attached only to the original full suite; child admission and
cleanup checks remain active in both scopes. Unknown nested invocations retain
the strict outer observer and cannot acquire this exception.

A single delayed diagnostic for each original startup-cleanup case records only
thread and coroutine code locations and cancellation counts in the existing
private encrypted stderr capture. It reads no source bodies, saves no locals or
task names, adds no public event or archive member, and cannot alter a test,
signal, wait or result. A call result or teardown cancels the observer. This retains
evidence for the observed cancellation hang without declaring it a product or
guard defect before the suspended task is identified.

Startup cancellation diagnosis uses the existing TEST executor with the exact
nine original startup-cleanup selections. Its existing 180-second trace bound
closes a hang and exports encrypted task locations without waiting for FULL's
two-hour bound. The dedicated exact-ref supplementary job executes no release
checkpoint or package certification. The ordinary CI workflow and literal full
source command remain unchanged; TEST output cannot issue or reuse a release
certificate. No original test, deadline, child admission or review restriction
changes. Ordinary cancellation may retain only a partial wrapper archive; that
archive remains incomplete and cannot substitute for task or wait evidence.

For the nine bounded startup-cleanup cases in FULL only, a successful stall
snapshot flush after 60 seconds without a call result ends that isolated root
with nonzero diagnostic status 89. It cannot produce passing test outcomes,
settled parent waits or a release certificate. Other cases and the existing
two-hour root budget are unchanged. TEST diagnostics retain their existing
three-minute trace bound. This stricter diagnostic failure bound preserves the
original product timeouts and assertions while avoiding silent multi-hour hangs.

The census reuses only immutable no-effect row indices while the complete
current chunk bytes and complete registered/timing membership sets are equal.
Equal set cardinality is insufficient. Every unresolved registration, forbidden
row and required lifecycle witness still reaches the unchanged original refresh
on each acquisition; kernel identity and permission decisions are never cached.
Materialized JSON values remain fresh. Malformed or non-reflexive metadata falls
back to the complete original loop.

The registration-order fixture's two original boolean cases bind their captured
stdlib spawn alias to the frozen original owner. Its initial two literal children
keep checkout cwd/inherited environment; the third requires the original paused
producer, actual terminal-create method, same two owned client children, exact
owned cwd and empty terminal environment. They reuse only the existing guarded
inline literal class; no generic alias, Python or provider authority is added.

After a real root test failure, the observer sets pytest's supported session
failure flag. The original item completes ordinary teardown before pytest stops;
the failed report and any missing waits stay failed. A passing candidate still
executes the complete unexcluded collection, and an incomplete failed attempt
cannot issue or reuse a release certificate.

The complete 51-case cleanup diagnostic selection uses the existing ten-minute
TEST allocation. It remains a separate non-certifying selection, not a filtered
FULL invocation. The third registration-order child has an exact empty-env
post-init locale mapping bound to the actual consumed exec, source pins, case,
owned cwd, runtime and registration identity; exec bytes stay empty and no
command or provider permission follows. Ten-second passive task snapshots for
the three adapter cleanup families do not change their original 15/20-second
assertions or failure types.

An early source-free control failure forwards its already bounded private output
to the existing encrypted coordinator log before required-witness checks run.
Missing kernel controls still refuse the run; no witness or source certificate
is synthesized and no raw body enters public metadata.

Only the exact complete-cleanup TEST selection also receives FULL's existing
disposable read-only Git configuration. This suppresses incidental automatic
maintenance in the diagnostic's own home; other TEST selections, user homes,
original Git commands and native launch permissions remain unchanged.

Activation re-resolves the registration-order fixture through the same pinned
live-owner resolver after the original guard consumes the launch token. Its
ordinary startup seal retains the actual alias/product source anchor rather
than substituting the registry's unrelated line-51 call site. Foreign cases,
changed vectors and calls outside the original activation frame still refuse.

The PRIMARY integration retains pure dependency comparison derivations across
launches: compiled comparison-only code is keyed by complete source bytes,
filename and compilation options, and immutable code identities by complete
marshaled code bytes. Every dependency read, custody/race check, directory
census, cache header, source/image binding and final byte recheck still runs
on every consumption. No stat-only cache, prior verification result, launch
permission or mutable namespace is reused. This removes repeated synchronous
compilation from the event-loop spawn path without extending test deadlines.

The paused spawn alias is anchored to the frozen original await expression at
line 437. A source-AST control distinguishes it from the unrelated line-434
cleanup-method assignment; synthetic frame metadata alone is insufficient.

Both inflight admission and activation combine the pinned original native-stack
walker with suspended task chains. A running coroutine has not yet installed
its current await-chain link, so task enumeration alone cannot establish its
active producer. A real async control exercises this boundary without launching
a child or executing the original product fixture. References are cleared after
each finite re-resolution; source, vector and caller checks remain unchanged.

The two frozen ACP readiness modes that intentionally launch a child without a
listener bind their port-1 negative probe through the existing plan RPC. The
plan requires the original live owner/exercise, exact source and vector, case
and launch token. It grants no listener or connection: unchanged supervisor
policy requires the admitted child token/vector and current kernel identity,
then returns the existing pending-listener refusal without a connect syscall.
Original 50-ms timeout and cancellation assertions remain intact.

Repeated references to one live frame are deduplicated by identity before owner
uniqueness checks; distinct active invocations still refuse. TCP readiness may
precede application accept. For the original connected stage's pending-peer
result only, the integration discards its provisional connection key and
reapplies the unchanged payload policy with fresh kernel observations. SYN
states keep waiting; only the existing owned-queue or reciprocal-peer policy
can establish the connection. Foreign and changed bindings still refuse.

The authenticated startup observer parses only the current journal prefix
ending in a newline. A live writer's partial final record cannot supply READY
evidence and is retried within the same original deadline. Malformed completed
records still fail closed; no bytes, cursor or deadline are repaired or edited.

The frozen inventory-FD worker fixture deliberately uses Git with global config
disabled. After its original successful init and before its original empty
commit, a bound setup step disables automatic maintenance in that exact owned
repository's local config. It preserves the existing bytes and mode, checks
source/caller/vector/environment, root, file identity and prior init result,
and refuses symlinks, hardlinks, races or changed repeated inputs. Commands,
environment and assertions stay unchanged; no maintenance executable is admitted
and no user/global Git configuration is read or written.

The two original inventory crash/restart modes explicitly supply `LANG=C` in
their minimal child environments. Their consumed, byte-pinned owned-role
registrations may map only CPython's post-initialization `LC_CTYPE=C.UTF-8`
addition. The native exec environment, original role arguments, inherited
inventory pipe, source bindings, nonce, process birth, and actual parent wait
remain exact. A missing or duplicated startup consumption, different owner,
case, environment, source, bootstrap or flags does not gain this mapping.

A raced whole-process socket census is discarded and reacquired at most three
times through the unchanged supervisor observation method. Each attempt checks
the registered process birth again and reads a complete fresh descriptor/table/
descriptor snapshot. Neither a partial inventory nor a previous successful
observation supplies authority. All other observation errors fail immediately;
three consecutive census races still fail closed. The original listener, peer,
cookie, address, ownership and payload checks run on the resulting fresh rows.
For a connect request with an already-admitted listener, only that exact listener
FD is reacquired: its current socket inode is read before and after a fresh TCP
diagnostic table, under the registered process birth before and after. The
complete resulting row must equal the admitted listener, including cookie, UID,
state and address. Closure, reuse, missing diagnostic rows and identity drift
cannot authorize the connect. Target-binding races retain the same three-attempt
bound; unrelated descriptor churn is not evidence about this listener. Listen,
connected reciprocal-peer and Unix-pair decisions retain whole-process censuses.

Dependency member reads use the already opened and custody-checked regular
descriptor directly. Each consumption still reads all current member bytes;
the bounded loop handles short reads and reads one byte beyond the original
size to detect growth. It retains no-follow opening, before/open/after/path
identity checks, original size and owner bounds, complete SHA256 comparison,
and the final directory census. Removing a second buffered descriptor wrapper
does not authorize a stat-only cache or defer verification beyond launch.

The checkout dependency integration control follows the authoritative full
0.4.7 CI lane: the unconditional, unexcluded Python 3.13 source command runs
before build and retains the waiting regression and original four affected
cases. Historical diagnostic job labels or duplicate selector strings do not
substitute for that source checkpoint. The exact source/clock pins and all
original functional tests remain required.

An authenticated new finite plan may expire a cached listener whose old owner
has completed its actual parent wait. Expiry joins the registered child and
parent births/tokens, run nonce, exact raw/numeric wait, and the observer's real
ordered kernel birth, exit, tracer terminal wait and original-parent wait.
Neither disappearance, a source-only wait claim nor a tracer wait alone is
enough. Only the old listener cache entry is removed: historical records and
existing connection evidence remain, and the replacement receives no network
authority until the original policy observes its new live listener.

The original oversized-stream worker and terminal-reviewer tests substitute a
fixed output-only Python child for the role command. Their separate route
binds both immutable source files, the actual original test and spy code,
captured stdlib coroutine, live factory, argv/environment/cwd and passed pipe.
It retains the existing owned-role descriptor census and independent repeated
resolution, with a truthful binding to the test's actual call expression.
Only these two consumed fixtures receive the exact CPython locale mapping.
Their original output sizes, redaction checks, bounded tails, five-second
cleanup deadline and actual exit/wait assertions remain unchanged. This
substitution is controlled local output coverage, not native provider or MCP
acceptance. Every unrelated role/vector retains its original refusal.

The original format-template fixture at `test_acp_runner.py:544` substitutes
only `/bin/sleep 30` for four worker/validator and Claude/Codex cases. After
the unchanged finite admission and authenticated READY, its exact stock
constructor uses `cwd="."` to select fork/exec instead of the refused
`os.posix_spawn` audit route. The effective sealed read-only directory, argv,
environment, descriptor options and original parent waits remain unchanged.
An independent stopped-child check joins that constructor to the consumed
launch token, original source binding, parent birth, current native image
bytes and kernel cwd before admitting this exact absolute native leaf. Other
absolute images and posix_spawn calls remain refused. This is fixture custody,
not native provider acceptance; all original format-preservation assertions
and review restrictions remain in force.

The dependency specialization still inherits every original authority method.
Its selected custody mixin delegates resolution to the byte-identical original
method first. Existing acceptance, non-selection and exceptions return unchanged;
only an explicit false result can enter the exact sleep-leaf join above. The
former auxiliary method-object identity assertion is now a delegation-order
contract for this mixin, with both selected authority classes, every original
return disposition and exception propagation checked. Unknown leaves still
return false; there is no generic native or absolute-path fallback.

The same constructor/kernel join covers the closed seven original sleep
call expressions at `test_acp_runner.py:544`, `632`, `1079`, `1380`, `1840`,
`2206` and `2265`, spanning exactly 17 original collected cases. Each table
entry binds its own original function, case IDs, source hash and DEVNULL or
PIPE pair. The vector remains exactly `/bin/sleep 30`; the table admits no
additional program, argument, case or source site. PIPE fixtures retain their
original drains. The bounded TEST command enumerates all 17 node IDs and
cannot certify FULL or substitute for the unexcluded source checkpoint.

### Source callback idle polling

The Linux tracer, its deadline algorithm and every original supervisor method
remain unchanged. The selected source custody mixin calls the original full
callback eagerly, when kernel records/active/pending/poison state changes,
whenever receipt clients exist or the receipt listener is readable, and when 100 milliseconds have elapsed after the last completed idle check.
Final trace settlement always forces
the callback. No request is accepted, read, authenticated or answered by the
readiness predicate itself.

Every source exec resolver invocation first forces the original complete
callback before running the original resolver. Poison or an acquisition error
refuses before any exec grant. This explicit barrier, the original pending
receipt callback and finalization all reacquire full current inputs and
journals. No decision is cached, no clock is paused and no original test or
receipt deadline changes. Empty wait spins merely avoid repeated full census
work while there is no decision to make. Controller timestamps stay actual.
The original one-second session-overlap assertion remains unchanged; direct
mock-only local diagnostics do not certify the guarded source suite.

### Setup follows the actual pinned child role

The inherited endpoint setup configures FastMCP's optional update check for
MCP users. A byte-pinned `tests/mock_acp_agent.py` process is a JSON-only ACP
backend and never imports FastMCP. Its authenticated ordinary mock classes
therefore omit this unrelated dependency preload. This does not defer a
product import or first call: that component is absent from this program.

Selection binds the actual guard child and endpoint install frames, current
source bytes and caller binding, script payload/argv/runtime, launch token and
READY identity. Other programs, roles, unknown contexts and dependency-window
negative or timing controls keep the existing eager FastMCP setup. All core
checks, authenticated READY, shared startup validation, audit/constructor
enforcement, descriptor lifetime, restart custody, pre-exit drains and
endpoint-complete evidence remain unchanged. No timer or launch grant changes.

### Original candidate Git and malformed launcher fixtures

Candidate fixture Git calls retain their absolute `/usr/bin/git` argv, isolated
configuration environment, owned repository, original configuration canaries,
and actual parent waits. Registration checks the current pinned original helper,
its callable and caller code/globals, the actual source call expression and
arguments, and the current case. The stopped-child adapter runs only after the
original resolver explicitly declines; it joins that consumed registration to
actual parent birth, cwd, argv/environment digests and the pinned native image.
The legacy candidate-object guard route admits only its pinned closed `cat-file`
kinds and full OIDs; the current restricted candidate reader performs no such
launch and independently decodes and hashes local loose objects.
Unknown absolute native commands remain refused. No missing mutable state key
implicitly creates source authority.

The exact full source command and closed positive source fixtures require an
explicit executable `/work` tmpfs option: Docker's implicit `noexec` otherwise
turns the original mode0700 malformed launchers into preflight permission errors.
Other phases, negative capsules and noexec mounts are unchanged. This mount flag
is not executable admission: every exec retains the unchanged kernel observer.
Only the three original malformed-launcher cases may attempt their exact single
relative argv, original workspace, mode0700 single-link owned file and literal
non-script/non-ELF bytes, after the consumed launch/parent identity join. A
successful exec is a poison condition stopped before the body. No script
conversion, shell fallback, arbitrary native image or provider launch is added.

The native join consumes the serialized admission event, which omits the template's
`python` field. Native bootstrap absence, exact class, source binding and image
remain mandatory; a supplied foreign Python marker is refused. Ordinary imported
product methods are compared with ordinary compiled source code; pytest assertion
rewriting applies only to the original test owners that actually use it.

Candidate commits retain stock Git's observed auto-maintenance child instead of
changing repository configuration to suppress it. This separate fallback admits
only `/usr/lib/git-core/git maintenance run --auto --no-quiet`, once per actual
byte-pinned candidate fixture commit parent at one of its four original source
callsites. The parent must retain its consumed native launch and current birth;
the stopped child must match cwd, image pin and exact stock-derived environment.
Current bounded, nonsymlink metadata must identify the tiny fixture repository,
its ordinary core/user configuration, main ref and SHA1-verified loose commit
with the original fixed author, committer, dates and source-bound message. Extra
config, changed metadata or descendants receive no authority. The unchanged
kernel trace retains actual native parent waits; no provider permission follows.

A passive failure diagnostic for the unchanged candidate manifest oracle records
only a bounded ASCII relative metadata entry name from its already-failed,
byte-pinned product `metadata` frame. It reads no file bodies, changes no exception
or report, and returns no replacement hook result. Other cases and failures are
inapplicable; source checkpoint and launch authority are unchanged.

The candidate template compatibility repair has a separate exact input
transition. It retains the original source template, requires both original
product/document pins and the absence of the added regression file, then reads
all three exact postimages through the existing read-only descriptor acquisition.
Only after every input matches does it update those three pins. This does not
admit a changed native Git owner, command, provider or arbitrary source drift;
the seven new source cases join the full unexcluded collection.

That transition also updates the one existing candidate Git passive observation's
source file hash. All 176 observations remain present. Its owner AST, exact
Popen expression AST, line151, route and family must match the original record;
only the file hash may become the exact repaired postimage. Unknown membership,
owner, expression, route or line drift refuses before any pin changes.

The literal terminal defaults fixture keeps its original `/usr/bin/true` launch.
The kernel resolver consumes the unique pre-existing finite registry entry, its
current source binding, actual parent birth, launch token, exact argv, cwd and
environment digest, and the current Linux image hash. The fallback is confined
to the two original optional-null parameter cases. An altered registry, extra
argument, foreign case or changed parent remains refused. The focused diagnostic
also runs the original separate mock-agent case, so the unchanged probe reducer
observes a genuine Python bootstrap rather than receiving a synthetic bridge.
This focused result carries no full-source or provider-acceptance certification.

The original LaunchPlan fixture slice retains actual shell scripts, relative and
empty PATH entries, direct argv0 spellings, PATH obstruction probes, immutable
plan fields, the Python symlink alias, legal empty environment names and genuine
ENOEXEC. Only its nine unchanged source call sites receive fixture registrations;
unknown owners, source/code changes, bodies, arguments, environments or roots fail
closed. The alias remains an actual PATH-resolved symlink to the pinned runtime,
confined to its one deterministic owned pytest directory. It is not translated to
a different executable. Native script and alias image custody checks the actual
exec stop before the first instruction, image bytes, argv, environment, cwd,
credentials, parent birth and absence of surviving extra descriptors. Directory
probes retain the actual EACCES; malformed files retain ENOEXEC.

Two observation defects are corrected without new launch authority. Lifecycle
image hashing uses the child's cwd for relative executable and PATH entries. Raw
exec environment parsing accepts a legal empty name and preserves equals signs
in the value, while duplicate names and malformed rows remain refused. The
structural proof requires those two exact AST changes and restores them solely
for comparison with the original complete executable-tree hash; original wait,
launch admission, callback and tracer scheduling algorithms remain protected.
All original product tests remain byte-identical. These focused custody tests do
not replace the full unexcluded source checkpoint or prove provider acceptance.

The primary constructor wrapper retains one exact guard-body hash. After the
closed lifecycle-image observation correction, that hash is updated coherently
to the new body. There is no alternative-hash allowance, skipped validation or
looser caller boundary. The complete original guard AST comparison independently
permits only the stated observation expression change; the endpoint closure,
installer, initialize-inner code/globals and original Popen constructor checks
remain mandatory. Related archive and diagnostic structural controls use the
same explicit delta normalization and retain their original baseline hashes.

The exact guard update propagates through the journal loader, package loader and
child-relative constructor binding. All three retain a single strict operations
hash. The historical constructor-domain control now enumerates the already
existing dependency-verification override as well as rows and admit, and pins
that override's original AST. It continues to forbid a constructor override.
The finite native/grammar/LaunchPlan regression controls run inside the Linux
compartment control suite as well as locally.

The synthetic compartment retains its noexec work mount. Image-search controls
there require refusal even for mode-0700 fixture files; they do not change the
mount or replace the real access probe. Successful script/PATH execution is
verified by the original source fixtures in the separately declared exec-mounted
SOURCE compartment. Direct-path observation does not grant execution authority.

Approval source tests use a separate finite Unix-channel envelope. It covers only
the original closed approval-test owners and the five byte-pinned bind/connect
call sites in ApprovalOwner.launch_environment, install_pending, review_approval
and the controlled relay. Actual source code/globals and await sites, original
address values, a mode-0700 owned temporary parent and the literal control name
are checked before an effect. Ordinary product code uses ordinary compilation;
only pytest fixtures use assertion rewriting. Unknown cases, roots, sites and
Unix addresses continue through the original custody refusal.

The endpoint retains original TCP and socketpair handling. Unix listen, connected
and payload operations require independent observer receipts. The existing
receipt ledger authenticates the kernel control peer and nonce; the journal
supervisor invokes the original authenticate method and retains global poison.
The observer duplicates the actual FD, verifies AF_UNIX/SOCK_STREAM, inode, kernel
SO_COOKIE, addresses, listening state, live owner birth and private socket-path
identity. Clients and accepted peers require actual SO_PEERCRED UID/GID/PID joined
to a live registered birth and the same-case listener. No native image, provider,
approval decision, submission or new process launch is authorized by this envelope.
Controlled API plumbing is not native human/provider acceptance.

A connect receipt is issued before the connect effect only while the registered
same-case listener still holds its exact live listening FD and kernel cookie.
The private socket path must retain its original inode/device, owner and mode
0600. Missing, closed, replaced or foreign listeners cannot acquire a client
plan; post-connect peer checks provide an additional boundary, not the first.

The two original unsafe socket-lock fixtures remain unchanged, including the
short /private/tmp spelling needed by macOS. The isolated primary image provides
a root-owned immutable /private/tmp symlink to the already owned /work/owned/tmp;
there is no additional writable mount or runtime redirect. A separate bind-only
envelope checks the exact two source cases, original test code/globals/site,
socket object and path locals, private temporary directory and owned lock target.
The authenticated observer checks the actual unbound AF_UNIX stream FD, cookie,
UID and birth before allowing only filesystem socket creation. It registers no
listener, connection or payload rights. The original test then moves that real
socket into the unsafe carrier and retains every outside-effect assertion.
The alias shares the existing owned tmpfs, preserving the original same-filesystem rename into the lock carrier.

Controlled approval process admission covers the original nine scenario values
and the seven exact durable-run boundaries, deriving the expected mode from the
original case. Scenario file names, trace destinations, environment mode and
byte-pinned Python adapter/relay/backend identities remain mandatory. Unknown
scenarios and executor modules remain refused. The one additional RunControl
executor reference is the pinned disposable approval fixture, bound to the
original test function, control object, owned project root, seven exact fixture
environment values and actual controlled-backend bytes. Ordinary product and
script functions are compiled ordinarily; only the actual pytest test module
uses assertion rewriting. No provider executable is substituted or admitted.

The closed 33-case approval diagnostic uses the existing finite 600-second
aggregate assignment budget, matching the existing cleanup/seam diagnostic
mechanism. Every original per-case assertion and 2/15/25-second deadline remains
unchanged; the command stays an exact source-only TEST selection with no release
checkpoint authority. Altered or shortened selections retain refusal.

The controlled approval MCP inherits its original sensitive-inventory read pipe.
Its two independent source registrations bind that FIFO's device and inode to
the exact approval case, argv and original ACP caller. The existing ordinary
pipe custody then observes pre-exec and successful-exec descriptor inventories,
UID, access mode, process birth, credentials and complete argv/environment. No
extra descriptor is omitted or accepted, and unrelated classes gain no pipe.

The closed 33-case approval diagnostic retains root thread and asyncio task
stacks after a single controlled ACP case exceeds 60 seconds, or a durable
crash/cancel case exceeds 120 seconds. It then ends that failed isolated TEST
root with status 89. This never certifies a checkpoint, changes a product-test
deadline, supplies missing results/waits, or applies to SOURCE/poison/foreign
selections. The original 25-second ACP and durable boundary assertions remain.

The original controlled approval adapter and relay inherit the already-owned
workspace directory. Their two exact child classes retain stock fork/exec with
`cwd="."`, preserving that directory rather than attempting the denied spawn
API. Source case/class/body/vector bindings and a single-use constructor token
remain required. The observer joins the original directory's device/inode,
UID/mode, parent birth and complete vector to the stopped child. The unchanged
native startup profile checks the actual child cwd before body execution.
This grants no general mutable-cwd or native provider route.

The approval-only diagnostic timer remains armed through pytest fixture
teardown. A call report cannot cancel the teardown diagnostic; the original
case's teardown report closes it. All other watchdog lifetimes are unchanged.

An established private Unix connection may outlive unlink of its listener path.
Only a previously authenticated same-case connection can retain that binding.
Every payload still reobserves the actual FD inode/device/kernel socket cookie,
local/remote endpoints, UID, owner birth and live peer credentials/birth. A
replacement path, changed descriptor or peer refuses; new connect/listen needs
the original live listener and path. Listener unlink supplies no new authority.
Global poison and original-parent wait requirements remain unchanged.

The three byte-pinned controlled JSON approval fixture actors do not use
FastMCP. They omit only the guard's unrelated FastMCP update-check configuration
when the original guard-child/endpoint-install frames, exact case/class/token,
source/body bytes, generated launcher and interpreter all match. The actual
approval MCP server and RunControl worker retain eager server configuration;
all unknown contexts and negative dependency controls retain the original
setup body. No product deadline, native/provider gate, audit hook, descriptor
check or launch permission changes.

An established Unix socket can also retain EOF or buffered bytes after its
peer exits. A missing peer is accepted only with its previously authenticated
socket cookie/identity plus current kernel records for the same process birth,
terminal status and actual original-parent wait. Pending waits use the existing
bounded receipt queue; missing, mismatched, duplicate or adopted-parent-only
records cannot establish that proof. This creates no wait exception or new
connection authority, and all original parent-wait assertions remain required.

For that diagnostic TEST only, the observer duplicates its original private
output pipe before pytest redirects descriptors for capture. The duplicate is
non-inheritable and rechecked by device/inode/mode/owner/access before a bounded
stack write, so an aborted teardown cannot discard the private snapshot. It is
closed at session finish only if its identity still matches. SOURCE and other
selections acquire no descriptor; snapshots remain encrypted opaque output.

The seven original durable RunControl fixtures deliberately use the production
minimal worker environment, which omits TMPDIR. Their private approval roots
therefore use the isolated container's native `/tmp`. Only those seven exact
cases may bind the original `unrest-approval-<8 chars>/control` under that root;
canonical directory identity, UID and 0700 ownership, original source sites,
kernel listener/peer checks and exact generated launcher bytes remain required.
Other cases retain the existing owned temporary root. No worker environment,
mount, generic `/tmp` execution authority or native/provider grant is added.

After the first 20 original approval cases pass with sealed kernel evidence,
a second closed diagnostic selection contains the shared mock plus the seven
durable cases and six remaining API cases. It retains the existing 600-second
aggregate budget and approval teardown diagnostics, and cannot certify SOURCE.
The 33-case selection and full unexcluded source command remain available.
Only exception class, errno and hashed traceback locations are recorded for
an exact controlled approval child constructor failure; its original exception
is re-raised without message/body capture or retry.

A controlled durable cancellation or intentional owner crash can reparent an
already READY child. Existing payload/drain receipts retain the original birth
and token, while a separate current kernel identity must differ only in PPID.
The observer must have the original parent's actual matching signaled terminal
wait and kernel exit, the exact original case and byte-pinned source. The
unchanged receipt admission and policy handlers still check the actual Unix
peer, nonce, one-shot ID, READY pins and established descriptor custody. This
permits no new launch, connection, listener, socket pair or READY registration.
Original-parent wait gaps remain recorded and continue to fail certification;
a reparenting proof is not a replacement numeric wait.

The dead parent's fork record retains its original process group/session before
RunControl's admitted session setup. Parent birth is therefore joined by PID,
original PPID, boot/start clock and all four UIDs, with matching actual exit and
terminal status. The surviving child's full current identity must still equal
its authenticated READY identity except for its independently proved PPID.

The source callback can separately observe the exact controlled approval child
at a kernel exit and after the tracer's actual terminal wait. These read-only
records bind their raw trace row, current identity (when still available),
observer PID/UID and post-wait process absence. They neither alter the trace
nor replace an original-parent wait, grant an effect, or certify a checkpoint.

Dependency-cache code comparison constructs the exact same immutable
`freeze(original_code_identity(code))` tuple directly from all original code
fields and typed constants. This removes an intermediate dictionary/list walk,
including recursive repeated traversal of fixed tuple-of-name fields. Compile
keys, current complete file reads, immutable-image source checks, cache headers,
UID/link/census checks and every comparison result remain unchanged. No
authentication result, file observation or mutable input is memoized.

When the actual source root has a matching nonzero kernel terminal wait and
owned descendants remain, the source callback immediately enters OwnedTrace's
existing failure drain. It preserves the failed root and actual child kill/wait
records instead of spending the remaining healthy-root budget polling a failed
assignment. A live root, zero root status or a finished trace takes the unchanged
path. The original tracer, kill/reap algorithm, source deadlines, statuses and
release predicates remain byte-identical.

The seven exact controlled durable-run executors can defer unused FastMCP
configuration to their actual MCP child. Admission binds the real guarded
module entry, executor argv, original spawn owner, runtime bytes, case/token,
canonical owned cwd and complete worker/fixture/approval source bytes. Other
executors and diagnostic negative modes retain the original eager setup body.
The actual MCP child still performs that setup. Full fresh dependency-site,
READY, descriptor and launch checks remain unchanged. The source-input
transition restores the entire old approval runtime AST except its type-only
import, preserves every function/class line and restores the complete old
fixture AST after substituting the identical explicit configuration constructor.
No original test case, parameter, assertion, native review or timeout changes.

The controlled reparenting composition preserves the already installed READY
snapshot callback for every ordinary request. Only an independently proved
reparented cleanup request enters the narrow current-identity authentication
path. This composes the existing instance callback with the specialized class;
class adoption alone cannot replace a callback already bound on the instance.
All nonce/token/READY and live socket checks remain required.

A controlled child can remain a zombie when its original parent dies after the
tracer's first terminal notification. For the same closed cancellation/crash
cases, the observer may perform a nonblocking wait only after its actual kernel
parenthood, unchanged child birth, zombie UID/state and the original parent's
matching signaled terminal status are independently proved. The real returned
PID/raw status must match the tracer's earlier terminal record. This separate
`actual_adoptive_parent_wait4` record never impersonates an original-parent wait
and does not by itself activate a checkpoint or satisfy a wait gate.
A living original parent retains its wait authority; absence alone creates no
wait record. The tracer's numeric wait algorithm and raw records remain unchanged.


### Actual legal-parent waits after controlled owner death

For the six original controlled approval cancellation/crash cases only, a
numeric wait by the kernel's actual adoptive parent satisfies the child wait
obligation when the original parent has died. This corrects the impossible
requirement that a dead parent subsequently reap its child; it is not a
missing-status exception. Original case bodies, parameters, assertions and
timeouts remain unchanged. The raw `missing_parent_waits`, original summary
failures and original trace records remain unmodified. Prior failed executions
remain failed; new evidence must satisfy the current frozen definition.

The common evidence reducer requires unique registration and READY/token
bindings, unchanged child birth, all four UIDs, matching original-parent
signaled exit and actual terminal status, ordered trace/hash references, and
passed setup/call/teardown for the exact original case. A tracer terminal wait
counts only when the preceding kernel-exit observation proves the observer is
the actual parent and the process is absent after the numeric wait. A separate
adoptive wait additionally binds its current identity and trace position after
the parent's death; returned PID/raw/normalized status must match the earlier
terminal record and the process must be absent after the actual wait. Duplicate
or contradictory original waits, absent inventories, PID reuse, living parents,
unknown cases/classes, nonnumeric status, residue or any poison remain failures.

The source result, package custody and checkpoint issuer use this same rule;
checkpoint receipts retain every original gap and a separate actual-adoptive
wait inventory. The complete unexcluded source collection, full package-byte
and extracted persistence checks, installed lifecycle, desktop and CI duties
remain required. No new launch, provider approval, native review recovery,
status substitution or native timing claim follows from this rule. Native
approval/reuse/final timing remain UNVERIFIED.

The retained-connection cleanup check uses that same exact evidence for a dead
adopted peer. Live cleanup does not require the current test's future teardown
report; final certification still requires passed setup, call and teardown.
The live response distinguishes `actual_adoptive_parent_wait` from a missing
`original_parent_wait`, preserves the retained descriptor/cookie and READY
checks, and waits rather than admitting a peer without real numeric evidence.

Authenticated controlled approval workers can retain at most sixteen passive
cleanup task/thread snapshots through the existing profile observer. Observation
starts only at cancellation or owned cleanup and records code locations and task
states, never locals or source bodies. It composes a prior observer, creates no
thread/process/timer, changes no deadline or result and cannot certify a run.

A read-only hook immediately before a known candidate's original numeric wait
can retain its current kernel identity. The following terminal observation
accepts that snapshot only at the exact next trace-record index for the same
PID. This distinguishes parenthood at exit-stop from parenthood at the later
reaping wait without altering wait flags, statuses, fairness or failure drain.
The former exit snapshot remains valid where already sufficient; raw records
and original missing-parent inventories stay intact. Pending controlled zombie
reaping retries current parenthood at a bounded 20ms interval even without new
trace rows, since reparenting can finish between observer notifications. Every
retry repeats current birth/UID/zombie/parent-death checks and only an actual
matching numeric wait can close it. Absence or an empty poll creates no status.

The controlled approval test setup bounds its settlement wait by the owner's
existing remaining expiry. If real expiry erases the denial before settlement,
the helper returns the ordinary unavailable review task instead of awaiting a
settlement event that can no longer arrive. The original 200ms real-deadline
case and every assertion remain unchanged. A separate regression synchronizes the actual settlement read, then allows
the real expiry timer to erase the denial before processing that message. It
asserts both synchronization points and the original expiry outcomes, without
advancing a fake clock or extending the original real-deadline test.
The exact diagnostic approval selection can capture this case's task stack and
end its failed TEST root after 20 seconds; SOURCE budgets and verdicts are
unchanged, and diagnostic output cannot certify the release.

The source preparer also pins the exact approval-composition helper before
executing it. Its support pin must change with a reviewed helper byte change;
a changed helper without that matching pin refuses before any source test runs.
A control exercises the real preparer function against the current helper and
an altered helper, independently of a checkout being mounted in the control tree.

Expiry closes the owned control transport. Linux can report a peer reset when
that closure races an unread settlement frame; the expiry cleanup test handles
only that ConnectionResetError and always closes the owner. It still requires
the unchanged 200ms cutoff, erased denial memory and no submission, and now also
requires no owned tasks, writers or temporary endpoint root. Separate injected
reset and unrelated-error cases verify that cleanup always runs and unrelated
errors propagate. Their exact TEST selection retains the existing controlled mock-agent case
to prove the unchanged native Python bridge and numeric child-wait floor, plus
these four in-process expiry cases. It cannot certify SOURCE or admit provider
launches.
The complete unexcluded release suite and every other release gate remain.

### Wait observation scheduling

The Linux tracer still observes both syscall stops and actual numeric results
of every wait4/waitid. A pending wait alone uses the 100 ms idle census
period rather than forcing a complete census at both stops. Recorded results,
exec decisions, child changes, poison, readable receipt channels and pending
receipt clients force the original immediate service. Adoptive-wait collection
and pre-wait identity acquisition remain outside this idle scheduling decision.
No test deadline, original parent wait, source selection or review policy changes.

The cleanup fixture's empty setup commit disables automatic Git maintenance and
GC through command-local settings. It does not need a housekeeping child or a
new native route. A reviewed fixture edit must update every current file-pin
consumer together: product inputs, passive call-site anchors, inline registry,
startup ownership and the exact in-flight locale predicate. Historical template
preimages remain fixed; current source/owner/line/vector checks stay exact.


A controlled approval child whose own exit and original parent's exit have
already been observed may be adopted before either numeric terminal wait is
collected. For the existing six cancel/crash cases only, the tracer defers that
child's wait until the original parent's actual terminal wait is collected.
Registration, READY, case, token, source pins and immutable birth identities
must agree, and a fresh snapshot must prove adoption by this observer. The
ordinary round-robin scan continues serving other tasks under the same deadline.
No persisted record is reordered and absence never supplies a status. The
independent evidence verifier and original cleanup assertions remain unchanged.

The existing twelve terminal environment-transform cases admit only their exact
Python inspection program through the original ACP handler, with authenticated
original test code, live parameter values, policy, request, owned cwd and exact
credential-free environment. Its consumed-exec locale mapping is independently
bound to the admitted event. This grants no provider launch or general terminal
Python permission. The filtered diagnostic selection contains those twelve cases
and the six original approval cleanup cases; it cannot certify the release.

### SOURCE self-pipe identity enforcement

Within existing authenticated SOURCE processes, the pinned guard retains the original observer socketpair admission from the authenticated
CPython `_make_self_pipe` caller. Before either object is exposed, both remote
rows must match native local FD, inode, socket cookie, UID, stream type and the
opposite peer inode. Each subsequent payload on those exact socket objects checks
fresh native FD/device/inode/type/cookie/owner-UID identity, AF_UNIX domain,
anonymous peer and creator credentials. Every local witness also preserves the
observer authentication: fresh Linux process identity equals its admitted birth,
current token/phase claims match, and the exact durable READY row remains in the
original owned journal. Uncertain or changed authentication falls back to the
original observer, including its existing exact orphan-recovery proof. The local
path never grants recovery. Non-SOURCE modes retain their original method. Reconnect is refused before a native effect. A durable
local record joins the fresh identity to the authenticated pair receipt before
unchanged native I/O; journal failure prevents I/O. The identity lock never covers
blocking I/O. Unknown objects, detach, reinitialization and identity drift retain
the original observer checks and poison. Closed exact objects retain native
behavior with no effect or new receipt connection.

This replaces redundant per-wakeup control IPC for this already admitted anonymous
self-pipe. The original MCP cleanup can force-kill the owned server; local identity
checks leave no partial control frame on that boundary. This enforcement does
not depend on normal interpreter shutdown. Original
numeric wait statuses remain evidence, including SIGKILL where observed. The
observer's partial-frame, unknown-peer and expired-channel refusals, every real completion/cleanup assertion,
all deadlines, the full-source command and release gates are unchanged. The exact
sixteen-case completion/cleanup diagnostic is supporting evidence, never a source certificate. No
network, generic interpreter, provider, or process-launch authority is added.

### Original controlled backend postimages

The source suite intentionally modifies its local backend fixture to exercise
pending cancellation, malformed warning privacy, notification revocation, large
configuration frames, admission bounds, receipt-controlled completion ordering,
and teardown. The guard admits only the closed eighty original case/parameter
identities and their twenty-six exact script digests, with byte-current outer and
inner test sources. A mutable `FIXTURE_SHA256` value alone supplies no authority.

Admission requires the original `_open_role_owned` code/globals and subprocess
call, explicit pinned `ControlledTransport`, the original backend bytes, owned
worker/validator roots, and the full unchanged argv/environment. Configured
variants additionally retain the original configuration renderer and input seal.
The child startup path re-resolves these checks before consuming its launch.
Native pin-refusal and parking-admission negative cases are excluded. Six finite
supporting diagnostic groups retain the existing 600-second root bound; original
test deadlines, assertions, full unexcluded source command, and release gates do
not change. These controlled proofs do not establish native-provider acceptance.

The revocation fixture distinguishes an open service's real HTTP stale-capability
rejection from automatic shutdown. After a failed turn has already closed the
owner, it now requires the original listener FD to be closed and the original
server task to have completed normally. It does not reconnect to a dead endpoint
or accept a guard exception as product evidence. Open/disabled sessions retain
the real HTTP rejection; grants, candidate bytes, no-send/no-ack, privacy and all
numeric child-returncode assertions remain.

The thirty original finite-order cases retain their original fixture and strict
candidate metadata grammar. They admit only twelve original custody Git call
sites, exact helper code/argv/environment and canonical owned repositories.
A stopped-image check joins the launch token to the sole concrete caller in its
original journal window, then checks parent birth and the native Git image.
Each of the three original commit sites can own one stock Git auto-maintenance
child with its exact image, argv, transformed environment and current process
birth. The current main reference must identify an actual bounded commit object
whose digest, author, timestamp and message match that site. Other Git commands,
provider launches and wait-status exceptions remain refused. All original
numeric waits, cleanup and scheduler assertions remain required.

The same shared finite-setup helper has a closed roster of 118 original cases.
Only the 25 priority pairs use the `combined` root; the remaining 93 use
`cohort`. Fifty additional barrier callers reuse the existing pinned backend
postimage. The diagnostic policy inventories all 168 affected original cases;
a single original capacity case with read-only task snapshots isolates the
remaining overhead before broader proof. Snapshots never end the test or alter
its deadlines, and are disabled for the full source checkpoint.

Git admission caches only immutable compilation after every original fresh
carrier read and hash. File identity, bytes, pin and compilation flags must
still match on every use; resolvers execute in fresh namespaces. Live source
frames, argv, environment, native process custody and numeric waits remain
unchanged. The pure compilation reproduction does not establish end-to-end
deadline improvement or a release certificate.

That single TEST diagnostic can sample its original main-thread stack at most
400 times after the existing ten-second snapshot, retaining only the forty most
frequent bounded location stacks. It records no locals or source bodies, stops
at the original case boundary, and never selects, admits, interrupts or extends
work. Sampling is absent from SOURCE and all other TEST selections. A local
profiler-delivery experiment alone is insufficient evidence to change the guard
or launch another full source checkpoint.


Guard stack bookkeeping uses the same fresh `realpath` result with a canonical
root boundary and a per-call anchor index. Only matching anchors construct file
objects; their current source hash, AST pin and complete observation rows remain
required. CLI translation normalizes only the two pre-existing consumer names,
and static owner binding computes its three literal path strings once per call.
These changes cache no file facts, move no admission checks and grant no routes.
The deep-stack reproduction proves complete-row equivalence; only the unchanged
original Linux case can demonstrate completion within its real deadline.


The exact single-case TEST can additionally attribute instrumented main-thread
CPU time to bounded metadata functions using a vacant CPython monitoring tool.
It leaves the existing process and thread profile guards installed, never
restarts other tools' events, and releases only its own callbacks and local
flags after the original call report. It records names, counts and CPU totals,
not values or bodies. This optional diagnosis is absent from SOURCE and other
cases; its timings cannot certify performance or change any test deadline.


The eight original private-configuration cases (four Boolean pairs each in the
original function and its warning wrapper) also bind the unmodified backend
bytes through the same closed postimage route. Both test sources, original
configuration renderer, current caller code/globals, exact argv/environment and
owned paths remain required. Only those exact cases reuse the existing stdlib
backend setup omission; unknown cases and changed bytes retain ordinary setup
and fail closed. The two four-case diagnostics preserve every original privacy,
completion, account, context-revocation and child-cleanup assertion. Original
failed custody and missing waits remain failures, not repaired evidence.


The unchanged controlled durable-success test can retain nine first-consumption
CPU/wall phase clocks across dependency receipt, source, cache and file checks.
The closed case and phases emit no source bodies or values, do not admit work or
change deadlines, and are explicitly diagnostic rather than certificates. Every
original acquisition, comparison, cleanup assertion and release gate remains.

The observer-owned primary dependency declaration uses
`unrest.v047.primary-dependency-output.v3`. After the existing image/wheel
projection and complete installed-byte checks, it seals a source SHA and digest
of the original complete compiled-code identity for each compilable Python
member, at the exact consumer filename with `exec`, `dont_inherit=True` and
optimization zero. This pure derivation runs once before test dispatch.

Consumers authenticate the complete declaration and join reference source SHAs
to its original file roster. They still acquire and check every current source
and cache byte, header, process/file identity and membership. Only an exact
current-body, canonical filename and compilation-option match can reuse the
expected comparison digest. Actual cache code still undergoes the original
complete identity comparison. Missing references or different inputs use the
real compiler. References are non-executable comparison data, never dispatch
inputs; the shared compile cache contains only real code objects, and digest
identities use a separate namespace. No launch, wait, cleanup or deadline
requirement changes. Pure comparison speedups exclude the separately measured
observer preparation cost and cannot certify original-test completion.

### Bounded V3 evidence capacity

PRIMARY explicitly selects V3 packed named records. The V2 raw codec and its
refusal controls remain separate, with no parse fallback. V3 uses one zlib
stream per record and binds both physical and logical sizes and SHA-256 values
to the current invocation. Names are sorted and closed; decompression rejects
truncation, trailing or concatenated streams, excess output and digest drift
before any decoded record is accepted. Opaque records are never interpreted.

Physical stdout and stored members retain the 64 MiB limit, and the entire
expanded stored archive retains its 128 MiB limit, including the exact physical
stdout, packed members and metadata. V3 deliberately introduces separate
logical limits of 128 MiB per original record and 256 MiB in aggregate. This
expands logical report capacity, not launch or test authority. All original
record bytes are reconstructed exactly before the unchanged verdict reducers.
The closed named result files may be acquired up to the same logical member
limit. SOURCE custody stores an explicitly versioned compressed representation
under its original MAC, with the phase file still bounded to 64 MiB; other
phase storage remains unchanged.

A valid bounded header and physical carrier are retained when V3 refuses an
incomplete or malformed frame. They are diagnostic evidence only. Missing
records, a refusal, or a header reporting success cannot issue a checkpoint.
Original completion, cleanup, numeric-wait and collection assertions remain
required. Capacity tests use synthetic data and cannot certify a source run.

### Historical payload-peer candidates

The payload handler still authenticates the requesting process and observes its
current socket before searching registered reciprocal peers. A historical
candidate whose `/proc` entry is absent cannot supply peer evidence, so that
candidate is skipped just as an identity mismatch is skipped. Only
`FileNotFoundError` joins the existing candidate-local `RuntimeError` handling;
permission and other acquisition errors remain fatal. The search must still find
a fresh, birth-bound reciprocal kernel peer or refuse the payload. No historical
registration is removed, and absence never supplies a numeric wait, cleanup
verdict or authorization. Requester and listener observation errors retain their
original behavior. Original completion, cleanup and deadline tests remain intact.

### Complete code comparison normal forms

The v3 observer declaration also seals SHA-256 values of code objects serialized
with marshal format zero under the pinned Python 3.13 interpreter. This format
removes reference/intern-table differences while retaining the complete code
structure, nested constants, filenames, line and exception tables and all original
identity fields. The observer compiles immutable source at the exact consumer
filename with optimization zero, round-trips that serialization, and independently
checks the complete original code identity before sealing its digest.

A consumer decodes each real current cache body as before. Only an exact normal
form hash can reuse that independently sealed original identity digest. Unknown
code takes the complete original projection. Expected compilation and actual-code
comparison data remain independent and must agree at the original comparison.
Global marshal, executable dispatch, every current source/cache byte, header,
FD identity, census and final read remain unchanged. References contain no
ownership, admission, wait or cleanup verdict. All original completion, cleanup
and deadline assertions remain required. Local comparison speedups cannot certify
native completion or release acceptance.

### Native profile lookup spellings

The native profile gate owns six immutable Unicode lookup names for its lifetime.
It still reads the actual state dictionary, composition attribute, source set,
observer and guard value on every event, in the original order. Only repeated
string allocation is removed. No policy value, predicate result, frame, owner or
code object is memoized. Property errors, observer exceptions, constructor return
binding and garbage collection retain their original behavior. The inverse
source control preserves the complete original C predicate and all branches.

Producer tick dispatch filters only current trace-row candidates in the existing
byte-pinned native module. The iterator reads every current row and live owner
map again on each traversal. It retains original-parent wait4 rows for current
native children and kernel-exit rows for current native children or UV contexts;
unknown row or owner shapes take the original callback path. It does not cache
eligibility, advance an event cursor, remove records or retire earlier rows.
Later registration and ownership changes can make an earlier row relevant.

The original response, cache-completion and poison handlers retain their bodies,
order and current checks. The iterator retains original list-iterator behavior,
row references, mutation visibility and error ordering. The profile observer's
existing predicate is unchanged. Module/source/compiler/runtime/ABI binding
remains mandatory; loading the metadata selector grants no process or network
authority. Current journal-byte acquisition, authentication, kernel observations,
original numeric waits, source cases and deadlines are unchanged. Four original
controlled registration cases are also available as one exact bounded diagnostic
selection; it cannot issue a full-source certificate.

The finite diagnostic selection consisting of the four original controlled
registration parameters followed by forwarding cancellation runs with 512
bootstrap-created journals containing 40,960 inert JSON rows. These rows have
no PID, token, READY, admission or wait authority. The unchanged test deadlines
and original completion, quarantine and cleanup assertions still apply. Only
that exact TEST-positive script receives this load; FULL, poison and other
selections do not. Its reducer requires every inert row and still returns no
release certificate. This bounded reproduction tests journal-size sensitivity
before another full source checkpoint. It does not substitute for that checkpoint.

Each immutable parsing chunk also records the READY positions, READY/admitted
positions and positions requiring full-list fallback. Appending reuses positions
only within the same byte-identical closed prefix; replacement and truncation
recompute them. No kernel result, authorization verdict or mutable event value
is retained in these indices. Every acquisition still enumerates and reads all
current journal bytes. Selection applies the original handler to freshly decoded
current rows, preserving the existing mutable-exposure and decoder fallbacks.

Only the exact five-case large-journal TEST-positive diagnostic may capture a
passive task/thread stack two seconds into `test_actual_registration[late-2]`.
It uses the existing identity-bound, non-inheritable original stderr descriptor
and private encrypted output. Capture reads frame locations and task state, not
locals or message bodies; it cannot cancel work, call the exit watchdog, change
any assertion/deadline or issue a certificate. The original five-second test
remains authoritative; other selections and FULL do not arm this capture.

The exact five-case large-journal TEST reproduction uses the existing full-source
3 GiB memory cap. Its workspace, 180-second root bound, original five-second
registration deadline and all launch/review restrictions remain unchanged. Other
TEST selections retain 1 GiB. Container construction and inspection use the same
closed selection predicate. Its passive private snapshot also retains bounded,
whitelisted numeric current-container CPU and memory counters; unavailable or
malformed diagnostics do not change test results. The earlier 1 GiB failure is
retained. This capacity alignment is not a performance or release certificate.

Seven exact original initialization/preflight cases select the existing canonical
controlled backend through the current postimage route. Their outer test,
configuration-wrapper and probe-tool bytes are pinned; the coordinator cleanup
case additionally pins its cohort source and retains its unconfigured path.
The existing line-506 caller, exact transport/runtime, configuration rendering,
environment, script and owned-root checks remain authoritative. The obsolete
broad configured-backend route is not reactivated. A finite ten-case TEST group
also retains the broker-before-launch failure and both native pin no-launch
negatives. Prior postimage entries and diagnostic groups remain unchanged; this
slice never carries a source or release certificate.

The exact ten-case initialization diagnostic also uses the existing 3 GiB
full-source memory cap, with its original 180-second root, smaller workspace,
three-second timeout case and every protocol/cleanup assertion unchanged.
Its timeout case receives the same passive two-second private stack/capacity
snapshot as the journal reproduction. Both selections are independently bound
to complete argv hashes; FULL and all other selections remain unarmed.

The seven exact initialization catalog cases use the same canonical stdlib-only
backend hash as the existing configuration cases. The optional FastMCP setup
classifier joins those seven case identities to that hash instead of choosing
the unrelated barrier postimage. The existing selector still independently
checks the actual child/install frames, current catalog and script bytes,
source/code/globals, runtime, payload, owned root, token and authenticated READY.
Only unused FastMCP configuration is inapplicable; parent shared/dependency
checks, original argv, interpreter flags, body, deadlines, protocol and cleanup
assertions are unchanged. Unknown cases retain the preceding classification.

The original coordinator startup/cleanup-failure case consumes four additional
Git setup callsites in `experimental_cohort.campaign`, at lines 567, 570, 571
and 572. The existing custody-Git route binds this one case, both current source
files, the actual helper and campaign code/globals, literal AST arguments,
canonical owned `campaign/P1/base` path, exact fixed environment and repository
configuration. Only init, add, commit `base` and HEAD lookup are applicable.
Existing stopped-image, owner birth, launch token, argv/environment and actual
wait checks remain required. Stock maintenance consumes only that exact base
commit and its object bytes; no other campaign episode or Git family is added.

### Canonical initialization backend domain

The seven original initialization cases can execute their unchanged, byte-pinned
standard-library app-server fixture with an exact `-I -S` translation. The
original live owner, renderer, vector, environment, script and call expression
are authenticated before translation and again at activation. Other cases and
all adapter launches retain their complete ordinary dependency consumption.

This backend consumes all current shared files, the complete standard-library
inventory, absent startup paths and interpreter link. After authenticated
endpoint setup it seals the module closure: no new import (including extension
initialization), changed module identity, changed search path or unknown Python
execution is admitted. The only subsequent module-body executions are the
single exact fixture dispatch through original `runpy` and current pinned guard
support through original `checked_source`, with its original compilation flags
and fresh destination namespace. The native pre-body profile still binds the
actual translated vector, flags, process birth and environment. This execution
domain excludes third-party packages rather than treating their mutable bytes
as verified. It is test setup, not OS confinement or native provider acceptance.
The original initialization deadline, completion and cleanup assertions remain
unchanged; bounded controls confer no release certification.

The same domain also covers the four original controlled cancellation boundaries
(`backend_registered`, `adapter_registered`, `auth`, and `forwarding`). These
have separate exact case and delegated-source pins; the seven initialization
cases remain unchanged. Only the canonical backend changes execution domain;
the ACP transport keeps ordinary checks. The new backend class also consumes
the existing five-second, token/PID/parent/manifest/guard/registry/interpreter-bound
core READY handshake before its constructor returns. Core READY does not claim
completed endpoint setup or a sealed payload. Original cancellation deadlines,
assertions, numeric waits and intentional early termination remain distinct.

The current runtime guard digest is consumed by `primary_operations`; its exact
current digest must also be consumed by the journal specialization, package
specialization and child-relative constructor binding. The compartment controls
check this entire startup pin chain before any original test is launched.
Each consumer retains one exact current digest and its original drift refusal.

The exact controlled ACP fixture has a separate isolated stdlib class for the
four existing registration parameters and the original initialization-timeout
case only. Translation follows the complete original registry and source-call
admission; activation rechecks that original binding before consuming current
shared startup bytes. The original fixture, real ACP/Bridge behavior, deadlines,
assertions and numeric process waits are unchanged. Both authenticated sockets,
stdin pipe, initialize/session/prompt/cancel and shutdown are exercised under the
same sealed execution barrier. Native evidence must join original/translated
argv hashes, token-bound consumption, core READY and endpoint/payload seals;
local controls do not claim native acceptance or a source checkpoint.
The four registration backend entries use their exact original canonical bytes
and source/delegated-test pins. All prior catalog rows and diagnostic ordering
are retained; no generic Python or provider authority follows from this domain.

Source-bound stdlib fixture controls run as an explicit trusted-host CI step on
both bounded diagnoses and the release lane. They need the original public test
fixtures and source-call binder. The source-free compartment deliberately has
no checkout mount and retains all its existing kernel and guard controls; these
source-dependent controls must not be placed in that compartment. Running them
is not the unexcluded source checkpoint and cannot issue a release certificate.
Host fixture controls suppress bytecode writes so importing source-only guard
support cannot create a later forbidden cache in the mounted support tree.
The runtime cache refusal is unchanged.

Host unit fixture controls normalize interpreter search-path aliases only after
ordered physical equality with the same three stdlib paths and absent zip is
proved. Foreign, reordered or missing entries fail with layout diagnostics.
Production native sealing retains exact path strings and does not normalize.

Listener retirement distinguishes immutable process birth from a recorded
`start_new_session=True` transition. The pre-exec fork/terminal tracer identity
may retain the registered parent's process group and session, while the READY
child identity has its own PID as both. This variation is accepted only with
one matching original admission, launch lifecycle and registration, exact
PID/parent/start/boot/UID/tick identity and the unchanged source/kernel/tracer/
actual-parent numeric wait join. It removes old listener authority only; the
replacement still requires a fresh kernel-bound listener before any admission.

### Empty controlled-child channels during SIGTERM cleanup

The observer captures SO_PEERCRED and a fresh identity equal to the registered
birth at accept, before parsing bytes. A zero-byte EOF can remain pending only
for that exact captured `controlled-acp` child, within the original four-second
channel deadline. It closes without a request, receipt, response, ledger admission
or effect only after the actual original-parent SIGTERM wait (-15/raw15), exact
nonce/token/owner joins and ordered kernel birth/exit/tracer/parent waits settle.
The terminal proof is shared with listener retirement; socket/listener facts are
not invented for channels. Partial frames, unknown peers, missing or stale birth,
other classes and expired or incomplete wait proof retain refusal. A nearby child
exit does not establish channel ownership; earlier unbound failures stay failed.

The exact 24-case completion/cleanup supporting selector uses the existing
600-second diagnostic root allocation in both preparation and consumer policy.
That setup allocation does not change any original case deadline or the
four-second receipt-channel deadline, and TEST evidence is not a source certificate.

### Controlled approval JSON startup

The original approval resolver still authenticates the original actor, source
expression, arguments, scenario, interpreter and owned paths before translating
only its byte-pinned controlled Python backend to `-I -S`. The adapter, relay
and worker MCP keep ordinary dependency startup. At activation the same resolver
is rerun on the original vector, applying the same `os.fspath` list
normalization as the original guard admission. The translated actor consumes the complete
current standard-library startup inventory and seal their module identities,
import paths and executable code before the unchanged fixture body. Unknown
imports, dynamic execution, module replacement and path drift fail closed. It
cannot execute third-party dependencies, so unrelated site-package verification
is inapplicable in this domain. Every other actor retains it. This is test
setup only, with no native-provider acceptance or OS-isolation claim.

The bounded diagnostic uses the existing exact 33-case approval-closure selection
and existing 600-second root allocation. Original tests, parameters, assertions,
per-case deadlines and the full source checkpoint remain unchanged.

### Original controlled C1 witness

The single existing controlled C1 protocol witness retains its original timing
(including the second worker's ten-second delay), stage ordering and owned-handle
cleanup assertions. Its custody Git routes bind only the original four campaign
setup sites, two candidate directories with their respective lane file, and
authored integration sites under the owned campaign/C1 root. The original
explicit ControlledTransport and fixture/runtime/source pins are required; no
native provider route is redirected or admitted. Existing stopped-image, stock
maintenance and actual-parent wait joins remain required. Its canonical backend
uses the original ordinary startup domain and unchanged fixture bytes.

The bounded diagnostic selects this exact original case plus the existing mock
control; it cannot issue a source checkpoint. The full unexcluded source command
and every release gate remain unchanged. Historical native-route review denial
and failed evidence remain preserved; this binding does not retry that route.

Custody launch evidence carries the freshly minted launch token before the
actual launch record and process creation. The stopped-image join requires one
matching owner/token binding with exact caller, source, vector, environment, cwd
and null bootstrap, preceding that launch. Interleaved threads cannot erase one
another's evidence. A previous launch by the same PID does not define ownership.
Missing, duplicate, late or mismatched token records fail; there is no legacy
window fallback. Current kernel parent birth, executable, repository and stock
maintenance checks remain independent requirements. Original concrete admissions
and historical concurrency failures remain retained.


### Accumulated journal observation cost

Idle periodic acquisition uses 100 ms; this is a service period, not a test or
receipt deadline. Actual trace progress, live receipt clients, readable receipt
channels, poison, exec decisions and final settlement still force immediate
original callbacks. Every acquisition reads all current journal bytes. No
authorization, wait result or kernel identity is reused. This reduces repeated
idle observation of large historical journals without delaying an admission
decision behind an idle timer.

Census chunks retain immutable positions of possibly effectful descriptors and
lifecycle witnesses. Each changed census re-evaluates registration and timing
membership against the current supervisor state; malformed metadata retains the
full original loop. Inert history cannot become registration authority.

The exact existing two-case controlled C1 diagnostic selection also receives
the existing 512-file, 80-row-per-file inert load before source execution. It
creates no PID, token, READY or wait witness, never overwrites process journals,
and retains its 600-second diagnostic cap, false source certificate and absent
carrier. The five-case registration/cancellation load selection is unchanged.
Original C1 ordering, completion, cleanup and test deadlines remain unchanged;
a loaded diagnostic pass does not replace the full unexcluded source suite.


### C1 controlled leaf startup domain

The exact original controlled C1 protocol witness now uses the existing sealed
standard-library domains for its byte-pinned local ACP adapter and synthetic
app-server. Both original admissions, live caller bindings, interpreter/script
pins, streams, authenticated READY and actual parent waits still precede or
constrain execution. The translated vector adds only `-I -S`; unrelated source
and native routes keep their existing setup. Third-party execution remains
refused by the existing import/code barrier. This avoids repeatedly preparing
unneeded third-party inputs in twelve stdlib-only C1 children while retaining
the original two-second RPC limit, ten-second slow worker, ordering assertions,
real broker completion and owned cleanup. Native adapter acceptance remains
UNVERIFIED. The loaded diagnostic and full-source gates remain required.


### Current launch journal projection

Only the original source launch resolver and the token-bound orders Git join
consume the fresh launch projection through the exact JournalSupervisor or
its existing ApprovalSupervisor composition. Other supervisor types retain
their complete events surface. Their journal predicates read exactly
`actual_launch_binding`, `admitted` and `orders_custody_launch_binding` rows.
Every current file byte is still acquired; immutable positions select these
three kinds in original order with fresh mutable values. No eligibility, kernel
identity, source pin or authorization verdict is cached. Malformed/nonportable
metadata, changed decoder policy, low recursion margin or previously exposed
values retain complete original materialization and error behavior. Generic
events, refresh, receipt policies and final evidence remain complete. The
original launch predicates, duplicate checks, token/source/argv/environment/cwd
joins and actual numeric waits are unchanged.


Launch fixture read stability compares device, inode, mode, link count, UID, GID,
size, nanosecond modification time and change time. Access time is excluded: the
required exact-byte read can itself update it. This prevents an unchanged
fixture from refusing at a timestamp boundary, while every material custody
field, exact body, alias target, owner and permission requirement remains.


### Post-admission exec bookkeeping

The source idle scheduler ignores only the short trailing suffix of successful
exec bookkeeping for resolver-mediated nonroot processes. It checks the current
exact OwnedTrace and nonempty static table on each classification: every static
entry must have an explicit integer root PID, and the candidate must be another
integer PID. Therefore that candidate cannot use the static fast path; the
unchanged PrimaryAuthority first calls source.resolve, whose existing mixin
forces the complete fresh callback before admission. No barrier verdict or
record eligibility is cached. Root, wildcard, foreign or malformed tables and
other trace types retain the original scheduling.

Only exact memory-boundary, accepted-True exec-attempt and zero-return record
shapes qualify; pending execve for that same proven resolver path likewise adds
no duplicate census. Real kernel exec/child/exit/vfork events, numeric waits,
failed/denied execs, unknown shapes, poison, receipt clients/readability and final
settlement remain immediate. All raw records, kernel decisions, clocks and
waits remain unchanged. This removes repeated journal reads after the fresh
barrier without extending idle time or changing any test/receipt deadline.

### Fresh journal file acquisition

The exact POSIX/default-path acquisition enumerates current matching names on
every snapshot, sorts those names, and opens and reads every file completely.
It reuses only normalized Path/string spelling for names still present. It
never reuses directory membership, descriptors, stat results or byte verdicts.
The original glob call and its audit behavior precede selection; changed path,
read, I/O or scan methods retain the original glob/read path. Matching dotfiles,
directories and symlinks stay in the sequence; individual read errors propagate.
Scan errors retain CPython glob suppression. Parsing, original census decisions,
receipt predicates and all fresh admission/final barriers are unchanged.


### Trace observation and decision-free journal service

Every existing kernel-progress callback still runs the original source producer
observation, trace-progress update, exit collection, adoptive reaping and poison
propagation. Journal service is separate: an exact known composition with no
clients, no readable receipt, no poison and live owned processes may defer only
the entire no-decision Supervisor.tick call until the existing 100ms idle period.
The optimization additionally requires the current exact source owner and native
producer object to have empty UV and child contexts. Any producer context, even
a completed one, retains full per-event service: producer completion consumes
poison state before journal service in the original callback. No receipt is
accepted, policy evaluated or grant returned by a skipped call.
This changes when a kernel-only progress callback acquires journal bytes; it
does not delay kernel observation or numeric-wait handling.

Every source exec forces the complete original fresh callback in a nested,
exception-safe census context before the original resolver. Static root execs
that bypass that resolver keep immediate journal service. Unknown composition,
static tables, records and pending operations retain full service. Trace poison,
receipt clients/readability and final settlement are immediate. Refresh itself
always reads current membership and full file bytes; it never returns a cached
authority snapshot. Only successful service advances its completion clock.

The composed supervisor explicitly wraps tick as well as refresh/events/handle.
The original Supervisor.tick, refresh and policy bodies remain unchanged.
Focused checks retain original source callbacks at every kernel event and prove
that current forbidden journal bytes or a current read error refuse before exec
admission, even while no-decision service would otherwise remain idle.

### Repeated ordinary role pipes and completed build producers

Ordinary MCP role custody binds the pipe resolved from the live, pinned source
frame to the unique launch token before the actual launch and admission records.
The logical argv digest remains distinct from the transformed bootstrap digest.
The stopped-image join requires one preceding sidecar, one actual launch and one
admission with the same owner, case, source, cwd, environment and bootstrap. A
read-only event view removes only well-formed historical observations of the
same logical argv outside that current case and pipe identity. The original
exactly-two-equal observations, parent identity and pre/post-exec descriptor
checks still decide custody. Missing, duplicate, late, crossed or malformed
bindings refuse; port or descriptor-number reuse never selects authority.

Completed UV contexts remain in the original producer maps. Idle journal service
may treat them as no-ops only while every live cache completion and helper
response receipt already exists, with exact known context shapes. Classification
is recomputed before each producer tick; pending work keeps the original full
service even if that tick completes it. Actual producer callbacks, exit-86
refusals and exec/receipt/finalization barriers retain their original checks.

The bounded release diagnostic runs the original mock, crosswalk history, actual
packaged-policy contract (with its build/install fixture), repeated terminal-review
cleanup, saved-review cancellation and C1 tests in that order
with inert journal history. It cannot certify the full source suite. The frozen
release still requires the full unexcluded Python 3.13 source checkpoint and all
archive, installed lifecycle, independent validation, desktop and release gates.

The default-policy journal acquisition opens a fresh unbuffered binary FileIO
stream and reads to EOF. It retains every current membership/byte acquisition
and avoids constructing a redundant BufferedReader for each file. Changed path
or IO policy still delegates to the original Path.read_bytes route. Empty and
large files, current rewrites/replacements, aliases, permissions and read errors
retain the original behavior; differential OS-descriptor controls cover FIFO
EOF/nonblocking reads, interruption and Linux PTY partial-data/EIO behavior.
No file content, type verdict or descriptor is cached across acquisitions.

The closed launch-row projection uses the same immutable ParseBlocks mechanism
as full journal materialization. Exact selected current line tuples bind cached
encodings; each acquisition decodes new mutable objects and preserves aliases
when that snapshot is later fully materialized. Appends, rewrites and truncation
recompute current positions. Changed decoder policy, exposed values, shallow-data
limits or a narrow recursion margin retain the complete original decoding path.
Only parsing metadata crosses acquisitions; no launch decision or mutable row does.


### Retained source metadata capacity

The exact full SOURCE command and the seven-case repeated-build diagnostic use
a finite 128 MiB observer-owned, non-executable `/receipts` tmpfs. Other commands
retain 32 MiB. This metadata allocation stays within the existing 3 GiB capsule
memory cap; it changes no candidate workspace, launch admission, source test,
assertion, deadline, original-parent wait requirement or evidence-retention rule.
The diagnostic retains the existing six cases and additionally executes the
original extracted-distribution checker after that six-case prefix, matching
the full source suite’s C1-before-distribution order. Its second native build
and all 15 persistence cases retain their original assertions. It is not a source checkpoint.

Trace failure observation covers resolver exceptions as well as tick exceptions.
It retains the first exception class/errno and current mount block/inode counts
without storing exception text or substituting a diagnostic error for the
initiating failure. Earlier write failures without an errno or failure-time
filesystem observation remain uncertain; a larger metadata budget is not proof
of their exact operating-system error.


### Separate loaded C1 and complete source acceptance

The native readiness job executes the original documented two-case loaded C1
gate: ordinary mock completion followed by the unchanged controlled C1 witness,
with all 512 files and 40,960 inert rows. Its 600-second diagnostic allocation,
original fixed timing, completion/cleanup assertions, sealed child domains and
actual numeric parent waits remain mandatory. It makes no repeated-build or
repeated-role coverage claim. The six- and seven-case diagnostic selections
remain available; their preceding workloads and failed results are not
reclassified by this narrower-purpose gate.

Acceptance requires both the loaded C1 gate and the complete unexcluded Python
3.13 source suite on the same frozen candidate, plus all archive, extracted
persistence, installed lifecycle, independent validation and desktop gates. The
full source suite retains every original build, role, distribution and C1 case.
Neither a subset result nor a prior candidate’s pass substitutes for that full
checkpoint. No assertion, deadline, denied review or evidence failure is waived.

The restricted candidate input reader decodes its already-required local loose
objects directly, checking bounded compressed/expanded bytes, canonical type and
length and full object hash. It no longer launches candidate-object `cat-file`
queries. Real fixture setup, custody Git commands, source cases, completion and
cleanup assertions remain intact; this grants no new command or provider
permission. Every verification still performs a fresh candidate observation.

The exact object-reader source transition validates the original 176-anchor
inventory before retiring only the removed candidate object Git launch anchor.
The resulting 175 live anchors retain their original identities and checks.
Unknown preimages, changed reviewed bytes, duplicate or foreign anchors refuse
atomically; no replacement launch route is admitted.

Original workspace and evolution fixture checks retain all collected cases and
literal Git calls. Their finite support binds the original helper, live owner,
source bytes, call expression, owned directory and environment. The workspace
product's existing Git methods also bind their original call sites; the one
cleanup fault wrapper is admitted only in its exact original case. Commit-tree
input must match the original subprocess call and is recorded by digest.

Stock Git maintenance is a distinct native child. Only the enumerated original
fixture commit sites can supply its authority, joined to the consumed parent
launch token, current source and native process identity, exact commit/config
bytes, image and environment. Each parent admits at most one such child. Numeric
wait evidence remains required; Python READY is not inferred for a native leaf.
The bounded two-module diagnostic is the complete original 24-case tuple, carries
no source checkpoint authority and grants no provider, generic Git or review
permission. The full unexcluded source checkpoint remains separate.

The original child-self-commit fixture admits its linked worktree only at the
exact self-merge lease path and test site. Its gitfile, common directory, admin
backlink and detached HEAD must agree with that owned repository; other gitdir
redirects retain refusal. Native environment behavior requires bounded proof.

The exact 24-case workspace diagnostic shares FULL’s read-only disposable-home
configuration disabling incidental automatic Git maintenance. Original Git
commands and assertions remain unchanged; subsets, reordering, extra arguments
and other modes cannot select this setup. Explicit maintenance still requires
its existing finite authority, and all focused refusal tests remain intact.

The original lease and integration worktree creation sites at WorkspaceManager
lines314 and616 may launch
stock Git update-ref HEAD with its same requested revision. That native child
is joined to the consumed parent token, exact source/argv/environment, current
process births and image, and the owned linked-worktree gitfile/admin backlinks.
The admin HEAD must be a regular all-zero detached initialization; symbolic,
foreign, missing or redirected HEAD refuses. Only one such child per parent is
admitted; actual numeric waits remain required.
Each site keeps its distinct owned directory shape. This route grants no other
worktree-site, generic Git or provider authority.

The product workspace Git method closure includes exactly60 original collected
cases: the24-case diagnostic plus36 existing foundation, adapter, server and
measurement callers. Additional callers bind their exact test-source bytes;
method, expression, argv, environment and native custody checks remain unchanged.
This does not expand the diagnostic command or permit unknown cases.

The observed integration reset at line616 is a separate once-only phase. It
requires the same parent birth and launch token, current detached HEAD equal to
the requested revision, and both a birth-matched terminal record and the actual
parent wait4 returning zero after the current update-ref admission. Historical
same-PID waits cannot authorize it. Later child waits remain required; no Python
wait receipt or native final timing is inferred. Other sites remain refused.

The separately observed rollback worktree creation at evolution line1881 admits
its stock update-ref child, with the exact evolution source/AST/class and
owned evolution/rollback directory shape. Zero-HEAD, launch-token, current birth,
image, environment and canonical backlink checks are unchanged. The separately
observed rollback reset uses the same current-birth, post-admission successful
parent-wait and exact detached-HEAD requirements as integration reset. No other
worktree creation site or reset shape is admitted.


The original bootstrap module's delayed backend fixture has a distinct finite
inline-wrapper binding. It verifies the current fixture code and closure, exact
case-specific delay (32,60 or0.5 seconds), the live original product owner and
configuration-derived vector, owned pinned backend bytes, interpreter, streams,
environment and subprocess options. It preserves the original runpy body and
actual sleep. Activation re-resolves this same binding. The32/60-second cases
consume the complete ordinary shared startup inventory; the exact half-second
cutoff case uses the two-stage standard-library seal described below. No generic
inline launch authority follows. All27 original bootstrap cases and their timing,
completion, no-prompt, lifetime and cleanup assertions remain unchanged. The
additive bounded module diagnostic preserves all existing diagnostic jobs and
cannot certify the full source checkpoint.
The wrapper also uses the existing five-second authenticated core READY join
before publishing a child handle. Its token, process/parent identities and
manifest, guard, registry and interpreter digests must match; early cancellation
does not waive that proof and no original probe deadline changes.


Diagnostic plan rendering and root allocation consume one shared closed extended
selection list. The original source budget and every test's own deadline remain
unchanged; a bounded diagnostic cannot supply a source certificate.

For connected TCP acquisition only, a directory entry that vanishes before its
symlink can be read contributes no socket row. Each attempt still checks process
birth and obtains complete before/after socket maps around the current kernel
TCP table; those maps must agree. There are at most three attempts. No old or
guessed row supplies authority. Missing client/listener/peer evidence, inode or
cookie replacement, ambiguous reciprocal peers, permission and malformed data
retain the original connection-policy refusal. Generic, Unix and payload census
behavior is unchanged. The complete original connected policy body and its
listener/peer predicates remain covered by their unchanged historical AST digest;
only the exact acquisition call and birth-checked getter are normalized.


For this exact delayed-wrapper registration only, the post-init Python profile
records CPython's observed absent-locale coercion to LC_CTYPE=C.UTF-8. The original
exec environment remains byte-exact. This projection requires the pinned original
fixture binding, one of its actual delayed cases and original Python flags; an
explicit locale is never replaced. It neither admits a launch nor changes any
bootstrap timing or completion assertion.


The two original short-cutoff bootstrap checks use the existing sealed standard-
library runtime only after their original live-owner admission. The sequential
initialize/session check retains its0.55-second cutoff and both0.3-second phases.
The inference-timeout check retains its2-second cutoff and real0.5-second wrapper
sleep. Their canonical backend and controlled ACP bytes, original vectors,
configuration/environment bindings, startup input inventories, core READY joins
and actual parent waits remain required. This is fixture setup only and adds no
provider or unknown-launch authority.

The half-second wrapper is a two-stage execution domain: the one exact compiled
sleep/runpy body may execute once in the unchanged guard child namespace; only
then may authenticated runpy execute the current pinned backend body in its
original main-module namespace. A different program, repeated wrapper, premature
backend dispatch, forged code, foreign import or module replacement refuses.
Other delayed bootstrap cases retain their ordinary complete startup domain.


A separate closed two-case TEST command can attribute selected guard CPU for
these original cutoff checks. It preserves installed profile hooks and test
results, releases only its own monitoring slot at the call report or interrupted
session shutdown, and writes metadata only to encrypted private diagnostics.
The observer adds cost: its output is neither uninstrumented timing proof nor a
source certificate. The full27-case module and all later release gates remain
required; SOURCE never enables this monitor.

The two short-cutoff bootstrap cases prepare content-bound source syntax during
guard setup. This stores only parsed syntax for the existing session and test
sources; it stores no live frame, namespace, evaluated expression or admission.
Every actual launch still reads and hashes current bytes, binds the current
anchor inventory, checks its actual loader/code/globals, and evaluates current
arguments and environment. Changed bytes select fresh syntax. Optional missing
or malformed preparation retains the original runtime error path. Product
clocks, deadlines, sleeps, full startup inventories and cleanup assertions do
not change.

For the two exact short-cutoff bootstrap cases, the separately sealed canonical
backend and controlled ACP children may install a closed leaf guard. Selection
requires their actual guard-child/endpoint-wrapper call chain, original exact
payload, current source pins, native prebody consumption, isolated flags and an
empty operation lineage. It grants no process-launch route: process creation and
profile replacement always refuse durably, including caught local refusals.
The child retains all common runtime, registry, support/spec byte checks and
acquires its activation spec through the original checked dependency loader.
It does not install or claim the general root operation observer. Original
parent admission, native custody, endpoint authentication, descriptor/socket
hooks, the complete execution/import seal and actual numeric parent waits
remain required. Every other case and the root retain the general guard.

### Endpoint observation and TCP reduction

`socket_observation.py` retains the existing Linux SOCK_DIAG, SO_COOKIE,
reciprocal peer, retained Unix pair and TCP descriptor observations. Local
observer descriptors use `dup`; foreign descriptors still require the actual
`pidfd_getfd` relationship. `acquire_tcp` checks the expected process birth
before and after reacquiring the affected descriptor. No cached port, inode,
PID or request-supplied identity supplies ownership.

`endpoint_policy.py` consumes independently declared routes, authenticated
ledger epochs and fresh kernel observations. Core readiness permits listener
registration; both peers need complete body readiness before a connect ticket
is issued. Tickets are single-use objects. Accepted peers remain usable after
a one-shot listener closes, but cannot authorize reconnect or a replacement
listener. Retained operations require the same birth, descriptor, inode,
SO_COOKIE, UID and addresses. Listener retirement additionally requires the
ledger's complete actual-original-parent wait join. Refusals remain sticky.

The native socket controls exercise the observation/reducer seam. They do not
prove control-channel authentication, launch-policy integration, Unix approval
path ownership, source-suite parity or release certification. The historical
release guard remains selected until those integrations and their crosswalk
are complete.

### Bounded control transport

`control_transport.py` retains the existing 8 KiB request, 16 KiB response and
four-second absolute channel bounds. Each scheduler call performs at most one
read or write; a complete request is delivered once and partial writes reuse
the encoded response. Duplicate JSON fields, unsupported values and excessive
nesting, work or text are refused before dispatch.

Accepted channels capture the actual Unix peer, process birth, token, exec
generation, command class and GID before reading bytes. Admission consumes
only that channel's decoded request, rechecks the actual peer and current
registration, and binds nonce, identifier and operation. Source callers must
independently verify the observer peer and the exact typed request echo.
Transport refusals reach the shared ledger poison sink. New channels can
still authenticate the fixed failure-drain methods; drains cannot clear the
original failure or enable ordinary operations.

Empty EOF supplies no permission or completion evidence. The controlled-ACP
SIGTERM exception requires the same captured ledger, birth, class, token and
exec generation, no request or response bytes, the unchanged channel deadline,
and the ledger's full original-parent wait join. Kernel disappearance or a
tracer reap alone cannot discharge it.

The framing, authentication and reduction controls remain source-free. Actual
policy handlers, finite operation schemas, descriptor inheritance restrictions,
Unix path ownership and root/child bootstrap integration remain prerequisites
before this transport can replace the selected release supervisor.


### Source-derived bootstrap intent

`controlled_startup.py` owns the direct backend, exact half-second wrapper and
controlled ACP intents for the two original short-cutoff bootstrap cases. It
reconstructs expected vectors and environments from prepared source and checked
owner state, then compares the complete observation. It checks the actual
product and asyncio call frames, original constructor options, runtime and
fixture pins, current class/function/closure links and owned-root generation.
The original request and prospective `-I/-S` translation remain separate.
There is no legacy resolution fallback inside this selector.

`Owner.verify_binding` checks retained function code, loader, globals, links,
closures and defaults without claiming an executing caller. `Owner.verify`
retains the additional actual frame, callsite and free-variable checks. This
allows the selector to check the original environment and transport methods
without executing arbitrary expressions or adopting their current code.

The focused controls reach the actual backend and ACP product/asyncio Popen
audit paths and stop before OS launch. The ACP controls use a test-only backend
protocol model with no PID or execution claim. They do not pass the two original
timing tests: kernel admission, native entry, authenticated READY, endpoint
sealing, actual child execution and original-parent waits are still mandatory
before selecting this path for a source checkpoint.


### Native prebody control integration

The CI-only `native_build.py` compiles `native_entry.c` against its actual
CPython 3.13 library and records the native image, bootstrap, compiler, runtime
and public evidence-recipient byte pins. A C audit hook precedes initialization;
one closed command body is released only after its birth-bound observer profile,
actual credentials/flags/vector/environment, two authenticated READY messages
and pinned native/bootstrap bytes agree. A caught forbidden process or network
effect still makes the native process fail with status 86.

`test_native_entry_control.py` exercises the real entry under the SEIZE observer,
with source UID 20000/capabilities zero and observer UID 20001/no CAP_KILL. It
requires actual numeric parent waits for positive, caught-refusal and mismatched
binding cases. Setup failure before attach closes the held startup pipe and
requires a numeric cancellation wait. Raw process records and diagnostics are
encrypted to the existing public recipient; only the encrypted archive is
uploaded. The source programs are fixed control canaries, not a product route.
These controls do not establish an immutable runtime capsule, pass either
original timing test, or certify the full source suite.


Peer authentication reads the observer's public kernel birth/credential fields;
it does not require the source to ptrace the observer's namespace links. Full
namespace acquisition remains an observer responsibility. The dedicated native
control driver begins childless and uses a bounded kernel direct-child census
as a fallback if an observer dies before delivering its PID notice. Adopted
cleanup always fails that source case and records its actual cleanup wait
separately; it never supplies original-parent certification. Actual EOF, live
adoption and missing-notice controls exercise this boundary.
