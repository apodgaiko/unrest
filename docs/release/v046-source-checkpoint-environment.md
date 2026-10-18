# v0.4.6 source-checkpoint environment

The Linux source-guard port is **incomplete**. No source checkpoint, selected
carrier, release certification, native-provider acceptance or timing claim
follows from the readiness workflow. `source_checkpoint_ready=false` and
`selected_carrier=null` remain mandatory until the source guard and subsequent
carrier/package certification are complete.

The first HTTPS credential could not write workflow files, and that rejected
ref remains absent. A separately configured Git SSH credential subsequently
authenticated to the same repository owner and accepted the authorized scratch
branch through normal GitHub enforcement. The connected API's branch creation
returned 403 despite its repository permission metadata; it was not retried.

The first original focused source proof succeeded in
[run 39060025630](https://github.com/apodgaiko/unrest/actions/runs/39060025630)
at `c746f728306934178ebd5d3f945e1e6ded65514f`. Downloaded ciphertext,
plaintext archive, GitHub run/artifact identities and support bytes were verified
locally. Original JUnit records all four in-process completion-refusal restart
parameters passing, with zero failures, errors or skips. Kernel records contain
16 actual original-parent wait4 results, root wait word 0 and zero poison. This
proof covers that source function and its Git descendants; it does not cover the
whole source suite, controlled backend or package certification.
The native profile predicate and the same four original parameters also passed
[run 39063771910](https://github.com/apodgaiko/unrest/actions/runs/39063771910)
at `f366e4dde0a36de7630fc606e820ea1a6f471b85`.

The whole original composed restart/stop/replacement/cancel test passed
[run 39064611100](https://github.com/apodgaiko/unrest/actions/runs/39064611100)
at `ba2cef976f7607fdd36e29b5097b677c823e3698`. Its original JUnit contains one
passing case, no errors/failures/skips, and all original assertions. All 33
registered descendants have actual waits; the kernel records 34 original-parent
waits including the finite stock Git maintenance child, and 12 original stock
`ps -axo pid=,ppid=,pgid=` inventories. Root and custodian returned zero, with
zero kernel/guard poison. Downloaded artifact identities and all support hashes
were independently checked locally before inspecting decrypted evidence.
Earlier failures remain failures.

## Synthetic compartment prerequisite

The readiness-only workflow uses the existing standard `ubuntu-latest` hosted
VM service. GitHub documents a fresh VM for each standard multi-CPU hosted job:
[hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
A Linux/amd64 public Python 3.13.12 OCI manifest is pinned to
`sha256:9a4a5ceafb4ddd7468a09ade0049463a7bd1acbefda52adee748544110fd032d`.
The trusted coordinator downloads the public uv 0.9.5 Linux/amd64 wheel pinned
to SHA256 `6507bbbcd788553ec4ad5a96fa19364dc0f58b023e31d79868773559a83ec181`.
It installs the exact locked dependency closure with `--no-install-project`;
the bootstrap image receives only `pyproject.toml` and `uv.lock`, without project
modules. A complete installed-file byte/mode/symlink manifest is sealed into the
read-only image and recomputed at boot. The dependency base remains pinned to
SHA256 `adac11fb5bbc8307263d775b8b89c776d1d71ee238ded6a764e480d862c34fac`;
one separately pinned, non-executable `.pth` line maps the read-only `/source/src`
view for ordinary site initialization. `-S` still omits site processing. The
complete closure must match both the base and that exact added member. This bootstrap does not install or
execute project source. Image content,
Python/native-program hashes, kernel interfaces, support definitions and CI
identities must accompany each result; Linux hashes do not stand for macOS
hashes.

The synthetic probe uses private Docker PID, mount, network, IPC and cgroup
scopes, a read-only image and public support mount, and finite writable tmpfs
roots. The Docker socket, host home, checkout, runner credentials and provider
configuration are absent. Root setup retains SETUID/SETGID/SETPCAP for
credential separation; observer records use an observer-owned tmpfs, without
granting CHOWN. The observer alone retains SYS_PTRACE for observation across
UIDs inside the private PID namespace; it loses the credential-changing
capabilities and cannot receive requests for arbitrary execution. The
observer also retains DAC_READ_SEARCH to enumerate/read the source UID's `/proc`
descriptor directories and private journals. This is read authority within the
container's finite mounts, not a payload capability. The source-control child
drops its capability bounding
set, supplementary groups, UID/GID and inherited nonstdio descriptors before
exec. `no_new_privs` and Docker's seccomp policy remain active. The observer
uses a distinct UID and a private records directory. Loopback IPC is allowed;
external network and a private foreign-broker canary must refuse.

`linux_observation.py` reads actual `/proc` status/stat/namespaces, process birth
ticks and boot identity; it checks `pidfd_open` and Unix peer credentials. These
are observation primitives, not launch admission or a sandbox. The synthetic
probe uses the unchanged native `ps -axo pid=,ppid=,pgid=` vector from the pinned
image. Process absence is never counted as a wait. Raw parent wait words and
normalized return codes are distinct from a subprocess handle's cached status.

The kernel observer follows fork/vfork/clone/exec/exit events and reads actual
original-parent wait results. Finite source journals bind each exec to its exact
admitted argv, effective environment, cwd, caller source and executable bytes.
For inherited environments, the binding reads libc's actual environment instead
of Python's potentially stale `os.environ` cache. Stock Git's one maintenance
child is bound to the exact empty-commit call, image bytes, environment and
content-addressed newly written commit object; this grants no other Git helper.

Selective observation passed the kernel controls and all four in-process
parameters in [run 39060461310](https://github.com/apodgaiko/unrest/actions/runs/39060461310).
The composed custodian exited before READY in that run; the composed source test
was not invoked. Its wait word 256 remains a failure. Added private stderr and
event export address the missing diagnostic capture for fresh runs.

The selective observation filter installs inherited
seccomp TRACE stops for execve/execveat and wait4/waitid, keeps ptrace birth,
exit and signal observation, and refuses foreign/x32 syscall ABIs. Unrelated
syscalls need no ptrace round trip; original test deadlines stay unchanged.
This changes kernel observation only, not finite Python source activation.
The readiness controls prove successful, failed and caught unknown exec,
both observation modes, vfork ordering and original waitid/wait4 custody before
source execution. These controls do not prove the remaining backend source domain.

A native callable for the existing profile skip predicate passed differential
controls and the original in-process and composed cases cited above.
It forwards the original frame, event and argument to the unchanged Python
observer for selected source, pytest, isolated-code and operation events.
`sys.getprofile()` and thread profile identity remain bound to that callable.
The C source, compiled module, compiler, CPython image and ABI are byte-bound at
boot. Differential event, exception and thread controls must pass before source
execution. No original source deadline, callback selection domain, source
assertion or process activation flag changes with this implementation.

Earlier composed runs failed their unchanged `submit_run` deadline; those failed
JUnit and subsequent poison remain preserved. The current proof above uses the
same original deadline. The Linux failure-drain inventory uses real per-thread
`/proc` children, including unreaped zombies. Zombie birth, parent and state are
retained fields; missing zombie namespace links are never invented. Namespace
custody stays attached to the earlier kernel birth record. The separate negative failure-drain controls passed
[run 39068515729](https://github.com/apodgaiko/unrest/actions/runs/39068515729)
at `17a5aaca2a316c079bbd37d84792701d4dbb39f1`. All five stale/foreign/late/source/
identity controls refused, caught refusals retained poison, all 23 registered
children and all 24 kernel-observed child processes had actual parent waits,
and the final role/adapter each had raw 15 / normalized -15. Worker return 2,
custodian return 1 and the original failed JUnit remain failed. Only the negative
control check passed; it cannot substitute for the separately passing original
composed test. Original source producer activation remains open.

The five original controlled-backend selectors passed
[run 39067921034](https://github.com/apodgaiko/unrest/actions/runs/39067921034)
at `b8fec700cec31499b481a74842c4f8d2a53f5616`.
Original JUnit records retained receipts, correction/rotation and fresh finals,
programmatic authenticated private preflight, and both default-native launcher
and runtime pin refusals passing without skips. All 12 registered descendants
have actual parent waits; all 13 kernel-observed exec attempts, including the
root, are the pinned Python runtime. Root returned zero, with no kernel or guard
poison. No native provider child executed. The same run passed 67 prerequisite
controls. This proves the controlled Python transport and experimental
`complete_turn` boundaries, not native adapter conversion or provider acceptance.

The Linux seams preserve one-shot listener acceptance by requiring its actual
reciprocal accepted peer in the same birth-bound server after listener closure.
An authenticated Unix socket-pair member retains authority through peer closure
only for its original inode, cookie, UID and peer identity; a reused descriptor
cannot inherit it. Focused controls cover listener closure, absent/foreign peer,
Unix peer closure and descriptor reuse. Earlier failed runs remain unchanged.

Public native adapter metadata is downloaded by the trusted image builder using
pinned archive and member digests. The original Darwin Node image is present
only as non-executable data for unchanged native-pin refusal assertions; it is
not a Linux runtime and has no admitted exec route. Provider execution remains
forbidden independently of absent credentials.

Future readiness runs capture the current owned process output privately in the
trusted coordinator and write `structured-envelope.json` directly into the
private archive before CMS encryption. Its finite record map names only the
kernel, collection, summary and original JUnit records (or the finite synthetic
control records). Source stdout/stderr, coordinator output and diagnostic logs
remain encrypted opaque members. No operator consumer parses a coordinator log.
Past artifacts and failed attempts are unchanged.

`consume_evidence.py` downloads an exact run/artifact/head identity, verifies the
GitHub ZIP size/digest, ciphertext and plaintext archive hashes, complete support
hash map and direct envelope identity, then opens only the named structured
members. It rejects duplicate fields/members, unknown record names, unsafe paths,
nonregular archive members, digest drift and scope escalation. Decryption uses a
read-only 0600 private key and an owned 0700 root. It never extracts or opens log
members. Operator output is a fixed enum/count/boolean/hash projection; original
JUnit failure messages, command bodies and arbitrary record strings stay private.
A negative-control pass retains the original failed source outcome and cannot
become a full checkpoint or a selected carrier. Synthetic private-canary controls
exercise the direct capture, archive consumption and CMS roundtrip.

The native producer body boundaries check both the finite READY binding and the
endpoint's sticky global poison. A caught launch refusal must stop the query
before its original dispatch/main call, as well as prevent later backend or
consumer progression. Historical failures retain their original outcomes;
changed-seam Ubuntu controls are required before using this repair.

## Remaining source integration

The primary CI workflow serializes the same SHA with `cancel-in-progress: false`
and the same concurrency group as readiness. It is not yet connected to the
isolated command executor or receipt reuse decision. Its
original source, type-check, repository, build, archive and installed lifecycle
commands remain executable and unchanged. The new readiness workflow cannot be
used to deduplicate a full primary checkpoint.

The following matrix distinguishes proved seams from remaining original source work:

| Domain | Required evidence | Current status |
| --- | --- | --- |
| Finite admission and activation | Original source/caller/AST/globals/argv/environment/cwd/READY bindings, including `-I`/`-S`, both producer profiles and backend/query descendants | Pending |
| Kernel descendant lifecycle | Short-lived/native/failed-exec descendants, exact original-parent waits and fail-closed launch poison | Controls, focused in-process source and whole composed source proved with selective exec/wait tracing |
| Endpoint and receipt custody | Owned socket peers/listeners, stale/foreign/replay/late refusals before effects | Genuine Linux socket/receipt controls and composed integration proved; one-shot Bridge changed seam and original backend integration proved |
| Restart and failure drain | Source-owned custodian across frontend restart; fresh Linux raw/normalized parent waits with bounded real journal publication | Whole composed owner and separate Linux negative failure controls proved |
| Original source slice | Whole composed owner, all four in-process restart parameters, producer settlements, controlled backend/Bridge/private preflight/complete_turn and default-native no-launch negatives | Four in-process parameters and whole composed owner proved; producer domains pending |
| Frozen primary CI | Exact head/checkout/guard/runtime identity, unfiltered original command, package certification and verified same-commit deduplication | Pending |

Existing failed/incomplete observations retain their original outcomes. The
approved exact orphan and stock-uv limitations do not expand on Linux. Native
approval, genuine provider reuse and final timing remain UNVERIFIED;
experimental behavior stays off by default. No provider, model or benchmark
campaign is part of readiness. Python audit hooks alone do not isolate arbitrary
hostile native syscalls; finite source bindings and kernel containment remain
complementary requirements.

## Producer runtime work in progress

The producer image adds a separate source-only Linux uv 0.11.0 image, matching the finite
producer renderer version already used by the portable operation bindings. Its
public wheel is pinned to SHA256
`30a08ee4291580784a5e276a1cbec8830994dba2ed5c94d878cce8b2121367cf`.
The dependency builder keeps uv 0.9.5 and the existing complete dependency closure.
Earlier successful proofs retain their original image identities.
The source-build backend is the public setuptools 84.0.0 wheel, SHA256
`51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670`.
A trusted, source-free setup seeds its offline cache; source operations will receive
only a finite writable copy. The local runtime/configuration is unchanged.

A separate CPython entry compiled against the pinned image's actual libpython
uses `PySys_AddAuditHook` before `Py_BytesMain`. Its source, bootstrap, compiler,
shared library, stock runtime and compiled entry are sealed separately. The
observer must supply a read-only UID/PID/birth/argv/environment/cwd-bound startup
profile before a producer body can run. This entry does not change `-I`/`-S` or
add environment injection. Native entry controls passed
[run 39069697864](https://github.com/apodgaiko/unrest/actions/runs/39069697864):
all four ordinary/`-I`/`-S`/`-I -S` unregistered bodies exited 86 before their
marker effects. The 72 controls in
[run 39073851823](https://github.com/apodgaiko/unrest/actions/runs/39073851823)
also passed the differential check against the actual portable operation
profile method. These are prerequisite controls; original producer acceptance
remains pending. That run's original producer failed in the observer's bounded
exec-string reader and retains its failed result.

The original sdist helper creates and removes a temporary artifact directory in
its original `/source` cwd. The producer mount view therefore uses an empty,
finite writable tmpfs for directory metadata at `/source`, with every candidate
top-level file or subtree mounted separately read-only. Only `build` and the
finite generated egg metadata have declared writable overlays. An actual source
UID write attempt against `pyproject.toml` must fail before source dispatch;
creating/removing an artifact directory must succeed. This does not grant source
file writes or a host path. The finite trusted-source binding remains necessary:
Python audit hooks do not claim arbitrary hostile-native filesystem isolation.

A same-commit receipt parser and trusted read-only Actions lookup are under
implementation. They reject readiness, another SHA, incomplete package duties,
missing parent waits, poison, filtered collection and artifact/definition drift.
The signed artifact download receives no API authorization header. Controlled
parser fixtures are not CI acceptance, and these modules do not yet replace or
skip any executable primary duty.


The original contract producer and both unchanged installed-provider parameters
passed [run 39074209663](https://github.com/apodgaiko/unrest/actions/runs/39074209663)
at `3a9bb6a3e24de4ebcc770be987eeb3f6d2562c58`. Original JUnit has two passing
cases with no failures/errors/skips. Both UV source operations settled after
genuine parent waits; both query returns and all four original setuptools helper
bodies were observed under the native pre-initialization entry. All 12 registered
descendants and all 18 kernel-observed child processes have real original-parent
waits; root returned zero and poison is absent. The same run passed 73 controls,
including a real long-argument exec with exact untruncated argv. Its ciphertext,
GitHub identities, support bytes and decrypted records were checked locally.
The separate distribution-test producer profile and primary CI integration
remain pending. This is a focused source proof, not a release checkpoint.


The separate unchanged distribution-test producer passed
[run 39074587647](https://github.com/apodgaiko/unrest/actions/runs/39074587647)
at `b2d548d07c917fc305db7363ca9364fe19f892d8`. Its one original case passed
without errors/failures/skips, including the extracted fifteen-case persistence
oracle. All eight kernel-observed child processes have actual original-parent
waits, all three registered descendants were waited, the producer settled, and
all four original backend helpers plus the isolated query were observed. Root
returned zero with no poison. Both original producer profiles now have focused
source proofs; negative producer controls and primary CI integration remain open.


## Direct-record producer verification

The fresh negative trial in [run 39076926173](https://github.com/apodgaiko/unrest/actions/runs/39076926173)
failed: the query caught a launch refusal and continued into its original main.
Its failed outcome and direct encrypted records remain preserved. This does not
diagnose the separate earlier interrupted run, whose private failure remains
unverified and whose ciphertext was preserved without log interpretation.

After adding global-poison checks at native producer entry/body boundaries,
[run 39077210671](https://github.com/apodgaiko/unrest/actions/runs/39077210671)
passed the negative control with original source exit 2, query wait raw 22016 /
status 86, two genuine kernel parent waits, retained poison and no original query
body or consumer dispatch. Its deliberately failed original JUnit stays failed.
The same run serially repeated only the two affected positive producer profiles:
the installed-provider fixtures passed both cases with 18 genuine parent waits,
four backend calls, two query returns and two settlements; the original
distribution fixture passed with eight genuine parent waits, four backend calls,
one query return and one settlement. All were verified from exact direct record
members against their actual run/head/artifact/support and archive identities.
Earlier unaffected in-process, composed and controlled-backend proofs retain
their original OS/runtime/hash attribution. No full checkpoint was run.


The CI mutation readiness profile selects the original ten constant-dead-guard,
three dead-shell-branch and four live/dynamic-guard cases. Its work mount is a
finite 512 MiB under the unchanged 1 GiB container memory limit. Seventeen public
repository copies require 168,370,176 file-page bytes before journals, exceeding
the earlier 128 MiB mount. Other source profiles retain their existing work
mount sizes. The observer records actual filesystem block/inode counts before
and after this profile. No source bytes, test parameters, assertions, deadlines,
external network authority or launch admissions change with this capacity bound.

Source-free synthetic controls now export their original JUnit as a separate
named encrypted record. Repository-dependent support checks run separately.
Source runner failures use atomic typed stage records with error enums and
hashed frame locations; incomplete pytest execution retains a null exit record.
Missing/empty records refuse verification. They never trigger a private-log
fallback. Failed prior readiness trials remain failed and separately preserved.


The original seventeen CI mutation cases passed in
[run 39079570669](https://github.com/apodgaiko/unrest/actions/runs/39079570669)
at `278142e4b5f60565accfdf0ac1a4bd699c5cbb00`, with 51 genuine kernel-observed
original-parent waits, root wait zero and no poison. Its source-free controls
passed all 113 cases, also verified from direct encrypted JUnit/kernel records.
Only the declared `unrest` SOURCE console is materialized as read-only script
data at `/opt/deps/bin/unrest`. Its current project declaration, exact script
bytes, selected interpreter and original copied-repository caller remain bound;
the complete dependency base must still match its original digest. The extra
console is admitted only for the explicit CI mutation profile. This is source
fixture setup, not installation or package certification.

At the preceding run, primary custom-shell execution and actual same-SHA
full-checkpoint receipt reuse were still unimplemented. The original primary run blocks remain executable,
with both job-name and Type-check mutation anchors intact. Readiness does not
supply a selected carrier, a primary receipt, a frozen checkpoint or authority
to skip any downstream stage.


## Primary script control plane

The primary workflow routes each original executable duty through `ci_shell.py`.
The custom shell binds the actual GitHub-generated file and runs those same bytes
with Bash inside the isolated source capsule. Plain YAML scalars omit a trailing
newline; literal `|` blocks retain it. Logical command registration and generated
wire-byte registration are separate checks. Substitution, unknown job identity,
duplicate or decorative shells, conditional duties, merged controls and changed
working directories refuse before source execution. Original run blocks, the
unexcluded source command, job-name anchor and Type-check anchor remain intact.

Primary shell/UV authority is separate from fixture/caller-bound UV admission.
The controller copies the exact committed public snapshot, checks checkout/head
and support identities, and supplies no runner credential, host control socket,
private home or external network. The source UID, capabilities, no-new-privileges,
process births and actual parent waits are kernel observations. The primary
native CPython entry consumes an observer-owned PID/birth/argv/environment/cwd
profile before the body, including with `-I -S`. Unknown execs retain poison even
when the caller catches their failure; unregistered process births also fail.
The focused assignment budget remains 180 seconds. Original source/subprocess
deadlines and all existing guard/runtime pins remain unchanged.

Docker's tmpfs defaults made the writable source view non-executable despite the
absence of an explicit `noexec` option in its requested string. This prevented a
real Pydantic extension import after successful dependency installation. The
finite source mount explicitly requests `exec`; extension imports from the
installed environment must match bytes in the pinned public dependency image.
Unknown native launches and ctypes loading remain refused. Original public
source files stay separate read-only binds. Generated Git discovery metadata
uses the real source UID on a read-only bind; Git ownership checks are preserved
without global configuration overrides. A source-free private-path control
uses a real owned host canary outside every payload mount.

Private plans, actual argv, output and exception bodies remain encrypted.
Public phase metadata uses closed duty/stage/error enums, counts and hashes.
Typed native failure records preserve import class, bounded hashed frame
locations and mount diagnostics without a log-opening fallback. Early trial
metadata contained the already-public declared command vectors; later exports
use the closed hash-only projection. Original failed artifacts are retained.

`checkpoint_decision.py` resolves only eligible original successful primary
runs through the Actions read API. The full-certificate parser closes commit,
tree, workflow, guard, runtime, command and lock identities; complete unexcluded
source counts/waits/poison; package archive bytes; extracted fifteen-case proof;
and the unrelated-cwd installed lifecycle. Readiness and focused evidence use a
separate always-false channel and cannot become full certificates. Reuse markers
must resolve back to that authenticated original full certificate, including
its exact run/job/artifact and ciphertext digest. A marker alone never qualifies.
Package replay downloads only the original versioned archive artifact, verifies
its server ZIP digest and every wheel/sdist/checksum byte, and never extracts or
executes it. Same-SHA workflows serialize without cancellation; failed or partial
source execution cannot silently rerun at the same SHA.

The release-ref trigger is wired, but current readiness scratch refs cannot
activate primary full execution. Focused capsule execution and receipt controls
are implementation evidence. The primary SOURCE root bridge is implemented behind complete downstream
readiness input. Ordinary-Python/producer activation composition remains blocked
as described below. Package capsule integration remains incomplete and refuses closed. No
original full certificate or actual same-SHA reuse is claimed.
Source checkpoint readiness remains false and selected carrier remains null.
The existing downstream source carrier/package/final closure, single frozen
Python3.13 source checkpoint, certification, independent checks, desktop/exact-head
CI, publication and protected local update remain required.

## Current-run phase custody and original certificate export

Successful primary capsule captures enter a host-only custody journal. Its
per-run MAC key is never mounted into a capsule or included in evidence. Each
phase binds the frozen definition, actual workflow script hash, run/attempt,
committed input-byte map and directly captured structured records. Admission
rechecks actual kernel parent waits, including reaping waitid observations;
cached handle status, a wrong parent, caught refusals, unknown births, native
pre-init refusal or poison cannot produce a successful phase record.

The package-output interface permits only the versioned wheel and sdist from
the original build. Archive checking and installed lifecycle must consume those
same bytes. The final checksum phase can add only the exact `SHA256SUMS` bytes.
Phase links, output digests and the current-run MAC are checked before an input
directory can cross a compartment boundary. No environment, cache, interpreter,
or arbitrary file is a package output. The observer-side exporter checks regular
files, source UID, link count, bounds and stable file identity. Atime is excluded
from mutation detection because reading the output may update it.

`checkpoint_issuer.py` reduces the authenticated phase journal into the original
receipt schema. It requires every original duty, a complete unexcluded
collection/JUnit correspondence and unchanged items, root READY, zero poison,
actual waits, the same package bytes across all phases, complete archive-member
byte digests, the original extracted fifteen-case result and original installed
restart/persistence effects from an unrelated cwd. Package return observations
must link to the observer's original native-startup identity and pinned source
function; supplying a result boolean or readiness metadata is insufficient.

`checkpoint_finalize.py` performs that reduction before creating its output
directory, encrypts only the current structured phase records and public input
hash map, and exports the original receipt and exact current package bytes.
It never exports the custody key. The existing decision control plane obtains
the current primary job identity through its existing Actions read credential;
the finalizer requires no API credential. The finalizer follows the checksum
duty and precedes artifact upload. Same-head reuse preserves its separate marker
and original ciphertext instead of minting another original certificate. The
existing authenticated GitHub run/job/artifact consumer remains the external
eligibility boundary.

The reducer/exporter and negative controls have controlled synthetic proofs;
these are not an original source checkpoint or release certificate. Actual full source execution awaits complete downstream readiness input; the
primary package producers still lack execution/activation integration. The
custody and issuer interfaces alone do not supply those records. Full activation
stays closed pending those inputs, `source_checkpoint_ready=false`, and
`selected_carrier=null`.

The original lint and mypy duties passed through actual isolated primary
execution in [run 39086693592](https://github.com/apodgaiko/unrest/actions/runs/39086693592)
at `b7779dec07635061d93a588919e32ccf0b6fd230`. Direct encrypted kernel records
show five genuine parent waits per duty, root zero, no missing waits or poison,
and no native pre-init refusal. This result retains that head's support/input
identity; later issuer/export changes are separate implementation changes.


### Primary SOURCE entry bridge

The primary native entry now has a distinct SOURCE activation path. Its root
still comes from the byte-bound generated Bash script and exact ENV/UV dispatch.
Only the real pytest console can activate the existing fixture guard. Descendants
must match its current source/caller/argv/environment/cwd registration and actual
launch record; neither primary root authority nor fixture admission replaces the
other. The observer retains endpoint READY, kernel births, poison and original
parent waits. Native producer setup/activation remains the existing implementation.
No native provider selection is redirected.

Full mode retains exactly `env -u CODEX_PATH uv run pytest -q`. It accepts only
`primary-source-input.json` in the host runner temporary directory, with schema
`unrest.v046.primary-source-input.v1`, the complete current `definition` used by
phase custody, `source_carrier_sha256`, `package_closure_sha256`,
`final_closure_sha256`, `source_checkpoint_ready=true`, and `selected_carrier`
equal to the source carrier digest. These are downstream closure inputs; this
implementation does not create or assert them. Missing or foreign inputs refuse
before execution. The source input is mounted read-only with mode 0600, unreadable by the
source UID; MAC keys and CI credentials remain host-only. Public output still reports readiness false and no
selected carrier until downstream closure and certification.

SOURCE sets its temporary environment below the existing owned-root boundary
and configures pytest basetemp to the existing `owned_root/pytest` subtree, as
required by the unchanged finite Git/custody predicates. JUnit and basetemp are
setup options; invocation arguments, selection and source cases stay unchanged.
The full root budget is 7200 seconds, collection is bounded to 300 seconds and
provenance/guard drain to 60 seconds. Those finite setup bounds are separate from
the existing focused 180-second capsule and all original per-test deadlines.
The collection observer records before/after lists, deselection, original argv,
root READY, JUnit and guard summary; it does not alter items, order, marks or
selection. These direct named records enter existing phase custody and issuer.

Readiness probes use explicit TEST-positive/TEST-poison identities and a separate
literal focused script. They exercise the same ENV/UV/native/fixture/observer
bridge and cannot enter original phase custody or issue a certificate. A TEST
profile cannot activate the unfiltered SOURCE duty. The poison probe catches an
unknown launch after the unchanged representative test, then requires a failing
capsule with retained global poison and actual parent waits. No full source run,
freeze, package build or release certification is authorized by these probes.


The initial isolated-Python primary probe failed after ordinary finite admission:
the globally installed producer callback required an unrelated `self.direct`
tuple. Its failed evidence is retained. SOURCE activation now composes the two
domains explicitly. Producer consumers still require and consume their exact
producer profile; the four reference-integrity routes still re-resolve their
original reference binding. Every registered callback consumes a unique token
from the actual byte-bound guard launch frame, with the original state, argv,
registration, environment and cwd. Reusing that token or invoking the callback
outside that frame refuses.

Ordinary fallback entries must be the actual current registry object and match
the byte-pinned registry, runtime, source, vector, owned root and original
source-expression/code/module-globals binding. The HTTP port token already
consumed by admission is never recreated. Direct routes are limited to existing
finite resolver outputs and the exact pinned cohort SITES; their original
resolver must independently reproduce both registration and transformed vector.
The existing isolated startup fixture has a minimal environment. In the pinned
CPython image, isolated initialization adds exactly `LC_CTYPE=C.UTF-8` when its
locale keys are absent. The native profile binds that post-init environment
separately for this exact source registration; the kernel exec comparison still
consumes the original environment. Other registrations and explicit locale keys
retain exact environment equality.

All paths retain shared startup checks, READY, native pre-init, caught-refusal
poison, kernel tracking and genuine original-parent waits. This composition does
not grant authority to arbitrary class strings or arbitrary Python commands.

Only bounded TEST proofs are eligible at this stage. Complete source-carrier,
package and final input closure remain downstream; readiness remains false and
the selected carrier remains null. One full frozen unexcluded Python3.13 source
checkpoint and all remaining release checks are still required.

The closed primary TEST selection also admits one exact four-case tuple: the
original composed restart/stop/replacement/cancel case, both controlled installed
provider matrix parameters (claude and codex), and the original distribution
checker extracted-provenance case. Arbitrary selectors, filters, reordered or
partial tuples refuse. The reducer requires actual ordinary composed-adapter,
four reference-integrity classes and producer consumer startup consumption,
with unchanged native custody, READY and actual original-parent waits. These
fixture builds are setup evidence only; TEST remains certificate-ineligible.


Ordinary source-owned worker, validator and terminal-reviewer inventory pipes
require two equal concrete role registrations from the authenticated source
owner. The observer binds the owner's birth and the child's PID, parent, birth,
boot, exact exec argv/environment/cwd and pinned native image. Its pre-exec
census includes every nonstdio descriptor and retains the exact FIFO, UID20000,
device/inode and read-only inventory identity. Descriptor flags grant no
exemption. The observer advances only the admitted exec syscall to a successful
`PTRACE_EVENT_EXEC` stop, before the image's first instruction, and performs a
second complete census. Only the same single inventory descriptor may remain;
every additional pre-exec descriptor must have actually closed. Missing pipes,
extra survivors, changed registrations, failed execs or identity drift poison
custody and prevent native/body release. The tracer retains its syscall-return
and original-parent wait observations.

The observer creates the read-only native startup profile after that proof.
Native pre-body entry independently compares every descriptor with this exact
profile. Its directory census accounts for its single live proc-directory
iterator and proves the iterator descriptor closed; unknown descriptor errors
and extra proc-directory aliases refuse with the sticky native exit. TEST
custody records are diagnostic evidence only. They do not select a source
carrier, close package/final inputs or waive any release gate.

Receipt-channel diagnostics are closed structured records within the authenticated
`kernel-source.json` member. They record a finite request-kind enum (unknown
kinds are hashed), frame lengths, received/authenticated/output-pending state,
original monotonic acceptance and finish times, registered peer birth, pending
reason, and observer/event/kernel progress counts. They exclude request bodies,
credentials, command vectors, environments and endpoint paths. A diagnostic
record proves only its observed transport state; it cannot authorize an effect.

The diagnostic record retains the original four-second acceptance clock without
resetting it. Pending transactions retain the complete policy handler, and
other clients continue to receive nonblocking service. Partial frames and
partial writes retain their original state and deadline. Unknown peers cannot
have an effect while registration is unresolved. Expiry or disconnect retains
poison. Diagnostics do not establish successful original SOURCE composition;
that still requires actual child READY and complete original-parent waits.

The `source-composed-adapter` callback composes two distinct finite bindings.
Its unchanged resolver metadata names the original literal producer at
`tests/test_server.py:3302`; that fixture need not be on the descendant's live
stack. The callback authenticates the pinned producer AST, exact literal and
regular owned generated adapter bytes, trace and cwd, then independently
requires the pinned `acp_runner.spawn_launch` function, live frame, module
globals and exact callsite. The original `LaunchPlan` type/code and immutable
argv/environment must match the observed launch, including asyncio's live
streams and limit. Original guard-frame/token consumption, unchanged resolver
re-resolution with the complete translated vector, duplicate refusal and
shared READY checks still apply. This is one enumerated literal/launcher join;
it grants no generic generated-script or Python trust and rewrites no source
binding. Unknown or mismatched provenance retains sticky poison.

The `codex/source-guard-structured-20261018-layered-source-*` nonrelease TEST
family uses the existing closed four-case affected-seam tuple. Local coroutine
controls stop before OS launch; they are not actual SOURCE acceptance. Hosted
original-case JUnit, collection, child READY/domain consumption and original
parent waits provide that separate bounded proof. Neither TEST nor a finite
SOURCE applicability seal is the frozen unexcluded source checkpoint, package
certification or a readiness carrier.

A failed primary capture retains a closed transport-refusal code and the
container's running/OOM/exit status when available. These fields diagnose
missing structured evidence without reading private process output. Missing
envelopes remain failed, and the original transport and container bounds stay
unchanged.

The observer reuses only the compiled `finite/custody_host.py` code object and
its exact `run_control.py:1147` call-AST digest. These are two finite,
observer-local derivations; no policy decision, snapshot, request, READY,
peer, wait or operation result is cached. Every custody operation still
executes in a fresh namespace. Compilation retains the original filename,
inherited annotations future flag and interpreter optimization setting.
Every use first opens the exact resolved source without following a symlink,
reads and hashes its actual bytes against the manifest pin, and checks the
regular single-link carrier before/after reading and against its path.
After population, any byte, filename, pin or carrier identity change refuses
before reuse. The source digest is checked before AST parsing, which can only
make drift refuse earlier. All dynamic checks remain per-request/per-poll.
Closed receipt diagnostics report read/compile/derivation counts and phase
seconds; they contain no source or request bodies. The bounded pinned-policy
TEST branch uses the existing four-case tuple and unchanged receipt/endpoint
4s, custodian READY8s and wait25s limits. These controls and TEST execution
remain certificate-ineligible; SOURCE applicability requires actual native
startup, domain consumption and original-parent numeric waits.
Closed residual-phase timing also separates fresh namespace execution,
durable snapshot validation and custody-handler work from compilation and AST
derivation. These observations do not alter admission, polling or deadlines.

The restart custodian prepares the one pinned `run_control.py` source-code
and `_spawn` derivation in the existing process-local content-addressed guard
cache before starting its IPC listener. Preparation verifies current source
bytes and the imported function's code, filename and module globals; failure
poisons admission and prevents listener readiness. It creates no request,
launch plan, child or admission decision and never invokes `_spawn`.
Each actual job still runs the original snapshot and admission path, including
fresh source reads/hashes, AST, live frame/code/globals, request generation,
argv/environment/cwd/owner, READY, ledger and actual-parent wait checks.
Closed custodian stages identify imports, preparation, snapshot, admission
and native READY boundaries without recording source or request bodies.
The 8s READY, 4s receipt/endpoint and 25s wait limits remain unchanged.
Local controls establish that the first pure source derivation moves before
listener readiness and remains reused by the existing cache. Hosted timing
benefit and original composed SOURCE acceptance remain unverified.

### Repeated finite resolver compilation

Ordinary restart startup traverses the same finite direct-route support during
original admission, guarded admission and callback re-resolution. The direct
resolver keeps only compiled support code on that guard state. Every use still
opens the current carrier with `O_NOFOLLOW`, reads and hashes all bytes, and
compares device, inode, owner, group, mode, link count, size and change times
before/open/after/path. A populated entry refuses replacement or metadata drift
even when bytes match. Only an exact currently pinned direct-support file can
supply code; each execution retains its original fresh namespace and compiler
flags. No admission result, environment, frame, READY, registration or wait is
cached. The existing outer checks and all route predicates still execute.

Focused controls test post-population drift and fresh globals/live inputs.
Compilation reuse alone does not establish a deadline result. The unchanged
four-case SOURCE execution, native READY, receipts and actual numeric parent
waits must prove acceptance; synthetic success remains a separate result.


Startup diagnosis records closed phase names, monotonic/process/thread CPU
nanoseconds, numeric resource counters and code/location hashes. Observer tick
and refresh totals and harvested trace-stop/resume timestamps are diagnostic
only. They do not replace kernel exec, authenticated READY, receipts or original
parent waits. The finite guard admission predicates and call order remain
unchanged; a complete stripped-AST comparison pins that distinction. A late
observer event alone cannot attribute native startup latency. TEST evidence
remains ineligible as a release certificate.


Trace startup diagnostics aggregate numeric counts and timing in fixed-width
rows per owned PID. They never append per-stop telemetry to original records.
Original evidence bounds, ordering and security/wait records remain intact.
The synthetic launcher also exports `prerequisite-status.json`, independently
bound to the exact run/head/support identity and a provenance member digest.
Its finite stage/status/exception-class values and code-location hash diagnose
early refusal without exposing exception messages, stack, argv or environment.
A status record without a complete structured envelope is prerequisite evidence
only and cannot establish SOURCE acceptance.

The shared-startup subphases distinguish fresh READY, shared-file and tree
validation, absence/link checks, operation-file/tree validation and final static
serialization. These closed timestamps localize CPU work without bypassing or
reusing any startup decision or input observation.

Inner startup sampling is selective: operation input phases emit only while the
shared-startup caller invokes them, and each closed inner/shared phase emits at
most once per process. Repeated ordinary policy/input verification keeps running
in full and does not grow the phase transport.

Fresh filesystem capture retains each independent enumeration and every original
no-follow open, before/open/after/path stat, byte hash and final tree comparison.
Identity capture converts its Path once before passing the same pathname to the
OS; POSIX tree ordering materializes component tuples once per entry. No tree,
identity, result or authorization is reused across calls. The focused differential
tests retain the preceding public implementations and compare complete vectors,
serialization, fresh syscall sequences and post-first-call mutations. Local
measurements alone do not establish original SOURCE acceptance.

Outer diagnostic phases also retain only their first observation per owned PID
and closed phase. Repeated launches still execute every admission, identity,
READY, IPC and original-parent wait check. Only diagnostic emission is bounded;
its values never supply authority. A transport-bound failure remains a failure
and supplies no SOURCE acceptance proof.

Within one fresh capture, a concrete POSIX Path already has the original lexical
pathname; other inputs still pass through Path construction. Immutable stat
results contribute one local tuple each to the same short-circuit comparisons.
The shared tree's type check still makes its own fresh no-follow stat. These
changes remove object/conversion work without removing any filesystem observation
or sharing an identity across captures.

The operation-tree type probes reuse one lexical pathname per current entry.
Each probe still performs its original separate stat, with the same follow-link
flag and the same pinned CPython ignored-error predicate. File identity capture
then performs all original independent before/open/read/after/path observations.

The automatic TEST lane runs the fresh-tree differential controls on Linux. A
successful original four-case positive tuple is followed by the existing
TEST-poison mode over the identical tuple, with separately named encrypted
evidence. That mode catches one unknown-command refusal after the original tests
return and requires the guard poison to remain sticky. Neither TEST proof is a
release certificate.

### Bounded current SOURCE transport provenance

The primary producer emits one `SOURCE-TRANSPORT` header before aggregate
base64 serialization. Its closed schema binds the exact execution identity,
support snapshot, and invocation nonce to named record hashes, decoded and
encoded sizes, top-level logical field sizes/cardinalities, and directly
available source status and collection/JUnit counts. The header is at most
8192 bytes and contains no record values, paths, command arguments, environment,
exception text, or opaque output. The collector accepts it only from the current
owned invocation, rejects extra/duplicate/malformed/stale headers or stream
fragments, and preserves the named header before enforcing the unchanged
64 MiB whole-stdout ceiling. Complete transport also checks each descriptor
against the original record bytes. A header without the complete structured
envelope supplies diagnostics only; it never establishes SOURCE acceptance.
No historical process output or opaque log is a recovery source.
