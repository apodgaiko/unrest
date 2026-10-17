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
