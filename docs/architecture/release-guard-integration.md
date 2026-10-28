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

Actual original-parent waits and kernel terminal observations establish cleanup.
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
