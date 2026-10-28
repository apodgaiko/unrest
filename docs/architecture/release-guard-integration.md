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
in that inventory. A size report alone does not certify a release.

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
product negative catches the exception.

Actual original-parent waits and kernel terminal observations establish cleanup.
Adopted fallback cleanup is failure evidence. An interrupted connection can
retire as cancelled-unjoined only after its authorized termination and actual
parent reap; that does not prove application accept or descriptor close. Native
status86 always retains its refusal meaning.

Multiprocessing declarations currently cover only the two original numeric-exit
cases. Their tracker and child retain distinct FIFO identities, directions,
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
The native `pytest` console entry normalizes Python startup to isolated
`-I -S -m pytest`; both the original kernel argv and normalized Python argv are
recorded and checked. Subsequent Python children use the canonical guarded entry.

The additive pytest plugin does not select or deselect tests. Normal discovery
produces the complete ordered inventory, sealed into a content-addressed,
observer-owned file bound to source and dependency hashes. Profiles carry only
its small reference. This avoids enlarging profile or RPC limits.

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
