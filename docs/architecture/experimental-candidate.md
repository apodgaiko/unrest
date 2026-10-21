# Experimental candidate input observation

`experimental_candidate.observe_candidate_inputs` returns a deeply immutable,
nonpersistent manifest for a **stable controller-prepared committed disposable
Git repository**. Normal dispatch does not import or enable this module.
`verify_candidate_inputs(root, original_manifest)` reobserves with the original
base, candidate, exact extra files, output directories and targets; it accepts
no replacement declarations. Neither function writes, stages, commits, returns
leases, integrates, publishes a cursor, or grants provider authority.

The manifest binds full base/commit/tree SHA-1 OIDs, sorted tracked and extra
file inventories (path, Git mode, raw length, SHA256), sorted exact declarations
and target coverage. Canonical JSON uses the existing canonical encoder and
verifier. Its SHA256 preimage is `unrest.experimental-candidate-inputs.v1`, a NUL,
and the canonical bytes (including their final LF). This experimental domain
does not extend the closed foundation identity catalog. A digest establishes
content identity, not authenticity: the controller must retain the original
trusted binding. A caller's self-rehashed replacement confers no authority.
Workspace patch/custody identities remain separate authority references.

Custody persistence computes the immutable manifest digest once for its snapshot
name, record and authority digest within that operation. Each operation still
reobserves the copied snapshot and flushes every file, directory and published
record. Digest reuse never replaces a filesystem or Git observation; no digest
cache survives the operation or enters the manifest's dataclass projection.
Replacing the retained manifest during persistence refuses before publication.

## Restricted fixture format

Only ordinary directories with a real `.git` directory, SHA-1 loose objects,
full local history and a version-2 index are supported. The sole admitted index
extension is optional `TREE`, which is not trusted as a tree oracle. Extended
flags, assume-unchanged, skip-worktree, sparse indexes, intent-to-add, unmerged
entries, symlinks and gitlinks refuse. The actual HEAD must equal the expected
candidate, and the candidate must equal or descend from the expected base.
Every traversed ancestry commit and every relied-on base/candidate tree/blob
is independently hashed as `type + space + decimal length + NUL + raw bytes`.
Missing, corrupt or wrongly typed objects fail locally without repair.

Metadata permits HEAD, config, index, description, COMMIT_EDITMSG, ORIG_HEAD,
info/exclude, ordinary heads/tags, local branch logs, inactive `hooks/*.sample`,
loose object directories, and empty branches, objects/info and objects/pack directories.
The legacy template branches directory is inert only while empty; files, nested
directories and links beneath it still refuse before Git. No branch alias or
remote lookup is interpreted.
Other metadata refuses, including packed objects/refs, shallow history,
replacement refs, grafts, alternates, promisor files, linked-worktree indirection,
active hooks, extensions and nested repositories. Metadata links/special files
refuse. This is intentionally a restricted fixture reader, not a generic Git
compatibility layer or repository-wide fsck.

Config is parsed before Git runs using a closed ASCII fixture grammar. Only
`[core]` and `[user]` sections are allowed; core repositoryformatversion=0,
bare=false, boolean filemode/logallrefupdates/ignorecase/precomposeunicode and
plain user name/email values are supported. Includes, remote/credential/filter/
diff/textconv/fsmonitor/hook helpers and every other setting refuse. Ambient
Git overrides are discarded. `/usr/bin/git` is resolved once, with fixed
`--no-replace-objects cat-file -t OID` and `cat-file TYPE OID` argument templates,
closed stdin, discarded stderr and no shell. The entire environment is PATH
(`/usr/bin:/bin`), LC_ALL=C, GIT_CONFIG_NOSYSTEM=1,
GIT_CONFIG_GLOBAL=/dev/null, GIT_OPTIONAL_LOCKS=0 and GIT_TERMINAL_PROMPT=0.
There is no network recovery path or dependence on lazy-fetch suppression.

Limits: 8 MiB per file/object/command output; 64 MiB aggregate bytes read from
input/index/config/ref files and Git stdout; 512 unique relied-on objects;
4096 admitted filesystem entries across metadata and the full worktree (including
root children and the root `.git` entry), with a separate 4096 worktree ceiling;
4096 expanded tree entries across base and candidate traversals, including every
directory occurrence even when its object is cached; 5 seconds per Git command;
60 seconds per observation, starting before declaration validation. Directory
iterators admit and count entries before sorting, stopping at the first excess
entry. Cached traversal, enumeration, declaration/overlap and parsing loops
check the deadline; bounded sorts and bulk byte operations check on completion.
Declarations accept only concrete built-in lists and tuples, at most 4096 items
each. Deterministic sorting follows bounded admission. Regular
filesystem reads assume local stable custody; these are not hard real-time
bounds on a stalled filesystem syscall. Git children are killed and reaped on
failure/deadline. No child is retained after return.

## Paths and file coverage

Paths use ASCII alphanumerics, underscore, hyphen and dot components, at most
512 characters and 32 components. Empty/dot/traversal, trailing dots, globs,
backslashes, non-ASCII and case-fold aliases refuse. Git and Unrest control
components are reserved at every depth. Absolute roots and all their ancestors
must be real directories. Use a resolved temporary root on systems where
`/tmp` itself is a symlink.

Tracked tree and index entries must agree exactly; raw worktree bytes and
modes (restricted to 0644/0755) must match the tree independently of Git status, filemode config
and index stat caches. Extra inputs are exact regular files, never globs.
Declarations cannot overlap by path component, including outputs with each
other. Output directories must exist. Their contents can vary, but the whole
worktree, including ignored/untracked files and output descendants, is walked
without following symlinks. Unknown input files, unrelated directories,
symlinks and special files refuse. All non-Git regular files, including outputs,
require link count one and unique device/inode identities; directories are not
subject to the link-count rule. Equal-content independent files are permitted.

## Acceptance boundary

Stable fixture custody is a precondition; this is not an atomic snapshot of
hostile concurrent writers. Failure returns no new manifest and leaves a
previous immutable value untouched. This observation module does not itself
persist candidate/correction history or prove crash/rotation recovery. The
[cohort controller](experimental-cohort.md) owns materialization, sealing,
integration and recovery; ordinary `return_workspace` still requires HEAD at
the lease base. Neither module's controlled tests prove genuine provider acceptance.

Run `uv run pytest -q tests/test_experimental_candidate.py tests/test_experimental_candidate_templates.py` for disposable
committed-fixture success/refusal and independent byte/digest evidence.
