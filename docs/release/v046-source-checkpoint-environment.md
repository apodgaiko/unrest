# v0.4.6 source-checkpoint environment

The Linux source-guard port is **incomplete**. No source checkpoint, selected
carrier, release certification, native-provider acceptance or timing claim
follows from the readiness workflow. `source_checkpoint_ready=false` and
`selected_carrier=null` remain mandatory until the source guard and subsequent
carrier/package certification are complete.

Hosted execution has not occurred: the available push credential cannot write
GitHub Actions workflow files. The readiness ref was rejected before creation.
Local unit/static checks do not establish Linux boot, isolation, native `ps`,
encryption/export or original source behavior.

## Synthetic compartment prerequisite

The readiness-only workflow uses the existing standard `ubuntu-latest` hosted
VM service. GitHub documents a fresh VM for each standard multi-CPU hosted job:
[hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
A Linux/amd64 public Python 3.13.12 OCI manifest is pinned to
`sha256:9a4a5ceafb4ddd7468a09ade0049463a7bd1acbefda52adee748544110fd032d`.
The five pure-Python packages needed for observer tests are downloaded by the
trusted coordinator from their exact wheel URLs and SHA256 values in `uv.lock`.
This bootstrap does not install or execute project source. Image content,
Python/native-program hashes, kernel interfaces, support definitions and CI
identities must accompany each result; Linux hashes do not stand for macOS
hashes.

The synthetic probe uses private Docker PID, mount, network, IPC and cgroup
scopes, a read-only image and public support mount, and finite writable tmpfs
roots. The Docker socket, host home, checkout, runner credentials and provider
configuration are absent. Root setup retains only SETUID/SETGID/SETPCAP for
credential separation; the source-control child drops its capability bounding
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

Raw output and observer records travel only to the trusted coordinator's private
log and are encrypted with OpenSSL CMS to the repository's public recipient
certificate before artifact upload. Only the recipient's public certificate is
in the repository; its private key belongs to the operator. Public provenance
contains hashes, counts, CI identities and the explicit synthetic-only scope.
Encryption does not establish execution: downloaded artifacts still require
GitHub run/head/workflow/artifact identity checks and local decryption/inspection.

## Remaining source integration

The primary CI workflow is not yet connected to these synthetic controls. Its
original source, type-check, repository, build, archive and installed lifecycle
commands remain executable and unchanged. The new readiness workflow cannot be
used to deduplicate a full primary checkpoint.

The following Linux seams still require implementation and genuine evidence
before an original source case can be invoked:

| Domain | Required evidence | Current status |
| --- | --- | --- |
| Finite admission and activation | Original source/caller/AST/globals/argv/environment/cwd/READY bindings, including `-I`/`-S`, both producer profiles and backend/query descendants | Pending |
| Kernel descendant lifecycle | Short-lived/native/failed-exec descendants, exact original-parent waits and fail-closed launch poison | Pending |
| Endpoint and receipt custody | Owned socket peers/listeners, stale/foreign/replay/late refusals before effects | Pending |
| Restart and failure drain | Source-owned custodian across frontend restart; fresh Linux raw/normalized parent waits with bounded real journal publication | Pending |
| Original source slice | Whole composed owner, all four in-process restart parameters, producer settlements, controlled backend/Bridge/private preflight/complete_turn and default-native no-launch negatives | Pending |
| Frozen primary CI | Exact head/checkout/guard/runtime identity, unfiltered original command, package certification and verified same-commit deduplication | Pending |

Existing failed/incomplete observations retain their original outcomes. The
approved exact orphan and stock-uv limitations do not expand on Linux. Native
approval, genuine provider reuse and final timing remain UNVERIFIED;
experimental behavior stays off by default. No provider, model or benchmark
campaign is part of readiness. Python audit hooks alone do not isolate arbitrary
hostile native syscalls; finite source bindings and kernel containment remain
complementary requirements.
