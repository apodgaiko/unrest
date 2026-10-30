# Unrest v0.4.7 — release preparation

Version metadata identifies the prepared source as 0.4.7. This is a reviewable
preparation note, not final candidate certification or a published release.
Independent preparation review and source/archive certification remain pending.

## Prepared capabilities

- Experimental scheduling models authored-order entitlement, streaming
  validation, one correction and bounded generation rotation. The opt-in
  runtime adds exact-session reuse, sealed candidate inputs, isolated lanes,
  serial integration and fresh final validation. See the
  [model](../architecture/experimental-flow-model.md),
  [lease](../architecture/experimental-lease.md) and
  [cohort](../architecture/experimental-cohort.md) documentation.
- Startup construction and import work has historical measured evidence,
  subject to the attribution and final applicability limits below.
- Ordinary supervision retains bounded transaction ownership, terminal attempt
  fencing and crash diagnostics. ACP cleanup preserves primary failures and
  observational callbacks while settling owned resource inventories. Trusted
  configuration-root aliases are normalized at construction; later redirects
  still refuse. See the [architecture index](../architecture/index.md).
- Native approval recovery adds the orchestrator-only `review_approval` tool.
  Recovery is opt-in and **disabled by default**. Controlled local checks exist;
  **genuine human/host/native-provider approval acceptance is unverified**.
  A queued native acknowledgement is not proof that the action succeeded.
  See [approval recovery](../architecture/approval-recovery.md).
- The controlled speed runner uses its version-2 workload and result schema.
  Historical version-1 results retain their original meaning; this preparation
  does not certify benchmark performance. See the
  [runner guide](../architecture/controlled-speed-runner.md).

## Trust and compatibility limits

Experimental reuse and cohort dispatch remain disabled by default. Broker
authority, exact identity, bounded turns, owned cleanup and observed mutation
checks are required. Strong OS isolation, including background or descendant
write revocation, remains explicitly unverified. Callback denial is not proof
of that isolation. Experimental Claude continuation is unsupported until proven;
ordinary provider compatibility still requires final integration review.

Approval recovery preserves external review and exact action scope. It grants
no blanket permissions or automatic denied-action retry. Static display grammar
refuses unsupported tools/options; opaque values, file contents and executable
semantics remain outside that syntax proof. Controlled forms cannot establish
actual host rendering, inherited configuration or genuine provider acceptance.

Python >=3.13 is required; Python 3.13 remains the single CI/release lane.
This identity slice upgrades no dependency. The existing LICENSE, earlier
notices and historical release records are retained. The root NOTICE attributes
the bundled OpenAI Codex rust-v0.160.1 model catalogue. Local USER policy changes
are separate operator state and must not enter the release candidate.

## Historical timing attribution

The 2026-10-06 confirmation compared integrated candidate source manifest
`e2eb5760d6583615c55f4b1716a84a0ca413ecf560e500fb5b0e3bc8d24f9ef3`
with baseline commit `5a3d568aa881c746432b7034597bbb8a1ffe025f`.
Its 1,680 launches comprised 1,440 alternating baseline/candidate observations
across 24 isolated cases and 240 concurrent candidate observations across
24 cases. Reported per-case median discovery reductions were
38.953694117042744%–44.31113446755696%, below the aspirational 50%.
These measurements describe that original integrated candidate, not an isolated
causal estimate or the current source. Frozen discovery p95 and first-call
median guardrails passed there; universally improved first-call tails were not
established. The reported ten-second desktop incident remains unresolved.

Later approval catalog, lifecycle and configuration changes require an
independent final functional applicability review. Final-candidate timing,
including discovery p95/noise/first-call equivalence and desktop timing, is
**UNVERIFIED** under the accepted release risk. No new timings or
unchanged-performance claim accompany this preparation. Symbolic flow
times are simulation evidence; live factorial benefit remains unmeasured or
inconclusive without the separately authorized comparison.

## Remaining release obligations

The accepted release risk permits release with **genuine native approval and
ACP live reuse campaign evidence UNVERIFIED**, alongside **final-candidate
timing UNVERIFIED**. Experimental features remain **disabled by default**.
Failed recovery-gate evidence, false approval results, incomplete checks and
earlier failures remain historical evidence; controlled local tests do not pass
those genuine acceptance assertions. No new provider calls or benchmarks follow
from this disposition. Strong OS isolation and comprehensive descendant cleanup
remain unverified; owned-handle cleanup and observed digest equality have their
documented limits.

Every functional requirement remains mandatory: ordinary scheduling, attention
and dissent, isolated admission, steering/replay/stop/restart, immutable
completion/refusal/correction, persistence, ordinary providers and fail-closed
startup. Preparation binds exact source bytes and an incremental evidence-impact
map; independent reviewers must check functional applicability on that source.
Final archives and installed layouts are bound and reconciled at certification.
Ordinary certified-candidate desktop discovery still requires the supported
[isolated registration and user-assisted refresh](../../tools/V046_DESKTOP.md).
Genuine approval presentation and desktop timing remain unverified.

Release verification still requires the single frozen Python 3.13 full source
checkpoint, recursive checks, archive byte verification, extracted-sdist
persistence checks, unrelated-directory installed-wheel lifecycle and exact
remote CI. CI uses the required `env -u CODEX_PATH uv run pytest -q`
command; the historical 0.4.5 speed-runner exclusion has been removed.
Configuring that command does not execute or certify the frozen checkpoint.
Publication and global editable installation update follow only the completed
release process. This preparation performs neither.

Expected artifacts are `unrest_harness-0.4.7-py3-none-any.whl` and
`unrest_harness-0.4.7.tar.gz`, with CI bundle `unrest-v0.4.7-python313`.
Actual archive hashes belong in build-local `SHA256SUMS` after the final build.
No new release manifest or archive certification is claimed here.

For source preparation, `uv run python tools/release_binding.py` hashes the
prospective committed source/test/tool inventory, including new regular files.
`--revision` selects paths, while `--root` supplies the actual bytes: select an
isolated export of that same commit when checking a committed candidate. Earlier
release manifests bind their original tagged bytes and remain immutable; they
do not declare the current 0.4.7 candidate. Archive and installed-layout binding
is completed after packaging.

## Simplified release guard

The replacement guard removes the previous release executor and uses a finite
native entry, a separate process observer, immutable measured inputs and actual
kernel exit/original-parent wait evidence. Its ceiling is 10,000 physical
enforcement lines, counting every non-test file under `.github` and the complete
`tools/check_distribution.py` oracle; guard tests are reported separately. The earlier
9,999-line snapshot lacked launch families exposed by the unexcluded checkpoint.
The integrated replacement currently exceeds the ceiling and is not certified;
the frozen candidate must satisfy the same counter and dependency-closure review.
The counter does not itself prove dependency closure or release eligibility.
See [guard integration](../architecture/release-guard-integration.md) for the
retained boundaries and explicitly retired duplicate enforcement claims.

Bounded native controls and selected original source families have execution
evidence. The shared extracted-sdist path completed all 15 original persistence
cases in CI run 40933142225 on 2026-10-29. Selected diagnostics are not the frozen
unexcluded checkpoint. The canonical CI workflow now owns the full source,
archive, installed lifecycle and native controls; certification and publication
remain pending until that frozen run and independent review pass.
