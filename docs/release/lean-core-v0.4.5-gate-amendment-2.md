# v0.4.5 focused release gate

Status: maintainer approved 2026-09-30. This is the effective v0.4.5 release
evidence floor. It does not approve a candidate, tag, installation, or
publication. The original correctness profile and the 2026-09-28 integrated
validation amendment remain historical records; their omitted gates must not
be described as passed.

## Scope of the decision

For v0.4.5 only, replace the `independent-integrated-70` and original
`functional` release gates with the finite focused safety gate below. The
52-case correctness campaign and its runner/ruler gates remain superseded.
The 70 contract targets remain an inventory of intended behavior, but this
release does not certify each target independently. Existing target-specific
passes retain their exact evidence scope; blocked or unexercised targets stay
`not_certified`, never silently passed. The 27 applicable ACT006 outcome
scenarios and positive ACT008/ACT009 project/improvement dogfood proofs are
deferred without complete execution or PASS credit. The nine historical ACT006 CLI
outcome scenarios were already deferred by the earlier applicability decision.
The exact external project and improvement request files remain externally
owned; this release must not fabricate them or turn their absence into success.

This narrows release assurance. It does not change the shipped code's existing
fail-closed provider, workspace, Mission, validation, promotion, or release
authority boundaries. A demonstrated product failure in the required checks or
an unresolved privacy, authority, compatibility, restart, or recovery blocker
still stops the release.

## Required evidence on one frozen candidate

1. **Identity and integration.** Record predecessor, exact candidate commit,
   tree, source binding and five authenticated slice returns. Reconcile the
   corrected W-LEG return against the historical INT return with a fresh,
   independently reviewed candidate-bound integration supplement. Preserve
   historical failures and return bytes; one integrator consumption path and
   no unowned product changes are required.
2. **Focused safety and compatibility.** Independently verify installed `run-task` refusal before
   provider/durable work, and `run-project`/`run-improvement` exact-request
   refusals while their external requests are absent. Check invalid bounds and
   safe diagnostics; current evidence/frontier persistence and restart;
   attention privacy and deterministic inspection; ACP preflight/refusal and
   genuine Python 3.13 subprocess startup; real MCP/ACP supervision,
   cancellation, cleanup and fail-closed startup. The final source suite's
   real-surface cases and existing independent captures may support these
   observations only with exact candidate/source-byte reconciliation. Record
   observed results and any gap in a short signed-off safety checklist. The
   closed checklist must also exercise the public profile and ABI, legacy
   missing/null identity and absent-lineage reads without rewrite, and a
   corrupt or stale record recovery refusal. Each row records the candidate
   identity, real surface, expected and observed result, evidence path, and
   `pass`, `fail`, or `blocked` verdict. No category passes by inference from
   a source-suite aggregate.
3. **Live Inquiry.** One separately approved installed-library Codex
   subscription run must produce a schema-valid branch and synthesis, a
   bounded safe non-null answer, named planner consumption, and Mission
   before/after byte proof, read-only capabilities, and private provider
   artifacts kept outside product and release material. Keep the prior gpt-6-astra/medium route and limits:
   at most two branches, one synthesis, three attempts, 600 seconds total,
   65,536 response bytes per attempt, max_steps=8, and no automatic replay or
   API spending. An unavailable or failed live run is a blocker, not a mock
   substitute.
4. **Source and distribution.** On the final frozen Python 3.13 candidate,
   run recursive Ruff, mypy on `src`, `unrest check-repository`, and exactly
   one full source suite with `CODEX_PATH` unset. Then build wheel and sdist,
   verify complete archive bytes/membership and safe extraction, run all 15
   extracted-sdist persistence cases with provenance outside the checkout,
   and exercise installed entry points, policy discovery, lifecycle/restart
   and fail-closed startup from an unrelated directory. Preserve exact
   archive SHA-256 values in `SHA256SUMS`.
5. **Decision.** Obtain a fresh applicable planning review, successful CI for
   the exact final HEAD, and an explicit maintainer release decision after
   every above result and blocker is reconciled. Tagging, publication and
   installation are separate later actions.

Release reporting retains `benchmark_certified: false` and
`improvement_claims: []`. Do not claim the 52 cases, the 70-target matrix,
ACT006's deferred outcomes, positive ACT008/ACT009 dogfood, or comparative
quality/speed/resource/workflow campaigns passed.
