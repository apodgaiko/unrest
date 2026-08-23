# Parent handoff: Unrest v0.2.1

This file is intentionally pre-tag. Resolve the candidate from the existing
local branch, and resolve the annotated tag only after the parent creates it:

```sh
CANDIDATE_REF=refs/heads/codex/v0.2.1-foundation-safety
CANDIDATE_COMMIT=$(git rev-parse "$CANDIDATE_REF^{commit}")
CANDIDATE_TREE=$(git rev-parse "$CANDIDATE_REF^{tree}")
TAG_REF=refs/tags/v0.2.1
```

Before tagging, the exact candidate commit/tree and validated wheel/sdist sizes
and SHA-256 values are recorded only in the out-of-tree
`mission-002/evidence/candidate-release-receipt.json`. After tagging, the exact
commit/tree/annotated-tag-object identities and the unchanged archive values
belong only in the finalized post-tag handoff evidence.

As checked on 2026-08-23, no local or remote `v0.2.1` tag was observed and no
push or publication was performed. The candidate must descend from
`2b17a613b99ef182c9bae18b8171efc17e8fe8d2`.

## Dirty-main-safe integration

The main checkout is currently at
`96d5c0f0b240bd3373809546d7aecc1e407f837b` with one tracked user edit
(`src/unrest_harness/bundled/policies/role-capabilities.v1.json`) and untracked
`docs/proposals/harness-evolution-research-directions.md` and
`validator-regressions/`. Preserve those bytes before advancing main:

```sh
cd /Users/aleksandrpodgaiko/Desktop/unrest
test "$(git rev-parse HEAD)" = "96d5c0f0b240bd3373809546d7aecc1e407f837b"
git status --short
git stash push --include-untracked -m pre-v0.2.1-main-preservation
test -z "$(git status --porcelain)"
git merge --ff-only "$CANDIDATE_COMMIT"
test "$(git rev-parse HEAD^{tree})" = "$CANDIDATE_TREE"
git stash apply stash@{0}
git status --short
```

Do not drop the stash until the three pre-existing change groups are visibly
restored and any conflicts are resolved. If the initial HEAD or inventory is
different, stop and reassess; do not reset, clean, or force-update main.

## Parent-owned tag and editable installation

After independent validation and successful integration:

```sh
git tag -a v0.2.1 "$CANDIDATE_COMMIT" -m "Unrest v0.2.1"
test "$(git rev-parse "$TAG_REF^{commit}")" = "$CANDIDATE_COMMIT"
test "$(git rev-parse "$TAG_REF^{tree}")" = "$CANDIDATE_TREE"
TAG_OBJECT=$(git rev-parse "$TAG_REF^{tag}")
test "$(git cat-file -t "$TAG_OBJECT")" = tag
uv tool install --editable --force /Users/aleksandrpodgaiko/Desktop/unrest
unrest --help
unrest-server --help
/Users/aleksandrpodgaiko/.local/share/uv/tools/unrest-harness/bin/python -c \
  'import importlib.metadata as m, inspect, unrest_harness as u; assert m.version("unrest-harness") == u.__version__ == "0.2.1"; print(inspect.getfile(u))'
```

The printed package path must resolve under
`/Users/aleksandrpodgaiko/Desktop/unrest/src/unrest_harness`, and main's HEAD and
tree must still match the candidate. Do not push the tag or branch in this
handoff.

## External v0.3 plan update outline

Apply these edits only in
`/Users/aleksandrpodgaiko/Desktop/unrest-lab/research/unrest-v0.3-general-thinker-proposal`
after v0.2.1 closes. The observed-to-change trace is explicit:

- `04-program-plan.md`: replace the parallel FM-000/FM-010 PH-00 launch with a
  sequence. Record FM-000 as delivered proposed groundwork, return FM-010 to
  redesign, and block every downstream FM-010 dependency until a small
  canonical measurement bundle exists.
- `05-parallel-future-missions.md`: retain separate-workspace parallelism only
  for bounded, ownership-disjoint missions; add a stop rule forbidding a fresh
  server/advance after a host timeout while the prior process is alive, and cap
  repair waves rather than spawning a cascade.
- `06-validation-metrics-and-risks.md`: add orchestration burden metrics—task
  definitions, all attempt reports, decisions, and wall bound—with the measured
  FM-000 `206/106/51/39.87 h`, FM-010 `61/38/24/10.47 h`, and R2
  `468/214/66/99.87 h` as comparison points. Missing canonical commit/handoff is
  an invalid outcome, not a zero baseline.
- `07-decision-register.md`: record that FM-000 artifacts remain proposed,
  original FM-010 and R2 are aborted/untrusted, and only the narrow
  cross-process mutation lock graduated into v0.2.1.
- `mission-packets/FM-010-measurement-baseline.md`: split oracle/corpus freeze
  from measurement execution; set hard task, decision, repair-wave, and wall
  ceilings; prohibit runtime, custody, telemetry, capability, and release-file
  edits; require one canonical commit and handoff or stop.
- `registries/future-mission-registry.json`: mark FM-010 blocked for redesign
  and remove it as a satisfied dependency until a new versioned result bundle
  passes independent validation.
- `registries/ownership-matrix.md`: keep FM-010 confined to its measurement
  roots and state that measurement defects cannot expand ownership into the
  runtime or a custody framework.
- `registries/risk-register.md`: add the duplicate-server/host-timeout risk and
  repair-cascade risk, with process-parentage checks, per-project locking,
  bounded retries, and threshold-triggered abort as detection/stop controls.

These are recommendations, not mutations performed by this release task. The
measurement result is plain: complexity outran authority. The plan should make
that condition terminal sooner.
