# Batch 0 safe-subset extraction

This record classifies the release split from:

- base: `main` at `9ebed0a9007289d419dae476f0dd582e8a21a550`;
- preserved full stack: `codex/capability-follow-up` at
  `b3523d92ced098f5ff587c9c898458082b4ca7b0`;
- release branch: `codex/batch-0-safe-subset`, based directly on the base.

The release includes the eligible B0-T1 through B0-T5 baseline,
documentation, governance, repository-contract/CI, and scheduler slices. It
does not include B0-T6 capability implementation, configuration, package
wiring, policy assets, capability repairs, or repair-only tests. It makes no
claim that `VAL-CAP-004` or `VAL-CAP-006` is fixed.

The B0-T1 `BASE-CAPABILITY-DEFECT-001` fixture and the B0-T3 protected
`capability-policy` category remain included because they characterize the
approved base and reserve human review for that security surface. Neither is
capability implementation or evidence of repair.

## Provenance aliases

All paths below are relative to the original Batch 0 mission's
`mission-001/attempts/` directory. Hashes are SHA-256 of the preserved reports.

| Alias | Original report | SHA-256 | Use |
| --- | --- | --- | --- |
| T1 | `2026-07-24T06-46-13Z-0000__B0-T1.md` | `119ad703270d3c849ac386b55c7519249e0fbecdcee15b444a3a4fd6a7d329d3` | Baseline generator, artifacts, and tests |
| T2 | `2026-07-24T07-02-24Z-0000__B0-T2.md` | `61dc831f4828007dc197b20246d1d9f314602297b5f8468b294ba74cfa7970c7` | Guidance, specifications, architecture metadata, and documentation tests |
| T3 | `2026-07-24T08-19-02Z-0000__B0-T3.md` | `6ec9ab0c298d808522896ee734f259a5de495d4075620d3a509a0dc11d7f153e` | Governance policy, schema, CLI, docs, and tests |
| T4 | `2026-07-24T08-42-46Z-0000__B0-T4.md` | `6f246bcd51d1b133bf1771534dae9c2fee791c8e87d7a5c20d926721309e3d62` | Repository-contract CLI/CI, dependencies, docs, and tests |
| T5 | `2026-07-24T09-16-43Z-0000__B0-T5.md` | `b864c3bf440255acbf42c92463679dded12151990525d7cb272f02bccfa0586f` | Scheduler serialization and baseline decoupling |
| S1 | `2026-07-24T15-09-24Z__FIX-SCHED-CAPACITY.md` | `3c0b40f0403e93bd54a8d9748ce9710a4e2c2a1f2d83fde79852b6d34c55fce6` | Ready-gate capacity repair |
| D1 | `2026-07-24T16-18-44Z__FIX-DGC-BYPASSES.md` | `264aaeb3664b55e76bb822f503c14b2a9899de9a558afea8ab8dba2aa25ac1af` | Documentation/governance/CI hardening |
| D2 | `2026-07-27T08-24-09Z__FIX-DGC-GENERALIZE.md` | `2dd496e4d691c946d69664ae5bf4d1c55508f9619b2cdb0f48ac228df1b7662d` | Generalized documentation/governance/CI hardening |
| D3 | `2026-07-27T11-37-25Z__FIX-DGC-STRUCTURAL-MODEL.md` | `ba98f4c716bd4dea4ccc192be0c0c738159357c21ad08919aca2fff8c6aac915` | Structural parser/model hardening |
| D4 | `2026-07-27T13-36-40Z__FIX-DGC-SEMANTIC-PROVENANCE.md` | `dd28985c4ed0ede1a5d68e2bbf5a0c6a3b88c9024d8956c4f671b9f0fabedf0b` | Semantic/provenance hardening |
| VD | `2026-07-24T14-07-45Z-0001__V-DGC-REAL.md` | `995b3eb8a62181a831307727c535d92424f8f01bbb64c58a49638a91406324a3` | Original cleared real-surface DOC/GOV/CI evidence |
| VBS-S | `2026-07-24T15-56-54Z-0000__V-BS-FINAL-SCRUTINY-4.md` | `a32fcdb287ccd3f879c9781914f1b2b250629299ae7b60b9094b07be8b13e2e9` | Final cleared BASE/SCHED scrutiny |
| VBS-R | `2026-07-24T15-56-54Z-0001__V-BS-FINAL-REAL-4.md` | `e29d9d8b4d3e10a5e6aa03a9d0c0a913f3c9e8bc532ece980f29a8597068853e` | Final cleared BASE/SCHED real flow |
| T6 | `2026-07-24T09-49-52Z-0000__B0-T6.md` | `e4117d46da82568bb648aa7069c5291ddb004070e16b8eb1145829091e0631a6` | Excluded capability slice |
| VCAP-S | `2026-07-29T07-54-50Z-0000__V-CAP-AST-RECOVERY-SCRUTINY-23.md` | `44dbbac2c59e97f03476639c1da3239a2d90bc06114c5db0737d34ede3c9151a` | Final scrutiny failure for `VAL-CAP-004/006` |
| VCAP-R | `2026-07-29T07-54-50Z-0001__V-CAP-AST-RECOVERY-REAL-23.md` | `fba64b7c51ad15d35c6a4808ca2ba290e5c813e44cde7b897cc44d6ec87118c9` | Final real-flow failure for `VAL-CAP-004/006` |

Later DOC/GOV/CI adversarial reports found additional accepted-invalid
families after the original clearance. This split does not rewrite those
reports as passes or delete their seven locally preserved regression records.
The current release mission classifies B0-T2 through B0-T4 as eligible; fresh
release-branch verification is required in addition to the historical
evidence.

## Whole paths included

Every path in this table is copied from the preserved full stack without
capability-specific editing.

| Path | Provenance |
| --- | --- |
| `.github/PULL_REQUEST_TEMPLATE.md` | T3, D1-D4 |
| `AGENTS.md` | T2, T4 |
| `CLAUDE.md` | T2 |
| `CONTRIBUTING.md` | T4 |
| `docs/architecture/annotation-policy.json` | T2 |
| `docs/architecture/annotations.md` | T2 |
| `docs/architecture/change-governance.md` | T3, T4, D1-D4 |
| `docs/architecture/removal-registry.json` | T2 |
| `docs/architecture/repository-contract.md` | T4, D1-D4 |
| `docs/decisions/index.md` | T2 |
| `docs/templates/adr.md` | T2, T3, D1-D4 |
| `docs/templates/change-closeout.md` | T2, D1-D4 |
| `docs/templates/implementation-plan.md` | T2, D1-D4 |
| `docs/templates/task-packet.md` | T2, D1-D4 |
| `docs/v5/10-implementation-plan.md` | T2 |
| `evals/AGENTS.md` | T2 |
| `evals/baseline/fixtures/attempt-kind-heuristic.json` | T1 |
| `evals/baseline/fixtures/attempts-decisions-terminal-storage.json` | T1 |
| `evals/baseline/fixtures/blocking-scheduler-selection.json` | T1 |
| `evals/baseline/fixtures/concurrent-writers.json` | T1 |
| `evals/baseline/fixtures/gate-aggregation.json` | T1 |
| `evals/baseline/fixtures/implicit-unrestricted-defaults.json` | T1 |
| `evals/baseline/fixtures/resume-reconciliation.json` | T1 |
| `evals/baseline/fixtures/storage-state.json` | T1 |
| `evals/baseline/fixtures/terminal-review-closure.json` | T1 |
| `evals/baseline/fixtures/typed-handoffs-and-task-list.json` | T1 |
| `evals/baseline/manifest.yaml` | T1 |
| `evals/baseline/report.json` | T1 |
| `policy/protected-surfaces.yaml` | T3, T4, D1-D4 |
| `pyproject.toml` | T4 |
| `schemas/protected-surfaces.schema.json` | T3, T4, D1-D4 |
| `specs/memory_v2/PRODUCT.md` | T2 |
| `specs/task_list/PRODUCT.md` | T2, T5, S1 |
| `src/unrest_harness/AGENTS.md` | T2 |
| `src/unrest_harness/bundled/AGENTS.md` | T2 |
| `src/unrest_harness/coordinator.py` | T2, T5, S1 |
| `src/unrest_harness/governance.py` | T3, T4, D1-D4 |
| `src/unrest_harness/repository_contract.py` | T4, D1-D4 |
| `src/unrest_harness/task_list_patch.py` | T2 |
| `tests/AGENTS.md` | T2 |
| `tests/fixtures/governance/valid-protected-commit.txt` | T3 |
| `tests/test_baseline.py` | T1 |
| `tests/test_coordinator_parallel.py` | T5, S1 |
| `tests/test_documentation_contract.py` | T2, T3, D1-D4 |
| `tests/test_governance.py` | T3, D1-D4 |
| `tests/test_repository_contract.py` | T4, D1-D4 |
| `tests/test_runnable_selection.py` | T5, S1 |
| `uv.lock` | T4 |

## Whole paths excluded

For paths already present on `main`, the release keeps the exact `main` blob.
For paths introduced by the full stack, the release has no path.

| Path | Excluded provenance and reason |
| --- | --- |
| `docs/architecture/capability-policy.md` | T6 and capability repairs; capability contract |
| `schemas/role-capabilities.schema.json` | T6; capability schema/package wiring |
| `src/unrest_harness/acp_runner.py` | T6 and capability repairs; enforcement and redaction wiring |
| `src/unrest_harness/bundled/policies/role-capabilities.v1.json` | T6; packaged policy asset |
| `src/unrest_harness/capability_policy.py` | T6 and every capability repair; failed implementation |
| `src/unrest_harness/config.py` | T6; capability resolution/configuration wiring |
| `src/unrest_harness/providers.py` | T6; provider capability declarations |
| `tests/fixtures/acp_terminal_emitter.py` | Capability repair-only fixture |
| `tests/mock_acp_agent.py` | Capability repair-only fixture changes |
| `tests/test_acp_runner.py` | T6 and repair-only capability tests |
| `tests/test_acp_sandbox.py` | T6 capability tests |
| `tests/test_assets.py` | T6 policy packaging tests |
| `tests/test_capability_policy.py` | T6 and every capability repair test |
| `tests/test_cli.py` | T6 and repair-only capability tests |

This exclusion restores rather than deletes the pre-existing ACP, sandbox,
asset, CLI, and mock-agent security tests on `main`; the release introduces no
negative delta for those contracts.

## Mixed-path hunk classification

| Path | Included hunks | Excluded hunks |
| --- | --- | --- |
| `.github/workflows/ci.yml` | T4 exact `uv run unrest check-repository` step before build | T6 unsafe-profile/help/resource/server policy smoke |
| `README.md` | T4 repository-gate command | T6 safe/unsafe capability setup, provider-role, and callback-security prose |
| `docs/architecture/component-map.json` | T2-T4 and D1-D4 components | T6 `COMP-CAPABILITY` record and repair-only sensitivity ID |
| `docs/architecture/id-registry.json` | T2-T5 and D1-D4 IDs, including `SEC-MCP-001` and scheduler text | T6 `COMPAT-CAPABILITY-POLICY-001`, `SEC-CAPABILITY-001`, and repair-only `SEC-SENSITIVITY-PROVENANCE-001` |
| `docs/architecture/index.md` | T2-T4 canonical architecture/governance/repository entries | T6 role-capability document, schema, and packaged-policy links |
| `docs/architecture/normative-documents.json` | T2-T4 and D1-D4 normative inventory | T6 `ARCH-CAPABILITY-001` record |
| `docs/v5/07-runtime-architecture.md` | T2 runtime contract and T5/S1 scheduler/recovery behavior; T1 capability defect remains historical only | T6 capability source/test metadata, invariant, callback-resolution section, and repair claim |
| `docs/v5/08-mcp-surface.md` | T2 MCP shape and `SEC-MCP-001`; T1 capability defect remains historical only | T6 capability test metadata, startup failure rule, and repair claim |
| `src/unrest_harness/baseline.py` | T1 baseline plus T5 static approved-scheduler replay | T6 static replacement of the approved-base capability observation; release uses the original provider-backed characterization |
| `src/unrest_harness/cli.py` | T3 `check-governance`/`check-commit` and T4 `check-repository` commands/imports | T6 capability imports, unsafe flag, policy/config/environment/credential wiring, and all capability repairs |
| `src/unrest_harness/server.py` | T2 `SEC-MCP-001` structural annotation | T6 capability preflight and removal of the pre-existing diagnostic dispatcher fallback |

## Release-only path

`docs/release/batch-0-safe-subset.md` is added solely for `VAL-SPLIT-002`.
It records the three-way classification and is not copied from either side of
the Batch 0 product stack.

## Reproduction

Reviewers can audit the split with:

```bash
git diff --name-status main..codex/capability-follow-up
git diff --name-status main..codex/batch-0-safe-subset
git diff --name-status codex/batch-0-safe-subset..codex/capability-follow-up
git diff --no-ext-diff main..codex/batch-0-safe-subset -- <mixed-path>
git diff --no-ext-diff codex/batch-0-safe-subset..codex/capability-follow-up -- <mixed-path>
```

The release verification must also prove the capability-only paths are absent,
the excluded existing paths are byte-identical to `main`, the historical
baseline still regenerates, the focused B0-T1..B0-T5 surfaces pass, and the
common repository gate/build succeed.
