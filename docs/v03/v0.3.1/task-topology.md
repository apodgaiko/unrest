# v0.3.1 implementation and validation topology

This topology is subordinate to `mission.md`, `scope-inventory.md`,
`public-surface.v1.json`, and the 39 reviewed `VAL-*` contracts. Every live
assertion has exactly one work owner. Validation is independent and does not
transfer ownership or promotion authority.

## Work tasks

| Task | Owned assertions | Owned implementation | Depends on | Parallel rule |
| --- | --- | --- | --- | --- |
| FM-FND | VAL-ID-001/002, VAL-RCP-001/002, VAL-SEC-002 | `canonical_identity.py`, `receipts.py`, `foundation_store.py`, catalogs/schemas and focused tests | reviewed contract | Runs beside FM-ACP in a separate worktree. |
| FM-ACP | VAL-SEC-001 | Generic bounded structured provider session, role/policy/config/ACP extraction, private artifact custody and redaction tests | reviewed contract | Runs beside FM-FND; sole owner of ACP/capability/config/provider files. |
| FM-RUN | VAL-AUTH-002, VAL-RUN-001/002 | `run_control.py`, subprocess worker, durable run state/attach/cancel/restart and tests | FM-FND, FM-ACP | Runs beside FM-WS after both prerequisites merge. |
| FM-WS | VAL-WS-001/002/003/004 | `workspaces.py`, T1 leases, returns, deterministic parent integration, cleanup and real-Git tests | FM-FND | May start beside FM-RUN in a separate worktree. |
| FM-INQ | VAL-INQ-001/002/003/004 | `inquiry.py`, four read-only branches, provider fan-out, synthesis/dissent, handoff and tests | FM-FND, FM-ACP, FM-RUN | Runs beside FM-EVO after prerequisites merge. |
| FM-EVO | VAL-EVO-001/002/003/004/005 | `evolution.py`, frozen campaigns, genealogy, evaluation/review, promotion/rollback and tests | FM-FND, FM-ACP, FM-RUN, FM-WS | Runs beside FM-INQ in a separate worktree. |
| FM-INT | VAL-FND-001, VAL-AUTH-001, VAL-SURF-001, VAL-COMP-002 | `api.py`, `foundation_tools.py`, minimal server/coordinator/dispatcher integration, accepted ADRs/registries/assets, exact catalog parity tests | FM-RUN, FM-WS, FM-INQ, FM-EVO | Serial integration owner; sole editor of server/coordinator/dispatcher and architecture registries. |
| FM-COMP | VAL-COMP-001/003, VAL-BUR-001/002 | Persistence, Python/package/no-extra compatibility, routine-test burden evidence and focused fixes | FM-INT | Runs beside FM-MSR protocol implementation but not provider execution. |
| FM-MSR | VAL-MSR-001/002/003/004/005/006/007 | `measurement.py`, CLI adapter, P1/P2/E1/E2 protocol/oracles, sanitized bundle and release/manual execution | FM-INT | Protocol/tooling may run beside FM-COMP; 20 repetitions start only on the frozen candidate. |
| FM-REL | VAL-REL-001/002 | Version/notes/manifests, frozen validation, packages, remote release, local fast-forward/editable reinstall | FM-COMP, FM-MSR | Serial and last. |

## Merge order and shared-file reservations

1. Commit the reviewed contract pack on the integration branch.
2. Merge FM-FND, then FM-ACP. They are file-disjoint; the order only makes
   conflict handling deterministic.
3. Branch FM-RUN and FM-WS from the same merged foundation. Merge FM-RUN, then
   FM-WS. Neither may edit the other's modules.
4. Branch FM-INQ and FM-EVO from the merged runtime/workspace point. Merge
   FM-INQ, then FM-EVO.
5. FM-INT alone edits `server.py`, `coordinator.py`, `dispatcher.py`, public
   registration, accepted decision indexes, component maps, and shared assets.
6. FM-COMP and FM-MSR tooling may proceed in parallel, but `cli.py`,
   `pyproject.toml`, version files, and release records remain reserved for the
   integration/release owner. FM-MSR exposes its command through a separate
   Click command object that the integration owner registers.
7. Freeze executable/product/test bytes, run FM-010, add only excluded result
   artifacts, then perform FM-REL without changing protected bytes.

No concurrent mutable worker uses the same checkout. A lane commits only its
declared paths. Integration uses explicit commits and stops on overlap rather
than resolving a semantic conflict heuristically.

## Validation tasks and gates

| Validation task | Targets | Required surface |
| --- | --- | --- |
| VAL-FND-SCRUTINY | FM-FND, FM-ACP, FM-RUN assertions | Installed library, subprocess restart, mutation vectors, canary scan. |
| VAL-WS-FLOW | VAL-WS-001..004 | Real temporary Git repository, overlapping processes, disjoint/conflicting returns, cleanup/restart. |
| VAL-INQ-FLOW | VAL-INQ-001..004 | Real MCP plus configured provider; Mission/workspace byte comparison and private/public scan. |
| VAL-EVO-FLOW | VAL-EVO-001..005 | Real MCP/provider/Git flow with reward-hack, stale promotion, crash, and rollback cases. |
| VAL-PUBLIC-PARITY | VAL-FND-001, VAL-AUTH-001, VAL-SURF-001, VAL-COMP-002 | Installed MCP/CLI/library differential against the frozen catalog and v0.3.0 seven-tool oracle. |
| VAL-COMPAT | VAL-COMP-001/003, VAL-BUR-001/002 | Exact 14-case extracted-sdist suite, Python 3.11-3.13 lanes, no-extra wheel, timed routine tests. |
| VAL-MEASURE | VAL-MSR-001..007 | Independent protocol/oracle validation, 20-repetition ledger, bundle recomputation, privacy and publication faults. |
| VAL-RELEASE | VAL-REL-001/002 | Exact-head CI, remote refs/assets, fresh install, local editable provenance, v0.3.0 immutability. |

Milestone gates follow each merge wave. The release gate requires all 39
per-assertion verdicts, one Python 3.13 full source suite on frozen bytes, the
specified archive/wheel lifecycle, and the candidate-bound FM-010 bundle.
