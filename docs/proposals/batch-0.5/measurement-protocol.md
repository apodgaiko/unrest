# Lean Core compaction measurement protocol

Status: accepted 2026-08-09 as the measurement protocol for ADR-0002; no
optimization result is claimed by acceptance alone.

## Fixed reference and working point

- Scoring reference commit: `93c59e4378407f3d7cfb918cf86c8bdc81daa141`.
- Scoring reference tree: `35152a4a8c56198664f519691ec952ec9ca519f4`.
- Initial working point: the same commit, with pre-existing untracked
  `.validation/` and `validator-regressions/` excluded from every measurement.
- Correctness oracle: the accepted Lean Core behavior/security contract, current
  schema-version-1 persisted fixtures, real CLI/MCP/storage surfaces, and
  installed-wheel lifecycle—not the candidate's own output.

The scoring reference never moves. An accepted slice may become the next
working point, but all final percentages remain relative to this reference.

## Reference environment

- Date recorded: 2026-08-09.
- Platform: macOS 26.6.1, arm64.
- Python: CPython 3.13.12.
- Environment runner: repository `.venv`/`uv`, with a controlled writable
  `UV_CACHE_DIR` where sandboxing requires it.
- Full-suite rule: one source-suite run for the frozen candidate, consistent
  with repository guidance.

## Verified current measurements

| Metric | Reference value | Evidence/qualification |
| --- | ---: | --- |
| Installed production Python physical LOC | 25,730 | Recursive `wc -l` over `src/unrest_harness/**/*.py` |
| Test Python physical LOC | 26,466 | Recursive `wc -l` over `tests/**/*.py` |
| Maintained first-party Python physical LOC | 52,351 | Recursive `wc -l` over `src/`, `tests/`, and `tools/` Python files |
| Collected tests | 3,441 | Current HEAD, `pytest --collect-only`, cache provider disabled |
| Collection time reported by pytest | 0.82 seconds reference; 1.02 seconds review rerun | Expected noise; not a release-latency metric |
| Recorded full source suite | 4,246.59 seconds | Python 3.13 release checkpoint: 2 environment-only loopback failures, 3,432 passed, 7 skipped |
| Recorded closed capability/source-graph suite | 476.99 seconds | 338 passed in the telemetry release checkpoint |
| Existing wheel size | 309,041 bytes | `dist/unrest_harness-0.1.0-py3-none-any.whl`; unrebuilt artifact with unverified comparison provenance, so both reference and candidate must be rebuilt |
| CLI module cold import median | 0.29 seconds | Seven fresh `.venv/bin/python -c 'import unrest_harness.cli'` processes; samples 0.49, 0.29, 0.28, 0.28, 0.30, 0.29, 0.28 |
| Server module cold import median | 0.78 seconds | Seven fresh `.venv/bin/python -c 'import unrest_harness.server'` processes; samples 0.77, 0.78, 0.71, 0.72, 0.79, 1.07, 0.85 |
| Root release-evidence physical lines | 7,946 | Current `evidence/` tree; context metric only |

The recorded full-suite result is release evidence for the current product
tree, not a new rerun performed for this review. The wheel must be rebuilt from
the fixed reference before wheel-byte comparison is accepted.

## Feasibility arithmetic and independent floors

- The five targeted large modules total 16,940 production lines; all other
  installed production Python totals 8,790 lines.
- The 15,438-line production ceiling leaves at most 6,648 lines for all five
  targeted modules combined.
- If the capability replacement consumes the 2,500-line stop-rule ceiling,
  the other four targeted modules receive 4,148 lines combined.
- Leaving the current 7,532-line capability module untouched makes the
  production floor impossible: even deleting the other four targeted modules
  completely would leave 16,322 lines, 884 above the ceiling.
- The 2,500-line capability ceiling is net candidate production code and
  includes all new inventory plumbing, sink handling, pipe lifecycle, and
  other replacement code; it is not a retained-old-code allowance.

The total-maintained floor is separate. A 30% reduction requires 15,706 lines;
landing production exactly at its 40% ceiling removes 10,292, leaving at least
5,414 test/tool lines to remove. The three obvious whole-test-file deletions
total 3,902 lines, leaving another 1,512. Neither hard floor is inferred from
the other; both are measured independently at every candidate checkpoint.

## Exact size metrics

### Installed production Python

Command:

```bash
find src/unrest_harness -name '*.py' -print0 | xargs -0 wc -l
```

- Hard acceptance: at most 15,438 lines, a reduction of at least 40%.
- Stretch: at most 12,865 lines, a reduction of at least 50%.

### Total maintained first-party Python

Command:

```bash
find src tests tools -name '*.py' -print0 | xargs -0 wc -l
```

Any optional in-repository package or new first-party Python root is added to
this command. Code moved to another repository counts unless ownership and
maintenance are genuinely transferred outside the Lean Core project.

- Hard acceptance: at most 36,645 lines, a reduction of at least 30%.
- Stretch: at most 31,410 lines, a reduction of at least 40%.

### Complexity guardrail for rewritten modules

- No newly written or rewritten function above 250 logical lines.
- No newly written or rewritten function with Ruff C901 complexity above 30.
- Report the five largest functions and five highest C901 values before and
  after. File count and a universal per-module LOC cap are not metrics.

## Test latency metrics

Latency comparisons use the same machine, power state, Python/toolchain, and
cache preparation. Reference and candidate runs are interleaved when both are
available rather than measured in two long blocks. Record every raw sample,
median, range, failures/retries, and any environmental deviation. The decision
threshold is the explicit absolute budget below; small differences inside the
observed range (such as 0.82 vs 1.02 seconds of collection) are reported as
noise, not wins. A claimed latency improvement must exceed 10% and the combined
run-to-run range; otherwise classify it as neutral even if the median is lower.

### Focused contract suites

Before production work, define exact manifests for:

- lifecycle/task/gate/attention/terminal review;
- persistence/restart/single-writer scheduling;
- provider configuration/authority/redaction;
- narrow repository-checker behavior and import isolation;
- compact status; and
- package/import lifecycle.

Each manifest is measured as three warm runs on the reference runner. The
median must be at most 30 seconds. No manifest may omit a retained behavior ID
assigned to that surface merely to meet the time budget.

### Provider-independent source suite

Command:

```bash
env -u CODEX_PATH uv run pytest -q
```

Live provider smokes remain explicit opt-ins and skip without credentials. The
frozen candidate must produce a clean provider-independent result in at most
600 seconds on the reference runner. Every retained behavior ID must map to a
collected test; shorter runtime from deleting unwithdrawn evidence is invalid.

## Import and package metrics

- `unrest --help`, `unrest init`, and ordinary project operations must not
  import repository governance, repository contract, historical baseline, or
  the full status implementation unless that command needs it.
- CLI module cold-import median target: at most 0.20 seconds over seven fresh
  processes on the reference runner.
- Server cold-import hard rule: no regression above the 0.78-second reference
  median outside the characterized noise band; stretch target 0.60 seconds.
  Import comparisons use seven interleaved fresh-process samples per revision.
- Rebuild wheel and sdist from both scoring reference and frozen candidate with
  the same toolchain. Report bytes and archive membership. Wheel size is a
  secondary metric, not a substitute for LOC or behavior.
- Run installed-wheel help, safe startup, policy loading, one provider-
  independent mission, and one exact-value redaction scenario from an unrelated
  temporary working directory.

## Correctness and security guardrails

A candidate is non-promotable when any of the following holds:

- a retained behavior ID lacks candidate-specific evidence;
- current schema-version-1 persisted fixtures cannot load/resume;
- safe Claude or Codex initialization becomes broader;
- unsafe settings can appear without exact opt-in;
- callback path containment or read/write separation regresses;
- terminal children receive any value in the finite selected provider/role
  credential set by default, in either profile;
- any credential occurrence under the reviewed short-token boundary policy
  crosses one of the seventeen protected named sinks;
- output/persistence is moved outside the named centralized primitives without
  updating the reviewed sink inventory;
- status writes state, claims liveness/ETA, or suppresses bounded project
  failures; or
- a deleted subsystem is recreated under another name or maintained location.

Inventory propagation through coordinator persistence, runtime cursors,
CLI/config/bootstrap writers, and diagnostics must be proven before payload-
derived inference is deleted. Per-sink results identify all seventeen sink IDs,
not merely one aggregate pass. The security run includes safe and unsafe
finite-inventory cases and records transformed-secret non-redaction as an
approved runtime behavior cut rather than a regression.

## Per-slice ledger

Every implementation slice reports:

```text
parent_ref:
candidate_ref:
changed_files:
withdrawn_guarantees:
preserved_behavior_ids:
production_python_loc_before:
production_python_loc_after:
maintained_python_loc_before:
maintained_python_loc_after:
focused_commands_and_times:
correctness_results:
security_sink_results:
import_results:
package_results:
tradeoffs:
recommendation: accept | reject | rerun
```

Replacement helpers and tests are included in the relevant before/after LOC.
Any claim that a slice creates margin must show its per-module arithmetic; no
unstated ledger estimate is accepted as feasibility evidence.

## Stop rules

Stop and return to scope review when:

- the complete capability candidate, including all new replacement work,
  requires more than 2,500 production lines after the static and transformed-
  secret claims are removed;
- total maintained first-party code does not fall even though installed-core
  code does;
- a time target can be met only by dropping evidence for a retained behavior;
- a compatibility shim or optional package recreates the removed system;
- a compaction slice changes mission authority, autonomous recovery,
  concurrency, or evidence freshness; or
- three consecutive clean candidate slices fail to achieve a meaningful size,
  comprehension, or latency reduction.

Compaction completion does not claim improvement in external host wake,
attention, gate-checkpoint, or closure cadence. That requires a separately
scoped authority and idempotency design.
