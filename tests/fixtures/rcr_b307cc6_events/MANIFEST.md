# RCR LG-2 legacy event-tree corpus — b307cc6 writer-generated (CANDIDATE)

Status: CANDIDATE evidence for RCR V3 §13 LG-2 (sha256 V3 `4c6f95db…c1218`). Not a post-fix PASS:
no HEAD/RCR reader was run against these bytes. LG-5 (user trees, external writers) UNKNOWN.

- Producer: original v0.4.7 code (b307cc6 blobs in `source/`, see `PROVENANCE.txt`), public
  `RunControl` methods only; every byte under `corpus/*/cases/*/tree/` was written by that code.
- Classes (V3 §11): **B-N** — server submit/cancel/recover plus the worker call sequence of baseline
  `run_worker.main` (`reference/run_worker.py.txt` :128–184) replayed in-process; **B-L** — public
  method orders an uninterrupted worker does not produce (external signal, races, repeated calls).
  `s*` cases are the same flows stopped mid-way (no truncation, no planting).
- Hermetic: fake `_spawn` recorder (n17: real `_spawn`, Popen stub raises OSError, no process);
  `os.kill` recorder (never delivers; fake live set); `os.getpgid/getsid` fakes; killpg, fork/exec/
  spawn/Popen, `_posixsubprocess.fork_exec`, sockets, `signal.signal` hard-fail; writes outside
  work/out refused; `recover=False` except the 6 `server.RunControl(recover=True)` cells (n11–n16).
- Fixed values: server owner `server:4242:0123456789ab`; worker owner `worker:424242:1`, fake
  pid=pgid=424242; executor ref `lg2_fake_executor:execute` (stubbed, never invoked); operation
  `abort_project`; clocks A/B (controlled `_utc_now`, reset per case).
- Copied per case: the whole `.unrest/` and `.unrest-runtime/` tree except the mutation journal
  (`.unrest/foundation/public-mutations/`: uuid4 + real owner_pid, non-deterministic) and empty
  `*.lock` files; omitted paths are listed in `manifest.json` (`omitted_not_copied`).

| case | class | states | kill rec. | spawn rec. | recover=True | run_worker except-branch |
|---|---|---|---|---|---|---|
| `n01-submit-queued` | B-N | queued | 0 | 1 |  |  |
| `n02-worker-success` | B-N | queued → running → effect_complete → report_complete → succeeded | 0 | 1 |  |  |
| `n03-worker-executor-failure` | B-N | queued → running → failed | 0 | 1 |  |  |
| `n04-worker-exception` | B-N | queued → running → attention | 0 | 1 |  | yes |
| `n05-cancel-queued` | B-N | queued → cancel_requested → draining → cancelled | 0 | 1 |  |  |
| `n06-cancel-live-worker` | B-N | queued → running → cancel_requested → draining → cancelled | 2 | 1 |  | yes |
| `n07-cancel-dead-running` | B-N | queued → running → cancel_requested → draining → cancelled | 0 | 1 |  |  |
| `n08-cancel-after-effect-dead` | B-N | queued → running → effect_complete → cancel_requested → attention | 0 | 1 |  |  |
| `n09-cancel-after-report-dead` | B-N | queued → running → effect_complete → report_complete → cancel_requested → attention | 0 | 1 |  |  |
| `n10-cancel-after-effect-live` | B-N | queued → running → effect_complete → cancel_requested → draining → attention | 2 | 1 |  | yes |
| `n11-recover-queued` | B-N | queued | 0 | 2 | yes |  |
| `n12-recover-running-dead` | B-N | queued → running → attention | 0 | 1 | yes |  |
| `n13-recover-effect-complete` | B-N | queued → running → effect_complete → report_complete → succeeded | 0 | 1 | yes |  |
| `n14-recover-report-complete` | B-N | queued → running → effect_complete → report_complete → succeeded | 0 | 1 | yes |  |
| `n15-recover-cancel-requested` | B-N | queued → running → cancel_requested → draining → cancelled | 2 | 1 | yes |  |
| `n16-recover-draining` | B-N | queued → running → cancel_requested → draining → attention | 2 | 1 | yes | yes |
| `n17-spawn-oserror` | B-N | queued → failed | 0 | 0 |  |  Popen-OSError |
| `l01-external-signal-drain` | B-L | queued → running → draining → cancelled | 0 | 1 |  | yes |
| `l02-progress-after-draining` | B-L | queued → running → draining → effect_complete → report_complete → succeeded | 0 | 1 |  |  |
| `l03-cancel-race-then-success` | B-L | queued → running → cancel_requested → effect_complete → report_complete → succeeded | 2 | 1 |  |  |
| `l04-cancel-then-failure` | B-L | queued → running → cancel_requested → failed | 2 | 1 |  |  |
| `l05-draining-then-failure` | B-L | queued → running → draining → failed | 0 | 1 |  |  |
| `l06-effect-then-failure` | B-L | queued → running → effect_complete → failed | 0 | 1 |  |  |
| `l07-report-then-failure` | B-L | queued → running → effect_complete → report_complete → failed | 0 | 1 |  |  |
| `l08-effect-then-worker-failed` | B-L | queued → running → effect_complete → attention | 0 | 1 |  | yes |
| `l09-report-then-worker-failed` | B-L | queued → running → effect_complete → report_complete → attention | 0 | 1 |  | yes |
| `l10-queued-worker-failed` | B-L | queued → failed | 0 | 1 |  |  |
| `s01-snapshot-running` | B-N | queued → running | 0 | 1 |  |  |
| `s02-snapshot-effect-complete` | B-N | queued → running → effect_complete | 0 | 1 |  |  |
| `s03-snapshot-report-complete` | B-N | queued → running → effect_complete → report_complete | 0 | 1 |  |  |
| `s04-snapshot-cancel-requested-live` | B-N | queued → running → cancel_requested | 2 | 1 |  |  |
| `s05-snapshot-draining-after-cancel` | B-N | queued → running → cancel_requested → draining | 2 | 1 |  | yes |
| `s06-snapshot-draining-external-signal` | B-L | queued → running → draining | 0 | 1 |  |  |
