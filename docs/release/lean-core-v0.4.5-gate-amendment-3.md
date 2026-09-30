# v0.4.5 historical speed-runner test exclusion

Status: maintainer approved 2026-09-30. This narrows only the source-suite
checkpoint in the [focused release gate](lean-core-v0.4.5-gate-amendment-2.md).
All other obligations in that gate remain required.

The frozen `e5de22a` full suite returned 1,889 passes, 16 failures, 721 setup
errors and 7 skips. A focused reproduction showed that
`tests/test_v04_speed_runner.py` invokes a historical fake improvement manager
with an empty campaign freeze. The v0.4.5 improvement adapter rejects that
input before benchmark execution. The module is an old comparative measurement
harness, and this release makes no benchmark, speed or improvement claim.
Other failing stale documentation, envelope and attention fixtures were repaired
at `36d6187`; their focused tests then passed. That repair does not make the
failed full-suite run a pass.

For this release, the source-suite command is exactly:

```bash
env -u CODEX_PATH uv run pytest -q --ignore=tests/test_v04_speed_runner.py
```

Only `tests/test_v04_speed_runner.py` is excluded. Every other discovered
source test remains in the checkpoint. The exclusion is visible in CI and
release records, has no PASS credit, and is not a diagnosis that the v0.4 speed
benchmark works on v0.4.5. If any included test fails or errors, the source
suite gate fails. Do not broaden `--ignore`, use `-k` to hide other failures,
or reinterpret this as general permission to skip product checks. The
historical runner can be repaired separately after release preparation.
