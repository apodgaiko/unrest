# Compatibility evidence

Baseline: immutable upstream commit `a21c071`.

## Offline gates

- Contract review: pass after three sequential reviews.
- Python 3.11: Ruff pass; pytest `251 passed, 7 skipped`.
- Python 3.12: Ruff pass; mypy pass; pytest `251 passed, 7 skipped`.
- Python 3.13: Ruff pass; mypy pass; pytest `251 passed, 7 skipped`.
- Python 3.11 mypy is locally blocked by macOS rejecting the signed
  `librt/internal.cpython-311-darwin.so`; the same source passes mypy on 3.12
  and 3.13.
- Upstream test-node inventory: 219 nodes. Candidate inventory: 258 nodes.
  No upstream file or assertion was silently deleted. Two command-string tests
  were intentionally replaced by stronger environment-boundary tests because
  `codex-acp` does not accept Codex CLI `-c` flags:
  `test_augment_acp_command_codex_appends_bypass_flags` and
  `test_augment_acp_command_codex_reasoning_effort_override`.
- Protected upstream assets are unchanged except `zenith/pyproject.toml`, whose
  sole manifest change adds the Textual dependency required by `zenith live
  --dashboard`; the lockfile resolves it.
- `git diff --check` passes.

## Real local surfaces

- Installed CLI help exposes `zenith live` and its text, JSON, watch, project,
  and dashboard options.
- `zenith live --once` and `zenith live --json` ran against a disposable empty
  project directory; mode, size, and mtime were identical before and after.
- The Textual dashboard launched in a real PTY, rendered the empty fleet, took
  `r/j/k/n/b/p/f/o/a`, and exited on `q` without a traceback.
- Automated fixture tests cover populated, partial, corrupt state, corrupt
  project-record discovery, externally refreshed, and strict closed-manifest
  read-only cases.

## Deliberately unclaimed

The seven default-suite skips are live external-provider smokes. Both local ACP
adapters are installed, but these tests have not been run because they send a
test mission through locally authenticated external model services. Run them
only with explicit authorization:

```console
ZENITH_SMOKE_REAL_ACP=codex uv run pytest tests/test_smoke_real_acp.py tests/test_smoke_parallel_acp.py -s
ZENITH_SMOKE_REAL_ACP=claude uv run pytest tests/test_smoke_real_acp.py tests/test_smoke_parallel_acp.py -s
```
