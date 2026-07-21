# Contributing to Unrest

Bug reports, documentation fixes, provider integrations, and harness improvements
are welcome.

## Development setup

The Python project lives in [`unrest/`](unrest/) and requires Python 3.11+ and
[`uv`](https://docs.astral.sh/uv/).

```bash
cd unrest
uv sync --locked
```

## Checks

Run these from `unrest/` before opening a pull request:

```bash
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run pytest -q ../research/2026-07-production-log-mission/test_analyze_trace.py
uv build
```

Hermetic tests are the default. Tests that require live ACP agents are skipped
when their adapter binaries are unavailable.

## Pull requests

- Keep each pull request focused on one coherent change.
- Explain the user-visible behavior and how it was verified.
- Add or update tests for behavior changes.
- Preserve deterministic research fixtures and generated outputs.
- Use full type annotations and the configured Ruff line length of 100.

Provider definitions live in
[`unrest/src/unrest_harness/providers.py`](unrest/src/unrest_harness/providers.py),
with bundled assets under
[`unrest/src/unrest_harness/bundled/providers/`](unrest/src/unrest_harness/bundled/providers/).
New providers should include an orchestrator prompt path, ACP adapter command,
and tests.

## License

Contributions are licensed under the [Apache License 2.0](LICENSE).
