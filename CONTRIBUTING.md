# Contributing to Unrest

Bug reports, documentation fixes, provider integrations, and harness improvements
are welcome.

## Development setup

The project requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --locked
```

## Checks

For a focused change, run the narrow pytest, Ruff, and mypy targets that cover
the edited behavior (record why a check type is inapplicable when necessary):

```bash
uv run pytest -q <focused-test-paths>
uv run ruff check <changed-product-paths>
uv run mypy <changed-typed-paths>
```

At an implementation milestone, run these from the repository root:

```bash
uv run ruff check .
uv run mypy src
uv run unrest check-repository
uv run pytest -q <milestone-test-paths>
```

Run the full source suite once for the frozen release candidate on Python 3.13
with `env -u CODEX_PATH uv run pytest -q`. Python 3.11 and 3.12 are focused
compatibility lanes, not duplicate full-suite lanes. When CLI entry points,
bundled assets, package data, or MCP surfaces change, also run `uv build`,
`uv run python tools/check_distribution.py dist`, and the installed-wheel
lifecycle from an unrelated working directory; do not rerun the source suite
after build.

Hermetic tests are the default. Tests that require live ACP agents are skipped
when their adapter binaries are unavailable.

## Pull requests

- Keep each pull request focused on one coherent change.
- Explain the user-visible behavior and how it was verified.
- Add or update tests for behavior changes.
- Use full type annotations and the configured Ruff line length of 100.

Provider definitions live in
[`src/unrest_harness/providers.py`](src/unrest_harness/providers.py),
with bundled assets under
[`src/unrest_harness/bundled/providers/`](src/unrest_harness/bundled/providers/).
New providers should include an orchestrator prompt path, ACP adapter command,
and tests.

## License

Contributions are licensed under the [Apache License 2.0](LICENSE).
