# Contributing to Unrest

Bug reports, documentation fixes, provider integrations, and harness improvements
are welcome.

## Development setup

The project requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --locked
```

## Checks

Run these from the repository root before opening a pull request:

```bash
uv run ruff check .
uv run mypy src
uv run pytest -q
uv run unrest check-repository
uv build
```

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
