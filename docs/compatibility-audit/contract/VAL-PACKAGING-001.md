# VAL-PACKAGING-001: Package resolves across supported Python versions

Surface: library and CLI.
Needs: committed `pyproject.toml`, `uv.lock`, and uv-provisioned Python 3.11,
3.12, and 3.13 runtimes.
Behavior: A clean locked sync installs the integrated package and Textual CLI on
every upstream-supported Python version without rewriting dependency metadata.
Evidence: Per-version `uv sync --locked`, import, `zenith --help`, Ruff, mypy,
and full pytest output; explicit blocked evidence for any unavailable runtime.

