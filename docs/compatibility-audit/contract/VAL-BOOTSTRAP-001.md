# VAL-BOOTSTRAP-001: Installed init pins runtime executables safely

Surface: CLI and generated artifact.
Needs: installed `zenith` command, controlled PATH, and existing-config fixtures.
Behavior: `zenith init --agent codex` emits valid idempotent MCP configuration,
preserves unrelated host configuration, forwards role efforts and runtime cache,
pins resolved uv/Codex executables, and emits a worker model only when requested.
Evidence: Real CLI exit/stdout/stderr, parsed JSON/TOML, before/after unrelated
config comparison, controlled executable resolution, and idempotent rerun.

