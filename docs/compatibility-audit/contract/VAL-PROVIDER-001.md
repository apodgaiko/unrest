# VAL-PROVIDER-001: Non-Codex providers are isolated

Surface: subprocess environment.
Needs: Claude and Hermes provider fixtures with a Codex-contaminated parent env.
Behavior: Claude and Hermes subprocesses receive no Codex config, executable,
sandbox, or mode variables while provider-neutral environment remains present.
Evidence: Captured environment at each provider subprocess boundary and focused
unit tests for contaminated parent state.

