# VAL-REL-002 — Exact local checkout and editable-tool update

**Surface:** `/Users/aleksandrpodgaiko/Desktop/unrest`, global `unrest` executable,
and installed distribution metadata.

**Needs:** VAL-REL-001 remote release complete.

**Behavior:** Fetch `origin main`, fast-forward-only the named local checkout to
the exact released commit, then run
`uv tool install --editable --force /Users/aleksandrpodgaiko/Desktop/unrest`.
The checkout HEAD, `importlib.metadata.version("unrest-harness")`, imported
module provenance, CLI executable provenance, `unrest --help`, orchestrator
tool catalog, and a no-provider inspect call must all resolve to v0.3.1 bytes.
Dirty/unrelated local user files are preserved; non-fast-forward or provenance
mismatch stops without destructive repair.

**Evidence:** Before/after status and refs, exact remote/tag/local commit,
installer output, distribution version/location, module/executable paths, CLI
help, MCP schema set, inspect result, and rollback command.
