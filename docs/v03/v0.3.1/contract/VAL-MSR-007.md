# VAL-MSR-007 — Atomic fail-closed baseline execution/publication

**Surface:** installed `measure-baseline`, matching library call, destination filesystem.

**Needs:** VAL-MSR-001 and an explicit operator confirmation for provider work.

**Behavior:** Drifted protocol/product digest, invalid oracle, provider failure,
timeout/cancel, 20-minute repetition/200-minute wall/USD-50 reported-cost exhaustion,
cache/concurrency violation, missing repetition, >15% noise, unsafe non-empty
destination, private-data leak, partial output or verification mismatch yields
invalid/inconclusive and no valid publication. Any unattributed nested provider
invocation is invalid. Success verifies then atomically
publishes only below `docs/v03/measurement/results/**`; interruption preserves
the previous valid bundle.

**Evidence:** Fault at each boundary, exit/stdout/stderr contract, destination
inventory, process/cache/concurrency logs, secret-safe errors, unrelated cwd,
atomic replacement and protected product digest before/after.
