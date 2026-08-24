# VAL-RUN-002 — Attach, cancel, and restart recovery

**Surface:** MCP `attach_run`/`cancel_run`, matching library calls, and subprocess state.

**Needs:** VAL-RUN-001.

**Behavior:** `attach_run(run_id)` follows the same worker and returns its
durable terminal result across reconnect/restart. `cancel_run(run_id, reason)`
is idempotent and records requested, draining, effect-complete,
report-complete, and terminal boundaries as applicable. Server restart either
reattaches a live owned worker or marks an orphan for attention; no live worker
loses its lock and no effect is repeated.

**Evidence:** Cancel before dispatch and at each boundary, disconnect, kill and
restart the server, inspect ancestry/locks/receipts, concurrent attach, repeated
cancel, missing run, orphan recovery, and exact effect count.
