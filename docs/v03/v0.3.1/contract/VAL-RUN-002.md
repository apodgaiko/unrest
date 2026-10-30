# VAL-RUN-002 — Attach, cancel, and restart recovery

**Surface:** MCP `attach_run`/`cancel_run`, matching library calls, and subprocess state.

**Needs:** VAL-RUN-001.

**Behavior:** `attach_run(run_id)` follows the same worker and returns its
durable terminal result across reconnect/restart. `cancel_run(run_id, reason)`
is idempotent and records requested, draining, effect-complete,
report-complete, and terminal boundaries as applicable. Server restart either
reattaches a live owned worker or marks an orphan for attention; no live worker
loses its lock and no effect is repeated.

Within the spawning interpreter, controllers share the actual worker process
handle. Terminal attach also joins that child, respecting the caller's remaining
timeout without changing the durable result or killing it. A timed-out join
retains the handle for a later attach. Recovery polls known local children before
checking liveness, so an exited child cannot appear live merely as a zombie.
After fork, local ownership is reset. Persisted PID records never grant wait
ownership to a different interpreter.

**Evidence:** Cancel before dispatch and at each boundary, disconnect, kill and
restart the server, inspect ancestry/locks/receipts, concurrent attach, repeated
cancel, missing run, orphan recovery, and exact effect count.

Cancellation terminalizes Mission attempt snapshots only for the built-in
`unrest_harness.runtime_executor:execute` executor. Custom executors keep their
own project identifiers and cannot cause ambient Mission configuration discovery
or cross-project snapshot mutation. All executors still complete durable
RunControl draining/cancellation and retain cancellation exit code 2.

Cancellation first sends SIGTERM only to the retained worker matching its durable
request and current session. Managed executor finalizers drain their owned
process chains before that worker exits; simultaneous group termination must not
kill those parents before they can wait for their children. If opaque registered
descendants remain after those finalizers unwind, the worker retains its resource
lock, verifies that it leads its current process group and session, and preserves
bulk SIGTERM for remaining group members. SIGTERM and SIGINT are ignored only
during that group signal and descendant drain, with prior handlers restored in
`finally`. Terminal cancellation follows draining. No new watchdog or automatic
escalation deadline is implied. Direct children receive actual parent waits;
the pre-existing nonchild registration path observes disappearance and does not
establish an original-parent wait.
