# VAL-AUTH-002 — Effect and failure custody

**Surface:** MCP, subprocess, durable state, and process locks.

**Needs:** VAL-AUTH-001 and VAL-RUN-001.

**Behavior:** Cancel-before-start, in-flight cancellation, timeout, disconnect,
worker/server crash, restart, partial effect, orphaning, and report failure
retain exact owner, generation, worker ancestry, effect boundary, and evidence;
they end typed terminal or attention states. Retry appends a new operation and
cannot rewrite custody, release a live worker's lock, or duplicate an effect.

**Evidence:** Cross-process fault injection at pre-effect, effect-complete,
report-complete, and receipt-complete boundaries, followed by restart/attach,
lock inspection, and effect-count proof.

