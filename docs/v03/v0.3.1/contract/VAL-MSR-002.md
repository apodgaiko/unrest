# VAL-MSR-002 — Project case P1 artifact oracle

**Surface:** configured provider through public run/Mission surfaces and private raw artifacts.

**Needs:** VAL-MSR-001 frozen P1 request and expected invariant.

**Behavior:** Each of five cold-root P1 top-level repetitions completes a bounded real project
that creates the requested artifact. An independent non-provider oracle checks
its SHA-256 and exact frozen text invariant. Record monotonic total/phase time,
transitions, failures/rework and persisted bytes. Every nested provider call's
timing, tokens, reported cost, cache and outcome is attributed to this P1
repetition and global ceilings; failed oracle or missing attribution remains
visible and is not successful.

**Evidence:** Five private repetition timelines/artifacts, five sanitized
top-level records, their complete nested invocation records, independent oracle
logs, full denominator, median/MAD and noise disposition.
