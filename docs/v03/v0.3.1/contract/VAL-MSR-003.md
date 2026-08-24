# VAL-MSR-003 — Project case P2 validator rework oracle

**Surface:** configured provider through public run/Mission/validator surfaces.

**Needs:** VAL-MSR-001 frozen P2 task and deterministic validator fixture.

**Behavior:** Each of five cold-root P2 top-level repetitions must produce one deliberately
validator-rejected result, record the rejection/rework transition, and then
produce the correct terminal artifact. An independent oracle verifies both the
single rejection/rework and final SHA-256/text invariant; bypassing validation,
zero or multiple seeded rejections, or wrong artifact fails that repetition.
Every nested provider invocation is attributed with timing, tokens, reported
cost, cache and outcome to the P2 repetition and global ceilings.

**Evidence:** Five complete private repetition timelines, their nested provider
invocation records, validator records, terminal artifacts, sanitized metrics,
oracle logs, denominator, median/MAD and noise status.
