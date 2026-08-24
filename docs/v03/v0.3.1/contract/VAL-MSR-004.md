# VAL-MSR-004 — Evolution case E1 exact improvement

**Surface:** configured provider through public campaign/candidate/evaluation/review surfaces.

**Needs:** VAL-MSR-001 frozen tiny text/config fixture and exact tests.

**Behavior:** Each of five cold-root E1 top-level campaign repetitions goes signal → candidate →
independent evaluation → review → recorded human decision. The candidate must
improve the frozen fixture according to an exact before/after test oracle while
preserving protected bytes. Acceptance/rejection/rework/failure remains in the
denominator; measurement does not auto-promote product source. Every nested
provider invocation is attributed with timing, tokens, reported cost, cache and
outcome to its E1 repetition and global ceilings.

**Evidence:** Five private repetition timelines/candidates, complete nested
invocation records, exact tests, identities/receipts, sanitized metrics,
denominator, median/MAD and noise status.
