# VAL-MSR-001 — Frozen exact FM-010 protocol

**Surface:** `measure-baseline`, matching library call, and frozen protocol artifact.

**Needs:** fully validated release candidate before any observation.

**Behavior:** Freeze P1, P2, E1, E2, exact fixtures/oracles/protected paths,
runner/source/build/Python/platform, current configured provider/model/route,
budgets, monotonic clock, cold-root policy, cache prohibition, concurrency one,
and order. Each case has five sequential top-level repetitions: exactly 20.
A repetition may contain required nested provider invocations; derived
`provider_invocation_count` may exceed 20. Every invocation binds its parent
repetition and records monotonic timing, tokens, reported cost, cache status and
outcome, all charged to that repetition and the global ceilings. Each top-level
repetition is at most 20 minutes; total wall is at most 200 minutes and reported
cost at most USD 50. Median/MAD use top-level repetitions; MAD/median greater
than 15% is inconclusive. Missing/cancelled/timed-out/replayed repetitions or
unattributed nested calls cannot enter a successful denominator.
The product digest hashes every tracked release-candidate byte except only
`docs/v03/measurement/results/**`. Provider/model/route values are freeze-time
configuration, never source constants.

**Evidence:** Protocol receipt before observations, independent oracle and
digest recomputation, mutation of every bound field/exclusion/budget/order,
fresh empty roots, cache/concurrency instrumentation, 20-repetition ledger,
nested invocation ledger, and independent provider invocation count.
