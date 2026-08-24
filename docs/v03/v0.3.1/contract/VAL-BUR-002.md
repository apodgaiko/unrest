# VAL-BUR-002 — Routine verification burden

**Surface:** imports, tests, CI and command ledger.

**Needs:** v0.3.0 timing baseline and frozen v0.3.1 candidate.

**Behavior:** Import, collection, focused lanes and ordinary CI never invoke a
provider or baseline. Focused subsystem lanes target ten seconds; misses and
full-suite delta are published. The full Python 3.13 source suite runs exactly
once for the frozen candidate; build/install checks do not repeat it.

**Evidence:** Provider/network sentinels, CI inspection, timed focused lanes,
before/after timing, and deduplicated command ledger.

