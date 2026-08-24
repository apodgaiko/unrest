# VAL-MSR-006 — Recomputable sanitized measurement bundle

**Surface:** generated public result bundle and independent verifier.

**Needs:** all 20 terminal top-level repetition records and every attributed
nested provider invocation from VAL-MSR-002..005.

**Behavior:** Public output contains protocol/product/config identities,
sanitized per-repetition records and nested invocation event/outcome/timing/
token/reported-cost/cache records,
digests, complete denominators, median/MAD, dispositions, failures and limits.
It excludes prompts, source/report bodies, transcripts and raw provider/tool
output. Identical input records serialize identically; independent provider
reruns are not claimed byte-identical.

**Evidence:** Independent recomputation, two renders of identical inputs,
one-field/digest/unknown/zero/proxy mutations, private-canary scan and receipt.
