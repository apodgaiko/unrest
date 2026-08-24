# VAL-ID-001 — Canonical JSON v1 common grammar

**Surface:** installed `unrest_harness.api` canonical encoder/parser.

**Needs:** frozen independent golden vectors.

**Behavior:** One schema-independent grammar performs strict UTF-8 and NFC
validation, duplicate-key rejection, closed JSON scalar rules, safe integers,
code-point key order, exact escaping, no insignificant whitespace, and exactly
one trailing LF. Schemas validate before encoding; they do not reimplement or
weaken the grammar. Domain-separated SHA-256 preimages use exact kind domains.

**Evidence:** Independent recomputation plus BOM, duplicate, null/float,
exponent, unsafe integer, surrogate, non-NFC, unknown-field, order, escape,
whitespace, domain-replay, and missing/extra-LF mutations.

