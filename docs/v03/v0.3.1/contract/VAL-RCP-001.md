# VAL-RCP-001 — Receipt Encoding v1

**Surface:** installed receipt encoder/parser and persisted canonical bytes.

**Needs:** VAL-ID-001 and independent receipt vectors.

**Behavior:** Receipt Encoding v1 is one closed common record and domain-
separated self-digest encoding shared by all receipt families. It binds issuer,
subject, dependencies, outcome, terminal disposition, artifact references,
deviations, cost completeness, integrity, consumers, and immutable predecessor.
Byte integrity does not authenticate issuer, establish freshness, or authorize
an operation.

**Evidence:** Independent preimage/stored-byte recomputation, family replay,
single-byte/common-field mutations, invalid grammar, missing cost, correction,
and append-only predecessor tests.

