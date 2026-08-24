# VAL-COMP-001 — Exact schema-v1 compatibility

**Surface:** durable data and extracted sdist.

**Needs:** frozen 14-case `tests/test_persistence_schema_v1.py` corpus.

**Behavior:** All 14 cases retain exact outcome. Only absent attempt may adapt;
null, mismatch, replay, malformed, and future records fail before dispatch or
mutation. New v0.3 records use explicit kinds/versions and no heuristic reader.

**Evidence:** Run all 14 cases from safely extracted sdist with package/test
module, cwd and `sys.path` outside checkout, fixture digests and focused probes.

