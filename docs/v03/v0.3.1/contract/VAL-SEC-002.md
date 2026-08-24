# VAL-SEC-002 — Local authenticated custody and export boundary

**Surface:** installed verifier/export API and durable local custody chain.

**Needs:** VAL-RCP-002; no accepted detached-signature suite.

**Behavior:** Unsigned records may be authoritatively consumed only under
verified local custody by exactly `cleanup_authority`, `evaluation_authority`,
`evidence_store`, `maintainer`, `parent_integration_authority`,
`promotion_authority`, `reviewer`, `rollback_authority`, `workspace_authority`,
and `workspace_return_authority`, subject to each receipt family's narrower
consumer set. Export to any third-party authoritative consumer is rejected with
`signature_suite_unsupported`; integrity-only export is labeled
non-authoritative. v0.3.1 adds no crypto dependency and offers no signed export.

**Evidence:** Same-custody accepted cases, wrong local consumer, copied-root/
issuer substitution, unsigned third-party rejection, non-authoritative export,
dependency inspection, and installed no-extra verification.

