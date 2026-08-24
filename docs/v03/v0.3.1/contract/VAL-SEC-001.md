# VAL-SEC-001 — Private content and public metadata separation

**Surface:** library, CLI, MCP, durable artifacts, handoffs, results, and release assets.

**Needs:** finite public field allowlists and private-artifact classification.

**Behavior:** Prompts, source/report bodies, transcripts, raw provider/tool/
command output, environment dumps, secrets, and secret hashes remain private
artifacts and are referenced publicly only by allowed typed identity/digest.
Public errors, metadata, receipts, handoffs, measurement output, and release
assets contain only allowlisted identifiers, outcomes, timings, token counts,
reported cost, and digests. Public release archives never include private raw
provider data.

**Evidence:** Distinct canaries through success/failure library, CLI, MCP,
stdout/stderr, persistence, handoff, measurement, wheel, sdist, and release
bundle, followed by byte scans and allowlist checks.

