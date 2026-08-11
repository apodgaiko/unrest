# Batch 0.5 review — verification of the revised package

Status: reviewer notes; non-normative; recorded 2026-08-09 (second pass)
against the revised drafts (mtimes 23:11–23:17) and the revised ADR-0002.
Companion to `review-notes-2026-08-09.md`, which the README correctly treats
as immutable input.

## Verdict

The revision resolves all three blocking findings and all six major revisions
from the first pass, and the three points of pushback are each accepted as
correct. The package is now, in this reviewer's opinion, ready for the
maintainer's acceptance decisions as listed in the README, subject to one
residual risk flag and two minor notes below. No new blocking issue was
introduced by the revision.

## Finding-by-finding verification

- **B1 (inventory plumbing unbuilt)** — resolved. `security-contract.md`
  "Required new inventory plumbing" names the coordinator/CLI gap explicitly
  and charges the work to the capability budget; new LEAN-SECURITY-005 adds
  the right invariant ("a missing inventory is not treated as permission to
  rediscover secrets from the payload"); the measurement guardrail orders it
  correctly ("inventory propagation … must be proven before payload-derived
  inference is deleted"), and the slice-2 topology's two green internal
  milestones (wire first, compact second) encode the same ordering.
- **B1 corollary (unsafe `*` empty inventory)** — resolved by a design better
  than either option the first pass offered: `*` is forwarding authority only,
  never credential identity; both profiles retain a finite provider/role
  credential set that stays inventoried, redacted, and terminal-excluded
  (LEAN-SECURITY-007, evidence item 11). Accepted.
- **B2 (runtime cut disguised as assurance cut)** — resolved. The contract now
  splits "Repository assurance deliberately removed" from "Runtime security
  behavior deliberately withdrawn," requires inversion rather than silent
  deletion of the transformed-secret tests, and the ADR Consequences split
  compatibility/runtime cuts from assurance cuts.
- **B3 (slice-order CI break)** — resolved. Baseline code, its four bundled
  sink anchors, and affected repository-contract sections land atomically;
  "every intermediate slice must pass the then-current `check-repository`" is
  now stated in the topology and the ADR slice-dependency bullet.
- **Majors 1–6** — all verified present: replace-not-rehome for the
  governance→checker imports with counted replacement LOC (plus new
  LEAN-REPOSITORY-001); ledger rows for `test_documentation_contract.py`,
  `test_repository_contract.py`, and the AGENTS.md/registry edits; seventeen
  sinks including SEC-SINK-WORKSPACE-WRITE, SEC-SINK-CODEX-CONFIG, and
  SEC-SINK-DIAGNOSTIC (covering MCP `ToolError`); terminal-credential removal
  labeled a behavior cut with before/after evidence; the sub-8-character
  token-boundary guard retained and specified (`KEY`/`MONKEY`); dependency
  rationales split by actual consumer with `types-jsonschema` added.
- **Minor items** — fd-number-in-argv wording fixed; the undrained MCP child
  pipes were promoted to a first-class behavior (LEAN-PROVIDER-005, ledger
  row, ADR §11) — a better outcome than the first pass asked for; wheel
  provenance now requires rebuilding both reference and candidate; the
  latency-noise discipline paragraph (interleaved samples, 10%-plus-range
  threshold) is new and good measurement hygiene.

## Pushback assessment — all three accepted

1. **−30% maintained floor is independent**: correct. At the production floor
   landing point (15,438), tests/tools must shed 5,414 lines while whole-file
   deletions supply only 3,902; the first pass's "comfortable" framing assumed
   a near-stretch production landing. Measuring both floors independently at
   every checkpoint is the more rigorous protocol stance.
2. **The third child provider as a maintainer-approved compatibility hard cut**: correct
   framing — documented and tested surface, even without a consumer.
3. **Unsafe `*` as forwarding authority with a retained finite credential
   set**: accepted; stronger than the first pass's either/or suggestion.

## Residual risk flag (not blocking)

The 2,500-line capability ceiling is now defined as *net candidate code
including all new replacement work* — inventory threading, seventeen-sink
handling, diagnostics, and pipe lifecycle. Today's retained runtime block
inside `capability_policy.py` is roughly 2,100 lines before any new plumbing
is added, so the budget assumes the retained parts also shrink materially
during the rewrite (command-matrix simplification, transform-path removal
help). That is plausible but unproven; the stop rule will fire if it fails,
which is the designed outcome — the maintainer should just approve the floors
knowing slice 2 may legitimately return to scope review rather than deliver.

## Minor notes

- `security-contract.md` "Resolved review decisions" reads as settled while
  the README still (correctly) lists the same items among "Review decisions
  required." Suggest retitling to "Proposed resolutions for review" to keep
  the authority line clean.
- The README review order could add this verification file after item 6 when
  convenient; content-wise nothing else is outstanding from this reviewer.
