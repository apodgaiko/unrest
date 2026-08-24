# VAL-EVO-005 — Exact human rollback

**Surface:** MCP `rollback_promotion`, matching library call, Git and rollback record.

**Needs:** VAL-EVO-004 promoted transaction and explicit human rollback grant.

**Behavior:** Rollback targets only the exact predecessor bound by the selected
promotion, validates it, atomically restores it, and appends a rollback receipt.
Latest-known-good, score, chronology, arbitrary revision, candidate, or rollback
receipt cannot choose the target. Failure leaves current accepted state intact;
post-accept receipt recovery never reapplies.

**Evidence:** Successful rollback, wrong/stale target/grant, validation failure,
crash before/after accept, missing receipt recovery, exact trees and effect count.
