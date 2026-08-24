# VAL-COMP-003 — Install, root, and Python compatibility

**Surface:** no-extra wheel/sdist on Python 3.11, 3.12 and 3.13.

**Needs:** built archives and unrelated temporary install roots.

**Behavior:** Imports, entry points, old configuration, `.unrest/` durable and
`.unrest-runtime/` cursor boundaries, policy/prompt/schema discovery, old
first-project flow, new read-only inspection, restart and fail-closed startup
work without checkout provenance. Missing/corrupt assets fail safely.

**Evidence:** Three compatibility lanes, archive byte/member checks, installed
wheel lifecycle, roots/permissions inspection, missing/corrupt assets and rollback.

