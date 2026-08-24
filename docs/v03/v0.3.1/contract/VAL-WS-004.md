# VAL-WS-004 — Workspace drainage and cleanup

**Surface:** MCP `cleanup_workspace`, matching library call, Git and subprocess.

**Needs:** VAL-WS-001 and terminal/expired/orphan lease cases.

**Behavior:** Returned, cancelled, expired, crashed and orphaned workspaces drain
owned processes, inventory changes/effects, and remove only owned worktree
resources. Outcomes are released, quarantined, cleanup-failed, or unsettled;
evidence and returned patches outlive cleanup. Retry is idempotent.

**Evidence:** Normal cleanup, live/killed worker, restart orphan discovery,
locked-removal failure, retry, unrelated worktree protection, retained evidence,
and cleanup receipt.

