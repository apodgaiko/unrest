# VAL-WS-002 — Identity-bound patch return

**Surface:** MCP `return_workspace`, matching library call, Git, and patch artifact.

**Needs:** VAL-WS-001.

**Behavior:** Return freezes an identity-bound patch against the exact lease
base, inventories all changed/untracked/deleted paths, validates declared scope,
and appends a patch receipt without changing the parent. Empty, stale,
out-of-scope, protected-path, binary-policy, and mutated-after-return patches
receive typed dispositions and cannot masquerade as integrable.

**Evidence:** Valid/empty/out-of-scope/stale/mutated returns, independent patch
application/hash recomputation, parent tree equality, and receipt mutations.

