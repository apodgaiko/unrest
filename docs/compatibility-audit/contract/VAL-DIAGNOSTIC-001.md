# VAL-DIAGNOSTIC-001: Missing worker handoffs retain bounded diagnostics

Surface: background runtime and artifact.
Needs: agent-message stream with no `end_node` handoff.
Behavior: The synthesized failed handoff includes the most recent diagnostic
tail, omits older content beyond 4,000 characters, and persists no more than a
2,000-character normalized diagnostic excerpt.
Evidence: Boundary-length tests, persisted JSON inspection, and an ACP shim flow
that ends without a handoff after emitting recognizable head and tail markers.

