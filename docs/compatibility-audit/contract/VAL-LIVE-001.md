# VAL-LIVE-001: Snapshot content matches stored project state

Surface: CLI and artifact.
Needs: disposable active, attention, terminal, partial, corrupt, and legacy
project buckets.
Behavior: Snapshot data accurately attributes project, mission, task, contract,
attention, attempt, evidence, and recent activity state; unreadable or invalid
state is surfaced rather than silently represented as an ordinary empty state.
Evidence: Independent file-to-output comparisons for each fixture and explicit
error annotations for corrupt/unreadable cases.

