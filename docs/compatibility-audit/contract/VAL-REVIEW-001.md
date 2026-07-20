# VAL-REVIEW-001: Terminal-review runtime failures are recoverable

Surface: background runtime and artifact.
Needs: clean, negative, crashing, and retrying reviewer fixtures.
Behavior: A reviewer crash persists a failed review and enters attention; a
negative verdict remains attention; neither seals the mission. After explicit
attention resolution, a later clean verdict can seal done while earlier review
artifacts remain.
Evidence: State and artifact assertions for all four paths, including upstream
stderr-drain regression coverage.

