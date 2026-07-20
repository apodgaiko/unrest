# VAL-UPSTREAM-SUITE-001: Upstream suite and protected assets are preserved

Surface: parity and artifact.
Needs: immutable upstream tree `a21c071` and the integrated candidate.
Behavior: Every upstream test and protected license, CI, security, contribution,
and package file remains unless an inspected compatibility edit preserves or
strengthens its original assertion; deleted test nodes cannot create a pass.
The closed protected-asset set is `.gitignore`, `README.md`, `LICENSE`,
`SECURITY.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`,
`.github/ISSUE_TEMPLATE/bug_report.md`,
`.github/ISSUE_TEMPLATE/feature_request.md`,
`.github/PULL_REQUEST_TEMPLATE.md`, and `zenith/pyproject.toml`.
Evidence: Machine-readable name/status diff, upstream-versus-candidate test-node
inventory, review of every modified upstream test, and complete candidate suite.
Oracle: commit `a21c071`.
