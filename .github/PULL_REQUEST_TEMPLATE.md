## Scope and stable IDs

<!-- GOV-FIELD:scope -->

- Summary:
- In scope:
- Out of scope:
- Base SHA:

<!-- GOV-FIELD:task-ids -->

- Task IDs:

<!-- GOV-FIELD:contract-targets -->

- Contract targets:

<!-- GOV-FIELD:decision-ids -->

- Decision IDs: `none`

## Protected surfaces and accountable review

<!-- GOV-FIELD:protected-surfaces -->

- Protected categories: `none`
- Resolved changed paths:

<!-- GOV-FIELD:human-reviewers -->

- Required human/team reviewers: `none`
- Approval evidence: `none`

Agents and providers may implement or evaluate this change. They do not count
as `release-maintainer` or `security-maintainer` approval.

## Evaluation evidence

<!-- GOV-FIELD:evaluation-evidence -->

- Strongest-applicable tiers:
- Commands/artifacts:
- Non-applicable tiers and stable reasons: `none`

## Compatibility and schema impact

<!-- GOV-FIELD:compatibility-schema -->

- Compatibility mode: `unchanged | backward-compatible | hard-cut`
- Schema versions: `none`
- Stable reason code: `none`
- Fixtures:
- Migration and recovery evidence: `none`

## Rollback

<!-- GOV-FIELD:rollback -->

- Trigger:
- Procedure:
- Data recovery:
- Verification:

## Required commit trailers

<!-- GOV-FIELD:trailers -->

Task-ID:
Contract-Targets:
Decision-IDs: none
Protected-Surfaces: none
Human-Reviewers: none
Evaluation-Evidence: none
Schema-Change: none
Rollback-Plan: none

## Verification checklist

- [ ] `uv run ruff check .`
- [ ] `uv run mypy src`
- [ ] `uv run pytest -q`
- [ ] Tests cover positive, negative, boundary, and recovery behavior.
- [ ] Protected paths were resolved through `policy/protected-surfaces.yaml`.
- [ ] Schema changes include versioned fixtures, migration/recovery, and rollback.
- [ ] Exact commands, exit codes, and concrete observations are recorded.
