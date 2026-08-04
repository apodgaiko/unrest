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

- Required maintainer reviewer: `none`
- Approval evidence: `none`

For a protected change, use the repository owner acting as the one human
`maintainer`; the owner may self-approve and no second account or team is
required. Agents and providers may implement or evaluate the change, but they
cannot satisfy accountable review. This records repository policy only and
does not claim GitHub identity enforcement.

For a protected commit, record exactly `Human-Reviewers: maintainer`.

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
