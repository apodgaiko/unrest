# Validation Assignment

## Assignment

{{ assignment_body }}

## Required Context

Read these before validating when they exist:

- Assigned skill: `{{ skill_name }}`
  Load and follow this validation procedure.
- Operational guidance: `{{ agents_path }}`
  Constraints, setup rules, and project-specific operating guidance.
- Project memory: `{{ memory_path }}`
  Reusable project facts, oracle/setup notes, decisions, and known risks.

## Contract Files

Audit these assigned contract files:

{{ contract_target_paths }}

## Assertions To Audit

{{ contract_assertions }}

## Prior Work

Prior attempt reports:

- Attempts directory: `{{ attempts_dir }}`

Find the latest worker report for each assigned target in this directory when
present. Treat worker and validator reports as claims, not truth. Re-run or
independently verify before passing any target.

## Output Paths

- Evidence directory: `{{ evidence_dir }}`
  Save raw validator evidence and artifacts here.
- Regressions directory: `{{ regressions_dir }}`
  Write failed or unverifiable target entries here.

## Finish

Call `end_node` once with one verdict item for each assigned contract target.
