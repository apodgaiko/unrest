# Worker Assignment

## Assignment

{{ assignment_body }}

## Context

Read these before editing when they exist:

- Assigned skill: `{{ skill_name }}`
- Operational guidance: `{{ agents_path }}`
- Project memory: `{{ memory_path }}`

## Contract Targets

Read and satisfy these contract files before editing:

{{ contract_target_paths }}

## Prior Work

Prior attempt reports, if relevant:

- Attempts directory: `{{ attempts_dir }}`

Treat prior reports as claims, not truth. Verify the current workspace yourself.

## Finish

Call `end_node(done, report, request_attention)` exactly once when finished.
