# Evaluation artifact guidance

This file adds evaluation rules to the root `AGENTS.md`.

- Evaluation manifests, fixtures, and reports are evidence or oracles only
  when their classification says so. `observed_legacy` records observation;
  `known_defect` must never become an acceptance oracle.
- Generation must be provider-independent where declared, sort inputs before
  serialization, freeze or inject volatile values, and produce identical bytes
  under reversed enumeration.
- Never persist credential values, prompts, private source bodies, unrelated
  environment values, or raw conversational traces.
- Historical evaluation material must not be reintroduced as an installed
  baseline generator or a repository-check prerequisite.
