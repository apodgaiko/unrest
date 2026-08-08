# Test guidance

This file adds test-suite rules to the root `AGENTS.md`.

- Prefer hermetic `pytest` tests using `tmp_path`, controlled clocks, and
  in-process or mock ACP surfaces. Live-provider tests must remain explicit
  opt-ins and must not require credentials for focused or milestone checks.
- Prove public behavior, negative paths, recovery, ordering, and deterministic
  bytes. A test for a `known_defect` fixture must keep that classification
  non-normative.
- Do not weaken an assertion, fixture, or expected diagnostic merely to make a
  failure green. Use source inspection only as support when a real CLI, MCP,
  storage, or generated-artifact surface can run.
- Run the narrow test module while iterating and the milestone tier from the
  root guidance before implementation closeout. Run the full suite only at the
  single frozen-candidate release checkpoint.
