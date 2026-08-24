# VAL-EVO-001 — Campaign freeze

**Surface:** MCP `open_campaign`/`inspect_campaign`, matching library calls, and durable campaign record.

**Needs:** VAL-ID-002 and frozen workload/evaluator/reviewer policies.

**Behavior:** Opening freezes exact accepted point, workload, oracle/tests,
author policy, evaluator policy, reviewer policy, route/provider configuration,
environment, budget, seed, stopping rule, promotion rule, and protected paths
before any candidate is admitted. Later input mutation creates a new campaign;
it never edits the freeze.

**Evidence:** Real open/restart/inspect plus one-field mutations of every frozen
input, candidate-before-freeze rejection, and canonical campaign identity.

