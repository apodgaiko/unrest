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

- Controlled experimental transport must be selected explicitly with the internal
  `ControlledTransport` and exact fixture/interpreter pins. Omitted selection and
  native pin-refusal tests retain native construction with zero launches.
- Preserve backend-first/adapter-second registration, real Bridge and private
  preflight faults, authenticated `complete_turn`, ledger ACK/uncertainty and
  production sealing before independent validation. ThreadObservation config
  framing/eligibility/typed-ID/retirement and ProviderConfig private admission
  are separate supporting surfaces, not inference allowance or generic process
  observations. Native adapter conversion remains UNVERIFIED.
- Finite child-command registrations must include exact bytes, argv templates,
  permitted owned-root substitutions and exit/wait proof. Nested test/role/helper
  processes must inherit the certification guard; unknown or forbidden attempts
  fail the checkpoint even when caught. Keep real-provider opt-ins disabled.

Use `tests.controlled_transport.controlled_transport()` explicitly at controlled
owner, campaign and probe construction, including source executed in isolated
children. Native byte/pin refusal constructors keep omitted transport. Preserve
original collected node IDs, literal parameter decorators, assertion and refusal
contexts when changing selection; an incomplete guard or failed local oracle
cannot establish source-checkpoint readiness.

The controlled `mock_provider_session_acp.py` adapter owns its child wait. Its
SIGTERM handler suppresses recursive entry, retains bounded terminate/wait then
kill/wait cleanup, and restores SIG_DFL before signaling itself. The adapter must
remain externally signal-terminated (-15); child markers or PID absence do not
substitute for a numeric owned wait. Production provider group termination and
the original 0.3-second timeout oracle remain unchanged.
