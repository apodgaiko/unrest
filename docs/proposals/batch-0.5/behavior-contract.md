# Lean Core retained-behavior contract

Status: accepted 2026-08-09 as the retained-behavior scope for ADR-0002.

## Evidence rule

Every accepted behavior below must map to at least one executable test through
the real CLI, MCP, controller, storage, installed-artifact, or provider-adapter
surface. Source inspection may support but cannot replace real-surface evidence.
The eventual contract-test change may add test lines; test reduction is judged
after withdrawn guarantees and their tests are removed.

The candidate mapping and individual results are recorded in
`docs/release/lean-core-v0.2-evidence-crosswalk.json`. Its focused test collects
and executes every unique mapped pytest node; the mapping does not substitute
for the mapped behavioral test passing.

## Lifecycle

### LEAN-LIFECYCLE-001: Create a project

Surface: MCP and persistence.
Behavior: `start_project` creates one project and mission in planning state,
persists the original brief, returns the canonical envelope, and does not place
mission state in the target workspace.
Failure: invalid workspace or configuration fails without a partial project.
Evidence plan: temporary workspace plus temporary Unrest home through the real
controller/server call.

### LEAN-LIFECYCLE-002: Submit a contract-backed plan

Surface: MCP.
Behavior: `submit_plan` accepts an acyclic task list only when every declared
assertion has exactly one live work owner and task type/body/skill/dependency
rules hold.
Failure: missing contract files, duplicate ownership, unknown dependencies,
cycles, or malformed tasks fail without changing the accepted plan.
Evidence plan: valid plan plus one independently failing case per rule family.

### LEAN-LIFECYCLE-003: Execute work, validation, and gates

Surface: controller and persisted task state.
Behavior: work dispatches before its validators; validators independently
report per target; gates clear only when every required validator passes every
target.
Failure: missing evidence or validator dissent leaves the target unsealed.
Evidence plan: one complete success flow and one dissent flow.

### LEAN-LIFECYCLE-004: Repair after failed validation

Surface: MCP attention flow.
Behavior: a failed validation creates bounded attention; one complete patch
decision can add, supersede, or cancel eligible tasks and resume dispatch with
dependency edges rewritten consistently.
Failure: incomplete decisions, invalid patches, or mutation of cleared/running
tasks fail without partial application.
Evidence plan: failed validation, replacement work, revalidation, and closure.

### LEAN-LIFECYCLE-005: Terminal review controls closure

Surface: MCP and terminal-reviewer handoff.
Behavior: quiescent work is not done until terminal review succeeds. A failed
or timed-out review leaves the mission unsealed and can be retried through the
documented attention path.
Failure: `end_mission` cannot bypass runnable work, validators, or gates.
Evidence plan: success, failure/retry, timeout, and premature-close cases.

### LEAN-LIFECYCLE-006: Abort is explicit and terminal

Surface: MCP and persisted state.
Behavior: explicit abort records a bounded reason and terminal state while
retaining forensic task and attempt records.
Failure: terminal projects do not resume ordinary mission execution.
Evidence plan: abort during planning and during attention.

## Persistence and restart

### LEAN-PERSIST-001: Durable and runtime roots remain separate

Surface: filesystem artifact.
Behavior: durable mission records stay under `.unrest/`; orchestrator cursors
stay under `.unrest-runtime/`; the workspace receives only documented host
discovery shims.
Evidence plan: exact tree inventory after creation, work handoff, and closure.

### LEAN-PERSIST-002: Text and JSON writes are atomic

Surface: storage library and filesystem.
Behavior: normal persistence writes a sibling temporary file and atomically
replaces the target, leaving deterministic UTF-8 text/JSON and no accepted
partial cursor.
Failure: interrupted writes preserve the preceding complete generation.
Evidence plan: replacement spy plus injected failure before replacement.

### LEAN-PERSIST-003: Current schema-version-1 projects remain readable

Surface: controller and storage.
Behavior: v0.2 reads and resumes representative current project states from
schema version 1 without rewriting them merely for inspection.
Failure: malformed or unsupported future states fail closed with bounded
diagnostics.
Evidence plan: frozen planning, running, attention, quiescent, and terminal
fixtures produced by current `main`.

### LEAN-PERSIST-004: Restart reconciles landed handoffs

Surface: controller restart.
Behavior: after a child has landed a valid handoff but before the coordinator
has advanced, restart observes it once, records the appropriate transition,
and does not redispatch duplicate mutable work.
Evidence plan: restart between handoff replacement and coordinator step.

### LEAN-PERSIST-005: Missing or malformed handoffs require attention

Surface: controller restart.
Behavior: a missing, malformed, or mismatched handoff is classified truthfully
and routed to bounded attention rather than silently treated as success.
Non-goal: automatic recovery or liveness inference from file age.
Evidence plan: missing, malformed, wrong-task, and stale-attempt fixtures.

## Scheduling

### LEAN-SCHEDULE-001: Shared-checkout mutable work is single

Surface: coordinator selection.
Behavior: at most one mutable work task is selected before persistence in a
shared checkout, even when several work tasks are ready.
Evidence plan: multiple-ready authored-order matrix and restart repetition.

### LEAN-SCHEDULE-002: Validator-only batches may be independent

Surface: coordinator selection.
Behavior: ready validators may be selected together only when no mutable work
is selected and their dependencies are cleared; authored order remains
deterministic.
Evidence plan: capacity, dependency, and mixed work/validator matrices.

### LEAN-SCHEDULE-003: Gates remain authored and evidence-driven

Surface: coordinator/gate evaluation.
Behavior: ready gates follow authored order and never infer a pass from task
completion alone.
Evidence plan: multiple-ready gates, missing target verdict, and dissent.

## Provider and authority configuration

### LEAN-PROVIDER-001: Claude safe and unsafe modes are explicit

Surface: generated provider configuration and adapter environment.
Behavior: safe mode cannot inherit unmanaged bypass settings; unrestricted
settings appear only after the exact unsafe-development opt-in.
Evidence plan: absent, safe, exact unsafe, malformed, and conflicting inputs.

### LEAN-PROVIDER-002: Codex safe and unsafe modes are explicit

Surface: generated provider configuration and adapter environment.
Behavior: safe mode emits workspace-write/on-request semantics and removes
unrestricted ambient controls; danger-full-access/never requires exact opt-in.
Safe child configuration is constructed from an explicit supported-field
allowlist and never copies credential aliases from ambient `CODEX_CONFIG`.
Evidence plan: absent, safe, exact unsafe, malformed, and conflicting inputs.

### LEAN-PROVIDER-003: Unsupported combinations fail before spawn

Surface: startup.
Behavior: unsupported provider, role, profile, or bounded configuration values
fail closed before an MCP or ACP child starts and without echoing rejected
values.
Evidence plan: subprocess-spawn trap and value-absence assertions.

### LEAN-PROVIDER-004: Environments are explicit projections

Surface: ACP adapter and terminal process creation.
Behavior: adapter environments contain only named forwarded values, selected
provider/role credentials, and internal runtime values in safe mode. Explicit
unsafe mode may broadly inherit adapter variables, but its finite known
provider/role credential set remains distinct. Terminal children receive none
of that finite credential set by default and cannot inject undeclared
environment.
Compatibility cut: current `main` supplies role credentials to terminal
children; v0.2 intentionally stops doing so.
Evidence plan: ambient-sentinel and provider/role matrix, including a
before/reference case where the terminal receives a sentinel and a candidate
case where it does not.

### LEAN-PROVIDER-005: MCP child pipes cannot deadlock dispatch

Surface: worker/reviewer MCP subprocess lifecycle.
Behavior: child stdout and stderr are drained, redirected, or otherwise
bounded for the entire child lifetime, including startup and shutdown.
Failure: output above the platform pipe capacity cannot indefinitely block an
otherwise responsive worker or terminal reviewer.
Evidence plan: chatty mock child exceeding the pipe capacity plus bounded
completion and shutdown cases.

## Security boundaries

### LEAN-SECURITY-001: Filesystem callbacks enforce canonical roots

Surface: ACP read/write callbacks and terminal cwd validation.
Behavior: read and write authority remain separate; traversal, absolute outside
paths, escaping symlinks, and nonexistent-parent escapes fail; valid new
in-root parents work for authorized writers.
Limitation: this does not confine arbitrary subprocess side effects.
Evidence plan: path matrix with an external sentinel.

### LEAN-SECURITY-002: Exact known credentials are redacted

Surface: every sink named in `security-contract.md`.
Behavior: each non-empty credential selected from the finite provider/role
credential set is removed from structured keys, structured values, and streamed
output across every split in safe and explicit unsafe modes. Token-like values shorter than eight
characters require token boundaries (`KEY` is removed but `MONKEY` is not);
longer or non-token-like values are removed wherever embedded.
Limitation: explicit unsafe mode may broadly inherit undeclared ambient values;
those values are outside the guarantee unless named in the finite credential
set. Wildcard forwarding is not credential identity.
Evidence plan: per-sink sentinel matrix and all split points, including short
standalone/structured/semicolon-delimited values, preservation of `MONKEY`,
`KEY-label`, and `.KEY`, plus long embedded and overlapping values.

### LEAN-SECURITY-003: Inventory transport is bounded and non-persistent

Surface: adapter-to-MCP inherited file descriptor.
Behavior: the exact-value inventory uses the bounded private inherited-FD
channel. The descriptor number may appear in argv; credential values are
absent from argv, ordinary environment, logs, status, and persisted artifacts.
Evidence plan: process inventory plus crash/restart inspection.

### LEAN-SECURITY-004: Reduced secret claim is explicit

Surface: documentation and black-box output.
Behavior: Lean Core does not claim detection of unknown, partial, encoded,
hashed, encrypted, reordered, or otherwise transformed secrets. A transformed
sentinel that current `main` redacts may remain visible in v0.2; this is an
intentional runtime security behavior cut.
Evidence plan: one exact sentinel is removed and one documented transform is
not, proving the implementation and documentation describe the same boundary.

### LEAN-SECURITY-005: Orchestrator-owned writers receive the safe inventory

Surface: coordinator, storage, CLI/config/bootstrap writers, and process-local
inventory ownership.
Behavior: the safe-mode exact-value inventory is explicitly threaded to every
orchestrator-owned attempt mirror, terminal-review mirror, runtime cursor, and
CLI/config/bootstrap write that can contain child- or environment-derived content. A
missing inventory is not treated as permission to rediscover secrets from the
payload.
Failure: an orchestrator path that can persist untrusted content cannot call a
protected writer without the inventory in scope.
Evidence plan: reflect one selected credential through a worker handoff and a
terminal review, have the orchestrator write the JSON/Markdown mirrors, and
prove it is absent from both trees and CLI output.

### LEAN-SECURITY-006: Child-supplied writes and errors are protected sinks

Surface: ACP filesystem write callback, structured provider configuration,
diagnostic exceptions, and MCP `ToolError` payloads.
Behavior: child-supplied workspace bytes are redacted before Unrest writes
them; safe structured provider configuration excludes credential aliases;
diagnostic and `ToolError` message/details are value-free or redacted before
crossing the named boundary.
Evidence plan: one sentinel through each surface, plus ordinary neighboring
content proving the narrow transform does not erase unrelated text.

### LEAN-SECURITY-007: Unsafe forwarding does not erase known credentials

Surface: unsafe role-policy resolution and child environment construction.
Behavior: `*` authorizes broad unsafe forwarding/inheritance but never acts as
a credential name. Each supported provider/role retains a finite known
credential-name set, whose values enter the redaction inventory and remain
excluded from terminal children in both profiles.
Limitation: undeclared ambient values inherited in explicit unsafe mode remain
outside the exact-known-value guarantee.
Evidence plan: unsafe environment containing one finite known credential, one
ordinary value, and one undeclared secret-like value; verify adapter delivery,
finite inventory, terminal exclusion, protected-sink redaction, and the stated
limitation.

## Repository development surface

### LEAN-REPOSITORY-001: The narrow repository check is finite

Surface: real `unrest check-repository` command and import graph.
Behavior: the command lazily loads a small checker for required guidance,
explicitly retained important references, basic component ownership, packaged
role-policy loadability, and installed-wheel CI wiring. Results and diagnostics
are deterministic and bounded.
Non-goals: baseline regeneration, broad root-schema validation, governance DSL,
CI-topology proof, generated evidence comparison, or recursive self-protection.
Evidence plan: real-command success plus one mutation per retained duty, an
import-edge assertion for ordinary CLI commands, and absence of every withdrawn
baseline/governance/static-capability dependency.

## Packaging and operation

### LEAN-PACKAGE-001: Installed wheel works independently of source

Surface: installed artifact from an unrelated working directory.
Behavior: the wheel exposes supported CLI and MCP entry points, loads packaged
runtime policy, starts safely, and executes one complete provider-independent
mission without importing the source checkout.
Evidence plan: build, archive inspection, import provenance, safe startup, and
mock-dispatch lifecycle.

### LEAN-STATUS-001: Compact status reports one project truthfully

Surface: CLI text and JSON.
Behavior: schema version 2 reports observation time, project/mission ID,
persisted and derived state, attention count, running/runnable/failed task IDs,
last runtime-change age, and bounded relevant failure/anomaly codes without
writing or exposing bodies, reports, credentials, environment, or workspace
paths.
Evidence plan: representative current states plus before/after tree inventory.

### LEAN-STATUS-002: Compact status aggregates projects safely

Surface: `observe-project --all [--strict]`.
Behavior: projects and bounded failures are deterministically ordered, one bad
project does not suppress good projects, and `--strict` retains its nonzero
degraded-collection behavior.
Evidence plan: empty, mixed valid/corrupt, stale, and all-failed roots.

### LEAN-STATUS-003: Status has no authority

Surface: CLI and import graph.
Behavior: observation performs no persistence, dispatch, recovery, gate,
attention, scheduler, or liveness action and makes no completion prediction.
Evidence plan: mutator traps, import-edge check, and repeated real CLI reads.

## Explicit non-goals

- Autonomous wake, dispatch, recovery, or retries.
- Evidence/gate-result reuse, ETA, or promotion decisions.
- Concurrent mutable workers in one checkout.
- Network-denial enforcement or kernel-level subprocess confinement.
- Compatibility for removed public development commands or observer schema 1.
- Preservation of unpublished Python internals.
