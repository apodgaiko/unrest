# Experimental scheduling and lifecycle contract

This provider-free research contract implements the accepted v0.4.6 model
slice. Its callable surface is `unrest_harness.experimental_model`. Normal
CLI/MCP dispatch does not import or enable it. `Config.enabled` defaults to
false. These lane records never clear, reopen, or migrate public tasks and
never call ordinary `end_node`.

## Production boundary and admission

The current `MissionCoordinator._select_dispatch_tasks` prioritizes a complete
ready gate-validator lane, then admits isolated disjoint worker batches when
supported, otherwise preserving serial fallback. `_dispatch_isolated_work_batch`
checks admission and integrates the returned patches. The validator-only prose
and method docstring in the task-list contract describe the shared-workspace
fallback too broadly: they are not a prohibition on the already implemented
isolated-worker path. This model changes neither path nor production integration
order. Research streaming and authored integration are separate opt-in behavior.

`admit(specs, base=..., clean=..., isolated_dispatch=..., config=...)` accepts
one to four lanes in **authored order**, with a pinned 40-character Git SHA,
clean base, explicit normalized relative write paths, pairwise disjoint scopes,
no repeated declared shared resources, and enabled integration settings.
Missing scopes, absolute/dot/traversal/Git-internal/glob paths, shared resources,
unsupported dispatch, dirty/unpinned base, disabled experiment, and insufficient
initial/final budget return bounded reason codes and no state. The caller
supplies facts; this pure model does not inspect Git, resolve symlinks, discover
undeclared resources, or establish OS isolation. Those are runtime admission
proof obligations. Rejection does not select or mutate a normal task.

## State and deterministic selection

`State` and all nested records are immutable values. Each function returns a
new value. Controlled time is nonnegative integer monotonic seconds, initially
zero. No environment, clock, filesystem, process, network, provider, or store is
read or written by the model. Zero-based turn ordinals increase across the
whole lane; generation rotation never resets history or the correction flag.
Candidates are sealed revision numbers, not claims about file bytes.

The first authored lane owns the only reusable W0/V0 pair for this episode.
Finish order cannot transfer that entitlement. Other lanes use fresh sessions
for the same bounded correction/recheck workload; all fresh session identities
are distinct. Disabling reuse uses that fresh control for every lane.

`ready` orders recheck, authorized correction, first validation, already-admitted
work (including W1), then unrelated admissions; every tie uses authored order.
`reserve_next` reserves at most one turn. Call until no change to fill available
capacity. The maximum active count is `min(config.capacity, 4)`; reservations
occupy active slots before send. Streaming validation starts on the worker's
seal without waiting for other workers. The barrier control waits for every
initial worker's seal before first validation, without changing coverage.

The reusable pair reserves **two parking slots before W0 admission** and keeps
them until pass, rotation, or closure. Active sessions consume their reserved
parking entitlement without counting as parked. Only suspended sessions count
as parked. Parking never exceeds four; the current one-pair topology reaches
at most two. Fresh sessions close on completion and do not park. Consequently
valid admission cannot exhaust parking midway through a pair. A configured
parking cap below two with reuse enabled rejects admission; it must not create
a permanently delayed lane. Active pressure returns unchanged state until a
turn completes or reaches its deadline; it does not evict or reassign a pair.

## Transition table

| Completed phase | Outcome | Next phase |
| --- | --- | --- |
| W0 | sealed | V0, candidate 0 |
| V0 | pass | passed; close sessions |
| V0 | correctable defect | one correction |
| correction | sealed | full recheck, candidate 1 |
| full recheck | pass | passed; close sessions |
| full recheck | second defect | close pair; W1 |
| W1 | sealed | fresh V1, next candidate revision |
| V1 | pass | passed; close sessions |
| V1 | any defect | attention; no further generation |
| any active phase | other failure | attention; no correction |

Every validator receives all original lane targets and the current sealed
revision. A reusable lane has at most six early turns: W0,V0,W0,V0,W1,V1.
Fresh controls retain the same six-turn ceiling with distinct sessions.
W1/V1 are always one-shot. Generation rotation keeps the last sealed revision;
unsealed work cannot become integration input. Target coverage and every
failure reason survive pass, rotation, stop, serialization, and restart.

## Reservation, completion, and recovery

`reserve_next` appends a `reserved` turn and consumes its turn budget before
any transmission. Persist `dump_state(result)` **before** sending. Then use
`transmission(..., "sent")`, `transmission(..., "acked")`, and `complete`.
The correction flag is consumed at reservation, not acknowledgment. The model
has no automatic retransmission and conservatively offers no reservation refund.
An explicit `uncertain` transmission closes the lane into attention.

`dump_state` returns canonical JSON plus a trailing newline. `load_state`
validates it and applies controller restart: every unfinished reserved/sent/acked
turn becomes uncertain, even a crash immediately before send. Its allowance
remains consumed. Idle admitted unfinished lanes become nonresumable. Passed
lanes remain passed. Repeated reload cannot manufacture an unused allowance.
This is a persistence protocol model, not an atomic filesystem journal.

An active completion must match its exact ordinal and acknowledged status.
Late/duplicate completions, wrong-role outcomes, and invalid transmission order
raise bounded `ValueError`s without changing the old immutable state.
Simulated continuation retains session and managed-process generation identity;
these labels do not prove live ACP reuse or stale-credential denial.

`advance(state, now)` expires parked leases at `parked_at + 3600 <= now` and
active turns at their reserved deadline (at most 300 seconds). It rejects clock
reversal. Expiry is fail-closed at the boundary. `recover_fresh` is an explicit
caller decision, allowed only after expiry/restart, with no active cohort work,
no stop/budget halt, generation zero, and enough remaining budget for W1/V1 plus
final checks. It preserves history and uses only generation one. Ambiguous send
and other failures have no recovery shortcut. Restart never resurrects a lease.

## Attention, stop, and projection

Any blocking lane stops new cohort dispatch and integration. Parked sessions
close immediately. A merely reserved turn cannot transition to `sent` after
stop, sibling attention, budget exhaustion, or TTL expiry: `transmission` raises
`ValueError("dispatch_halted")` without changing its consumed allowance. Such
reservations retain their active slots until deadline cancellation or restart;
they cannot be refunded or retried. Only turns already marked `sent` may
acknowledge and finish under their original bounded deadlines; they cannot
repark after halt. Callers must serialize send/halt transitions; this API does
not accept a late first-send record as proof of a pre-halt dispatch.
`stop` and budget exhaustion
retain incomplete disposition, even if a racing completion reports pass.
The controller must advance controlled time to model cancellation at deadlines.
Cancellation is logical here, not a process-kill claim.

Initial admission reserves at least two separate fresh final-check turns;
early work cannot consume them. Exhaustion before correction/recheck/rotation
halts dispatch and preserves incomplete targets and dissent. No final validator
or integration is executed by this model. `projection` exposes authored
integration order only when **every** lane passed and no halt/block remains.
The final gate always stays pending. It includes all original targets and lane
history; early passes never act as final-gate evidence.

Normalized projections exclude clocks and global completion interleaving, but
retain candidates, coverage, generation, per-lane decisions and dissent. Causally
equivalent completion permutations produce identical canonical bytes. Races
that change causal outcomes can retain different lane histories; stop/expiry
still prevents integration in every ordering.

## Independent oracle and runnable surface

`tests/fixtures/experimental_model/scenarios.json` is hand-authored from this
transition table and the accepted flow protocol; it does not import the model
or compute expected results. It fixes pass/correction/rotation/attention turn
sequences, exact counts, revision numbers, and straggler/equal/long-validator
start traces for barrier and streaming. Its independent future file fixture is
`lane_a.txt: base\n -> A\n`, `lane_b.txt: base\n -> B\n`; this revision-only model
does not claim to write or validate those bytes.

A minimal callable probe (no provider credentials required):

```python
from unrest_harness.experimental_model import (
    Config, LaneSpec, admit, complete, projection, reserve_next, transmission,
)

result = admit(
    (LaneSpec(id="lane-a", writes=("lane_a.txt",), targets=("VAL-A",)),),
    base="5a3d568aa881c746432b7034597bbb8a1ffe025f",
    clean=True, isolated_dispatch=True, config=Config(enabled=True),
)
assert result.state is not None
state = result.state
for ordinal, outcome in enumerate(("sealed", "pass")):
    state = reserve_next(state)  # Persist dump_state(state) before a real send.
    state = transmission(state, "lane-a", ordinal, "sent")
    state = transmission(state, "lane-a", ordinal, "acked")
    state = complete(state, "lane-a", ordinal, outcome)
print(projection(state))  # integration_ready, final_gate=pending
```

Run `uv run pytest -q tests/test_experimental_model.py`. The module also
exhaustively explores finite four-lane completion orders at capacities 1,2,3,4,8
and parking caps 2,4; checks every priority pair/tie, authored entitlement under
contention, TTL/reload/crash windows, bounded drain, budget before recheck,
sibling pass/failure/stop and cancellation/expiry/completion permutations, and
production-free execution in a disposable root. Ordinary compatibility is
checked through the existing coordinator test modules. Independent validators
can construct their own inputs and call the library without the test helpers.

The model proves symbolic scheduling/lifecycle behavior only. Actual sealing,
Git integration, atomic durable writes, resource isolation, ACP continuation,
MCP authority, descendant cleanup, and independent final validation belong to
later disabled-by-default runtime slices and require their own real evidence.
