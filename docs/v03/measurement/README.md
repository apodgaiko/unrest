# FM-010 baseline measurement

The canonical, installed protocol is
`src/unrest_harness/bundled/measurement/fm010-baseline-v1.json`. This directory
documents its operator contract and is the only product-digest exclusion for
published results.

`unrest measure-baseline` is a manual release checkpoint. Importing Unrest,
ordinary help, and tests never start it. The operator must pass the exact
protocol identifier, a destination below this directory, and
`--confirm-provider-work`.

The protocol runs P1, P2, E1, and E2 five times each, sequentially, from unique
cold private roots. P1 verifies an exact project artifact. P2 verifies exactly
one seeded validator rejection and rework. E1 verifies an exact improving
candidate plus independent evaluation and review without promotion. E2 verifies
independent rejection of a seeded reward hack and proves that no promotion was
applied.

Provider prompts, responses, artifacts, and private timelines are stored with
owner-only permissions under `$UNREST_HOME/measurement-private/`; they are
never copied into this tree. A successful destination contains only
`bundle.json`, with sanitized invocation attribution, timing, token and
reported-cost fields, cache state, exact-oracle digests, full denominators,
median/MAD, and protocol/product/config identities. Model and route identities
distinguish configured values from provider-default or unavailable values;
reasoning effort is a separate field and is never relabelled as a model.
Missing provider telemetry is represented as JSON null, never estimated.
Unknown cost makes the observation invalid because the USD 50 ceiling cannot
then be proven. A task-body marker does not prove cache state: `disabled` must
come from provider/ACP telemetry, otherwise cache state is `unknown` and the
observation is invalid.

Publication fails closed. A protocol or tracked-product drift, failed oracle,
timeout, cancellation, cache hit, cost exhaustion, missing repetition,
unattributed call, noisy case (`MAD / median > 0.15`), unsafe destination, or
private-material scan failure cannot produce a valid bundle. Replacement of an
existing verified `bundle.json` uses an atomic file replace, so interruption
preserves the preceding valid file.

An invalid or noisy run is still retained as `invalid-observation.json` or
`inconclusive-observation.json`. These sanitized, digest-bound files preserve
the expensive denominators for audit, but can never be published as
`bundle.json` and never replace a prior valid bundle.

Example from the frozen release-candidate checkout:

```bash
unrest measure-baseline \
  --protocol fm010-baseline-v1 \
  --destination docs/v03/measurement/results/v0.3.1 \
  --confirm-provider-work
```
