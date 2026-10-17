# Controlled speed runner v2

The active provider-free compatibility runner is `tools/v04_speed_runner.py`.
Use `tests/fixtures/v04_speed_workloads.v2.json` with the packaged
`src/unrest_harness/schemas/v04-speed-result.v2.schema.json`. The workload and
result identities are `unrest.v04.speed-workloads.v2` and
`unrest.v04.speed-result.v2`; the revised row is `improvement-v2`. Task and project
row identities remain v1 because their workloads are unchanged.

The improvement row starts from deterministic prepared state: a valid frozen
campaign, its already admitted candidate, and a returned lease bound to the same
owner, accepted revision, patch and candidate identity. Preparation and evidence
hashing are outside the measured invocation regions. The primitive arm inspects
the campaign and lease, evaluates, reviews, then inspects the campaign again.
The adapter arm runs the actual `run_improvement` with its freeze and provenance
checks intact. Four primitive public boundaries compare with one adapter boundary.

Improvement requests copy dissent declarations into an immutable tuple at
construction. Each invocation sorts that tuple once and checks the expected
dissent and candidate provenance in both initial and final snapshots. Final
candidate, evaluation and review identities must still equal the observed
records. Reusing request-derived expectations establishes no timing benefit.

Both arms use the same narrowly scoped controlled workspace inspector. It returns
the prepared lease without constructing a git-backed WorkspaceManager. This is
controlled adapter composition evidence, not real workspace construction, lease
admission, provider performance or campaign-opening performance. Evaluation and
review still perform 16,384 and 8,192 digest rounds. Sample counts, timing limits,
raw-byte hashing, archive reopening and provider/network/subprocess guards remain
unchanged. Passing thresholds is no performance adoption claim, especially across
the changed workload revision.

The source-test fixture executes its five predefined subprocess runs exactly
once each before validating their results. Every run retains its result and raw
artifacts plus stdout, stderr and exit status, including failed gates. Collection
continues after an early failure, validates every available result, then fails
on any nonzero exit, missing or invalid result, or failed gate. The collection
summary lists each failed gate; it does not retry or adjust the 1.1 limit.

Example from the repository root (supply the actual candidate commit/tree):

```bash
uv run python tools/v04_speed_runner.py \
  --fixture tests/fixtures/v04_speed_workloads.v2.json \
  --schema src/unrest_harness/schemas/v04-speed-result.v2.schema.json \
  --result-root /tmp/speed-v2-artifacts --output /tmp/speed-v2.json \
  --candidate-head "$candidate_head" --candidate-tree "$candidate_tree"
```

`validate_result` reopens every archived raw artifact and recomputes the v2
invariants, operation/event inventories and outcome gates. It is a v2 Python
helper, not a dual-version reader or a validation CLI. Historical v1 reports must
be interpreted using their original source revision and schema. Their immutable
inputs remain:

- `tests/fixtures/v04_speed_workloads.json`, SHA256
  `34ecc3c4a3dd053095efd205cc81dfcef39d3ac7453b4069d7fc185e4b2ece2f`.
- `src/unrest_harness/schemas/v04-speed-result.schema.json`, SHA256
  `8d7a9ee59060697b968b67f1ab132e92e1a7a503c5503e76d1c57bf5f6578e6a`.

This fixture repair does not remove the historical CI exclusion or establish
release acceptance. Version identity, CI waiver removal and the frozen release
checkpoint belong to release preparation.
