# Guard evidence diagnostics projection

`tools/project_guard_evidence.py` turns an already-decrypted guard
`source-private.tar` into one small, closed-schema JSON document. It exists so
that the next failure of the full source checkpoint can be triaged from a fixed
projection instead of manual reading of private tracebacks and logs.

It is offline development tooling in the source tree. It is not a product
command, not part of the guard, not invoked by any workflow and not release
evidence. It does not change any guard predicate, pin or the guard size budget.

## Scope and non-goals

- Input: one operator-supplied, already-decrypted, uncompressed tar archive with
  the `source-private/` layout written by `.github/release-guard/source_host.py`.
  Directory input, compressed archives and encrypted `.cms` files are refused.
- Downloading artifacts, locating keys and decryption are out of scope. The tool
  never opens a network connection, starts a process, reads keys, reads the
  environment, extracts members or writes files.
- The output never contains node ids, paths, member names, exception messages,
  traceback lines, log text, content hashes or any other input-derived string.
  It contains only fixed schema keys, closed enum values, exact integers,
  booleans and `null`.

## Usage

From the checkout root:

```bash
.venv/bin/python -I -B tools/project_guard_evidence.py /path/to/source-private.tar
```

These commands use the existing project virtual environment directly. They do
not sync, install or update anything, so the environment must already exist.
The tool uses only the Python standard library, so any Python 3.13 interpreter
works. The projection is written to stdout as one line of sorted-key JSON
(at most 16 KiB).

| Exit | Meaning |
| --- | --- |
| 0 | `status: complete`: `source-result.json` and every present layer parsed. |
| 1 | `status: partial`: `source-result.json` is missing or unrecognised, or a present layer is invalid. |
| 2 | Rejected. stdout is empty; stderr holds `{"error": <code>, ...}` with a closed code. |

Rejection codes: `usage`, `input_unreadable` (including a symlinked input path),
`input_not_regular`, `input_too_large`, `archive_corrupt`,
`archive_trailing_data`, `too_many_members`, `member_name_rejected`,
`member_type_rejected`, `member_duplicate`, `member_too_large`,
`aggregate_too_large`, `header_span_too_large`, `header_accounting_gap`,
`member_unknown`, `output_too_large`, `internal_error`.

## Trust model

Every value is reported by the supplied bundle and is **not authenticated**:
`trust` is always `bundle_reported_unauthenticated` and `association` is
`bundle_reported`. The per-layer `source` names the writer role that guard code
assigns to that member: `host_written` means "the guard host is the expected
writer", not authenticated provenance; inside an unauthenticated bundle it can be
forged like any other byte. The decoded pytest root output is labelled
`subject_output` because candidate code controls it even in a genuine bundle.
`release_assessment` is always `not_evaluated`.

Layers appear in a fixed display order (`layer_order: display_only`). The order
is not causal, and the tool performs no root-cause election
(`causal_election: not_performed`). It never treats the deepest exception, the
first writer or a literal match as an observed cause. The guard does not record
which inventory condition was violated, so `violated_condition` is always
`cause_unavailable`.

## Projection

Top-level keys: `schema` (`unrest.guard-evidence-projection.v1`), `status`,
`trust`, `association`, `hints_basis` (`text_match`), `layer_order`,
`causal_election`, `violated_condition`, `release_assessment`, `input`
(`archive_bytes`, `regular_members`, `known_unprojected_members`), `layers` and
`reported_hints`.

Each layer is `{layer, source, state, reason, facts}`. `state` is `present`,
`absent`, `invalid` (with a closed `reason`) or `unavailable` (the subject output
when `source-result.json` is not usable). Missing optional layers are `absent`,
never success.

| Layer | Member | Facts |
| --- | --- | --- |
| `namespace_failure` | `namespace-failure.txt` | `final_line_hint` |
| `observer_parent_wait` | `observer-parent-wait.json` | `actual_parent_wait` (raw wait status or null) |
| `worker_failure` | `worker-failure.txt` | `final_line_hint` |
| `source_result` | `source-result.json` (schema `unrest.bootstrap-source-result.v5`) | `source_checkpoint_ready_reported`, `completed_count`, `outcomes_count`, `failure_recorded`, `trace_result_recorded`, `root_parent_wait_raw` |
| `subject_output` | `output_base64` inside `source-result.json` | `decoded_bytes`, `internalerror_reported`, `internalerror_frame_hint`, `internalerror_final_line_hint` |
| `collected_cases` | `collected-cases.json` | `case_count`, `collection_evidence` |
| `held_source_cleanup` | `held-source-cleanup.json` | `actual_parent_wait` |
| `namespace_fallback_cleanup` | `namespace-fallback-cleanup.json` | `adopted_count` |
| `fallback_cleanup` | `fallback-cleanup.json` | `adopted_count` |

`dependency-bytecode.log`, `package-inputs.json` and `package-preparation.log`
are known writer outputs; they are counted in `known_unprojected_members` and
never read. Any other member name is rejected.

`collected-cases.json` with zero cases is also the host's pre-collection seal,
so `case_count: 0` reports `collection_evidence: not_established`. It is not
evidence of successful collection or of zero tests. Exit statuses are never
inferred from exception text; only the integer wait fields written by the host
are reported.

### Hints

Hints are exact matches of a final line and are only reported text matches:

- `final_line_hint` in `namespace_failure`: `namespace_integration_failed`,
  `namespace_child_failed` or `unrecognised`.
- `final_line_hint` in `worker_failure` and `internalerror_final_line_hint` in
  `subject_output`: `inventory_finite_nodes`, `ambiguous_case_references`,
  `full_source_wait_refusal` or `unrecognised`.
- `internalerror_frame_hint`: `pytest_collection_finish` when an
  `INTERNALERROR>` frame line names that hook, otherwise `unrecognised`.

`reported_hints` is the sorted set of recognised final-line hints from all layers,
including the candidate-controlled `subject_output`. It carries no source label;
consult the per-layer facts to see which layer reported a hint and its `source`.
An `inventory_finite_nodes` hint does not say which of its conditions failed.

## Bounds

Before parsing: the archive is at most 32 MiB (checked on the file and again on
the bytes passed to `project()`), read into memory only. After `tarfile` has
parsed the headers, the tool enforces:

- at most 64 **logical** members as returned by `tarfile` (a member together with
  its PAX or GNU extension headers counts once; raw 512-byte headers are not
  counted);
- extension header span per logical member at most 8 KiB;
- contiguous accounting: the first member starts at offset 0, each member starts
  where the previous member's data blocks end, and the end-of-archive marker
  follows the last member. Global PAX headers and any other unaccounted header or
  gap are rejected (`header_accounting_gap`);
- everything after the last member is zero padding of at least two blocks;
- only the directory `source-private` and non-sparse regular files directly below
  it: links, devices, FIFOs, GNU or PAX sparse members, nested paths, absolute or
  traversal names and duplicates are rejected;
- declared member sizes (each at most 8 MiB, aggregate at most 32 MiB) are checked
  before any member data is read, and reads are length-checked.

Then: decoded subject output at most 1 MiB, JSON nesting at most 64. JSON
duplicate keys, non-finite numbers, invalid encodings and booleans in integer
fields mark the layer invalid.

**Residual limitation.** Extension headers (PAX records, GNU long names, sparse
maps) are parsed by the standard library `tarfile` before any of the checks above
run. The post-parse checks reject such archives but do not cap the work already
done: a crafted archive within the 32 MiB input bound can make `tarfile` spend
CPU and memory amplified relative to its size. Chains deep enough to exhaust
recursion end as `archive_corrupt`. A `MemoryError` raised inside the process is
caught and reported as `internal_error`, but there is no guarantee for memory
exhaustion in general: the operating system may kill the process, or heavy
swapping may stall it, and then no JSON is written at all. The genuine guard
writer emits no global, chained, long-name or
sparse headers, so this matters only for forged or tampered input. Use the tool
only on bundles from the expected decryption step.

## Validation

From the checkout root, using the existing environment (no sync or install):

```bash
.venv/bin/python -I -B -m pytest -q -p no:cacheprovider tools/tests/test_project_guard_evidence.py
.venv/bin/ruff check --no-cache tools/project_guard_evidence.py tools/tests/test_project_guard_evidence.py
```

The tests are synthetic, in-process and outside the default `tests` collection
(`testpaths = ["tests"]`). The tool and its tests are not included in the wheel
or the sdist under the current packaging configuration. Validation against a
real decrypted bundle is a separate private operator step; real bundles and
their projections are never committed.
