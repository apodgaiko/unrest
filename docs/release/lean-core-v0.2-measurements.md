# Lean Core v0.2 final measurement report

This report compares fixed reference
`93c59e4378407f3d7cfb918cf86c8bdc81daa141` with the final tracked-file
candidate. The exact machine-readable values, raw arrays, order, arithmetic,
archive hashes, and member inventories are in
[`lean-core-v0.2-measurements.json`](lean-core-v0.2-measurements.json); raw
transcripts and both build sets are retained in mission evidence.

The measurement environment was macOS 26.6.1 arm64, CPython 3.13.12, uv
0.11.0, and one shared populated offline build cache with `setuptools>=77`.
Static measurements use `python tools/release_measurements.py <archive-root>`.
Imports use seven fresh processes for each revision/module with the alternating
28-process order recorded verbatim in the JSON. Builds use the same command:

```text
UV_CACHE_DIR=<same-populated-offline-cache> uv build --offline --python 3.13 --no-progress --no-create-gitignore --out-dir <revision-output> .
```

## Accepted results

- Production Python: 25,730 → 12,532, 13,198 fewer, 51.294209% shorter.
- Maintained first-party Python: 52,351 → 29,414, 22,937 fewer, 43.813872% shorter.
- Largest function: 1,364 → 226 lines; the JSON publishes both top-five lists.
- Maximum C901: 219 → 30; the JSON publishes both top-five lists.
- CLI import median: 0.259181s → 0.194501s; candidate range 0.190629–0.197637s, passing the 0.20s ceiling.
- Server import median: 0.611325s → 0.621812s; candidate range 0.603442–0.630230s, below 0.78s and neutral within observed spread.

The reference wheel/sdist are 309,041/445,080 bytes with SHA-256
`91848bf7…782ad`/`3977ed94…da41f`. The final candidate wheel/sdist are
217,860/297,214 bytes with SHA-256 `36358758…41e5`/`077fd548…dc81`.
The wheel changes from 55 to 51 members and the sdist from 113 to 115; the
complete membership lists and exact added/removed comparison are in the JSON.

The candidate is 102 tracked regular files at
`4b42b98529c723bc137ffb5ba77c75337f5457a7a390cc960b32acea115e4199`.
The single new frozen-candidate checkpoint passed 899 tests with 7 skipped in
170.80 seconds, exit 0. Its pre/post manifests and bound diffs are identical.
The exact candidate wheel then passed distribution verification and an
unrelated-directory Python 3.13 install, all three help surfaces, imports, and
the installed-wheel lifecycle check.

## Deviations

The first import harness attempt resolved the venv symlink to a standalone
interpreter and failed before yielding a sample. The accepted run used the
literal venv path and produced all 28 successful interleaved samples without
retry. Two offline-cache probes for the reference build lacked `setuptools>=77`
and failed before backend execution; the accepted reference build used the
populated offline cache. No retry is permitted for the final candidate build.
