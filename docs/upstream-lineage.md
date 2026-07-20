# Upstream lineage

This project is derived from
[Intelligent-Internet/zenith](https://github.com/Intelligent-Internet/zenith),
an Apache-2.0-licensed continuous-improvement harness for long-running agent
tasks.

## Baselines

- Original local development baseline:
  `17ef688eb142e6151aa47024981215dd922a00cf`
- First fully fetched, explicitly licensed upstream baseline used for the
  independent product line:
  `a21c071`
- Upstream remote:
  `https://github.com/Intelligent-Internet/zenith.git`

The technical report and its figures are licensed separately under CC BY 4.0,
as documented by upstream. Do not assume the Apache-2.0 software license applies
to report assets.

## Local development lines at separation

- `fork/runtime-reliability` preserves the local ACP runtime, worker-model,
  diagnostics, and terminal-review recovery changes that were developed from
  the earlier `17ef688` baseline.
- `experiment/terminal-dashboard` preserves the read-only terminal supervision
  experiment developed from the same earlier baseline.
- `product-main` starts from the current licensed upstream baseline and is the
  integration line for the independent derived product.

Some newer upstream changes overlap the runtime-reliability work. Integrate that
branch by reviewing behavior and tests, not by blindly replaying its entire diff.

## Attribution policy

- Retain the upstream Apache License 2.0 text in `LICENSE`.
- Retain relevant upstream copyright, patent, trademark, and attribution
  notices in redistributed source.
- Mark materially modified inherited files when distributing a derivative.
- Describe the product as derived from or based on Zenith; do not imply upstream
  endorsement.
- Record future upstream imports here or in normal Git history with their source
  commit IDs.

