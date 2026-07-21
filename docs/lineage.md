# Source lineage

Unrest contains software derived from
[Intelligent Internet's Zenith](https://github.com/Intelligent-Internet/zenith),
which is distributed under the Apache License, Version 2.0. The Apache license
text retained in this repository's [`LICENSE`](../LICENSE) is byte-identical to
the source baseline.

## Baselines and prepared imports

- Early local development baseline: `17ef688eb142e6151aa47024981215dd922a00cf`.
- Fully fetched, explicitly licensed source baseline: `a21c071`.
- Standalone product base: `677e417af00453490ba8b6bc4cd5412d6b5ccbde`.
- Prepared PR23 host-setup series: `b2bc962`, `3404285`.
- Prepared PR28 research series: `d735f1d`, `b097989`.
- Prepared PR29 terminal-review series: `f45b6ba`, `d456c90`, `1d1eb21`,
  `11cb553`.

The merge commits in Git history preserve those series as separate auditable
units. The source repository was
`https://github.com/Intelligent-Internet/zenith.git`.

## Modifications

OpenAIBot1 independently integrated the prepared changes, resolved them against
the standalone product line, changed the package and runtime identity to Unrest,
removed inherited product claims and report assets, revised public documentation,
and continued development. Git history is the detailed modification record.

The source technical report, *From RALPH to Zenith: Designing Harnesses for
Long-Running Agents*, and its figures were published separately under CC BY 4.0.
They are not redistributed in Unrest and are not covered by this repository's
Apache-2.0 software license. The historical source remains available in the
[source repository](https://github.com/Intelligent-Internet/zenith).

## Independence

Unrest is an independent product. It is not an official continuation of the
source project, and Intelligent Internet does not endorse it. Source names are
used here only for attribution and historically accurate research provenance.
