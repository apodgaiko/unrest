# VAL-REL-001 — Remote v0.3.1 integrity

**Surface:** Git origin, CI, tag, release API/assets, wheel/sdist and fresh install.

**Needs:** all contracts passed and a frozen source commit.

**Behavior:** Remote `main`, immutable annotated `v0.3.1`, manifest, assets and
installed package bind one source/version/digest set. `v0.3.0` ref/assets remain
byte-identical. Release assets contain no private measurement/provider data.

**Evidence:** Exact refs, CI result, release API, asset/archive digests,
installed behavior from remote artifact, private-canary scan, v0.3.0 comparison
and rollback instructions.

