# Disposable candidate desktop discovery

`v046_desktop_fixture.py` is external validation tooling, not a packaged MCP
feature. It prepares an inactive registration and a unique synthetic project.
It does not install a package, edit a client configuration, restart an app, or
change public tools or schemas. Use the candidate's Python 3.13 interpreter with
`-I`; keep the launcher at its recorded absolute path.

```sh
/absolute/candidate/bin/python -I /absolute/tools/v046_desktop_fixture.py prepare \
  --root /private/tmp/unrest-desktop-UNIQUE \
  --candidate-manifest /absolute/certified-candidate-manifest.json
```

The destination must not exist. Preparation uses the real project creation API
without dispatching work. It clears inherited environment authority and uses a
private home/workspace with the candidate's bundled capability policy. Outputs
are `setup.json`, `registration.json`, `call.json`, and a copy of the supplied
candidate manifest. The supplied manifest is a provenance reference, not a
certificate: the independent validator must compare it to certification and
verify that the interpreter's installed package members match the certified
wheel. Version alone is insufficient (development candidates may retain the
previous release version).

The registration uses an absolute interpreter, `-I`, the exact launcher and
fixture path, and a unique server name. It runs the real orchestrator stdio
entry point in that same process. Before service, the observer verifies prepared
package/dependency, interpreter, launcher, manifest and registration identities.
It records only its own PID and OS-reported process start, import paths, role,
policy/config identities and hashes under a unique observations directory.
`ps -p <own PID> -o lstart=` must be permitted; missing process provenance refuses
service. Do not bypass an execution-service refusal.

For a successful `inspect_project` response matching `call.json`, the observer
forwards the wire unchanged and records result/structured-content/wire hashes,
PID, fixture ID and observation time. It never saves response bodies, prompts,
credentials or environment dumps. Compare the returned structured-content hash
with the record and bind it to `process.json`, `setup.json` and the exact
registration. A server starting, a catalog appearing, or an unrelated successful
call does not establish this binding. `exit.json` is written on ordinary exit;
its absence after a forced stop must remain explicit.

This observer does extra hashing and configuration checks and is **not a timing
ruler**. Its functional checks establish provenance only. Keep startup timings
on the frozen measurement helper, without this observer. OS caches remain
uncontrolled; no timeout change or first-call cost deferral is an optimization.

## Activation and restoration after certification

1. Complete candidate certification first. Install the certified wheel into a
   dedicated disposable environment, outside global/main installations. Run
   preparation with that interpreter and the certified manifest. Verify all
   package members, dependencies, policy and candidate/launcher identities.
   A pre-certification fixture is only a rehearsal and must not be activated.
2. Inspect the exact current supported client registration surface. Existing
   plugin and user-config Unrest registrations can both exist; neither proves
   which process responded. Preserve their bytes and permissions in a private
   backup. Merge only the unique generated registration into one supported
   surface; do not replace the whole configuration with `registration.json`.
   For a TOML client use the identical command/args under
   `[mcp_servers.<registration_name>]`. Record the exact activated entry and
   its config-file digest. Leave existing registrations intact.
3. Only when that concrete certified setup is ready, ask the user to quit and
   reopen the desktop app and reply “refreshed”. No CUA or shell UI automation.
   Invoke the unique server's `inspect_project` with `call.json`, capture its
   structured result hash and compare the observation as described above.
   The responding PID must have a new start time from this activation.
4. Remove only the unique entry, preserving concurrent unrelated config edits.
   If no other edits occurred, restore the byte-identical backup. Use the same
   supported user-assisted refresh to unload it; verify the recorded child has
   exited and retain the evidence before removing disposable files. Never kill
   a PID based solely on an old numeric PID: verify its recorded start identity.

Independent candidate desktop discovery remains mandatory before publication.
A functional subprocess rehearsal is not evidence of desktop discovery.

## Startup evidence boundary

The startup optimization suppresses FastMCP's optional stdio banner and update
check. Required import, policy validation, registration and first-call semantics
remain eager. Historical confirmation belongs to its original candidate;
final-candidate timing, including desktop timing and p95/noise/first-call
equivalence, remains **UNVERIFIED**. Functional tests and this observer do not
produce scored timing observations. Frozen calibration, fixtures, thresholds
and launch accounting remain unchanged; no new measurement is authorized by
the accepted release risk. Do not use held-out cases for tuning.

Experimental reuse/cohort dispatch and approval recovery remain disabled by
default. Genuine native approval presentation/acceptance and ACP live reuse
remain **UNVERIFIED**. The supported discovery check above establishes only
ordinary certified-candidate registration, response and process provenance.

The reported ten-second desktop stall remains a separate incident. Local
imports or banner timings alone cannot explain an unbound desktop timeout.
Current client status logs can show starting/ready transitions but do not carry
candidate package identity or server phase timestamps. A supported unresolved
disposition must preserve that limitation and the prior CUA refusal; increasing
the client timeout does not diagnose or fix it.
