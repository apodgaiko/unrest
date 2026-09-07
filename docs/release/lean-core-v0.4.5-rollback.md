# Unrest v0.4.5 candidate rollback

The source perimeter is recorded in
[lean-core-v0.4.5-manifest.json](lean-core-v0.4.5-manifest.json). The immutable
release predecessor is `v0.4.0`, commit
`8decbecf7cad32552dfd7d48e069d4050e04ffd3`. The assembly parent is not the release
predecessor. This procedure is guidance; no live downgrade has been executed
as part of source preparation.

1. Stop active Unrest hosts and settle or explicitly record outstanding child
   and external effects before changing runtimes.
2. Preserve a private backup of the complete project, including `.unrest/`
   durable records and `.unrest-runtime/` recovery state. Retain current
   v0.4.5 records separately from a known-good pre-upgrade snapshot. Do not
   delete new Inquiry, evidence, supervision, identity or lineage records.
3. Obtain `unrest_harness-0.4.0-py3-none-any.whl`,
   `unrest_harness-0.4.0.tar.gz` and their `SHA256SUMS` from the immutable
   [v0.4.0 release](https://github.com/apodgaiko/unrest/releases/tag/v0.4.0).
   Authenticate the release provenance and verify both named archives against
   that release's checksum file before installation. For example, in the
   directory holding those exact downloaded files:

   ```bash
   shasum -a 256 -c SHA256SUMS
   ```

   Stop on any missing file or checksum mismatch. Do not substitute checksums
   computed from untrusted downloads for the predecessor's checksum file.
4. In a new isolated Python 3.13 environment, install the verified
   `unrest_harness-0.4.0-py3-none-any.whl`. Verify runtime and installed metadata
   both report `0.4.0`, then test it against a copy of the pre-upgrade project
   snapshot before any operator-authorized switch.
5. Keep the v0.4.5 runtime and backups available until that switch is verified.
   v0.4.0 compatibility with every additive v0.4.5 record is not established.
   There is no supported reverse-migration promise. Do not point v0.4.0 at
   new records and assume a successful read preserves their meaning.

For source inspection, resolve `v0.4.0^{commit}` and require the exact commit
above in a separate checkout. Do not move historical tags or mutate the current
candidate checkout as a rollback shortcut. Restoring a runtime never reverses
provider, workspace or external effects and never supplies release authority.
