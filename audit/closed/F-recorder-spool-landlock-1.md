# F-recorder-spool-landlock-1: recorder ciphertext spool to /tmp is denied under Landlock
- Severity: medium
- Status: Verified-Fixed
- Area: hardening

## Risk (kernel-review F-1)
The session recorder spills its **ciphertext** spool to disk once a recording
exceeds `spool_memory_threshold_bytes` (8 MiB default). The spill dir defaulted to
`std::env::temp_dir()` = `/tmp` (`recorder/mod.rs::spill`), but the Landlock
read-write set is only the data-dir (`deploy/kubernetes/gateway.yaml`,
`FS_HARDENING=full`). So a large session under the hardened profile would hit
`EACCES` on the spool open → the spill errors → in strict mode the whole session is
**torn down mid-flight** (doctrine: hardening must not break recording). Latent
because every E2E session was tiny, so the spill never ran under Landlock.

## Resolution (Verified-Fixed)
The daemon now defaults the ciphertext spool into a **data-dir subpath**
(`data_dir/recording-spool`, created at startup) instead of `/tmp` — it is inside
the Landlock read-write set on every deployment model, so a spilling session is not
denied (`gateway/src/main.rs`, recorder wiring; `RecorderConfig::spool_dir` doc at
`config.rs`). Plaintext is still never written — only sealed frames.

## Proof
`tests/fullstack/run.sh::assert_spill` (F-2 wires `FS_HARDENING=full` into
`fullstack-e2e.yml` PR + nightly): under the hardened profile the gateway launches
with a **small** spool threshold (65 KiB), a session emits >64 KiB, and the test
asserts the strict-mode session still SUCCEEDS (a `/tmp` spool would EACCES → tear
down) and the spool dir exists under the data-dir. This is the case the tiny E2E
sessions never exercised.
