//! Library surface of the `gateway` binary crate.
//!
//! Exists so the Tier-0 self-hardening module can be exercised by a spawned
//! canary binary + an integration test with the SAME code the daemon runs —
//! seccomp/Landlock are irreversible and process-wide, so they must be applied in
//! a subprocess, never in the test runner. The daemon (`main.rs`) uses this lib
//! too (`use gateway::hardening`).

pub mod hardening;
