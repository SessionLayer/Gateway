//! One test binary for the group. Each `tests/*.rs` is its own crate, so a
//! file per scenario recompiled the 3.3k-line `support` module once per file;
//! grouping compiles it once. nextest still runs every test in its own
//! process, so the isolation the suite relies on is unchanged.
#[path = "../support/mod.rs"]
mod support;

mod identity_it;
mod mtls_it;
mod signing_it;
