//! HA coordination, relay, failover and recovery.
//!
//! One test binary for the whole subsystem. Each `tests/*.rs` is its own crate,
//! so a file per scenario recompiled the 3.3k-line `support` module once per
//! file; grouping them compiles it once. nextest still runs every test in its
//! own process, so the isolation the suite relies on is unchanged.
#[path = "../support/mod.rs"]
mod support;

mod ha_e2e;
mod ha_instance_kill_it;
mod ha_relay_it;
mod native_recovery_it;
mod nats_it;
