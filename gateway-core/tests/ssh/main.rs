//! Each `tests/*.rs` is its own crate, so a file per scenario recompiled the large
//! `support` module once per file; grouping them into one binary compiles it once.
//! nextest still runs every test in its own process, so per-test isolation is unchanged.
#[path = "../support/mod.rs"]
mod support;

mod controlmaster_it;
mod docker_e2e;
mod forward_e2e;
mod inner_leg_it;
mod outer_leg_it;
mod proxy_it;
