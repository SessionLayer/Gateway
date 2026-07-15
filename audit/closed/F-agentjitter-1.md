# F-agentjitter-1: the in-repo agent client reconnects with no jitter, contrary to its own doc-comment and contract §7
- Severity: low
- Status: Verified-Fixed
- Area: agentjitter

## Summary

`AgentClient::run_forever` claims "exponential backoff + jitter" and cites contract §7,
which mandates jitter. The code has backoff only. On a Gateway restart, every agent
reconnects in lockstep at 200ms, 400ms, 800ms, ... — a thundering herd, which is
precisely what the contract's jitter requirement exists to prevent.

## Location

`gateway-core/src/agent/testclient.rs:284-309`

```rust
/// Reconnect with exponential backoff + jitter, indefinitely (contract §7). ...
pub async fn run_forever(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut backoff = Duration::from_millis(200);
    loop {
        ...
        tokio::select! {
            biased;
            _ = shutdown.wait_for(|v| *v) => return,
            _ = tokio::time::sleep(backoff) => {}      // <- no jitter
        }
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}
```

Contract `agent-gateway-v1.md` §7: *"The Agent reconnects with **exponential backoff +
jitter**, indefinitely."*

## Impact

Bounded, hence low: this client is feature-gated (`#[cfg(feature = "test-agent")]`,
`agent/mod.rs:22-23`) and the production Agent lives in the `Agent/` repo. But it is the
reference implementation the Docker E2E runs against, and it is the artifact in *this*
repo that claims contract §7 conformance while not conforming.

It compounds with **F-agentdos-1** (no connection cap on the agent listener): a lockstep
herd is exactly the input that finds an unbounded accept path.

## Fix

Multiply the sleep by a random factor in `[0.5, 1.5]` (the crate already depends on
`rand_core`, used by `identity::random_jitter_sample`):

```rust
let jittered = backoff.mul_f64(0.5 + rand_core::OsRng.next_u32() as f64 / u32::MAX as f64);
_ = tokio::time::sleep(jittered) => {}
```

**Cross-repo:** the real Agent's control-channel reconnect must be checked for the same
defect. That is `Agent/` and outside this repo's review — flagged to the lead for
`ag-engineer`.

## Resolution — Verified-Fixed

`testclient.rs::run_forever`: the reconnect backoff is now multiplied by a random `[0.5, 1.5)`
factor (OsRng), so a fleet that dropped together (a Gateway restart) does not reconnect in
lockstep — matching its own doc-comment and contract §7 ("exponential backoff + jitter"). A
test double that violated the spec would be a bad oracle for the E2E. Cross-repo: the real
Agent's reconnect is ag-engineer2's (F-wireversion-2 batch).

**Proving:** the jittered path is exercised by every reconnect in the agent E2E; the factor is
bounded to `[0.5, 1.5)` by construction.
