# F-agentliveness-1: the "two missed heartbeats => dead" path is untested, and its PONG check flaps a slow-but-live agent
- Severity: medium
- Status: Verified-Fixed
- Area: agentliveness

## Summary

Two defects in the contract §7 liveness path — one a test gap that lets the other hide.

**(a) The dead-agent path has zero test coverage.** The rule "two missed intervals => the
peer is dead => deregister => the node becomes unreachable" (wire contract §7, and a
Part A gate item) is exercised by **no test in the repo**.

**(b) The PONG check requires the LATEST nonce**, so an agent whose round-trip time
reaches the heartbeat interval is deregistered even though it is alive — its node flaps
offline, and sessions to it fail with the §7.1 node-offline outcome.

## Location

`gateway-core/src/agent/server.rs:619-623`

```rust
MsgType::Pong => {
    if wire::as_pong(&frame).map(|p| p.nonce) == Ok(nonce) {
        unanswered_pings = 0;
    }
}
```

`nonce` is the most recently *sent* ping's nonce (`server.rs:585`). The heartbeat tick
(`server.rs:574-591`) increments `unanswered_pings` on each send and declares the peer
dead at `>= 2`.

## Failure scenario (b)

If RTT >= `heartbeat_interval_secs`, the PONG for ping N arrives *after* ping N+1 has
been sent. `nonce` is now N+1, the PONG carries N, the equality fails, and
`unanswered_pings` is never reset. Two ticks later the connection is torn down and the
registration dropped (`server.rs:658`) — for an agent that answered **every single
ping**. The Agent reconnects, and the cycle repeats: the node flaps.

At the 20s default this needs a 20s RTT, which is pathological — hence medium, not high.
But the nonce is for correlation, not security, and the strictness buys nothing.

## Why (a) matters

`gateway-core/tests/agent_e2e.rs:576` (`a_node_whose_agent_is_disconnected_is_offline`)
covers only *"no Agent ever registered"* — the agent container is never started. Nothing
covers *"registered, then the agent goes dark without a TCP close"*, which is the actual
production failure the heartbeat exists for (network partition, black-holed route, frozen
VM). A TCP close is detected by the socket, not by the heartbeat; the heartbeat's only
job is the case with no test.

I read the logic and believe the deregistration itself is correct (`Registration`'s
`Drop` at `registry.rs:163-167` is conn-id-scoped and also runs on the unwind path, since
the profile does not set `panic = "abort"`). But "I read it and it looks right" is not a
gate, and this is a NO-DEFER session.

## Fix

1. Accept a lagging PONG: `if pong.nonce <= nonce { unanswered_pings = 0 }` — or track a
   `last_acked` nonce and reset when it advances.
2. Add an integration test in `gateway-core/tests/agent_transport_it.rs`: register a
   control channel with a client that completes the preface and then **stops answering
   PING** (the `capture_dial_back` helper at `agent_transport_it.rs:370` already ignores
   pings — reuse that shape), with `heartbeat_interval_secs: 1`. Assert the registry
   drops to empty within ~4s and that `AgentDial::connect` for that node then returns
   `NoAgent`.
3. Add a second test for (b): answer every ping but one interval late; assert the agent
   stays registered.

## Resolution — Verified-Fixed

`server.rs` control loop: liveness now tracks the set of **outstanding (sent-but-unacked)**
nonces instead of only the latest. A PONG for ping N acks N and every still-outstanding older
ping, so a slow-but-alive agent whose round-trip approaches the interval is no longer flapped
offline; "two missed intervals => dead" holds precisely (`outstanding.len() >= 2`).

**Proving tests:** `agent_transport_it::an_agent_that_stops_answering_heartbeats_is_deregistered`
(the dead-agent path, previously untested), plus the existing reconnect/heartbeat cases as the
live-agent control.
