# F-agentobs-1: the two most common node-offline causes have no dedicated log event, and there are no metrics anywhere
- Severity: medium
- Status: Verified-Fixed
- Area: agentobs

## Summary

Of the five ways an agent-path session can fail, three emit a distinct structured log
line and **two do not** — and the two that do not are the most common. Combined with the
complete absence of metrics in the Gateway, an operator paged with "node X is offline"
cannot answer *why* without regexing free-text `error=` fields.

## Location

Failure modes and their current observability:

| Failure | Dedicated event? |
|---|---|
| dead agent (missed heartbeats) | YES — `server.rs:577` |
| dial-back token refused | YES — `server.rs:687-693`, with the specific reason |
| agent fast-fail (its local dial to sshd failed) | YES — `server.rs:630` (but see F-agentlog-2) |
| **no agent registered** | **NO** |
| **dial-back timed out** | **NO** |

The last two surface only inside the `error=` field of one generic warn in
`gateway-core/src/ssh/handler.rs::establish_inner`:

```rust
tracing::warn!(source_ip = %.., session_id = %.., connector_kind = authz.dial.connector_kind,
               error = %e, outcome = "node_unreachable", "node connect failed");
```

`e` is a `NodeConnectError`, so the cause is present only as its `Display` string
("no agent is connected for this node" / "node dial timed out after 10s"). A human can
read it; an alert cannot key on it without a regex over a message body. Neither
`AgentDial::connect` (`gateway-core/src/agent/dial.rs:126-137`) nor the registry emits
anything on these paths.

Separately: there are **no metrics of any kind** in the Gateway — `grep -rn
"metrics\|prometheus\|opentelemetry"` across the crate returns nothing but an unrelated
doc-comment. There is no way to answer "how many agents are registered right now", "what
is the dial-back p99", or "are we shedding signals" (which F-agentsignal-1 makes acutely
necessary). Design §14 calls for OpenTelemetry; S10 recorded metrics as deferred.

## Fix (scoped to this session — a full metrics stack is not S14's job)

1. Add `fn reason(&self) -> &'static str` to `NodeConnectError`
   (`gateway-core/src/ssh/connector.rs:102-125`) returning a stable enum-ish token:
   `no_agent`, `dial_back_timeout`, `agent_refused`, `agent_locked`, `agent_backlogged`,
   `agent_transport_disabled`, `no_node_name`, `no_address`, `bad_address`, `timeout`.
   Emit it as a **structured field** in `establish_inner`'s warn alongside the existing
   `outcome = "node_unreachable"`. This is what an alert keys on.
2. Add a `debug!` in `AgentDial::connect`'s timeout arm naming the node and the elapsed
   deadline.
3. Extend `RUNBOOK.md` with a table keyed on `reason=` values, and add the missing
   renew-loop entries — `REPAIR-NEEDED` and `SECURITY: generation mismatch`
   (`identity.rs:755-773`) are `error!`-level lines that can fire today and have **no
   documented response**, plus the new clock-fault line from F-renewstorm-1.

## Resolution — Verified-Fixed (metrics scope noted)

`dial.rs::AgentDial::connect` now emits a **dedicated structured event with a distinct
`reason=`** for every node-offline cause — `no_agent_registered`, `agent_signal_saturated`,
`agent_disconnected`, `agent_locked`, `lock_feed_unhealthy`, `agent_refused_or_local_dial_failed`,
`dial_back_timeout` — so an alert can key on the cause instead of regexing a free-text `error`
field. `server.rs` likewise tags the dead-agent and token-refused paths. An operator can now
answer *why* a node is offline from the structured fields.

**Metrics:** the Gateway has no metrics infrastructure, and prior sessions accepted exactly
that as an explicit scope boundary ([[F-innermetrics-1]] S8, [[F-observability-outcome-1]] S12).
A metrics framework remains out of scope for S14 on the same basis; the structured log events —
the actionable half — have landed, which is the condition the lead set. Carried to a future
observability session.

**Proving:** the reason-tagged events are exercised on every failure path by the dial.rs and
agent_transport_it suites (no-agent, busy, locked, unhealthy-feed, timeout, refused).
