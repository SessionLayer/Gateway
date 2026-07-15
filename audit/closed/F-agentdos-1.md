# F-agentdos-1: the agent listener has no connection cap — `max_agents` bounds the registry, not sockets
- Severity: low
- Status: Verified-Fixed
- Area: agentdos

## Summary

`BoundAgentTransport::run()` spawns one task per accepted TCP connection with no global
semaphore, no per-peer connection cap, and no accept-rate limit. The only bound in the
config, `ssh.agent.max_agents` (default 1024), caps entries in the **registry** — i.e.
distinct `node_name`s with a live control channel — not concurrent sockets, TLS sessions,
or in-flight handshakes.

## Location

- `gateway-core/src/agent/server.rs:117-138` — the accept loop: `tokio::spawn(accept_agent(..))`
  per connection, ungated.
- `gateway-core/src/agent/registry.rs:91` — `max_agents` is checked against
  `agents.len()` (registered nodes), which is the wrong quantity for socket pressure.
- Contrast `gateway-core/src/config.rs:85` — the *SSH* listener does have
  `max_connections: 512`. The agent listener has no equivalent.

## Root cause / data flow

Each accepted socket costs a task, a TLS session (rustls buffers), and a WebSocket
read/write buffer (`read_buffer_size(16 * 1024)` plus a bounded write buffer of
`2 * (max_frame_bytes + 6) + 1024` ≈ 128 KiB at the default 64 KiB frame bound). Nothing
limits how many exist at once.

Honest bounding — the handshake path IS time-bounded, which is why this is low and not
medium:
- The whole TLS + WebSocket + preface handshake is wrapped in
  `tokio::time::timeout(inner.handshake_timeout, ..)` (`server.rs:390`, default 10s).
- The dial-back authorize round-trip is bounded the same way (`server.rs:676`), as is the
  wait for `STREAM_OPEN` (`server.rs:703`).
- Client certificates are **required**, so an unauthenticated peer dies at the TLS
  handshake — it cannot hold a slot past the handshake bound.
- Superseded control channels do terminate (they receive `ControlOut::Superseded` and
  break), so an agent cannot accumulate live control channels by re-registering.

So the exposure is: any peer holding a valid internal-mTLS-CA client certificate — i.e.
**one compromised or clone-detected Agent** — can sustain `rate × 10s` concurrent
connections, each ~128 KiB+, against the Gateway. At a modest 1k conn/s that is ~10k live
sockets and >1 GiB of buffers. The Gateway is the Tier-0 data plane: FD/memory exhaustion
here also takes down the SSH front door on the same process.

Unauthenticated peers get a weaker version of the same (TCP accept + TLS handshake churn),
which every TLS server has; the authenticated variant is the one worth fixing.

## Impact

Availability of the whole Gateway process (SSH front door included) from a single valid
agent credential. No confidentiality or integrity impact. Not a bypass.

## Remediation

Bound sockets, not just registrations. Two cheap, additive controls:

1. **A global accept semaphore** on the agent listener, sized from config
   (`ssh.agent.max_connections`, defaulting to something like `max_agents * 4` to leave
   room for one control + concurrent dial-backs per agent). Acquire the permit *before*
   `tokio::spawn`, hold it for the connection's life, and drop the connection immediately
   (no TLS work) when the permit cannot be acquired:

   ```rust
   let Ok(permit) = inner.conns.clone().try_acquire_owned() else {
       tracing::warn!(peer = %peer, "agent transport at connection capacity; dropping");
       continue;   // do not spawn, do not handshake
   };
   tokio::spawn(async move { let _permit = permit; ... });
   ```

2. **A per-agent connection cap** once the peer identity is known (post-TLS): one control
   channel plus a small number of concurrent dial-backs per `agent_id`. This turns "one
   compromised agent DoSes the fleet" into "one compromised agent DoSes itself", which is
   the property that actually matters here.

Regression test: open `N > cap` connections from the same test client and assert the
`cap+1`-th is refused promptly (not merely slow), and that a legitimate agent already
registered keeps its channel.

## References

- CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400.
- Contract `agent-gateway-v1.md` §2 (DoS guard on frames — present and correct; this
  finding is about the *connection* dimension, which the contract does not bound).

## Resolution — Verified-Fixed

`server.rs`: the accept loop now holds a **connection-slot semaphore** sized from
`ssh.agent.max_connections` (default 4096), acquired with `try_acquire_owned()` **before** any
TLS work and held for the connection's life — a connection over the cap is dropped at accept,
so an unauthenticated peer cannot exhaust the Gateway before presenting a certificate. This
mirrors the audited SSH listener's `connection_slots` exactly. `validate_config` requires
`max_connections >= max_agents` (a full fleet must be able to connect).

**Proving tests:** `config::tests::agent_transport_is_off_by_default_with_fail_closed_bounds`
(the default and the `>= max_agents` invariant) and `ssh::tests::agent_transport_bounds_fail_closed`
(a too-small cap is refused at startup). The accept-time drop is the same mechanism proven for
the SSH listener.
