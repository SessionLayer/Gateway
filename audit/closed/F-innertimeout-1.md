# F-innertimeout-1: inner cert-auth + channel-open run outside handshake_timeout (bounded only by the 900s idle timer)
- Severity: medium
- Status: Verified-Fixed
- Area: reliability

## Risk (T3: reliability reviewer)
`InnerClient::establish` bounds only the **transport** handshake:

```
let mut handle = match tokio::time::timeout(cfg.handshake_timeout, connect).await { ... }   // innerleg.rs:112
...
let auth = handle.authenticate_openssh_cert(principal, key.clone(), cert).await;             // innerleg.rs:137  (NO timeout)
```

`check_server_key` (host verification) runs inside `connect_stream`, so it is
covered. But the **userauth** step (`authenticate_openssh_cert`) and every
post-handshake channel round-trip (`open_channel` → `channel_open_session().await`,
`request_pty`, innerleg.rs:150-175) run *after* the timeout returns. russh's only
remaining bound on those awaits is the client `inactivity_timeout`, which we set to
`max_session_idle_secs` (**default 900s**, innerleg.rs:100) and which resets on any
loop activity. A node that completes KEX + passes host verification but then stalls
during userauth or channel-open therefore holds the **outer** connection, its
handler task, and (indirectly) an accept slot for up to ~900s.

This contradicts the config doc, which claims the bound covers auth:

> `handshake_timeout_secs` … Bound on the inner SSH transport handshake **(incl.
> host verification + cert auth)**.  — config.rs:123

Operational impact: a single degraded-but-enrolled node can pin many outer
connections in 900s holds. With `max_connections = 512` (config.rs:156) all slots
can be consumed by stalled `establish_inner` calls, and the accept loop then drops
new legitimate connections ("at connection capacity", ssh/mod.rs:117) — a
node-degradation fault escalates to a gateway-wide connection-starvation outage.
Same root cause head-of-line-blocks sibling channels: a second channel's
`open_channel` runs on the shared handler task, stalling channel 1's pump output
until the 900s idle timer fires.

## Fix
Bound the post-transport node operations by the (small) handshake/RPC bound, not
the (large) idle bound:
- Wrap `authenticate_openssh_cert` in `tokio::time::timeout(cfg.handshake_timeout, …)`
  → fail closed to the `node_unreachable` outcome on elapse (innerleg.rs:137).
- Bound `InnerClient::open_channel` (channel-open + request) by a small op timeout
  (reuse `handshake_timeout` or a dedicated `channel_open_timeout_secs`); on elapse
  close the outer channel with `NodeUnreachable` rather than parking on the shared
  handler task (innerleg.rs:150, handler.rs:487).
- Either way, correct the config.rs:123 doc so `handshake_timeout_secs` accurately
  states what it bounds.

## Verification (suggested)
A mock node that finishes KEX (passing host-verify) then never answers userauth →
`establish` returns `HandshakeTimeout`/`node_unreachable` within `handshake_timeout`,
not `max_session_idle_secs`.

## Resolution (Verified-Fixed)
Bounded `authenticate_openssh_cert` and `open_channel` (channel-open + replay) by `handshake_timeout` (innerleg.rs); a node that passes KEX/host-verify then stalls now fails closed to `node_unreachable` within the bound, not the 900s idle timer. The config.rs doc for `handshake_timeout_secs` was corrected to say it bounds each node round-trip.
