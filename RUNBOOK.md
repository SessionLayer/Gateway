# SessionLayer Gateway — Operations Runbook

Operator guidance for the Tier-0 Gateway. Structured-log fields referenced below
come from `tracing` (`RUST_LOG`, default `info`); correlate by `session_id`.

## Break-glass (Design §7, FR-ACC-6) — access model

Break-glass is the always-available, IdP-independent override path: a registered FIDO2
`sk-ecdsa` key (primary) or a single-use offline code (fallback). Every use fires a
high-priority CP-side alert, is force-recorded (strict), is Lock-beatable, and is
time-boxed.

### Log outcomes / reasons

- `reason=breakglass_lock_feed_unhealthy` (a break-glass channel refused). The Gateway's
  pushed lock deny-set is not healthy, so it cannot confirm the absence of a Lock and
  fails closed (§8.4 — deny wins under feed degradation; this refusal is CORRECT).
  Action: check the lock-feed gRPC stream to the CP (`:9443`, `LockFeed.StreamLocks`);
  it self-heals on reconnect (0.5–10s). Existing channels run to `grant_expiry`.
- `outcome=recording_unavailable` with `break_glass=true` (a break-glass connect refused).
  Break-glass forces strict recording; the recording could not start (no customer
  encryption key, or the WORM/spool backend is down). The session is intentionally
  refused (fail closed). Action: restore the customer key / WORM backend (MinIO/S3).
- `reason=breakglass_no_grant_expiry` (`break_glass=true`). The CP signed a break-glass
  ALLOW without a `grant_expiry` — refused because an override must be time-boxed. Action:
  a CP contract issue; check break-glass policy TTL configuration.
- `reason=authorization_denied` with `break_glass=true`. A break-glass Authorize was
  denied (e.g. a matching Lock — deny wins). Correlate with the CP decision log.
- A warn line "break-glass auth resolved to a non-BREAKGLASS access model" indicates a
  token mis-binding / contract drift between the Gateway and CP — investigate.
- A warn line "non-sk-ecdsa security key offered; break-glass supports only sk-ecdsa"
  means an operator offered a wrong-algorithm FIDO2 key (e.g. `ed25519-sk`) for
  break-glass. It was routed to the ordinary pin path. Re-provision as `ecdsa-sk`.

Break-glass **activation alerts are CP-side** (raised at Authorize, on use). Correlate an
alert with the Gateway's session by `session_id`.

### Deployment requirements (hard rules)

- Break-glass FIDO2 keys MUST be **`sk-ecdsa`** (`ssh-keygen -t ecdsa-sk`) AND
  **touch-required** — never `-O no-touch-required`. russh verifies possession only and
  does NOT assert the user-presence (touch) bit
  ([[audit/closed/F-gw-breakglass-userpresence-1.md]]); touch is enforced by the
  authenticator, so the key must require it.
- Do NOT dual-register one key as BOTH a pin and a break-glass credential — a routine
  login with it would fire the high-priority alert and force strict recording.
- Offline break-glass codes are entered **echo-off over keyboard-interactive**; never
  place a code in an environment variable in production (the E2E's `SL_CODE` env is a
  test-only convenience via `SSH_ASKPASS`).
- A break-glass session is **time-boxed**: `break_glass.mid_session_expiry` must be
  `grace_then_kill` or `hard_kill` (never `run_to_ttl` — startup rejects it). A Lock
  always overrides with immediate teardown.

## Outbound-agent transport (Session Fourteen; Design §9.2, FR-CONN-1/2/3, FR-HA-8)

An `OUTBOUND_AGENT` node is never dialled by the Gateway. Its Agent dials **out** to
`ssh.agent.listen_addr` (dev `:9444`) over `wss://` with mutual TLS, registers a control
channel, and — when signalled — dials back and splices the session to its own
`127.0.0.1:22`. The node needs **zero inbound reachability**.

### Configuration (fail-closed; startup rejects a bad combination)

- `ssh.agent.listen_addr` — empty (default) disables the transport. An `OUTBOUND_AGENT`
  node is then simply **offline** — never a silent fallback to an agentless dial.
- `ssh.agent.advertise_url` — the `wss://` URL agents dial back to. **Required when
  `listen_addr` binds a wildcard** (`0.0.0.0`/`::`): the address rides in the signal, so
  advertising `0.0.0.0` would leave the whole agent fleet unreachable. Startup aborts.
- `max_frame_bytes` (64 KiB) must exceed `inner.max_packet_bytes`; `dial_back_timeout_secs`
  must be less than `dial_back_token_ttl_secs`. Both are checked at startup.

The Gateway obtains its agent-facing **serverAuth** certificate from the CP
(`GatewayIdentity.IssueGatewayServerCertificate`) over a separate, never-persisted
keypair. If the CP will not issue one, the transport does **not** start: an Agent must be
able to verify this Gateway, and there is no TOFU on this path either.

### Log outcomes / reasons

- `"no agent is connected for this node"` / `"the agent refused or could not serve the
  dial-back"` / `"node dial timed out"` — the user always sees the single generic §7.1
  outcome ("target node is offline or unavailable"). Check whether the node's Agent is
  registered (a control channel is logged as "agent control channel registered").
- `"agent missed two heartbeats; deregistering"` — the Agent is gone (network or process
  death); its node is unreachable until it reconnects. Reconnection is the Agent's job.
- `"control channel superseded by a newer connection"` — normal after an Agent reconnect
  (e.g. a partition healed). The newer connection wins by design; a stale channel must
  never lock a node out.
- `"refusing a locked agent (deny wins)"` / `"dial-back refused (fail closed)"` — a Lock
  covers this agent identity, or a dial-back token failed one of its bindings. The agent
  sees only the coarse `UNAUTHORIZED`; the specific reason is here, in the operator log.
  A dial-back token is **never** logged, persisted, or echoed.

### Node-local second trail (FR-AUD-4)

In the agent model the node's own `sshd` log is a **tamper-independent** second record:
the Gateway's inner certificate carries `key_id = session_id + principal`, and a node
running `LogLevel VERBOSE` logs that key-id on every accepted certificate. The two trails
cross-correlate on the session id with **no trust in the Agent** — which is exactly what
makes the second trail independent. To investigate a session on the node:
`journalctl -u ssh | grep '<session_id>'`.
