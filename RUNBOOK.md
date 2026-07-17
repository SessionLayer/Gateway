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
- `heartbeat_interval_secs` (1–300) and `max_frame_bytes` (4 KiB–1 MiB) are bounded by the
  **wire contract §3** and enforced from BOTH ends: a value outside the range is refused at
  startup, precisely so the Gateway cannot boot healthy and then be refused by every Agent.
- `max_connections` (4096) caps concurrent sockets — distinct from `max_agents` (registered
  nodes) — and must be `>= max_agents`.

### Deny fails closed on the agent surface

The agent transport honours the actively-pushed Lock deny-set exactly as the session path
does: **a deny-feed that cannot be confirmed is treated as a deny.** Consequences an
operator should expect:

- On boot, the transport does **not** accept agent connections until the lock feed has
  delivered its first snapshot (log: `"agent transport waiting for the lock feed before
  serving agents"`). If the CP lock stream is down, **no agent nodes are served** — they are
  "offline" (§7.1). This is the correct deny-wins trade; usually the CP being down also means
  `Authorize` is failing closed, so few sessions were possible anyway. It self-heals the
  moment the feed connects.
- Mid-life, if the lock stream drops, new registrations and dial-back redemptions are refused
  (log `reason=lock_feed_unhealthy`) until it reconnects. Already-spliced sessions continue.

The Gateway obtains its agent-facing **serverAuth** certificate from the CP
(`GatewayIdentity.IssueGatewayServerCertificate`) over a separate, never-persisted
keypair. If the CP will not issue one, the transport does **not** start: an Agent must be
able to verify this Gateway, and there is no TOFU on this path either.

### Log outcomes / reasons

- `"no agent is connected for this node"` / `"the agent refused or could not serve the
  dial-back"` / `"node dial timed out"` — the user always sees the single generic §7.1
  outcome ("target node is offline or unavailable"). Check whether the node's Agent is
  registered (a control channel is logged as "agent control channel registered").
- `"agent missed two heartbeats; deregistering"` (`reason=missed_heartbeats`) — the Agent is
  gone (network or process death); its node is unreachable until it reconnects. A
  slow-but-alive agent whose round-trip approaches the heartbeat is NOT killed (a late PONG
  still counts), so this line means genuinely no answer for two intervals.
- `reason=agent_signal_saturated` — the node's Agent is registered and answering, but its
  control-channel queue stayed full for the whole dial-back window: a **capacity shed under
  load**, NOT a dead agent. Do not chase the agent; look at session concurrency to that node.
- `reason=dial_back_timeout` / `reason=agent_refused_or_local_dial_failed` /
  `reason=no_agent_registered` — the distinct node-offline causes, each its own structured
  event so an alert can key on the cause rather than a free-text field.
- `"SECURITY/OPS: adopted a certificate already expired at this Gateway's clock"` — the CP
  issued a cert already expired at this host's clock (clock skew beyond the TTL, or a CP TTL
  misconfig). The renew loop **stops** rather than storm the CP / burn the generation counter.
  **Fix NTP or the CP certificate TTL, then restart the Gateway.** Its identity will expire;
  treat this as urgent.
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

## High Availability (Session Fifteen; Design §10.2/§10.3)

The default mode is **single-instance** with an in-process signal bus and zero extra
dependencies — single-instance operators can ignore the NATS/relay guidance below.
Ownership, the coordination subject, and the relay token are keyed by the gateway
**NAME** (`gateway_identity.name`), never its UUID. **Session bytes never traverse the
coordination bus** — only the `DialBackSignal` does.

### Draining a Gateway gracefully (SIGTERM ordering — FR-HA-7)

On `SIGTERM`/`SIGINT` the Gateway drains in order (`ha.drain.*`):

1. `/readyz` flips to **503** but the Gateway KEEPS ACCEPTING for
   `pre_drain_grace_secs` (default 5s). Size your LB so
   `probe_interval × unhealthy_threshold ≤` this grace, so the LB deregisters this
   Gateway *before* it stops accepting (no window where the LB still routes a new
   connection to a Gateway that has stopped listening).
2. Accept loops stop; the heartbeat loop **releases presence** so a standby claims at
   once; agent control channels close so agents fail over.
3. Live sessions — both this Gateway's own ingress sessions AND relays it serves as an
   owner — finish to `deadline_secs` (default 30s); they are **not** cut instantly.
4. Any session still live at the deadline is torn down via the recorder-finalize path
   (recordings finalize; no orphaned WORM object), then in-flight finalizes drain.

Point the LB health check at `GET ha.drain.readyz_addr/readyz` (200 `ready` /
503 `draining`); empty `readyz_addr` disables it (default).

**No live migration (FR-HA-7):** a relayed session does **not** survive the death of the
*owner* it runs on — the client reconnects (cheap, pinned-key silent reconnect) and
re-routes to the new owner. A session whose node is owned by the *ingress itself* is
unaffected by any other Gateway's drain.

### "Not owner" / presence contention — expected behaviour

Several Gateways may hold a live control channel for the same node, but only one **owns**
it (the monotonic-nonce claim). A non-owner is a warm **standby** — it keeps the channel
and keeps heartbeating, taking over the instant the owner goes stale (~30s TTL). The log
`presence: standby (another gateway owns this node)` is **normal**, not an error. A
heartbeat that fails (CP unreachable / stale-nonce reject) means the Gateway simply does
not own the node this tick; a session routed to it fails closed and self-heals next tick.

### M1 — presence-refresh flap on a large fleet

**Symptom:** a HEALTHY Gateway holding many nodes intermittently marks its own nodes
stale; new sessions fail closed; ownership flaps.
**Cause:** the per-node heartbeat RPCs did not all complete within the staleness TTL.
Heartbeats fan out ~16-wide, so hundreds of nodes at ~100ms/RPC stay inside the 30s TTL,
but a slow CP or a very large fleet can still blow the budget.
**Mitigation:** cut CP `Presence.Heartbeat` latency; add Gateways to lower owned-node count
per Gateway; or raise `ha.presence.heartbeat_interval_secs` / `staleness_ttl_secs` in
lockstep on BOTH the Gateway and the CP. Watch the `presence heartbeat failed` rate.

### NATS coordination bus (HA only)

The bundled NATS client is a minimal **core** pub/sub client connecting in **plaintext
with an unauthenticated CONNECT** — it targets a **trusted internal network** and is
deliberately dependency-free (supply-chain rationale).

- **Production requirement:** run the bus mutually authenticated + TLS + subject-authorized
  (only the owner may `SUB sl.dialback.<owner>`; only ingress Gateways may `PUB`). Provide
  TLS/auth via a **co-located sidecar** (localhost TLS-terminating proxy / NATS leaf-node
  TLS boundary), or substitute a TLS-capable `CoordinationBackend`.
- **Fail-loud:** if the broker advertises `tls_required`/`auth_required` this plaintext
  client cannot meet, the connection manager logs a single loud error and **stops** (no
  reconnect loop). HA signalling is then DOWN and remote-owned sessions fail closed — fix
  the sidecar/broker config and restart.
- **No-owner is invisible on NATS:** a `PUB` to a subject with no subscriber succeeds
  silently, so an absent owner is not surfaced at publish time; `ha.routing.relay_timeout_secs`
  is the backstop (the ingress waits out the bound and fails closed).
- **Defence-in-depth:** the owner drops a stale/replayed signal (owner_nonce older than its
  current presence nonce) and caps concurrent relays per node — bus publish-authz is the
  first line, these back it up.

### Observability (interim)

The metrics framework is deferred (Accepted-Risk, per the S8/S12/S14 precedent). Until it
lands, use the structured logs: `event=peer_relay_serving` / `event=peer_relay_closed`
(relay throughput as an owner), the `presence …` lines (ownership claim/standby/loss), and
`outcome=node_unreachable reason=…` (fail-closed routing).

## Tier-0 runtime hardening (Session Twenty-One; Design NFR-5)

The Gateway hardens **itself** at startup — after binding its listeners it drops
privileges, confines the filesystem with Landlock, and installs a seccomp syscall filter —
and ships with a container / OS security-context layer that composes with it. All of it is
OFF by default and enabled via the `hardening` config block; the deployment artifacts and
the full config reference live in **[`deploy/README.md`](deploy/README.md)** (hardened
Dockerfile, Kubernetes `securityContext` + egress NetworkPolicy, systemd unit).

Operational notes:
- **Roll out seccomp in stages.** Set `hardening.seccomp.mode` to `log` first, run a full
  session, and confirm `dmesg`/auditd shows no unexpected `SECCOMP` audit line before
  flipping to `enforce`. In `enforce`, an unlisted syscall returns `EPERM` (the op fails,
  the process does not crash); the exploitation set (`execve`/`ptrace`/module-load/…) is
  `KILL_PROCESS` — a `gateway` process that dies on one of those has attempted something it
  never legitimately does (treat as a compromise signal, not a flake).
- **Fail-closed vs degrade.** A requested step that cannot apply for an operator-controlled
  reason (privilege drop while not root, unknown user, a rule the kernel rejects) **aborts
  startup**. Only a kernel that lacks Landlock/seccomp entirely **degrades** with a loud
  warning (Accepted-Risk) — on such a host, lean on the container read-only rootfs +
  dropped capabilities.
- **Landlock allow-set.** If you enable `hardening.landlock`, remember it confines *all*
  filesystem access: a dynamically-linked binary must be allowed the library dirs
  (`/lib`,`/lib64`,`/usr/lib` — `getaddrinfo`/`getpwnam` load `libnss_*.so` at runtime),
  `/etc/resolv.conf`+`/etc/nsswitch.conf`+`/etc/hosts`, `/dev`, and the CA/config/data
  paths. A missing path denies that access (see the `deploy/` reference set).
