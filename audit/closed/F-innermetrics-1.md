# F-innermetrics-1: no RED / saturation metrics for the inner leg (logs only)
- Severity: low
- Status: Accepted-Risk
- Area: observability

## Risk (T3: reliability reviewer)
The inner leg emits structured logs but **no time-series metrics**: there is no
`prometheus`/`metrics`/`opentelemetry` dependency (Cargo.toml) and no counters,
histograms, or gauges anywhere on the hot path. At 3am an operator has only
`grep outcome=` — no alertable rate/latency/saturation series. For the Tier-0 data
plane this is the difference between "page fired on inner-leg error-rate SLO breach"
and "someone noticed users complaining."

Missing (RED + saturation) for the inner leg:
- **Rate/Errors:** counters per outcome (`bridged`, `node_unreachable`,
  `host_verification_failed`, `cp_unavailable`, `policy_denied`, `channel_cap`) per
  node / per listener.
- **Duration:** histograms for agentless dial, inner handshake, and
  `SignSessionCertificate` latency — with buckets covering the fail-closed bounds
  (connect 5s, handshake 10s, rpc 10s) so the SLO edge is visible.
- **Saturation:** gauges for active bridged sessions, open channels, live pump
  tasks, and connection-slot occupancy (`connection_slots` permits in use,
  ssh/mod.rs:82) — the early-warning signals for F-channelcap-1 / F-innertimeout-1.

## Fix
If a dedicated observability session owns platform metrics, record this as
**Accepted-Risk** with a pointer to that session and confirm the counter/gauge
seams (per-outcome, per-node, active-sessions) are reserved now so they drop in
without touching the bridge. Otherwise, add a minimal metrics facade behind the
same `outcome=` taxonomy this session.

## Verification
A `/metrics` (or equivalent) surface exposes per-outcome counters and dial/handshake
/sign histograms; an active-sessions gauge tracks bridge open/close.

## Disposition (Accepted-Risk)
The inner leg emits structured `tracing` with consistent `outcome=` fields (host_verified / bridged / node_unreachable / cp_unavailable / channel_cap / auth_succeeded), so operators have per-event signal. RED/saturation **metrics** need metrics infrastructure the platform does not yet expose (no Prometheus surface); that cross-cutting observability work is out of Tier-0 S8 scope.
