# F-ha-drain-owner-relay-1 (M2 + L4): graceful drain ignored owner-role relays and did not finalize deadline survivors
- Severity: medium
- Status: Verified-Fixed
- Area: ha-drain

## Summary

Graceful drain waited only on the ingress `LiveSessionRegistry`. Relays this Gateway serves AS AN
OWNER (`peer_client::serve_relay`) are detached tasks with no registry, so a pure owner/relay
Gateway cut its live relayed sessions instantly on SIGTERM. Separately, sessions still live at the
drain deadline were dropped un-finalized on exit → orphaned (un-finalized) WORM objects.

## Location

- `gateway-core/src/ha/peer_client.rs` (`ServedRelays`), `gateway/src/main.rs` (drain),
  `gateway-core/src/ssh/locks.rs::terminate_all`

## Remediation — Verified-Fixed

- **M2:** `ServedRelays` registers each in-flight served relay; `drain_live_sessions` now waits for
  BOTH the ingress `live_sessions` AND `served_relays.active()` to reach zero (bounded by the
  deadline).
- **L4:** at the deadline, `LiveSessionRegistry::terminate_all()` tears remaining sessions down via
  the S9/S10 recorder-finalize path (recordings finalize) before `finalize_tracker.drain`.
