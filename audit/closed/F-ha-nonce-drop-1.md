# F-ha-nonce-drop-1 (F4): owner did not drop stale/replayed signals or cap concurrent relays per node
- Severity: medium
- Status: Verified-Fixed
- Area: ha-relay

## Summary

An attacker able to PUBLISH to the coordination bus (without any subject-read) could make an owner
repeatedly perform its local dial-back (signalling-amplification), and a stale/replayed
`DialBackSignal` could trigger a node dial-back after ownership had advanced.

## Location

- `gateway-core/src/ha/peer_client.rs::serve_relay`, `ServedRelays`

## Remediation — Verified-Fixed

Before any costly work, `serve_relay` now:
1. **Drops a stale/replayed signal** whose `owner_nonce` is older than the ownership epoch the
   owner last observed in its `OwnerCache` (`RelayError::StaleNonce`) — no node dial-back occurs.
2. **Caps concurrent served relays per node** via `ServedRelays` (default 8/node), failing closed
   (`RelayError::PerNodeCap`) over the cap. The same registry backs the graceful-drain wait (M2).

Publish-authz on the bus (§8) is the first line; these are defence-in-depth. Unit test:
`served_relays_caps_per_node_and_counts_active_for_drain`.
