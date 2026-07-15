# F-ha-nodename-1 (item 1): presence addressed by node_id; E2E masked the name→id path with a UUID-shaped name
- Severity: high (build-breaking + correctness masking)
- Status: Verified-Fixed
- Area: ha-presence

## Summary

The re-vendored `presence.proto` renamed the request field `node_id → node_name` (the contract now
honestly says the Gateway sends the node NAME; the CP resolves name→node.id). The Gateway's
`cpauth::presence_heartbeat/release` still built the old field. Separately, the HA E2E used a
node name that could be UUID-shaped, which would have masked the CP's name→id resolution path.

## Location

- `gateway-core/src/cpauth.rs`, `gateway-core/tests/support/mod.rs` (MockCp Presence),
  `gateway-core/tests/ha_e2e.rs`

## Remediation — Verified-Fixed

- `cpauth` now builds `PresenceHeartbeatRequest{node_name, gateway_addr}` /
  `PresenceReleaseRequest{node_name}` (`HeartbeatLoop` already sends `owned_node_names()`); the
  MockCp Presence handler reads `r.node_name`. (Committed `1d3d171`.)
- The HA E2E node is a REAL human name (`web-01`, NOT UUID-shaped), so it exercises the fixed
  name-addressed path.
