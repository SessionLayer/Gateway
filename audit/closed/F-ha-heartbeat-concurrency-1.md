# F-ha-heartbeat-concurrency-1 (M1): serial presence heartbeats can miss the staleness TTL at fleet scale
- Severity: medium
- Status: Verified-Fixed
- Area: ha-presence

## Summary

`HeartbeatLoop::tick` heartbeated owned nodes SERIALLY, so a full refresh scaled linearly with the
owned-node count. A HEALTHY Gateway holding ~300 nodes at ~100ms/RPC could not refresh within the
30s staleness TTL → the CP marks its OWN nodes stale → new sessions to them fail closed / ownership
flaps. Hits single-instance too.

## Location

- `gateway-core/src/ha/presence.rs::tick`

## Remediation — Verified-Fixed

Both the release and heartbeat passes now fan out with bounded concurrency
(`for_each_concurrent(HEARTBEAT_CONCURRENCY = 16)`), so a full refresh of hundreds of nodes stays
well inside the TTL without stampeding the CP. Test
`a_large_fleet_refreshes_concurrently_within_the_ttl_budget` (100 nodes @ 20ms/RPC completes < 1s;
a serial loop would take 2s). Operator guidance in RUNBOOK.md §HA/M1.
