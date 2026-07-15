# F-ha-metrics-accepted-risk (item 19): metrics framework deferred; interim structured-log visibility
- Severity: low
- Status: Accepted-Risk
- Area: observability

## Summary

The HA work adds no metrics framework (counters for presence claim/refresh/loss, relay outcomes).
A dedicated metrics/telemetry framework remains deferred.

## Rationale (Accepted-Risk, with precedent)

The metrics FRAMEWORK has been carried as Accepted-Risk since S8, and again at S12/S14 — introducing
a telemetry stack is its own cross-cutting workstream, out of scope for the HA session. Interim
visibility is provided by structured `tracing` fields that an operator (or a log-based alert) can
count and correlate:
- `event=peer_relay_serving` / `event=peer_relay_closed` — relay throughput as an owner.
- `presence …` lines (standby / heartbeat-failed / release) — ownership transitions.
- `outcome=node_unreachable reason=…` — every fail-closed routing decision, keyed by cause.

RUNBOOK.md §HA/Observability documents these. When the metrics framework lands it should promote
these log points to counters.
