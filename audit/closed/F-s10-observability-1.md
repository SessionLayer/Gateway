# F-s10-observability-1: no RED/health metrics on the S10 re-eval + lock-feed path
- Severity: info
- Status: Accepted-Risk
- Area: observability

## Observation (T3: reliability, both repos)
No metrics on the feed-health gauge, reconnect counter, locks-applied/removed,
teardowns/sec, or per-channel re-validate/re-authorize RED — an on-call cannot alert on
"lock feed unhealthy" or "reconnect storm", and a dead CP hub is indistinguishable from
"no locks changed" without a subscriber-count metric.

## Disposition — Accepted-Risk (consistent with S8 F-innermetrics)
Structured `tracing` with consistent `outcome=` is present on every path (feed
connect/disconnect, lock add/remove/snapshot with torn_down counts, per-channel
denials), and the deny reason never leaves the operator log. RED metrics need the
metrics infrastructure the platform does not yet expose (same posture as S8
`F-innermetrics`). A RUNBOOK for the S10 surface (feed-unhealthy, reconnect-storm,
lock-applied-but-session-live, teardown-storm, SIGTERM drain) is captured for the
operator docs. Metrics land when the platform metrics stack does.
