# F-lockfeed-fleet-scale-1: feed reconnect/teardown fan-out is unbounded at fleet scale
- Severity: low
- Status: Accepted-Risk
- Area: ssh-lockfeed

## Observation (T3: reliability)
(1) The reconnect backoff has no jitter, so a CP blip makes the whole fleet reconnect
on the same schedule (thundering herd), each running a full O(sessions×locks) reconcile.
(2) A global lock (`all=true`) tears down every live session synchronously on the feed
task, spawning a disconnect each — an executor burst / feed-apply stall at very large
fleet sizes.

## Disposition — Accepted-Risk (scale follow-up)
Correct at the expected per-Gateway scale of this session (S10 does per-Gateway push +
resync; multi-Gateway/HA fan-out consistency + coordination is explicitly **S14**). The
mitigations (± reconnect jitter, reset-backoff-only-after-first-snapshot, chunk+yield
teardown, cap disconnect concurrency, facet-indexed matching) are S14 HA-scale work.
Backoff IS bounded (0.5s→10s) and reset on a healthy connect; a single global lock at
today's scale completes promptly.
