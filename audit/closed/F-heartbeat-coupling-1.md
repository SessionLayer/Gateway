# F-heartbeat-coupling-1: decouple the KI heartbeat cadence from poll latency
- Severity: low
- Status: Verified-Fixed
- Area: reliability

## Risk (T3: reliability + protocol reviewers)
The `num-prompts=0` heartbeat cadence was `CP-poll-latency + heartbeat_interval`
(~20s with defaults: a 10s poll timeout + a 10s sleep), above the FR-AUTH-4 ~10s
target, risking a stock-client idle timeout during device-flow polling.

## Resolution (Verified-Fixed)
`device_flow_step` now bounds each poll by the heartbeat interval
(`tokio::time::timeout(interval, poll)`) and then sleeps only the **remainder** of
that interval (`interval.saturating_sub(elapsed)`, never past the deadline) before
emitting the next info-request. The client-visible gap between heartbeats is
therefore ≈ `heartbeat_interval` regardless of poll latency (a slow poll → the
info-request follows immediately; a fast poll → the remainder is slept).

## Evidence
`ssh/handler.rs::device_flow_step`. The device-flow E2E
(`keyboard_interactive_otp_device_flow_and_degradation_e2e`) still completes across
heartbeats + approval with `heartbeat_interval_secs = 1`.
