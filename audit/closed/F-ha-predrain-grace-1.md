# F-ha-predrain-grace-1 (M3 + L5): no LB-deregister window before stop-accepting; control channels not closed on drain
- Severity: low
- Status: Verified-Fixed
- Area: ha-drain

## Summary

`/readyz`→503 and stop-accepting were driven off the SAME shutdown edge, so there was no window for
the LB to deregister this Gateway before it stopped listening (contradicts FR-HA-7 ordering).
Separately, agent control channels were not proactively closed on drain, so agents failed over only
after a heartbeat-miss timeout.

## Location

- `gateway/src/main.rs` (drain sequencing), `gateway-core/src/agent/server.rs::run_control`,
  `gateway-core/src/config.rs` (`DrainConfig::pre_drain_grace_secs`)

## Remediation — Verified-Fixed

- **M3:** `run` now splits the OS signal from the begin-drain signal. On SIGTERM it flips `/readyz`
  to 503 and KEEPS ACCEPTING for `ha.drain.pre_drain_grace_secs` (default 5s), THEN fires the drain
  signal (stop accepting, release presence, close channels). Size the LB probe so it deregisters
  within the grace.
- **L5:** `run_control` watches the drain signal and closes the control channel promptly so the
  agent fails over (Presence.Release + standby already covers correctness; this makes it prompt).
