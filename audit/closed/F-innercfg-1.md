# F-innercfg-1: inner-leg bounds are not validated (zero timeouts / window < packet)
- Severity: low
- Status: Verified-Fixed
- Area: config-validation

## Risk (T3: reliability reviewer)
`validate_config` (ssh/mod.rs:275) checks device-flow timing and
`max_session_idle_secs >= login_grace_secs`, but nothing in the new
`InnerLegServerConfig` block is validated. Misconfigurations that are fail-closed
but manifest as an undiagnosable total outage slip through:

- `connect_timeout_secs = 0` → `AgentlessDial::new(Duration::ZERO)` → every dial
  times out immediately → every session fails closed as `node_unreachable`
  (connector.rs:128).
- `handshake_timeout_secs = 0` → every inner handshake times out (innerleg.rs:112).
- `max_packet_bytes = 0`, or `window_bytes < max_packet_bytes` → broken/stalled
  inner flow control (russh advertises a window smaller than a single packet).
- `window_bytes = 0` → no window ever granted; all bridged data stalls.

`deny_unknown_fields` catches typos, but not a semantically-invalid-but-known knob.
At 3am "every session says node offline" with no config error is the worst kind of
outage to chase.

## Fix
Extend `validate_config` (the pattern already exists) to reject:
`connect_timeout_secs == 0`, `handshake_timeout_secs == 0`, `max_packet_bytes == 0`,
`window_bytes == 0`, and `window_bytes < max_packet_bytes` — each with a clear
`SshServerError::Config(_)` message. Consider a sane floor on `max_packet_bytes`
(RFC 4254 interop minimum 32 768) as a warning.

## Verification (suggested)
Unit cases mirroring `config_validation_fails_closed_on_bad_timing`
(ssh/mod.rs:371) for each rejected inner-leg value.

## Resolution (Verified-Fixed)
`validate_config` now fails closed on zero connect/handshake timeouts, `window_bytes < max_packet_bytes` (or zero packet), and `max_channels_per_connection == 0` — rejected at bind.
