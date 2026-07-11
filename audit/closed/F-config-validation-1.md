# F-config-validation-1: validate SSH timing at bind, warn on permissive config
- Severity: low
- Status: Verified-Fixed
- Area: security

## Risk (T3: security + reliability + protocol reviewers)
Inconsistent timing config could misbehave silently: `heartbeat_interval_secs = 0`
busy-polls the CP; `poll_timeout_secs >= login_grace_secs` lets the device flow
outlast the pre-auth deadline; a permissive (allow-all) source-IP gate or PROXY-off
posture behind an LB is a silent security downgrade.

## Resolution (Verified-Fixed)
`ssh::validate_config` (called at the top of `bind`, fail closed) rejects:
- `heartbeat_interval_secs == 0`,
- `poll_timeout_secs >= login_grace_secs`,
- `heartbeat_interval_secs >= login_grace_secs`.
`bind` additionally emits a startup `warn!` when the SSH server is enabled with an
empty `source_ip_allowlist` (allow-all gate) and when `proxy.lb_cidrs` is empty
(PROXY off — the LB address would become the source IP for every client).
`SshServerConfig` keeps `#[serde(deny_unknown_fields)]`, so a misspelled key already
fails closed.

## Evidence
`ssh/mod.rs` (`validate_config`, `bind` warnings) + the
`config_validation_fails_closed_on_bad_timing` unit test.
