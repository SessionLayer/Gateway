# F-ha-relay-budget-1 (L1): ingress relay_timeout could be below the owner's worst-case establish budget
- Severity: low
- Status: Verified-Fixed
- Area: ha-routing

## Summary

The ingress `relay_timeout` default (10s) could be less than the owner's worst-case establish
budget — its local agent dial-back (~10s) plus the relay handshake (~10s) ≈ 20s — so the ingress
could give up on a slow-but-HEALTHY owner and fail the session closed unnecessarily.

## Location

- `gateway-core/src/config.rs` (`RoutingConfig::relay_timeout_secs`), `gateway/src/main.rs` (token TTL)

## Remediation — Verified-Fixed

Default `relay_timeout_secs` raised to 25s — above the owner's worst-case budget, still well below
the SSH `login_grace_secs` (300s) so a hung peer never hangs the handshake. The SLGW1 token TTL is
minted above `relay_timeout` in turn (`relay_timeout + 20`). Test `ha_defaults_...` asserts
`relay_timeout_secs > 20` and `< login_grace_secs`.
