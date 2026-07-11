# F-observability-outcome-1: consistent outcome= on every §7.1 row
- Severity: info
- Status: Verified-Fixed
- Area: observability

## Risk (T3: reliability reviewer)
The §7.1 outcomes were logged inconsistently — some rows carried an `outcome=`
field, others did not — and there was no single per-connection record of an
auth-failed connection (methods tried / coarse reason), making the SSH surface hard
to monitor.

## Resolution (Verified-Fixed)
Every §7.1 row now carries a consistent structured `outcome=` field:
`blocked_source`, `auth_failed`, `policy_denied`, `device_flow_timeout`,
`cp_unavailable`, plus `authenticated`/`auth_succeeded`/`authorized` on the success
path. The accept loop emits **one consolidated record** when a connection ends
unauthenticated — `outcome = cp_unavailable | auth_failed` with the coarse
`methods_tried` list (no secrets) collected in `ConnState`.

## Evidence
`ssh/handler.rs` (`outcome=` fields, `ConnState::record_method`) and `ssh/mod.rs`
(`handle_connection` consolidated record). No OTP/token/key/plaintext appears in any
field (F-secretlog-1).
