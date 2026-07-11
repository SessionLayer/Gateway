# F-preauth-grace-1: bound pre-auth slot-camping + CP-RPC amplification
- Severity: medium
- Status: Verified-Fixed
- Area: dos

## Risk (T3: reliability + protocol reviewers)
russh 0.62 does not enforce `max_auth_attempts` (it increments a counter but never
compares it), and its `inactivity_timeout` resets on every packet. So a single
unauthenticated peer can (a) camp a Tier-0 connection slot indefinitely by dribbling
packets, and (b) drive unbounded CP resolve-RPCs — one signed publickey offer →
one `ResolvePin`/`ResolveUserCert` — over one connection.

## Resolution (Verified-Fixed)
Two app-level bounds, both fail-closed:
- **Auth-attempt cap** — `SshHandler::attempt_cap_exceeded()` counts every
  credential resolution (pin/cert/OTP); once `SshServerConfig::max_auth_attempts`
  (default 6) is exceeded, the handler returns `hard_reject()` (an empty
  proceed-methods set → the client cannot continue → the connection ends) **before**
  any further CP call. This bounds the CP-RPC amplification. Device-flow polls are
  not counted (they are bounded by the poll deadline instead).
- **Absolute pre-auth deadline** — the accept loop arms a watchdog at accept
  (`ConnState::authenticated` + `Handle::disconnect`) that drops the connection if
  auth has not completed within `login_grace_secs`, regardless of packet activity.
  It is disarmed in `auth_succeeded`. A legitimate device flow finishes within
  `poll_timeout_secs < login_grace_secs` (F-config-validation-1), so real logins are
  unaffected; S7 sessions close at the seam anyway, so this is pure upside.

## Evidence
`ssh/handler.rs` (`attempt_cap_exceeded`, `hard_reject`, `ConnState`), `ssh/mod.rs`
(`handle_connection` watchdog). Behavioural fail-closed cases proven by the E2E
suite; the reliability reviewer re-runs the slot-camping / amplification repro.
