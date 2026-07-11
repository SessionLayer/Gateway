# F-dos-accept-1: accept-path DoS is bounded
- Severity: medium
- Status: Verified-Fixed
- Area: dos

## Risk
A slow/abusive peer could try to exhaust accept-path resources by opening many
connections and stalling during the SSH handshake, and/or drive unbounded CP
resolve-RPCs over a single connection.

## Resolution (Verified-Fixed)
The accept path is bounded at every stage:
- The pre-banner PROXY read is time-bounded (`handshake_timeout_secs`, default 10s).
- Concurrent connections are capped by a semaphore (`max_connections`, default 512);
  a connection over the cap is dropped at accept.
- **Absolute pre-auth deadline** (F-preauth-grace-1): a per-connection watchdog
  armed at accept drops the connection if authentication has not completed within
  `login_grace_secs`. Unlike russh's `inactivity_timeout` (which resets on every
  packet and so does not stop a slow-loris), this is a wall-clock deadline; it is
  disarmed in `auth_succeeded`. Because a legitimate device flow completes within
  `poll_timeout_secs < login_grace_secs` (enforced by config validation,
  F-config-validation-1), this bounds slot-camping with no cost to real logins.
- **App-level auth-attempt cap** (`max_auth_attempts`, default 6): bounds the
  CP-RPC amplification a single connection can drive.

## Residual (Accepted, Session Eighteen)
Full Tier-0 hardening — seccomp / landlock / read-only rootfs / per-source rate
limits — is **Session Eighteen** (NFR-5), explicitly out of scope here. The
remaining residual (≤`max_connections` handshakes each bounded by
`login_grace_secs`) is bounded and operator-tunable.
