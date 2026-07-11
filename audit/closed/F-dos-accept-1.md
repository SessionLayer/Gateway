# F-dos-accept-1: accept-path DoS is bounded (full Tier-0 hardening is S18)
- Severity: medium
- Status: Accepted-Risk
- Area: dos

## Risk
A slow/abusive peer could try to exhaust accept-path resources by opening many
connections and stalling during the SSH handshake.

## Why this is accepted (bounded, not unfixable this session)
The session bounds the accept path already:
- The pre-banner PROXY read is time-bounded (`handshake_timeout_secs`, default 10s).
- Concurrent connections are capped by a semaphore (`max_connections`, default 512);
  a connection over the cap is dropped at accept.
- russh's `inactivity_timeout` (mapped from `login_grace_secs`) garbage-collects an
  idle connection; the device-flow heartbeat keeps a *legitimate* slow login alive.

A tighter pre-auth timeout is deliberately **not** applied because the OIDC device
flow legitimately keeps a connection in the auth phase for minutes (FR-AUTH-4); the
`max_connections` cap is the DoS bound instead. Full Tier-0 hardening (seccomp /
landlock / read-only rootfs / per-source rate limits) is **Session Eighteen**
(NFR-5), explicitly out of scope here. The residual (≤`max_connections` stalled
handshakes for up to `login_grace_secs`) is bounded and operator-tunable.
