# F-secretlog-1: no SSH secret / OTP / token / key / plaintext is logged
- Severity: high
- Status: Verified-Fixed
- Area: logging

## Risk
The Gateway is Tier-0. Logging an OTP, a session-signing token, a private key, a
device_code, or a CP-supplied string verbatim would leak secrets or allow
log-injection / terminal-escape via untrusted wire text.

## Resolution (Verified-Fixed)
- The OTP is read into a `Zeroizing<String>` (scrub-on-drop) and passed to the CP;
  it is never a log field. (Residual: prost transit buffers are not zeroized — see
  F-otp-transit-1.)
- The minted `session_token` lives in `SessionGrant`, whose `Debug` redacts it; it
  is never logged.
- `SigningError`/`CpError`/`IdentityError` render only the gRPC status **code**,
  never the CP-supplied message.
- Client- and CP-supplied strings shown in a log field or on the terminal
  (username, resolved identity, device-flow `verification_uri`/`user_code`) pass
  through `sanitize()` (strips control chars, bounds length).
- No private-key or plaintext bytes are logged anywhere on the outer leg.

## Evidence
- `ssh::handler::tests::sanitize_strips_control_and_bounds_length`,
  `ssh::outcome::tests::messages_are_terminal_safe`,
  `ssh::connector::tests::session_grant_debug_redacts_token`,
  `cpauth::tests::rpc_error_renders_only_the_status_code`.
