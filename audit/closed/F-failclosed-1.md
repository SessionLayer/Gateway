# F-failclosed-1: CP-unreachable fails closed, never open
- Severity: high
- Status: Verified-Fixed
- Area: reliability

## Risk
If the Gateway ever treated an unreachable/erroring CP as an implicit allow, a CP
outage (or a targeted disruption) would become an authentication/authorization
bypass (NFR-2, Design §2 step 3).

## Resolution (Verified-Fixed)
Every CP call is time-bounded (`cp_connect_timeout_secs` / `cp_rpc_timeout_secs`)
and every failure path denies:
- During authentication, a transport/timeout/status failure on a `Resolve*` call
  rejects that method (the connection ultimately fails auth — no access).
- At the connect-time `Authorize` decision, any error (transport, timeout, or a
  server-error status such as UNAVAILABLE) maps to `SshOutcome::ServiceUnavailable`
  → the user sees `"service temporarily unavailable"` and the session is refused.
- An `Authorize` ALLOW with an empty `session_token` is treated as a denial.

## Evidence
- `tests/outer_leg_it.rs` (`publickey_paths_and_error_taxonomy_e2e`): with the mock
  CP set to return UNAVAILABLE for `Authorize`, a stock `ssh` login gets the
  fail-closed `"service temporarily unavailable"` and a non-zero exit.
- `cpauth::tests` cover the redaction + timeout error surface.
