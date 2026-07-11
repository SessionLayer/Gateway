# F-signtimeout-1: SignSessionCertificate had no independent deadline (GW-SIGN-TIMEOUT)

- Severity: low
- Status: Verified-Fixed
- Area: signing

## Summary

`signing::sign_session_certificate` was bounded only if the injected
`tonic::transport::Channel` happened to carry a `.timeout()`. On the (future
S7/S8) SSH hot path a hung CP could hang the handshake (violates §10.3's
"bounded gRPC timeout so a hung peer never hangs the handshake").

## Fix

`sign_session_certificate` takes an explicit `timeout: Duration` and wraps the RPC
in `tokio::time::timeout`; an elapsed deadline is a fail-closed
`SigningError::Timeout(_)` (no certificate). This makes the reusable signer API
independently bounded regardless of the channel configuration.

## Verification

New integration test `signing_times_out_against_a_hung_cp` (mock CP configured to
never respond) asserts the call returns `Timeout` within its bound. Full gate green.
