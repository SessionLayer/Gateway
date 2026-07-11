# F-negotiate-2: version negotiation implemented but not invoked at runtime (GW-VERSION-NOT-INVOKED)

- Severity: low
- Status: Verified-Fixed
- Area: version

## Summary

`handshake::negotiate_over_channel` was implemented + tested, but nothing in
`main.rs::run()` / `bootstrap_identity` called it, so FR-HA-9's "negotiate a
common version at connect" was not actually enforced at runtime.

## Fix

`bootstrap_identity` now negotiates over a bootstrap (server-auth) channel at
connect — against the issued CA chain if enrolled, else the operator-pinned
bootstrap CA — **before** enrolling or renewing, and fails closed (aborts
startup) on a mismatch/disjoint range. The negotiated version is logged.

## Verification

`cargo build`/clippy green; the negotiation path is covered by the mtls_it tests
(`valid_bootstrap_channel_negotiates_1_1`, `n_minus_one_negotiates_1_0`) and the
handshake unit tests. Full gate green.
