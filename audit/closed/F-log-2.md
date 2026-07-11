# F-log-2: CP-controlled gRPC status message logged unsanitized (GW-LOG-SANITIZE)

- Severity: low
- Status: Verified-Fixed
- Area: log

## Summary

`IdentityError::Rpc`, `SigningError::Rpc`, and `HandshakeError::Rpc` rendered the
wrapped `tonic::Status` via its `Display`, which includes the **CP-supplied
message** — untrusted wire text that can carry ANSI / newline sequences
(log-forging / terminal-escape) once logged (e.g. the renew-ahead loop's
`tracing::warn!(error = %e, …)`, or the process-exit stderr from `main`).

## Fix

Neutralised **at the source**: the three `Rpc` error `Display` impls now render
only the gRPC **status code** (`#[error("… (gRPC status {:?})", .0.code())]`),
never the CP message. The `Code` enum is not attacker-controlled; the full
`Status` (with its code) remains available programmatically for matching. This
covers every current and future log/stderr sink that formats these errors via
`Display`, without needing per-site sanitisation. Peer-supplied diagnostic
strings in the handshake (`ComponentInfo` name/semver) were already run through
`sanitize_diagnostic` (handshake.rs) and remain so.

### Source-chain path (GW-3 residual, also fixed)

`#[from] tonic::Status` makes the `Status` the error's `source()`. If an
`IdentityError` from `enroll`/startup-`renew` propagated with a bare `?` up to
`fn main() -> anyhow::Result<()>`, the `Termination` **Debug**-print of the
returned `Err` walks the `source()` chain and would emit the `tonic::Status`'s
own `Display` (the full CP message) to startup stderr — bypassing the code-only
`Display`. Fixed by wrapping at the `bootstrap_identity` boundary with
`.map_err(|e| anyhow::anyhow!("gateway enrollment/renewal failed: {e}"))?`: the
`anyhow!` error carries only the code-only `Display` string and **no**
`tonic::Status` source, so the Debug walk stays clean (mirrors the
version-negotiation wrap). Regression test
`rpc_error_and_boundary_wrap_do_not_leak_cp_message` asserts a `\n`/ANSI CP
message appears in neither the `Display` nor the wrapped `Debug`, and that the
wrapped error has no source chain.

## Verification

Existing tests match on the error *variant* / status *code* (not the message), so
they are unaffected; all green. Full gate green.
