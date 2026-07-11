# F-token-1: bearer tokens held in un-zeroized plain Strings (GW-TOKEN-ZEROIZE)

- Severity: low
- Status: Verified-Fixed
- Area: identity

## Summary

The operator-provided enrollment token (a bearer credential) was held in a plain
`String` on `config::BootstrapConfig.enrollment_token`, and `BootstrapConfig`
derived `Debug` — so a config dump/log could leak it and the heap copy was not
scrubbed on drop.

## Fix

- `BootstrapConfig.enrollment_token` is now a `Zeroizing<String>` (scrubbed on
  drop) via the shared `#[serde(with = "crate::secret::serde_zeroizing_string")]`
  adapter.
- `BootstrapConfig` no longer derives `Debug`; a manual `Debug` **redacts** the
  token (`enrollment_token: "<redacted>"`), so `GatewayConfig`'s derived `Debug`
  can never surface it.

## Residual (accepted)

The single-use tokens are also copied into the prost-generated request structs
(`EnrollGatewayRequest.enrollment_token`, `SignSessionCertificateRequest.session_token`)
and prost's internal wire buffers, which are plain `String`/`Vec<u8>` we cannot
make `Zeroizing` without patching generated code. This is a transient, single-use,
short-TTL bearer value; the persistent config copy (the durable one) is now
zeroized + redacted. Accepted as a prost limitation.

## Verification

Config (de)serialisation tests green; full gate green.
