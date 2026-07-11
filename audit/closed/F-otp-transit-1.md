# F-otp-transit-1: OTP is zeroized on the Gateway; gRPC transit is not
- Severity: low
- Status: Accepted-Risk
- Area: zeroize

## Observation
The keyboard-interactive OTP is held in a `Zeroizing<String>` in the handler
(scrubbed on drop) and is never logged. However, `CpAuthClient::resolve_otp`
copies it into a prost `ResolveOtpRequest` for the gRPC call, and prost/tonic
serialization buffers are not zeroized.

## Why this is accepted (genuinely needs prost-level support)
Full transit zeroization would require zeroize-aware buffers throughout prost and
tonic, which the ecosystem does not provide — the same boundary accepted for the
session token in Session Four (`signing.rs`). Mitigating factors: the OTP is
single-use and short-TTL (60–300s, consumed atomically by the CP, S6), never
logged, and the handler copy is scrubbed. The authoritative OTP security
(constant-time compare, atomic mark-used, source binding, rate limiting) lives in
the CP. The residual in-memory window on the Gateway is small and unavoidable
without upstream changes.
