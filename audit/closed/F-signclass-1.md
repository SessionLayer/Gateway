# F-signclass-1: SignSessionCertificate CP-infra faults are misclassified as a node fault (taxonomy)
- Severity: low
- Status: Verified-Fixed
- Area: taxonomy

## Summary (T3: security-reviewer — API-contract/error-classification)
`SigningError::is_cp_down` (`gateway-core/src/signing.rs`) ignores the gRPC status
**code**, unlike its sibling `CpError::is_cp_down` (`cpauth.rs`):

```rust
// signing.rs
pub fn is_cp_down(&self) -> bool {
    matches!(self, SigningError::Unavailable | SigningError::Timeout(_))
}
```

A `SignSessionCertificate` call that reaches the CP but fails **server-side**
(session-CA unavailable, CP DB/internal error) returns `SigningError::Rpc(Status)`
with code `UNAVAILABLE` / `INTERNAL` / `DEADLINE_EXCEEDED`. `is_cp_down()` returns
`false`, so `handler.rs::establish_inner` takes the node-fault arm:

- the user sees `NODE_UNREACHABLE` ("the target node is offline or unavailable")
  instead of `SERVICE_UNAVAILABLE` ("service temporarily unavailable"), and
- `note_cp_down("sign")` is **not** called, so `ConnState.cp_unavailable` is never
  set and the consolidated end-of-connection record logs the wrong `outcome=`.

The identical CP-infrastructure fault on the adjacent `Authorize` RPC *is*
classified as CP-down (`CpError::is_cp_down` matches `Unavailable|Internal|…`), so
two back-to-back RPCs disagree on the same failure. This is the same §7.1 taxonomy
divergence that F-cpdown-taxonomy-1 (closed, medium) fixed for the resolution path,
here reintroduced on the signing path.

Not a security bypass: every arm fails closed and stays generic to the user (no
disclosure). Impact is user-message accuracy + operator observability only → low.

## Root-cause fix
Classify `Rpc(status)` by code in `SigningError::is_cp_down`, mirroring
`CpError::is_cp_down` but **excluding** the token-fault codes: a signing
`UNAUTHENTICATED` / `PERMISSION_DENIED` / `INVALID_ARGUMENT` almost always means the
single-use `session_token` was rejected (bad/expired/replayed) — a token/policy
fault that must stay `NodeUnreachable`, not `ServiceUnavailable`.

```rust
pub fn is_cp_down(&self) -> bool {
    match self {
        SigningError::Unavailable | SigningError::Timeout(_) => true,
        SigningError::Rpc(s) => matches!(
            s.code(),
            tonic::Code::Unavailable | tonic::Code::Internal
                | tonic::Code::DeadlineExceeded | tonic::Code::Unknown
                | tonic::Code::DataLoss
        ),
        _ => false,
    }
}
```

Add a `signing::tests` case asserting `Rpc(Status::internal)` ⇒ cp_down and
`Rpc(Status::permission_denied)` (token replay) ⇒ not cp_down.

## Resolution (Verified-Fixed)
`SigningError::is_cp_down` now classifies `Rpc(status)` by gRPC code (Unavailable/Internal/DeadlineExceeded/Unknown/DataLoss → CP-down → service-unavailable), **excluding** token-fault codes (UNAUTHENTICATED/PERMISSION_DENIED/INVALID_ARGUMENT → stays NodeUnreachable, a token replay/expiry). Mirrors `CpError::is_cp_down`. Test `cp_down_classifies_signing_faults_by_code`.
