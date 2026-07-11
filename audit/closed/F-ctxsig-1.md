# F-ctxsig-1: S7 trusts the connect-time decision over authenticated mTLS
- Severity: medium
- Status: Accepted-Risk
- Area: authz

## Observation
The outer leg accepts the `Authorize` decision (ALLOW + minted session token +
decision context) without verifying the decision-context **signature**
(`signed_context`/`signature`/`signer_certificate`).

## Why this is accepted (by design; not a fixable defect this session)
The decision is delivered over the **mutually-authenticated TLS 1.3 channel** the
Gateway already pins to the CP (S4); the CP is therefore authenticated as the
decision authority for this connect-time round-trip, and the Gateway requires
`decision == ALLOW` **and** a non-empty `session_token` before proceeding.

The signature exists for the **offline / cached** path: Session Ten caches the
signed context and runs per-channel-open local checks (capability / grant_expiry /
lock-set) against it without a CP call — *that* is where signature verification is
required, and `DecisionContext` already carries the fields. Adding an S7
verification of a context we just received live over mTLS would be redundant. The
S10 `DecisionContextVerifier` (already referenced in the S5 result) owns this. The
`SessionGrant` seam carries the context to Session Eight/Ten unchanged.
