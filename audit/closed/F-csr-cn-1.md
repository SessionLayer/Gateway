# F-csr-cn-1: the CSR's subject CN was inherited from an rcgen default, not set by us
- Severity: low
- Status: Verified-Fixed
- Area: identity

## What was actually wrong

**Nothing was broken, and nothing was failing.** This is a latent-fragility finding, not
an outage: it is filed because the code depended on a third-party default to satisfy a
Control-Plane contract rule that our own tests did not enforce.

`identity::generate_keypair_and_csr` built its PKCS#10 CSR with
`rcgen::CertificateParams::new(vec![gateway_name])`, which sets a dNSName SAN and leaves
the subject alone. It never set a subject CN.

The CP's shared PKCS#10 parser (`Pkcs10Csrs.parseAndVerify`, used by **EnrollGateway**,
**RenewGatewayIdentity** and the new **IssueGatewayServerCertificate**) **rejects a CSR
with a missing/blank CN** with `INVALID_ARGUMENT` (reported by cp-engineer during S14
integration).

Our CSRs were nevertheless accepted, because rcgen fills in a placeholder of its own.
Verified against the real artifact rather than assumed:

```
$ openssl req -in csr.der -inform DER -noout -subject
subject=CN=rcgen self signed cert
```

So the CN that satisfied the CP's rule was a **string chosen by a dependency**. Two
consequences:

1. If rcgen ever changed that default to an empty subject — a reasonable change for a
   library, since the CA discards the subject anyway — **enrollment and renewal would
   break against the real CP**, not just the S14 agent transport. The blast radius is
   every Gateway, at startup.
2. The failure would have been **invisible to CI**: the mock CP signed any parseable CSR,
   so every test would have stayed green while the real CP refused us.

## Pre-existing?

**Yes — pre-existing on `main` since Session Four**, not introduced by Session Fourteen.
S14 only surfaced it, because `IssueGatewayServerCertificate` is the first RPC whose CSR
would *naturally* carry no subject at all (the CA chooses every name).

## Fix (Verified-Fixed, commit cd8b77b)

- `identity.rs`: the CSR now sets `CN = <gateway name>` **explicitly**. The CP still
  discards it (it stamps the leaf from the `gateway_identity` row it holds), but we now
  state the value the CP requires instead of inheriting it.
- `identity.rs`: new unit test `csr_carries_a_non_blank_cn_and_a_p256_key` asserts the
  three properties the CP's parser rejects on — a non-blank subject CN, a valid proof of
  possession, and an ECDSA P-256 key.
- `tests/support`: the **mock CP now refuses a blank-CN CSR** (`TestCa::parse_csr`) and
  discards the CSR's requested names when issuing the server leaf, exactly as the real CP
  does. This is the part that stops the regression from hiding again: a mock laxer than
  the CP is what let this sit undetected since S4.

## Verification

`cargo nextest run --all-features` — 281 tests, 0 skipped, all green, with every
enroll/renew/sign path now flowing through the stricter mock CP
(`identity_it`, `mtls_it`, `signing_it`, `agent_transport_it`, `agent_e2e`).

## CP-side change needed?

**No.** The CP's rule is reasonable and already implemented; the Gateway was the side
relying on luck. No contract change is required.
