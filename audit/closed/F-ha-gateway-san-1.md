# F-ha-gateway-san-1 (F10a): peer-relay gateway identity was resolved by ABSENCE of an agent SAN, not a positive check
- Severity: low
- Status: Verified-Fixed
- Area: ha-relay

## Summary

`gateway_peer_identity` accepted a peer as a gateway on the strength of "one dNSName SAN and no
agent URI SAN". A leaf carrying a gateway-named dNSName but no gateway identity (a CA mis-issuance
residual) would have passed the gateway-only relay path.

## Location

- `gateway-core/src/agent/mod.rs::gateway_peer_identity`; mock faithfulness in
  `gateway-core/tests/support/mod.rs`

## Remediation — Verified-Fixed

`gateway_peer_identity` now requires a POSITIVE `sessionlayer://gateway/<uuid>` URI SAN to be
present (in addition to exactly one dNSName SAN and no agent URI SAN) — a CA never issues that SAN
to a non-gateway. The mock CP `EnrollGateway`/`RenewGatewayIdentity` now stamp the gateway URI SAN
(via `sign_csr_as_gateway_identity`), matching production, so the ITs exercise the real cert shape.
Unit test updated: a dNSName-only leaf is now `NotOneGateway`. The relay-token owner binding
(`owner_gateway_id == this name`) remains the decisive second check.
