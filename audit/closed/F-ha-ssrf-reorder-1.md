# F-ha-ssrf-reorder-1: the owner dialled the local node BEFORE validating the bus-controlled ingress address
- Severity: medium
- Status: Verified-Fixed
- Area: ha-relay

## Summary

On receiving a `DialBackSignal`, the owner (`peer_client::serve_relay`) produced the node byte
stream via a local `AgentDial` and only THEN dialled the ingress relay endpoint. The
`ingress_relay_addr` is bus-controlled, so a forged/injected signal could make the owner perform
a real local node dial-back before the ingress was authenticated — a partial SSRF / amplification
primitive gated only by later TLS.

## Location

- `gateway-core/src/ha/peer_client.rs::serve_relay`

## Remediation — Verified-Fixed

`serve_relay` now ESTABLISHES THE INGRESS CONNECTION FIRST — TCP + TLS (the ingress serverAuth
leaf must chain to the pinned internal CA and match `ingress_gateway_id`) + preface + RELAY_OPEN/
ACCEPT — and only produces the node byte stream AFTER the ingress is cryptographically proven. A
forged `ingress_relay_addr` fails the TLS certificate check and aborts before any node dial. The
residual — a bounded blind TCP-connect + ClientHello to a wire address — needs bus-publish
authorization (§8) and cannot complete without a valid internal-CA gateway certificate:
Accepted-Risk-with-controls (documented at the call site).
