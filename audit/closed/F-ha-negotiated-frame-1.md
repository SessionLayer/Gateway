# F-ha-negotiated-frame-1 (F10b + F6): relay client used its configured frame bound and never validated the negotiated major
- Severity: low
- Status: Verified-Fixed
- Area: ha-relay

## Summary

The owner's peer-relay client built the relay `WsByteStream` with its OWN configured
`max_frame_bytes`, discarding the HELLO_ACK-negotiated value — a latent `TooLarge` mismatch across
differently-configured gateways (F10b). It also proceeded on whatever wire major the HELLO_ACK
carried without validating it against the wire range (F6; moot at 1.0, load-bearing at 1.1).

## Location

- `gateway-core/src/ha/peer_client.rs::preface`, `open_relay`

## Remediation — Verified-Fixed

`preface` now parses the `GatewayHelloAck`, returns the negotiated wire major AND max-frame, and
`open_relay`/`serve_relay` build the `WsByteStream` with the negotiated frame bound clamped to the
owner's configured ceiling (so it agrees with what the ingress frames and never exceeds the WS-layer
cap). `preface` also refuses a negotiated major outside `[WIRE_PROTOCOL_MIN, WIRE_PROTOCOL_MAX]`
(fail closed) before proceeding.
