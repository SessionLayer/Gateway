# F-relaystale-1: the SLGW1 owner_nonce is ingress-self-referential — the anti-stale guard must be an owner-side ownership recheck
- Severity: high
- Status: Verified-Fixed
- Area: relaystale

## Summary

The SLGW1 relay token carries an `owner_nonce` intended as the anti-stale-ownership fencing
token (FR-HA-5). But the ingress (gw-A) mints BOTH the token and the pending-ledger entry from
the same `Authorize` response, so an ingress-side `owner_nonce` comparison is **self-referential**
— it can only catch an ingress self-bug, never ownership migrating away from the signalled owner
between `Authorize` and the relay. If gw-B is signalled but ownership has since moved to gw-C, a
gw-B that still (transiently) holds the node's agent channel would relay a stale session.

## Location

- `gateway-core/src/ha/relay_token.rs` — `RelayBinding.owner_nonce`, minted + checked entirely at
  the ingress.
- `gateway-core/src/ha/peer_client.rs::serve_relay` — the owner-side serve path.

## Root cause / impact

The nonce is a property of gw-A's decision, not of gw-B's current ownership. Without an owner-side
recheck, the anti-stale primitive is incomplete: a superseded-but-still-channel-holding owner could
serve a relay after ownership migrated. No confidentiality/integrity break (the owner can reach the
node), but it violates the FR-HA-5 anti-stale property and the "no live migration / fail fast" model.

## Remediation — Verified-Fixed

`serve_relay` now applies TWO owner-side guards before serving, both required:

1. **is_self_owner recheck (the anti-stale guard):** it consults the shared `OwnerCache` (updated by
   the heartbeat loop from the last `Presence.Heartbeat`) and refuses to serve unless it currently
   believes IT owns the node (`owner_id == self_gateway_id`). A superseded owner refuses ⇒ the ingress
   fails closed within `relay_timeout` ⇒ the client re-routes to the true owner. No CP round-trip on
   the relay hot path.
2. **Live agent-channel guard (the backstop):** it must still hold a live agent control channel to the
   node (`registry.lookup`) — a truly-dead owner cannot reach the node regardless of the cache.

The `owner_nonce` remains in the token for audit correlation, not treated as the anti-stale guard.
The `OwnerCache` is plumbed into `PeerClientDeps` and shared with the heartbeat loop in `main.rs` +
both HA tests.

**Proving test:** `ha_relay_it::a_superseded_owner_refuses_and_the_ingress_fails_closed` — an owner
whose cache does NOT say self-owner refuses to serve, and the ingress fails closed (measured) within
the bound. Normative in `gateway-relay-v1.md §6/§7.6`.

## References

- FR-HA-5 (anti-stale ownership), FR-HA-7 (no live migration).
