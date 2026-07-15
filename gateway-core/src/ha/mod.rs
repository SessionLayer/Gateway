//! High-availability coordination (Session Fifteen; Design §10.2/§10.3,
//! FR-HA-2/3/4/5/8). Normative contract: `contracts/wire/gateway-relay-v1.md`.
//!
//! **The seam is invariant (D21/D23).** HA changes only *how the ingress Gateway
//! obtains the node [`ByteStream`](crate::ssh::connector::ByteStream)*. Everything
//! above `NodeConnector::connect()` — the inner leg, no-TOFU host verification, the
//! byte bridge, the recorder — is byte-for-byte the single-instance path.
//!
//! Three mechanisms, no overlap (§10.2):
//! - **Postgres presence** (durable ownership) — reached through the CP `Presence`
//!   service; the Gateway has no database.
//! - **[`CoordinationBackend`](coordination::CoordinationBackend)** — signalling only;
//!   one [`DialBackSignal`](crate::pbgw::DialBackSignal) to the owner. **Session bytes
//!   NEVER traverse the bus.**
//! - **Direct relay** — the node byte stream over a direct Gateway↔Gateway WSS+mTLS
//!   connection, raw opaque frames exactly like the agent splice.

pub mod connector;
pub mod coordination;
pub mod nats;
pub mod peer_client;
pub mod presence;
pub mod readiness;
pub mod relay_token;
