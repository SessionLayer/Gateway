//! SessionLayer Gateway core library (Session One scaffold).
//!
//! The Gateway is the platform's Tier-0 data plane: it will terminate the outer
//! SSH leg, re-originate the inner leg, and see session plaintext (Design §1,
//! §15). This session builds only the load-bearing seams so later sessions drop
//! in without rework:
//!
//! - [`asyncio`] — the reactor-agnostic byte-I/O seam (`AsyncIo`) with an epoll
//!   default and an opt-in io_uring backend.
//! - [`handshake`] / [`pb`] — the CP <-> Gateway version-negotiation client,
//!   generated from the frozen contract (`proto/`); implements FR-HA-9 / D33.
//! - [`version`] — protocol/version constants and the pure highest-common
//!   resolver.
//! - [`health`] — a minimal health/version surface.
//! - [`config`] — the runtime configuration.
//! - [`tls`] — installs the ring rustls crypto provider for the mTLS plane.
//! - [`mtls`] — builds the CP <-> Gateway mTLS channels (Session Four, Part A):
//!   a bootstrap server-auth channel and the fully mutual channel, both TLS 1.3
//!   with a fail-closed custom certificate verifier.
//! - [`identity`] — the Gateway's renewable mTLS X.509 identity lifecycle
//!   (bootstrap → enroll → renew-ahead + generation counter; Part B).
//! - [`signing`] — the session-bound inner-leg signer client (generate the inner
//!   keypair locally, send only the public key; Part C).
//!
//! The SSH legs (outer/inner), PROXY protocol, recorder, and NodeConnector are
//! still later sessions; Session Four builds the mTLS/identity/signing seams.
//!
//! `unsafe_code` is forbidden workspace-wide via the `[workspace.lints]` table
//! (see the root `Cargo.toml`); this crate additionally warns on missing docs.
#![warn(missing_docs)]

pub mod asyncio;
pub mod config;
pub mod handshake;
pub mod health;
pub mod identity;
pub mod mtls;
mod secret;
pub mod signing;
pub mod tls;
pub mod version;

/// Generated protobuf types and gRPC client/server for the frozen CP <-> Gateway
/// contract (`sessionlayer.controlplane.v1`), produced at build time by
/// `build.rs` from the vendored `proto/`. This is generated code; its own docs
/// come from the `.proto` comments.
pub mod pb {
    #![allow(missing_docs)]
    tonic::include_proto!("sessionlayer.controlplane.v1");
}
