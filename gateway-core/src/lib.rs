pub mod agent;
pub mod asyncio;
pub mod config;
pub mod cpauth;
pub mod decisionctx;
pub mod ha;
pub mod handshake;
pub mod health;
pub mod identity;
pub mod mtls;
pub mod netmatch;
mod secret;
pub mod signing;
pub mod ssh;
pub mod telemetry;
pub mod tls;
pub mod version;

pub mod pb {
    #![allow(clippy::doc_lazy_continuation)]
    tonic::include_proto!("sessionlayer.controlplane.v1");
}

pub mod pbagent {
    #![allow(clippy::doc_lazy_continuation)]
    tonic::include_proto!("sessionlayer.agent.v1");
}

pub mod pbgw {
    #![allow(clippy::doc_lazy_continuation)]
    tonic::include_proto!("sessionlayer.gateway.v1");
}
