//! Gateway runtime configuration (Session One subset).
//!
//! Carries only what this session needs — the async-I/O backend selection and
//! the CP gRPC endpoint — and grows as subsystems land. Deserialisable so the
//! backend choice is config-driven (see [`crate::asyncio::select_io`]).

use crate::asyncio::IoBackend;
use serde::{Deserialize, Serialize};

/// Gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayConfig {
    /// Which async-I/O reactor to request for the byte-copy hot path. A `uring`
    /// request degrades to epoll when io_uring is unavailable (deny-safe).
    pub io_backend: IoBackend,
    /// CP gRPC endpoint. Plaintext dev default; mTLS in Session Four.
    pub cp_endpoint: String,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            io_backend: IoBackend::Epoll,
            cp_endpoint: "http://127.0.0.1:9090".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_epoll_on_dev_endpoint() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.io_backend, IoBackend::Epoll);
        assert_eq!(cfg.cp_endpoint, "http://127.0.0.1:9090");
    }

    #[test]
    fn deserialises_partial_config_with_defaults() {
        // Only io_backend given; cp_endpoint falls back to the default.
        let cfg: GatewayConfig = serde_json::from_str(r#"{"io_backend":"uring"}"#).unwrap();
        assert_eq!(cfg.io_backend, IoBackend::Uring);
        assert_eq!(cfg.cp_endpoint, "http://127.0.0.1:9090");
    }
}
