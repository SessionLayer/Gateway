//! Gateway runtime configuration.
//!
//! Session One carried only the async-I/O backend and the dev-plaintext CP
//! endpoint. Session Four adds the mTLS control plane: the CP's mTLS endpoint,
//! the credential data-dir, the operator-provided bootstrap credential, and the
//! renew-ahead knobs (§8.1). It grows as subsystems land.

use crate::asyncio::IoBackend;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Gateway configuration.
///
/// `deny_unknown_fields` makes misconfiguration fail closed: a misspelled or
/// unrecognised key is an error, not a silently-ignored setting that leaves a
/// (possibly security-relevant) default in place.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    /// Which async-I/O reactor to request for the byte-copy hot path. A `uring`
    /// request degrades to epoll when io_uring is unavailable (deny-safe).
    pub io_backend: IoBackend,
    /// Legacy CP gRPC endpoint (plaintext, dev-only) used by the Session One
    /// handshake smoke. The production plane is [`Self::cp_mtls_endpoint`].
    pub cp_endpoint: String,
    /// CP mTLS gRPC endpoint (`https://host:port`, TLS 1.3). All authenticated
    /// RPCs — renew + sign — go here; enroll + negotiate use the same endpoint
    /// with server-auth-only TLS (the bootstrap exception, VERSIONING §7).
    pub cp_mtls_endpoint: String,
    /// Directory that holds the persisted mTLS credential (leaf + key + CA chain
    /// + generation) and the single-writer lock. Created on first enrollment.
    pub data_dir: PathBuf,
    /// Bootstrap credential. `None` leaves the Gateway un-enrolled (the Session
    /// One scaffold behaviour — no CP calls). `Some` drives enroll-on-start.
    pub bootstrap: Option<BootstrapConfig>,
    /// mTLS identity lifecycle knobs (renew-ahead + bounded RPC timeouts).
    pub identity: IdentityConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            io_backend: IoBackend::Epoll,
            cp_endpoint: "http://127.0.0.1:9090".to_string(),
            cp_mtls_endpoint: "https://127.0.0.1:9443".to_string(),
            data_dir: PathBuf::from("/var/lib/sessionlayer-gateway"),
            bootstrap: None,
            identity: IdentityConfig::default(),
        }
    }
}

/// Operator-provided bootstrap credential (§2A "Gateway↔CP trust", §4.B).
///
/// The Gateway has no CP-issued client certificate before enrollment, so it
/// authenticates `EnrollGateway` with a single-use token and trusts the CP's
/// server certificate against an operator-provided anchor (the bootstrap CA /
/// server-CA pin). Both are secrets/roots supplied out-of-band (env / file);
/// never commit them.
/// Deliberately NOT `#[derive(Debug)]`: it holds the bearer enrollment token, so
/// [`Debug`] is implemented manually to **redact** it (no accidental secret in a
/// config dump / log). The token lives in a [`Zeroizing`] buffer, scrubbed on
/// drop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    /// The single-use, short-TTL enrollment token (bearer, `EnrollGateway`
    /// only). Sourced from the environment in real deployments. Held in a
    /// scrub-on-drop buffer; never logged.
    #[serde(with = "crate::secret::serde_zeroizing_string")]
    pub enrollment_token: Zeroizing<String>,
    /// Path to a PEM file with the CA (or exact server cert) the Gateway pins to
    /// verify the CP's server certificate pre-enrollment. This is the sole trust
    /// anchor for the bootstrap channel; a wrong-CA / unpinned server is refused.
    pub ca_cert_path: PathBuf,
    /// The stable Gateway name the token was provisioned for. Bound into the CSR
    /// subject + the issued cert SAN; a mismatch fails closed.
    pub gateway_name: String,
    /// Server name (SNI / SAN) to verify the CP server certificate against. When
    /// empty, the host of [`GatewayConfig::cp_mtls_endpoint`] is used.
    pub server_name: String,
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the bearer token.
        f.debug_struct("BootstrapConfig")
            .field("enrollment_token", &"<redacted>")
            .field("ca_cert_path", &self.ca_cert_path)
            .field("gateway_name", &self.gateway_name)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enrollment_token: Zeroizing::new(String::new()),
            ca_cert_path: PathBuf::new(),
            gateway_name: String::new(),
            server_name: String::new(),
        }
    }
}

/// mTLS identity lifecycle configuration (§8.1 renew-ahead).
///
/// The renew-ahead trigger fires when a configurable fraction of the certificate
/// TTL has elapsed, jittered to de-synchronise a fleet, so renewal completes
/// well before expiry. Defaults renew at 2/3 elapsed (≈1/3 remaining) with ±10%
/// jitter. Made fully configurable so tests drive a short TTL / manual trigger
/// rather than sleeping for real hours.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Fraction of the cert TTL that must elapse before renew-ahead fires
    /// (`0.0..1.0`). Default `0.667` → renew when ~1/3 of the TTL remains.
    pub renew_ahead_fraction: f64,
    /// Jitter as a fraction of the TTL applied to the trigger (`±`), to spread a
    /// fleet's renewals. Default `0.1` (±10%).
    pub renew_jitter_fraction: f64,
    /// On startup, renew immediately if the remaining TTL fraction is at or below
    /// this. Default `0.5` — an identity loaded near expiry refreshes at once.
    pub startup_renew_below_fraction: f64,
    /// Bound on establishing the gRPC transport to the CP (fail-closed, §10.3).
    pub connect_timeout_secs: u64,
    /// Per-RPC deadline (fail-closed): a hung CP never hangs the Gateway.
    pub rpc_timeout_secs: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            startup_renew_below_fraction: 0.5,
            connect_timeout_secs: 5,
            rpc_timeout_secs: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_epoll_on_dev_endpoint_unenrolled() {
        let cfg = GatewayConfig::default();
        assert_eq!(cfg.io_backend, IoBackend::Epoll);
        assert_eq!(cfg.cp_endpoint, "http://127.0.0.1:9090");
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
        assert!(cfg.bootstrap.is_none(), "un-enrolled by default");
        assert!((cfg.identity.renew_ahead_fraction - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(cfg.identity.connect_timeout_secs, 5);
    }

    #[test]
    fn deserialises_partial_config_with_defaults() {
        // Only io_backend given; the rest fall back to defaults.
        let cfg: GatewayConfig = serde_json::from_str(r#"{"io_backend":"uring"}"#).unwrap();
        assert_eq!(cfg.io_backend, IoBackend::Uring);
        assert_eq!(cfg.cp_mtls_endpoint, "https://127.0.0.1:9443");
    }

    #[test]
    fn deserialises_bootstrap_block() {
        let cfg: GatewayConfig = serde_json::from_str(
            r#"{"bootstrap":{"enrollment_token":"t","ca_cert_path":"/etc/cp-ca.pem","gateway_name":"gw-1","server_name":"cp.internal"}}"#,
        )
        .unwrap();
        let b = cfg.bootstrap.expect("bootstrap present");
        assert_eq!(b.gateway_name, "gw-1");
        assert_eq!(b.server_name, "cp.internal");
    }

    #[test]
    fn unknown_key_fails_closed() {
        // A misspelled key must error, not be silently dropped.
        let result: Result<GatewayConfig, _> = serde_json::from_str(r#"{"io_back_end":"uring"}"#);
        assert!(result.is_err(), "unknown config key must be rejected");
    }

    #[test]
    fn unknown_nested_key_fails_closed() {
        let result: Result<GatewayConfig, _> =
            serde_json::from_str(r#"{"identity":{"renew_ahead":0.5}}"#);
        assert!(result.is_err(), "unknown nested key must be rejected");
    }
}
