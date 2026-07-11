//! CP <-> Gateway mTLS channel construction (Session Four, Part A).
//!
//! The control plane runs over **TLS 1.3, mutually authenticated** (VERSIONING
//! §7, Design §10/§15), replacing the Session-One dev-plaintext localhost
//! channel. This module builds the two tonic channels the Gateway needs:
//!
//! - [`connect_bootstrap`] — a **server-authenticated** channel (no client
//!   certificate) used before the Gateway has an identity, for the two RPCs the
//!   trust model exempts from client auth: `GatewayIdentity.EnrollGateway` and
//!   `Handshake.Negotiate` (the bootstrap exception). The server is verified
//!   against the operator-provided bootstrap anchor.
//! - [`connect_mtls`] — a **mutually-authenticated** channel that presents the
//!   Gateway's issued client certificate, for `RenewGatewayIdentity` and
//!   `SessionSigning.SignSessionCertificate`.
//!
//! Both are **fail-closed** (NFR-2): a missing/invalid/expired/wrong-CA server
//! certificate, a hostname/SAN mismatch, a plaintext peer, or a TLS-1.2 peer is
//! refused — there is never a fallback to plaintext or an unauthenticated path.
//! Every phase is time-bounded so a hung peer cannot hang the Gateway (§10.3).
//!
//! ## Trust & TLS-1.3 enforcement
//!
//! tonic's `ClientTlsConfig` builds its rustls config with
//! `with_safe_default_protocol_versions()` (TLS 1.2 **and** 1.3) and does not
//! expose a version selector. We therefore inject a custom
//! [`ServerCertVerifier`] via `Endpoint::tls_config_with_verifier` that (a)
//! delegates chain + validity + **SAN/hostname** verification to rustls'
//! `WebPkiServerVerifier` built from *only* our trust anchor, and (b) **refuses
//! the TLS-1.2 handshake-signature path**, so a 1.2 peer is rejected and only
//! 1.3 completes. The client's own key never touches this path — it is presented
//! as the mTLS identity and its private half never leaves the Gateway (D2/§15).

use crate::tls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, PeerIncompatible, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

/// A failure while building or connecting an mTLS/bootstrap channel to the CP.
///
/// Every variant is a refusal: there is no success path that falls back to
/// plaintext or an unauthenticated channel.
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    /// The endpoint URL was not a valid `https://host:port` URI.
    #[error("invalid CP mTLS endpoint {endpoint:?}: {source}")]
    Endpoint {
        /// The offending endpoint string.
        endpoint: String,
        /// The underlying parse error.
        #[source]
        source: tonic::transport::Error,
    },

    /// The trust anchor(s) could not be assembled into a usable verifier (empty
    /// anchor set, unparseable CA, etc.). A channel with no trust anchor would
    /// verify nothing, so this fails closed.
    #[error("could not build the CP server-certificate verifier: {0}")]
    TrustAnchor(String),

    /// Establishing the transport (TCP + TLS 1.3 + HTTP/2) failed or was refused
    /// — wrong-CA/expired/missing server cert, hostname mismatch, plaintext or
    /// TLS-1.2 peer, or a connection error. All fail closed.
    #[error("failed to establish mTLS channel to {endpoint}: {source}")]
    Connect {
        /// The endpoint that was dialed.
        endpoint: String,
        /// The underlying transport error.
        #[source]
        source: tonic::transport::Error,
    },

    /// The connect did not complete within its bound — a hung or unresponsive
    /// peer must never hang the Gateway (fail closed, §10.3).
    #[error("timed out establishing mTLS channel to {endpoint} after {after:?}")]
    Timeout {
        /// The endpoint that was dialed.
        endpoint: String,
        /// The elapsed bound that was exceeded.
        after: Duration,
    },
}

/// Common per-channel parameters.
#[derive(Debug, Clone)]
pub struct ChannelParams {
    /// The CP mTLS endpoint, `https://host:port`.
    pub endpoint: String,
    /// The server name (SNI + the SAN the server certificate must carry). A
    /// mismatch fails closed.
    pub server_name: String,
    /// Bound on TCP connect + TLS handshake (fail-closed, §10.3).
    pub connect_timeout: Duration,
    /// Per-RPC deadline applied to the channel.
    pub rpc_timeout: Duration,
}

/// The Gateway's mTLS client identity (issued leaf certificate + its private
/// key), PEM-encoded for tonic. The private key is held in a [`Zeroizing`]
/// buffer so it is scrubbed on drop; it never leaves the Gateway.
#[derive(Clone)]
pub struct ClientIdentity {
    /// PEM of the issued leaf certificate.
    pub cert_pem: Vec<u8>,
    /// PEM of the private key (zeroized on drop).
    pub key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("ClientIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// A server-certificate verifier that pins trust to a specific CA set, verifies
/// the SAN/hostname, and **enforces TLS 1.3** by refusing the TLS-1.2
/// handshake-signature path. Wraps rustls' `WebPkiServerVerifier` for the
/// standards-compliant chain/validity/name checks and fails closed everywhere.
#[derive(Debug)]
struct Tls13OnlyPinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl Tls13OnlyPinnedVerifier {
    /// Build a verifier trusting exactly `trust_anchors_der` (DER X.509 CA — or
    /// pinned server — certificates). An empty or unparseable anchor set is an
    /// error (a verifier that trusts nothing would still "succeed" against a
    /// self-signed peer, so refuse to construct one).
    fn new(trust_anchors_der: &[Vec<u8>]) -> Result<Self, MtlsError> {
        if trust_anchors_der.is_empty() {
            return Err(MtlsError::TrustAnchor(
                "no CP trust anchor provided".to_string(),
            ));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for der in trust_anchors_der {
            let cert = CertificateDer::from(der.clone());
            roots
                .add(cert)
                .map_err(|e| MtlsError::TrustAnchor(format!("unusable CP trust anchor: {e}")))?;
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| MtlsError::TrustAnchor(format!("verifier build failed: {e}")))?;
        Ok(Self { inner })
    }
}

impl ServerCertVerifier for Tls13OnlyPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Delegates the full chain-to-anchor path build, validity-window, and
        // SAN/hostname match to webpki. Wrong-CA / expired / name-mismatch all
        // surface here as an error → the handshake aborts (fail closed).
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // TLS 1.3 only (VERSIONING §7). This callback fires only on a TLS-1.2
        // handshake; refusing it aborts any 1.2 negotiation. A 1.3-capable peer
        // negotiates 1.3 and never reaches here.
        Err(RustlsError::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a **server-authenticated** bootstrap channel (no client certificate)
/// for the pre-enrollment RPCs (`EnrollGateway`, `Handshake.Negotiate`). The CP
/// server certificate is verified against `trust_anchors_der` (the operator's
/// bootstrap anchor), TLS 1.3, SAN checked. Fail-closed.
pub async fn connect_bootstrap(
    params: &ChannelParams,
    trust_anchors_der: &[Vec<u8>],
) -> Result<Channel, MtlsError> {
    connect(params, trust_anchors_der, None).await
}

/// Build a **mutually-authenticated** channel presenting `identity` (the issued
/// client certificate + key) for the authenticated RPCs (`RenewGatewayIdentity`,
/// `SignSessionCertificate`). The CP server certificate is verified against
/// `trust_anchors_der` (the CA chain obtained at enrollment). Fail-closed.
pub async fn connect_mtls(
    params: &ChannelParams,
    trust_anchors_der: &[Vec<u8>],
    identity: &ClientIdentity,
) -> Result<Channel, MtlsError> {
    connect(params, trust_anchors_der, Some(identity)).await
}

async fn connect(
    params: &ChannelParams,
    trust_anchors_der: &[Vec<u8>],
    identity: Option<&ClientIdentity>,
) -> Result<Channel, MtlsError> {
    // A crypto provider must be installed before any rustls config is built.
    tls::install_ring_provider();

    let verifier = Arc::new(Tls13OnlyPinnedVerifier::new(trust_anchors_der)?);

    // The verifier owns all trust; do NOT also set ca_certificate/trust_anchor
    // (tonic returns VerifierConflict). `domain_name` drives SNI and is the
    // ServerName the verifier checks the SAN against.
    let mut tls_config = ClientTlsConfig::new()
        .domain_name(params.server_name.clone())
        .timeout(params.connect_timeout);
    if let Some(id) = identity {
        tls_config = tls_config.identity(Identity::from_pem(&id.cert_pem, id.key_pem.as_bytes()));
    }

    let endpoint = Endpoint::from_shared(params.endpoint.clone())
        .map_err(|source| MtlsError::Endpoint {
            endpoint: params.endpoint.clone(),
            source,
        })?
        .connect_timeout(params.connect_timeout)
        .timeout(params.rpc_timeout)
        .tls_config_with_verifier(tls_config, verifier)
        .map_err(|source| MtlsError::Connect {
            endpoint: params.endpoint.clone(),
            source,
        })?;

    // Belt-and-suspenders wall-clock bound over the whole connect (TCP + TLS +
    // HTTP/2) so no single phase can hang us even if an inner bound is missed.
    let overall = params.connect_timeout + params.rpc_timeout;
    match tokio::time::timeout(overall, endpoint.connect()).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(source)) => Err(MtlsError::Connect {
            endpoint: params.endpoint.clone(),
            source,
        }),
        Err(_elapsed) => Err(MtlsError::Timeout {
            endpoint: params.endpoint.clone(),
            after: overall,
        }),
    }
}

/// Parse a PEM bundle (one or more `CERTIFICATE` blocks) into DER trust anchors,
/// for loading an operator-provided bootstrap CA file. Non-certificate PEM
/// blocks are ignored; an empty result is an error (nothing to trust).
pub fn pem_certs_to_der(pem_bytes: &[u8]) -> Result<Vec<Vec<u8>>, MtlsError> {
    let text = std::str::from_utf8(pem_bytes)
        .map_err(|e| MtlsError::TrustAnchor(format!("bootstrap CA is not UTF-8 PEM: {e}")))?;
    let ders: Vec<Vec<u8>> = pem::parse_many(text)
        .map_err(|e| MtlsError::TrustAnchor(format!("bootstrap CA PEM parse failed: {e}")))?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect();
    if ders.is_empty() {
        return Err(MtlsError::TrustAnchor(
            "bootstrap CA PEM contained no CERTIFICATE blocks".to_string(),
        ));
    }
    Ok(ders)
}

/// DER-encode a single X.509 certificate as a PEM `CERTIFICATE` block. Used to
/// feed the enrollment-issued leaf (returned as DER) to tonic's `Identity`,
/// which accepts PEM only.
pub fn cert_der_to_pem(der: &[u8]) -> Vec<u8> {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec())).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_refuses_empty_trust_anchor_set() {
        // A verifier with no anchor would be a silent trust-nothing/verify-nothing
        // hazard; constructing one must fail closed.
        let err = Tls13OnlyPinnedVerifier::new(&[]).expect_err("empty anchors must be refused");
        assert!(matches!(err, MtlsError::TrustAnchor(_)));
    }

    #[test]
    fn pem_roundtrip_der_to_pem_to_der() {
        // A DER cert encoded to PEM must parse back to the identical DER.
        let der = sample_cert_der();
        let pem_bytes = cert_der_to_pem(&der);
        let text = String::from_utf8(pem_bytes).unwrap();
        assert!(text.contains("BEGIN CERTIFICATE"));
        let back = pem_certs_to_der(text.as_bytes()).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], der);
    }

    #[test]
    fn pem_with_no_certificate_blocks_is_refused() {
        let err =
            pem_certs_to_der(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
                .expect_err("no CERTIFICATE block must fail closed");
        assert!(matches!(err, MtlsError::TrustAnchor(_)));
    }

    /// A throwaway self-signed cert DER for PEM round-trip tests.
    fn sample_cert_der() -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }
}
