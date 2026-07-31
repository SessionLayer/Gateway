//! mTLS channel construction: TLS 1.3 only, time-bounded, fail-closed.

use crate::tls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, PeerIncompatible, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

/// mTLS channel errors (all variants are fail-closed refusals).
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    #[error("invalid CP mTLS endpoint {endpoint:?}: {source}")]
    Endpoint {
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("could not build the CP server-certificate verifier: {0}")]
    TrustAnchor(String),

    #[error("failed to establish mTLS channel to {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: tonic::transport::Error,
    },

    #[error("timed out establishing mTLS channel to {endpoint} after {after:?}")]
    Timeout { endpoint: String, after: Duration },
}

/// Channel parameters for CP mTLS connections.
#[derive(Debug, Clone)]
pub struct ChannelParams {
    pub endpoint: String,
    pub server_name: String,
    pub connect_timeout: Duration,
    pub rpc_timeout: Duration,
}

/// mTLS client identity (cert + key PEM, zeroized on drop).
#[derive(Clone)]
pub struct ClientIdentity {
    pub cert_pem: Vec<u8>,
    pub key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Server-certificate verifier: pinned CA, SAN check, TLS 1.3-only (refuse 1.2), fail-closed.
#[derive(Debug)]
pub struct Tls13OnlyPinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl Tls13OnlyPinnedVerifier {
    /// Pin trust to anchors; empty set is refused.
    pub fn new(trust_anchors_der: &[Vec<u8>]) -> Result<Self, MtlsError> {
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
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
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

/// Build server-authenticated bootstrap channel (no client cert).
pub async fn connect_bootstrap(
    params: &ChannelParams,
    trust_anchors_der: &[Vec<u8>],
) -> Result<Channel, MtlsError> {
    connect(params, trust_anchors_der, None).await
}

/// Build mutually-authenticated channel (with client cert).
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
    tls::install_ring_provider();

    let verifier = Arc::new(Tls13OnlyPinnedVerifier::new(trust_anchors_der)?);

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

/// Parse PEM bundle into DER anchors; empty result is an error.
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

/// Encode DER certificate as PEM CERTIFICATE block for tonic Identity.
pub fn cert_der_to_pem(der: &[u8]) -> Vec<u8> {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec())).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_refuses_empty_trust_anchor_set() {
        let err = Tls13OnlyPinnedVerifier::new(&[]).expect_err("empty anchors must be refused");
        assert!(matches!(err, MtlsError::TrustAnchor(_)));
    }

    #[test]
    fn pem_roundtrip_der_to_pem_to_der() {
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

    fn sample_cert_der() -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }
}
