//! Per-RPC authorization: session_token authorizes specific request (single-use, bound to gateway/session/node/principal/exp).

use crate::pb::session_signing_client::SessionSigningClient;
use crate::pb::{SignContext, SignSessionCertificateRequest};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::Channel;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("inner-leg key error: {0}")]
    Ssh(#[from] ssh_key::Error),

    /// Only the gRPC status **code** is rendered — never the CP-supplied message,
    /// which is untrusted wire text (log-injection / terminal-escape guard); the
    /// code is still available via the wrapped `Status`.
    #[error("Control Plane refused SignSessionCertificate (gRPC status {:?})", .0.code())]
    Rpc(#[from] tonic::Status),

    #[error("SignSessionCertificate timed out after {0:?}")]
    Timeout(Duration),

    #[error("Control Plane returned an empty certificate")]
    EmptyCertificate,

    #[error("Control Plane unreachable for SignSessionCertificate")]
    Unavailable,
}

impl SigningError {
    pub fn is_cp_down(&self) -> bool {
        match self {
            SigningError::Unavailable | SigningError::Timeout(_) => true,
            SigningError::Rpc(s) => matches!(
                s.code(),
                tonic::Code::Unavailable
                    | tonic::Code::Internal
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::Unknown
                    | tonic::Code::DataLoss
            ),
            _ => false,
        }
    }
}

pub struct InnerKeyPair {
    private: ssh_key::PrivateKey,
    public_wire: Vec<u8>,
}

impl std::fmt::Debug for InnerKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerKeyPair")
            .field("algorithm", &"ecdsa-sha2-nistp256")
            .field("public_wire_len", &self.public_wire.len())
            .field("private", &"<redacted>")
            .finish()
    }
}

impl InnerKeyPair {
    pub fn generate() -> Result<Self, SigningError> {
        let mut rng = rand_core::OsRng;
        let private = ssh_key::PrivateKey::random(
            &mut rng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )?;
        let public_wire = private.public_key().to_bytes()?;
        Ok(Self {
            private,
            public_wire,
        })
    }

    pub fn public_key_openssh_wire(&self) -> &[u8] {
        &self.public_wire
    }

    pub fn public_key_openssh_line(&self) -> Result<String, SigningError> {
        Ok(self.private.public_key().to_openssh()?)
    }

    /// The inner-leg **private** key as an OpenSSH PEM, zeroized. Used in-process
    /// by the inner SSH leg and to present the signed cert to the node.
    /// It is NEVER sent to the CP.
    pub fn private_key_openssh_pem(&self) -> Result<Zeroizing<String>, SigningError> {
        Ok(self.private.to_openssh(ssh_key::LineEnding::LF)?)
    }
}

#[derive(Debug, Clone)]
pub struct SignedInnerCert {
    pub certificate_line: String,
    pub certificate_blob: Vec<u8>,
    pub key_id: String,
    pub valid_after: SystemTime,
    pub valid_before: SystemTime,
}

/// Build the signing request from the inner public key + session token.
/// Kept separate so tests can assert it carries only public key and token, never private-key material.
fn build_request(
    session_token: &str,
    subject_public_key: &[u8],
    context: Option<SignContext>,
) -> SignSessionCertificateRequest {
    SignSessionCertificateRequest {
        session_token: session_token.to_string(),
        subject_public_key: subject_public_key.to_vec(),
        context,
    }
}

pub async fn sign_session_certificate(
    channel: Channel,
    session_token: &str,
    inner: &InnerKeyPair,
    context: Option<SignContext>,
    timeout: Duration,
) -> Result<SignedInnerCert, SigningError> {
    let request = build_request(session_token, inner.public_key_openssh_wire(), context);
    let mut client = SessionSigningClient::new(crate::telemetry::trace_channel(channel));
    let call = client.sign_session_certificate(tonic::Request::new(request));
    let resp = match tokio::time::timeout(timeout, call).await {
        Ok(result) => result?.into_inner(),
        Err(_elapsed) => return Err(SigningError::Timeout(timeout)),
    };

    if resp.certificate_line.is_empty() && resp.certificate_blob.is_empty() {
        return Err(SigningError::EmptyCertificate);
    }

    Ok(SignedInnerCert {
        certificate_line: resp.certificate_line,
        certificate_blob: resp.certificate_blob,
        key_id: resp.key_id,
        valid_after: epoch_to_systemtime(resp.valid_after_epoch_seconds),
        valid_before: epoch_to_systemtime(resp.valid_before_epoch_seconds),
    })
}

/// Convert CP-supplied epoch seconds to SystemTime with checked math; clamp on overflow
/// (these fields are advisory; never panic, overflow-checks on).
fn epoch_to_systemtime(epoch_seconds: i64) -> SystemTime {
    let checked = if epoch_seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(epoch_seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(epoch_seconds.unsigned_abs()))
    };
    checked.unwrap_or(UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_p256_inner_keypair_with_a_wire_public_key() {
        let kp = InnerKeyPair::generate().unwrap();
        let wire = kp.public_key_openssh_wire();
        assert!(wire.len() > 50);
        assert!(
            wire.windows(19).any(|w| w == b"ecdsa-sha2-nistp256"),
            "public wire blob must be an ecdsa-sha2-nistp256 key"
        );
        assert!(kp
            .public_key_openssh_line()
            .unwrap()
            .starts_with("ecdsa-sha2-nistp256 "));
    }

    #[test]
    fn request_carries_only_the_public_key_and_token() {
        let kp = InnerKeyPair::generate().unwrap();
        let priv_pem = kp.private_key_openssh_pem().unwrap();
        let req = build_request("tok-123", kp.public_key_openssh_wire(), None);

        assert_eq!(req.session_token, "tok-123");
        assert_eq!(req.subject_public_key, kp.public_key_openssh_wire());
        assert_ne!(
            req.subject_public_key,
            priv_pem.as_bytes(),
            "request must not carry the private key"
        );
        let needle = &priv_pem.as_bytes()[priv_pem.len() / 3..priv_pem.len() / 3 + 24];
        assert!(
            !req.subject_public_key
                .windows(needle.len())
                .any(|w| w == needle),
            "no private-key fragment may leak into the signing request"
        );
    }

    #[test]
    fn two_generations_produce_distinct_keys() {
        let a = InnerKeyPair::generate().unwrap();
        let b = InnerKeyPair::generate().unwrap();
        assert_ne!(
            a.public_key_openssh_wire(),
            b.public_key_openssh_wire(),
            "each session gets a fresh inner keypair"
        );
    }

    #[test]
    fn cp_down_classifies_signing_faults_by_code() {
        assert!(SigningError::Unavailable.is_cp_down());
        assert!(SigningError::Timeout(Duration::from_secs(1)).is_cp_down());
        assert!(SigningError::Rpc(tonic::Status::internal("x")).is_cp_down());
        assert!(SigningError::Rpc(tonic::Status::unavailable("x")).is_cp_down());
        assert!(!SigningError::Rpc(tonic::Status::permission_denied("token")).is_cp_down());
        assert!(!SigningError::Rpc(tonic::Status::unauthenticated("token")).is_cp_down());
        assert!(!SigningError::EmptyCertificate.is_cp_down());
    }
}
