//! Session-bound inner-leg signer client (Session Four, Part C).
//!
//! The Gateway obtains the short-lived inner-leg SSH certificate a node trusts
//! (via `TrustedUserCAKeys`) by calling `SessionSigning.SignSessionCertificate`
//! over the **authenticated mTLS channel**, presenting a single-use, CP-minted
//! session token. This module owns the Gateway half:
//!
//! - **Key custody (D2/§15).** [`InnerKeyPair::generate`] creates the inner-leg
//!   ECDSA P-256 keypair **locally**; only the OpenSSH-wire *public* key is sent
//!   ([`InnerKeyPair::public_key_openssh_wire`]). The private key never leaves the
//!   Gateway — it is held zeroized and used in-process by the inner SSH leg
//!   (S7/S8). The request type carries no private-key field at all.
//! - **Per-RPC authorization (§15).** mTLS authenticates the channel; the
//!   `session_token` authorizes the specific request (bound to
//!   `{gateway, session, node, principal, exp}`, single-use). The CP returns the
//!   certificate only.
//!
//! The API ([`sign_session_certificate`], [`SignedInnerCert`]) is written to be
//! reused by the S7/S8 SSH legs without change.

use crate::pb::session_signing_client::SessionSigningClient;
use crate::pb::{SignContext, SignSessionCertificateRequest};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::Channel;
use zeroize::Zeroizing;

/// A failure while generating the inner keypair or obtaining a session cert.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// SSH key / encoding error (keypair generation or wire encoding).
    #[error("inner-leg key error: {0}")]
    Ssh(#[from] ssh_key::Error),

    /// The CP refused the signing RPC — an invalid/expired/reused token, a
    /// cross-gateway or cross-session token, an unknown/locked identity, etc.
    /// The caller fails closed (no certificate). Only the gRPC status **code** is
    /// rendered — never the CP-supplied message, which is untrusted wire text
    /// (log-injection / terminal-escape guard); the code is still available via
    /// the wrapped `Status`.
    #[error("Control Plane refused SignSessionCertificate (gRPC status {:?})", .0.code())]
    Rpc(#[from] tonic::Status),

    /// The signing RPC did not complete within its deadline — a hung CP must
    /// never hang the Gateway (fail closed, §10.3).
    #[error("SignSessionCertificate timed out after {0:?}")]
    Timeout(Duration),

    /// The CP returned a malformed response (empty certificate).
    #[error("Control Plane returned an empty certificate")]
    EmptyCertificate,

    /// The mTLS channel to the CP could not be established for the signing call
    /// (CP down) — fail closed as "service temporarily unavailable" (§7.1), not
    /// as a node fault.
    #[error("Control Plane unreachable for SignSessionCertificate")]
    Unavailable,
}

impl SigningError {
    /// Whether the failure is a CP-down condition (→ service-unavailable), as
    /// opposed to a node/token/material fault (→ generic node/policy outcome).
    /// Mirrors `CpError::is_cp_down` — a transport/timeout/server-side gRPC fault
    /// is CP-down; a token-rejection code (`UNAUTHENTICATED`/`PERMISSION_DENIED`/
    /// `INVALID_ARGUMENT`, i.e. a bad/expired/replayed session token) is NOT
    /// (F-signclass-1).
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

/// A locally-generated inner-leg keypair. The private half never leaves the
/// Gateway; only [`Self::public_key_openssh_wire`] is transmitted.
pub struct InnerKeyPair {
    private: ssh_key::PrivateKey,
    public_wire: Vec<u8>,
}

impl std::fmt::Debug for InnerKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render private key material.
        f.debug_struct("InnerKeyPair")
            .field("algorithm", &"ecdsa-sha2-nistp256")
            .field("public_wire_len", &self.public_wire.len())
            .field("private", &"<redacted>")
            .finish()
    }
}

impl InnerKeyPair {
    /// Generate a fresh inner-leg ECDSA P-256 keypair locally.
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

    /// The inner-leg **public** key in OpenSSH wire format (the
    /// `ecdsa-sha2-nistp256` public-key blob the CP signs). This — and only this
    /// — is sent to the CP.
    pub fn public_key_openssh_wire(&self) -> &[u8] {
        &self.public_wire
    }

    /// The inner-leg public key as an OpenSSH `authorized_keys`-style line
    /// (`ecdsa-sha2-nistp256 AAAA...`), for diagnostics/logging.
    pub fn public_key_openssh_line(&self) -> Result<String, SigningError> {
        Ok(self.private.public_key().to_openssh()?)
    }

    /// The inner-leg **private** key as an OpenSSH PEM, zeroized. Used in-process
    /// by the inner SSH leg (S7/S8) — and by the Part D harness to present the
    /// signed cert to the node. It is NEVER sent to the CP.
    pub fn private_key_openssh_pem(&self) -> Result<Zeroizing<String>, SigningError> {
        Ok(self.private.to_openssh(ssh_key::LineEnding::LF)?)
    }
}

/// A signed inner-leg certificate returned by the CP (certificate only — never a
/// private key).
#[derive(Debug, Clone)]
pub struct SignedInnerCert {
    /// The OpenSSH certificate as an authorized-keys line
    /// (`ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA... <key-id>`).
    pub certificate_line: String,
    /// The certificate as the raw OpenSSH wire blob.
    pub certificate_blob: Vec<u8>,
    /// The certificate key id (`session_id+identity`) for node-local audit.
    pub key_id: String,
    /// Certificate validity window (backdated for skew, FR-CA-5).
    pub valid_after: SystemTime,
    /// Certificate validity window end.
    pub valid_before: SystemTime,
}

/// Build the signing request from the inner public key + session token. Kept
/// separate so a test can assert the request carries **only** the public key and
/// the token — never any private-key material (D2/§15).
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

/// Call `SignSessionCertificate` over the authenticated mTLS `channel`,
/// presenting the single-use `session_token` and the inner keypair's public key
/// (only). Returns the signed certificate; the inner private key stays on the
/// Gateway. Any CP refusal fails closed (no certificate).
///
/// `timeout` bounds the whole call independently of the channel's own deadline,
/// so a hung CP can never hang the (future S7/S8) SSH handshake (§10.3).
pub async fn sign_session_certificate(
    channel: Channel,
    session_token: &str,
    inner: &InnerKeyPair,
    context: Option<SignContext>,
    timeout: Duration,
) -> Result<SignedInnerCert, SigningError> {
    let request = build_request(session_token, inner.public_key_openssh_wire(), context);
    // Inject the current span's W3C trace context into this RPC (OTEL-CONTRACT §2.1).
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

/// Convert CP-supplied epoch seconds to a [`SystemTime`] with **checked** math,
/// clamping to `UNIX_EPOCH` on overflow. These validity fields are advisory —
/// the OpenSSH certificate itself carries the authoritative window the node
/// enforces — so a hostile/corrupt value is clamped rather than propagated as an
/// error; the important property is that it never panics (overflow-checks on).
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
        // The OpenSSH ecdsa-sha2-nistp256 public blob begins with the
        // length-prefixed key-type string.
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
        // Key-custody proof (D2/§15): what we would transmit contains the token
        // and the public wire blob — and NO fragment of the private key.
        let kp = InnerKeyPair::generate().unwrap();
        let priv_pem = kp.private_key_openssh_pem().unwrap();
        let req = build_request("tok-123", kp.public_key_openssh_wire(), None);

        assert_eq!(req.session_token, "tok-123");
        assert_eq!(req.subject_public_key, kp.public_key_openssh_wire());
        // The private key material must not appear anywhere in the request.
        assert_ne!(
            req.subject_public_key,
            priv_pem.as_bytes(),
            "request must not carry the private key"
        );
        // A distinctive middle slice of the private PEM must be absent from the
        // transmitted public blob.
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
        // Server-side CP faults → CP-down (service-unavailable); a token rejection
        // stays a node/policy fault (NodeUnreachable) — F-signclass-1.
        assert!(SigningError::Unavailable.is_cp_down());
        assert!(SigningError::Timeout(Duration::from_secs(1)).is_cp_down());
        assert!(SigningError::Rpc(tonic::Status::internal("x")).is_cp_down());
        assert!(SigningError::Rpc(tonic::Status::unavailable("x")).is_cp_down());
        assert!(!SigningError::Rpc(tonic::Status::permission_denied("token")).is_cp_down());
        assert!(!SigningError::Rpc(tonic::Status::unauthenticated("token")).is_cp_down());
        assert!(!SigningError::EmptyCertificate.is_cp_down());
    }
}
