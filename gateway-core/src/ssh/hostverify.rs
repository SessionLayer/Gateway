//! Node host-identity verification — **no TOFU**.
//!
//! Two anchors, checked in order: a CP-supplied host cert verified against the trusted
//! host-CA key(s) and BOUND to the plain host key the node presents at KEX, then an
//! explicitly pinned host key. Anything else is an abort — never trust-on-first-use.

use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::Fingerprint;
use russh::keys::{Certificate, HashAlg, PublicKey};

#[derive(Clone, Default)]
pub(crate) struct HostTrust {
    pub host_ca_keys: Vec<Vec<u8>>,
    pub expected_principals: Vec<String>,
    pub host_certificates: Vec<Vec<u8>>,
    pub pinned_host_keys: Vec<Vec<u8>>,
}

impl HostTrust {
    /// Whether the CP supplied any verification anchor at all. An agentless node
    /// with none is a misconfiguration; the Gateway MUST abort (never TOFU).
    pub fn is_empty(&self) -> bool {
        self.host_ca_keys.is_empty()
            && self.host_certificates.is_empty()
            && self.pinned_host_keys.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostVerified {
    HostCa,
    Pinned,
}

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum HostVerifyError {
    #[error("no host-verification material supplied for the node (misconfiguration; never TOFU)")]
    NoMaterial,
    #[error("presented host key matched neither a trusted host-CA cert nor a pinned key")]
    Untrusted,
}

/// The no-TOFU host-identity verifier built from the CP's [`HostTrust`].
pub(crate) struct HostVerifier {
    trust: HostTrust,
}

impl HostVerifier {
    pub fn new(trust: HostTrust) -> Self {
        Self { trust }
    }

    pub fn verify(&self, key: &PublicKey) -> Result<HostVerified, HostVerifyError> {
        if self.trust.is_empty() {
            return Err(HostVerifyError::NoMaterial);
        }
        if self.verify_host_ca(key) {
            return Ok(HostVerified::HostCa);
        }
        if self.verify_pinned(key) {
            return Ok(HostVerified::Pinned);
        }
        Err(HostVerifyError::Untrusted)
    }

    /// A CP-provided host cert verifies iff it is signed by a trusted host CA,
    /// currently valid, `type = host`, carries an expected principal, AND its
    /// certified key equals the plain key the node presented at KEX.
    fn verify_host_ca(&self, presented: &PublicKey) -> bool {
        if self.trust.host_certificates.is_empty() || self.trust.host_ca_keys.is_empty() {
            return false;
        }
        // Require an explicit expected principal for the host-CA path: an
        // unconstrained host cert cannot be tied to THIS node (fail closed).
        if self.trust.expected_principals.is_empty() {
            return false;
        }
        let ca_fingerprints: Vec<Fingerprint> = self
            .trust
            .host_ca_keys
            .iter()
            .filter_map(|b| PublicKey::from_bytes(b).ok())
            .map(|k| k.fingerprint(HashAlg::Sha256))
            .collect();
        if ca_fingerprints.is_empty() {
            return false;
        }
        let now = unix_now();
        self.trust.host_certificates.iter().any(|blob| {
            let Ok(cert) = Certificate::from_bytes(blob) else {
                return false;
            };
            cert.cert_type() == CertType::Host
                && cert.validate_at(now, &ca_fingerprints).is_ok()
                && cert
                    .valid_principals()
                    .iter()
                    .any(|p| self.trust.expected_principals.iter().any(|e| e == p))
                && cert.public_key() == presented.key_data()
        })
    }

    fn verify_pinned(&self, presented: &PublicKey) -> bool {
        self.trust.pinned_host_keys.iter().any(|b| {
            PublicKey::from_bytes(b)
                .map(|k| k.key_data() == presented.key_data())
                .unwrap_or(false)
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::PrivateKey;

    fn host_key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    #[test]
    fn no_material_aborts_never_tofu() {
        let v = HostVerifier::new(HostTrust::default());
        let key = host_key(1);
        assert!(matches!(
            v.verify(key.public_key()),
            Err(HostVerifyError::NoMaterial)
        ));
    }

    #[test]
    fn pinned_key_match_verifies() {
        let node = host_key(2);
        let trust = HostTrust {
            pinned_host_keys: vec![node.public_key().to_bytes().unwrap()],
            ..HostTrust::default()
        };
        assert_eq!(
            HostVerifier::new(trust).verify(node.public_key()).unwrap(),
            HostVerified::Pinned
        );
    }

    #[test]
    fn unknown_key_aborts_no_tofu() {
        let pinned = host_key(3);
        let impostor = host_key(4);
        let trust = HostTrust {
            pinned_host_keys: vec![pinned.public_key().to_bytes().unwrap()],
            ..HostTrust::default()
        };
        assert!(matches!(
            HostVerifier::new(trust).verify(impostor.public_key()),
            Err(HostVerifyError::Untrusted)
        ));
    }

    #[test]
    fn host_ca_material_without_a_cert_does_not_verify() {
        // host_ca_keys present but no cert → the host-CA path cannot verify; with
        // no pin either, the result is an abort (fail closed).
        let ca = host_key(5);
        let node = host_key(6);
        let trust = HostTrust {
            host_ca_keys: vec![ca.public_key().to_bytes().unwrap()],
            expected_principals: vec!["node1".to_string()],
            host_certificates: Vec::new(),
            pinned_host_keys: Vec::new(),
        };
        assert!(HostVerifier::new(trust).verify(node.public_key()).is_err());
    }

    #[test]
    fn is_empty_detects_missing_anchors() {
        assert!(HostTrust::default().is_empty());
        let node = host_key(7);
        let trust = HostTrust {
            pinned_host_keys: vec![node.public_key().to_bytes().unwrap()],
            ..HostTrust::default()
        };
        assert!(!trust.is_empty());
    }
}
